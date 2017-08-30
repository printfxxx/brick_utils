/*
 * Copyright (C) 2016
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	dpaa.c
 * @brief	DPAA ethernet driver for simplebit
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/kallsyms.h>
#include <linux/etherdevice.h>
#include <linux/cpumask.h>
#include <linux/percpu.h>
#include <linux/of.h>
#include <linux/of_mdio.h>

#include "netdev.h"
#include "worker.h"
#include "qman.h"
#include "bman.h"
#include "dpaa_eth.h"
#include "dpaa_eth_base.h"
#include "dpaa_eth_common.h"
#include "mac.h"

#include "mtrace.h"

#define INV_BPID	(0xffff)
#define INV_FQID	(0xffffffff)

#define DEFINE_KSYM_PTR(x)	typeof(x) *ksym_##x

typedef struct qportal_info {
	struct qman_portal *p;
	struct qm_portal_config *cfg;
} qportal_info_t;

typedef struct bportal_info {
	struct bman_portal *p;
	struct bm_portal_config *cfg;
} bportal_info_t;

typedef struct dpaa_fq {
	struct qman_fq fq;
	struct net_device *ndev;
} ____cacheline_aligned dpaa_fq_t;

typedef struct dpaa_ndev {
	uint16_t rx_ch;
	uint32_t rx_pcd_fq_nr;
	struct bman_pool *rx_bp, *tx_drain_bp;
	dpaa_fq_t *rx_err_fq, *rx_def_fq, *rx_pcd_fqs,
		  *tx_err_fq, *tx_fqs, *tx_conf_fq;
	struct dpa_bp *dpa_bp;
	struct net_device *ndev;
	struct mac_device *mdev;
	struct list_head node;
} dpaa_ndev_t;

static DEFINE_KSYM_PTR(qm_get_unused_portal);
static DEFINE_KSYM_PTR(qm_put_unused_portal);
static DEFINE_KSYM_PTR(bm_get_unused_portal);
static DEFINE_KSYM_PTR(bm_put_unused_portal);

static bool use_tx_conf = false;
static unsigned long skb_buf_nr = 2048;
static LIST_HEAD(dpaa_eth_priv_list);
static DEFINE_PER_CPU(qportal_info_t, cpu_qportal_infos);
static DEFINE_PER_CPU(bportal_info_t, cpu_bportal_infos);

module_param_named(tx_conf, use_tx_conf, bool, S_IRUGO);
MODULE_PARM_DESC(tx_conf, "Use tx confirm");

module_param_named(bufs, skb_buf_nr, ulong, S_IRUGO);
MODULE_PARM_DESC(bufs, "Number of skb buffers");

static void affine_qportal_acquire(void *arg)
{
	unsigned int cpu;
	qportal_info_t *info;

	cpu = smp_processor_id();
	info = per_cpu_ptr(&cpu_qportal_infos, cpu);

	if (!(info->cfg = ksym_qm_get_unused_portal())) {
		pr_err("CPU %u: failed to get qman portal\n", cpu);
		goto err;
	}
	info->cfg->public_cfg.is_shared = 0;
	info->cfg->public_cfg.cpu = cpu;

	return;
err:
	return;
}

static void affine_qportal_release(void *arg)
{
	qportal_info_t *info;

	info = this_cpu_ptr(&cpu_qportal_infos);
	if (info->cfg) {
		ksym_qm_put_unused_portal(info->cfg);
		info->cfg = NULL;
	}
}

static int cpu_qportal_create(unsigned int cpu)
{
	int rc;
	qportal_info_t *info;

	info = per_cpu_ptr(&cpu_qportal_infos, cpu);
	if (!(info->p = qman_create_affine_portal(info->cfg, NULL))) {
		pr_err("CPU %u: failed to create qman portal\n", cpu);
		rc = -EIO;
		goto err;
	}

	return 0;
err:
	return rc;
}

static void cpu_qportal_destroy(void *arg)
{
	unsigned long irqflags;
	qportal_info_t *info;
	const struct qm_portal_config *cfg;

	info = this_cpu_ptr(&cpu_qportal_infos);

	if (info->p) {
		local_irq_save(irqflags);
		cfg = qman_destroy_affine_portal();
		local_irq_restore(irqflags);
		BUG_ON(info->cfg != cfg);
		info->p = NULL;
	}
}

static void affine_bportal_acquire(void *arg)
{
	unsigned int cpu;
	bportal_info_t *info;

	cpu = smp_processor_id();
	info = per_cpu_ptr(&cpu_bportal_infos, cpu);

	if (!(info->cfg = ksym_bm_get_unused_portal())) {
		pr_err("CPU %u: failed to get bman portal\n", cpu);
		goto err;
	}
	info->cfg->public_cfg.is_shared = 0;
	info->cfg->public_cfg.cpu = cpu;

	return;
err:
	return;
}

static void affine_bportal_release(void *arg)
{
	bportal_info_t *info;

	info = this_cpu_ptr(&cpu_bportal_infos);
	if (info->cfg) {
		ksym_bm_put_unused_portal(info->cfg);
		info->cfg = NULL;
	}
}

static int cpu_bportal_create(unsigned int cpu)
{
	int rc;
	bportal_info_t *info;

	info = per_cpu_ptr(&cpu_bportal_infos, cpu);
	if (!(info->p = bman_create_affine_portal(info->cfg))) {
		pr_err("CPU %u: failed to create bman portal\n", cpu);
		rc = -EIO;
		goto err;
	}

	return 0;
err:
	return rc;
}

static void cpu_bportal_destroy(void *arg)
{
	unsigned long irqflags;
	bportal_info_t *info;
	const struct bm_portal_config *cfg;

	info = this_cpu_ptr(&cpu_bportal_infos);

	if (info->p) {
		local_irq_save(irqflags);
		cfg = bman_destroy_affine_portal();
		local_irq_restore(irqflags);
		BUG_ON(info->cfg != cfg);
		info->p = NULL;
	}
}

static int dpaa_eth_proxy_match(struct device *dev, void *data)
{
	struct device *mac_dev, *fm_dev;
	struct mac_device *mdev;
	struct proxy_device *proxy_dev;

	if (!(dev->of_node == data)
	||  !(proxy_dev = dev_get_drvdata(dev))
	||  !(mdev = proxy_dev->mac_dev)
	||  !(mac_dev = mdev->dev)
	||  !(mac_dev->of_node)
	||  !(fm_dev = mac_dev->parent)
	||  !(fm_dev->of_node)) {
		return 0;
	} else {
		return 1;
	}
}

static int dpaa_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	unsigned int txq;
	dma_addr_t baddr;
	dpaa_ndev_t *netdev;
	struct sk_buff **skbh;
	struct qman_fq *fq;
	struct qm_fd fd = {
		.format = qm_fd_contig,
	};

	if (skb_headroom(skb) < NET_SKB_PAD) {
		goto err;
	}
	skbh = (void *)skb->data;
	skbh--;
	*skbh = skb;
 	baddr = phys_to_dma(ndev->dev.parent, virt_to_phys(skb->data));
	BUG_ON(!baddr);
	txq = skb_get_queue_mapping(skb);
	netdev = netdev_priv(ndev);
	if (txq >= ndev->real_num_tx_queues) {
		txq = txq % ndev->real_num_tx_queues;
	}
	fq = &netdev->tx_fqs[txq].fq;
	qm_fd_addr_set64(&fd, baddr);
	fd.length20 = skb->len;
	if (!use_tx_conf) {
		fd.bpid = bman_get_params(netdev->tx_drain_bp)->bpid;
	}
	if (mtrace_skb_add(skb)) {
		goto err;
	}
	if (qman_enqueue(fq, &fd, 0)) {
		mtrace_skb_del(skb);
		goto err;
	}

	return NETDEV_TX_OK;
err:
	return NETDEV_TX_BUSY;
}

static struct net_device_ops dpaa_netdev_ops = {
	.ndo_start_xmit = dpaa_start_xmit,
};

static void dpaa_netdev_poll(struct net_device *ndev, unsigned int limit, bool stride)
{
	int i, ret;
	dma_addr_t baddr;
	dpaa_ndev_t *netdev;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	struct bm_buffer bufs[8];

	qman_poll_dqrr(limit);

	if (use_tx_conf) {
		goto end;
	}

	netdev = netdev_priv(ndev);
	dev = ndev->dev.parent;
	ret = 8;
	do {
		if (ret == 8) {
			ret = bman_acquire(netdev->tx_drain_bp, bufs, 8, 0);
		}
		if (ret == 8) {
			stride = true;
		} else if (!stride) {
			ret = bman_acquire(netdev->tx_drain_bp, bufs, 1, 0);
		}
		for (i = 0; i < ret; i++) {
			baddr = bm_buffer_get64(&bufs[i]);
			skbh = phys_to_virt(dma_to_phys(dev, baddr));
			skbh--;
			skb = *skbh;
			dev_kfree_skb(skb);
		}
	} while (ret > 0);
end:
	return;
}

static netdev_priv_ops_t dpaa_ndev_ops = {
	.netdev_poll = dpaa_netdev_poll,
};

static struct bman_pool *dpaa_bpool_init(struct net_device *ndev, uint32_t bpid, size_t sz, unsigned long nr)
{
	int i, rc, ret;
	dma_addr_t baddr;
	unsigned long cnt;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	struct bm_buffer bufs[8];
	struct bman_pool *pool = NULL;
	struct bman_pool_params params = {};

	if (bpid != INV_BPID) {
		if ((rc = bman_reserve_bpid(bpid))) {
			netdev_err(ndev, "failed to reserve bpool %u\n", bpid);
			goto err;
		}
	} else {
		if ((rc = bman_alloc_bpid(&bpid))) {
			netdev_err(ndev, "failed to alloc bpool\n");
			goto err;
		}
	}
	params.bpid = bpid;
	params.flags = BMAN_POOL_FLAG_THRESH;
	if (!(pool = bman_new_pool(&params))) {
		bman_release_bpid(bpid);
		netdev_err(ndev, "failed to create bpool\n");
		goto err;
	}

	cnt = 0;
	ret = 8;
	do {
		if (ret == 8) {
			ret = bman_acquire(pool, bufs, 8, 0);
		}
		if (ret < 8) {
			ret = bman_acquire(pool, bufs, 1, 0);
		}
		cnt += (ret > 0) ? ret : 0;
	} while (ret > 0);

	if (cnt) {
		netdev_warn(ndev, "bpool %u: drained %lu bufs\n", bman_get_params(pool)->bpid, cnt);
	}

	dev = ndev->dev.parent;
	for (cnt = 0; cnt < nr;) {
		ret = nr - cnt;
		ret =min(ret, 8);
		memset(bufs, 0, sizeof(bufs[0]) * ret);
		for (i = 0; i < ret; i++) {
			if (!(skb = __netdev_alloc_skb(ndev, sz, GFP_KERNEL | GFP_DMA))
			||  (skb_headroom(skb) < NET_SKB_PAD)) {
				while (i--) {
					baddr = bm_buffer_get64(&bufs[i]);
					skbh = phys_to_virt(dma_to_phys(dev, baddr));
					skbh--;
					skb = *skbh;
					dev_kfree_skb(skb);
				}
				goto err;
			}
			skbh = (void *)skb->data;
			skbh--;
			*skbh = skb;
			baddr = phys_to_dma(dev, virt_to_phys(skb->data));
			BUG_ON(!baddr);
			bm_buffer_set64(&bufs[i], baddr);
		}

		do {
			rc = bman_release(pool, bufs, ret, 0);
		} while (rc == -EBUSY);
		BUG_ON(rc);
		cnt += ret;
	}

	if (cnt) {
		netdev_info(ndev, "bpool %u: released %lu bufs\n", bman_get_params(pool)->bpid, cnt);
	}

	return pool;
err:
	if (pool) {
		ret = 8;
		do {
			if (ret == 8) {
				ret = bman_acquire(pool, bufs, 8, 0);
			}
			if (ret < 8) {
				ret = bman_acquire(pool, bufs, 1, 0);
			}
			for (i = 0; i < ret; i++) {
				baddr = bm_buffer_get64(&bufs[i]);
				skbh = phys_to_virt(dma_to_phys(dev, baddr));
				skbh--;
				skb = *skbh;
				dev_kfree_skb(skb);
			}
		} while (ret > 0);
	}
	return NULL;
}

static void dpaa_bpool_clean(struct net_device *ndev, struct bman_pool *pool)
{
	int i, ret;
	dma_addr_t baddr;
	unsigned long cnt;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	struct bm_buffer bufs[8];

	dev = ndev->dev.parent;
	cnt = 0;
	ret = 8;
	do {
		if (ret == 8) {
			ret = bman_acquire(pool, bufs, 8, 0);
		}
		if (ret < 8) {
			ret = bman_acquire(pool, bufs, 1, 0);
		}
		for (i = 0; i < ret; i++) {
			baddr = bm_buffer_get64(&bufs[i]);
			skbh = phys_to_virt(dma_to_phys(dev, baddr));
			skbh--;
			skb = *skbh;
			dev_kfree_skb(skb);
		}
		cnt += (ret > 0) ? ret : 0;
	} while (ret > 0);

	if (cnt) {
		netdev_info(ndev, "bpool %u: drained %lu bufs\n", bman_get_params(pool)->bpid, cnt);
	}

	bman_free_pool(pool);
}

static dpaa_fq_t *dpaa_fq_init(struct net_device *ndev, uint32_t start, uint32_t count,
			       uint32_t conf, uint16_t channel, qman_cb_dqrr dqrr)
{
	int s, rc;
	uint32_t i, flags;
	dpaa_fq_t *dpaa_fq, **fqh;
	struct device *dev;
	struct qman_fq *fq;
	enum qman_fq_state state;
	struct qm_mcc_initfq opts = {};

	dev = ndev->dev.parent;

	if (!(dpaa_fq = devm_kzalloc(dev, sizeof(*dpaa_fq) * count + L1_CACHE_BYTES, GFP_KERNEL))) {
		netdev_err(ndev, "failed to alloc dev memory\n");
		goto err;
	}
	fqh = (void *)PTR_ALIGN(dpaa_fq, L1_CACHE_BYTES) + L1_CACHE_BYTES;
	*(fqh - 1) = dpaa_fq;
	dpaa_fq = (void *)fqh;

	if (start != INV_FQID) {
		if ((rc = qman_reserve_fqid_range(start, count))) {
			netdev_err(ndev, "failed to reserve fqids at %x:%x\n", start, count);
			goto err_reserve;
		}
	} else {
		if ((rc = qman_alloc_fqid_range(&start, count, 0, 0)) < 0) {
			netdev_err(ndev, "failed to alloc %u fqids\n", count);
			goto err_alloc;
		}
	}

	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL;
	opts.fqd.dest.channel = channel;
	opts.fqd.dest.wq = dqrr ? 4 : 3;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;

	if (dqrr) {
		flags = QMAN_FQ_FLAG_NO_ENQUEUE;
		opts.fqd.fq_ctrl |= count > 1 ? QM_FQCTRL_HOLDACTIVE : QM_FQCTRL_AVOIDBLOCK;
	} else {
		flags = QMAN_FQ_FLAG_TO_DCPORTAL;
		opts.we_mask |= QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_CONTEXTB;
		opts.fqd.context_a.hi = FM_CONTEXTA_OVERRIDE_MASK;
		if (conf != INV_FQID) {
			opts.fqd.context_b = conf;
		} else {
#ifdef FMAN_V3
#define FMAN_V3_CONTEXTA_A2V	0x10000000
#define FMAN_V3_CONTEXTA_OVOM	0x02000000
#define FMAN_V3_CONTEXTA_EBD	0x80000000
			opts.fqd.context_a.hi |= FMAN_V3_CONTEXTA_A2V | FMAN_V3_CONTEXTA_OVOM;
			opts.fqd.context_a.lo = FMAN_V3_CONTEXTA_EBD;
#endif
		}
	}

	for (i = 0; i < count; i++) {
		dpaa_fq[i].ndev = ndev;
		fq = &dpaa_fq[i].fq;
		fq->cb.dqrr = dqrr;
		if ((rc = qman_create_fq(start + i, flags, fq))) {
			netdev_err(dpaa_fq->ndev, "failed to create fq %x\n", start + i);
			goto err_create;
		}
		if ((rc = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts))) {
			netdev_err(dpaa_fq->ndev, "failed to init fq %x\n", start + i);
			qman_destroy_fq(fq, 0);
			goto err_init;
		}
	}

	return dpaa_fq;

err_init:
err_create:
	while (i--) {
		fq = &dpaa_fq[i].fq;
		s = qman_retire_fq(fq, &flags);
		if (s == 1) {
			do {
				qman_poll_dqrr(16);
				qman_fq_state(fq, &state, &flags);
			} while (state != qman_fq_state_retired);
			if (flags & QMAN_FQ_STATE_NE) {
				s = qman_volatile_dequeue(fq, 0, QM_VDQCR_NUMFRAMES_TILLEMPTY);
				BUG_ON(s);
				do {
					qman_poll_dqrr(16);
					qman_fq_state(fq, &state, &flags);
				} while (flags & QMAN_FQ_STATE_VDQCR);
			}
		}
		s = qman_oos_fq(fq);
		BUG_ON(s);
		qman_destroy_fq(fq, 0);
	}
	qman_release_fqid_range(start, count);
err_alloc:
err_reserve:
	fqh = (void *)dpaa_fq;
	fqh--;
	dpaa_fq = *fqh;
	devm_kfree(dev, dpaa_fq);
err:
	return NULL;
}

static void dpaa_fq_clean(struct net_device *ndev, dpaa_fq_t *dpaa_fq, uint32_t count)
{
	int s;
	uint32_t i, flags;
	dpaa_fq_t **fqh;
	struct device *dev;
	struct qman_fq *fq;
	enum qman_fq_state state;

	dev = ndev->dev.parent;

	for (i = 0; i < count; i++) {
		fq = &dpaa_fq[i].fq;
		s = qman_retire_fq(fq, &flags);
		if (s == 1) {
			do {
				qman_poll_dqrr(16);
				qman_fq_state(fq, &state, &flags);
			} while (state != qman_fq_state_retired);
			if (flags & QMAN_FQ_STATE_NE) {
				s = qman_volatile_dequeue(fq, 0, QM_VDQCR_NUMFRAMES_TILLEMPTY);
				BUG_ON(s);
				do {
					qman_poll_dqrr(16);
					qman_fq_state(fq, &state, &flags);
				} while (flags & QMAN_FQ_STATE_VDQCR);
			}
		}
		s = qman_oos_fq(fq);
		BUG_ON(s);
		qman_destroy_fq(fq, 0);
	}

	fqh = (void *)dpaa_fq;
	fqh--;
	dpaa_fq = *fqh;
	devm_kfree(dev, dpaa_fq);
}

static void dpaa_recycle_skb(struct net_device *ndev, struct sk_buff *skb, dma_addr_t baddr)
{
	int rc;
	dpaa_ndev_t *netdev;
	struct sk_buff **skbh;
	struct bm_buffer buf = {};

	BUG_ON(atomic_read(&skb->users) != 1);

	skb->data = skb->head + NET_SKB_PAD;
	skb_reset_tail_pointer(skb);
	skb->len = 0;
	skbh = (void *)skb->data;
	skbh--;
	skb = *skbh;
	netdev = netdev_priv(ndev);
	bm_buffer_set64(&buf, baddr);
	do {
		rc = bman_release(netdev->rx_bp, &buf, 1, 0);
	} while (rc == -EBUSY);

	BUG_ON(rc);
}

static enum qman_cb_dqrr_result dpaa_rx_err_dqrr(struct qman_portal *p,
						 struct qman_fq *fq,
						 const struct qm_dqrr_entry *dqrr)
{
	dpaa_fq_t *dpaa_fq;
	dma_addr_t baddr;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	const struct qm_fd *fd;

	fd = &dqrr->fd;
	dpaa_fq = container_of(fq, struct dpaa_fq, fq);
	dev = dpaa_fq->ndev->dev.parent;
	baddr = qm_fd_addr_get64(fd);
	skbh = phys_to_virt(dma_to_phys(dev, baddr));
	skbh--;
	skb = *skbh;

	dpaa_recycle_skb(dpaa_fq->ndev, skb, baddr);

	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result dpaa_rx_def_dqrr(struct qman_portal *p,
						 struct qman_fq *fq,
						 const struct qm_dqrr_entry *dqrr)
{
	dpaa_fq_t *dpaa_fq;
	dma_addr_t baddr;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	struct net_device *ndev;
	const struct qm_fd *fd;

	fd = &dqrr->fd;
	dpaa_fq = container_of(fq, struct dpaa_fq, fq);
	ndev = dpaa_fq->ndev;
	dev = ndev->dev.parent;
	baddr = qm_fd_addr_get64(fd);
	skbh = phys_to_virt(dma_to_phys(dev, baddr));
	skbh--;
	skb = *skbh;
	skb_reserve(skb, fd->offset);
	skb_put(skb, fd->length20);
	skb_reset_mac_header(skb);
	skb_pull(skb, ETH_HLEN);
	dummy_netdev_receive(skb, ndev);

	dpaa_recycle_skb(ndev, skb, baddr);

	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result dpaa_tx_err_dqrr(struct qman_portal *p,
						 struct qman_fq *fq,
						 const struct qm_dqrr_entry *dqrr)
{
	dpaa_fq_t *dpaa_fq;
	dma_addr_t baddr;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	const struct qm_fd *fd;

	fd = &dqrr->fd;
	dpaa_fq = container_of(fq, struct dpaa_fq, fq);
	dev = dpaa_fq->ndev->dev.parent;
	baddr = qm_fd_addr_get64(fd);
	skbh = phys_to_virt(dma_to_phys(dev, baddr));
	skbh--;
	skb = *skbh;
	dev_kfree_skb(skb);

	return qman_cb_dqrr_consume;
}

static enum qman_cb_dqrr_result dpaa_tx_conf_dqrr(struct qman_portal *p,
						  struct qman_fq *fq,
						  const struct qm_dqrr_entry *dqrr)
{
	dpaa_fq_t *dpaa_fq;
	dma_addr_t baddr;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	const struct qm_fd *fd;

	fd = &dqrr->fd;
	dpaa_fq = container_of(fq, struct dpaa_fq, fq);
	dev = dpaa_fq->ndev->dev.parent;
	baddr = qm_fd_addr_get64(fd);
	skbh = phys_to_virt(dma_to_phys(dev, baddr));
	skbh--;
	skb = *skbh;
	dev_kfree_skb(skb);

	return qman_cb_dqrr_consume;
}

static void dpaa_netdev_cpu_bind(void *arg)
{
	uint32_t sdqcr;
	dpaa_ndev_t *netdev = arg;

	netdev_dbg(netdev->ndev, "bind to cpu %u\n", smp_processor_id());

	sdqcr = QM_SDQCR_CHANNELS_POOL_CONV(netdev->rx_ch);
	qman_static_dequeue_add(sdqcr);
}

static void dpaa_netdev_cpu_unbind(void *arg)
{
	uint32_t sdqcr;
	dpaa_ndev_t *netdev = arg;

	netdev_dbg(netdev->ndev, "unbind from cpu %u\n", smp_processor_id());

	sdqcr = QM_SDQCR_CHANNELS_POOL_CONV(netdev->rx_ch);
	qman_static_dequeue_del(sdqcr);
}

static void dpaa_netdev_bind(dpaa_ndev_t *netdev)
{
	cpumask_t cpumask;

	get_worker_cpumask(&cpumask);

	on_each_cpu_mask(&cpumask, dpaa_netdev_cpu_bind, netdev, 1);
}

static void dpaa_netdev_unbind(dpaa_ndev_t *netdev)
{
	cpumask_t cpumask;

	get_worker_cpumask(&cpumask);

	on_each_cpu_mask(&cpumask, dpaa_netdev_cpu_unbind, netdev, 1);
}

static int dpaa_netdev_start(dpaa_ndev_t *netdev)
{
	int i, rc;
	bool rx_pause, tx_pause;
	struct net_device *ndev;
	struct mac_device *mdev;
	struct phy_device *pdev;
	struct fm_mac_dev *fm_mdev;

	ndev = netdev->ndev;
	mdev = netdev->mdev;
	pdev = mdev->phy_dev;
	fm_mdev = mdev->get_mac_handle(mdev);

	for_each_port_device(i, mdev->port_dev) {
		if ((rc = fm_port_enable(mdev->port_dev[i]))) {
			netdev_err(ndev, "failed to enable port %d\n", i);
			goto err;
		}
	}

	if ((rc = phy_read_status(pdev))) {
		netdev_err(ndev, "failed to read phy status\n");
		goto err;
	}
	netdev_dbg(ndev, "link=%d, speed=%d, duplex=%d", pdev->link, pdev->speed, pdev->duplex);

	if ((rc = fm_mac_adjust_link(fm_mdev, pdev->link, pdev->speed, pdev->duplex))) {
		netdev_err(ndev, "failed to adjust link\n");
		goto err;
	}

	get_pause_cfg(mdev, &rx_pause, &tx_pause);
	netdev_dbg(ndev, "rx_pause=%d, tx_pause=%d", rx_pause, tx_pause);
	if ((rc = set_mac_active_pause(mdev, rx_pause, tx_pause))) {
		netdev_err(ndev, "failed to set active pause\n");
		goto err;
	}

	if ((rc = fm_mac_set_promiscuous(fm_mdev, true))) {
		netdev_err(ndev, "failed to enable promiscuous\n");
		goto err;
	}

	if ((rc = fm_mac_enable(fm_mdev))) {
		netdev_err(ndev, "failed to enable mac\n");
		goto err;
	}

	phy_start(pdev);

	return 0;
err:
	for_each_port_device(i, mdev->port_dev) {
		fm_port_disable(mdev->port_dev[i]);
	}
	return rc;
}

static void dpaa_netdev_stop(dpaa_ndev_t *netdev)
{
	int i;
	struct net_device *ndev;
	struct mac_device *mdev;
	struct phy_device *pdev;
	struct fm_mac_dev *fm_mdev;

	ndev = netdev->ndev;
	mdev = netdev->mdev;
	pdev = mdev->phy_dev;
	fm_mdev = mdev->get_mac_handle(mdev);

	phy_stop(pdev);

	fm_mac_disable(fm_mdev);

	for_each_port_device(i, mdev->port_dev) {
		fm_port_disable(mdev->port_dev[i]);
	}
}

static int dpaa_netdev_add(struct device *dev)
{
	int rc;
	char name[IFNAMSIZ];
	size_t bp_count;
	uint32_t fm_id, mac_id, fqids[6], channel;
	const __be32 *addr;
	dpaa_ndev_t *netdev = NULL;
	struct net_device *ndev = NULL;
	struct device *fm_dev, *mac_dev;
	struct mac_device *mdev;
	struct phy_device *pdev;
	struct proxy_device *proxy_dev;

	proxy_dev = dev_get_drvdata(dev);
	mdev = proxy_dev->mac_dev;
	mac_dev = mdev->dev;
	fm_dev = mac_dev->parent;

	if (!(addr = of_get_address(mac_dev->of_node, 0, NULL, NULL))) {
		pr_err("%s: failed to get mac id\n", mac_dev->of_node->full_name);
		rc = -EINVAL;
		goto err;
	}
	mac_id = (be32_to_cpu(*addr) - 0xe0000) / 0x2000;
	mac_id++;
	if (of_property_read_u32(fm_dev->of_node, "cell-index", &fm_id)) {
		pr_err("%s: failed to get fman id\n", fm_dev->of_node->full_name);
		rc = -EINVAL;
		goto err;
	}
	fm_id++;
	snprintf(name, sizeof(name), "fm%u-mac%u", fm_id, mac_id);
	if (!netdev_in_filter(name)) {
		goto ok;
	}

	if (!(ndev = dummy_netdev_add(sizeof(*netdev), nr_cpu_ids))) {
		pr_err("%s(): failed to add dummy ethernet device\n", __func__);
		rc = -ENOMEM;
		goto err;
	}
	SET_NETDEV_DEV(ndev, dev);
	ndev->netdev_ops = &dpaa_netdev_ops;
	ndev->features |= NETIF_F_LLTX;
	ndev->priv_flags |= IFF_TX_SKB_SHARING;
	memcpy(ndev->name, name, sizeof(name));
	netdev = netdev_priv(ndev);
	INIT_LIST_HEAD(&netdev->node);
	netdev->ndev = ndev;
	netdev->mdev = mdev;

	if ((rc = qman_alloc_pool(&channel))) {
		netdev_err(ndev, "failed to alloc rx channel\n");
		goto err_alloc_ch;
	}
	netdev->rx_ch = channel;
	netdev_dbg(ndev, "rx_ch=%x\n", netdev->rx_ch);

	netdev->dpa_bp = dpa_bp_probe(to_platform_device(dev), &bp_count);
	if (IS_ERR(netdev->dpa_bp)) {
		netdev_err(ndev, "failed to probe bpools\n");
		rc = PTR_ERR(netdev->dpa_bp);
		goto err_bp_probe;
	}
	if (mtrace_devm_add(netdev->dpa_bp)) {
		notrace_devm_kfree(dev, netdev->dpa_bp);
		rc = -ENOMEM;
		goto err_bp_probe;
	}
	netdev_dbg(ndev, "bpool[%u]: size=%zu\n", netdev->dpa_bp[0].bpid, netdev->dpa_bp[0].size);
	if (bp_count != 1) {
		netdev_err(ndev, "only support one bpool\n");
		rc = -EINVAL;
		goto err_bp_check;
	}
	if (netdev->dpa_bp[0].size < dpa_get_max_frm()) {
		netdev_err(ndev, "bpool size smaller than maximum frame size\n");
		rc = -EINVAL;
		goto err_bp_check;
	}

	if (!(netdev->rx_bp = dpaa_bpool_init(ndev, netdev->dpa_bp[0].bpid, netdev->dpa_bp[0].size, skb_buf_nr))) {
		netdev_err(ndev, "failed to init rx_bp\n");
		rc = -ENODEV;
		goto err_rx_bp;
	}

	if (!use_tx_conf && !(netdev->tx_drain_bp = dpaa_bpool_init(ndev, INV_BPID, 0, 0))) {
		netdev_err(ndev, "failed to init tx_drain_bp\n");
		rc = -ENODEV;
		goto err_tx_drain_bp;
	}

	fqids[4] = 0;
	fqids[5] = 0;
	if ((rc = of_property_read_u32_array(dev->of_node, "fsl,qman-frame-queues-rx", fqids, 6))
	&&  (rc = of_property_read_u32_array(dev->of_node, "fsl,qman-frame-queues-rx", fqids, 4))) {
		netdev_err(ndev, "failed to get property \"fsl,qman-frame-queues-rx\"\n");
		goto err_rx_cfg;
	}
	netdev_dbg(ndev, "rx_err_fqid=%x, rx_def_fqid=%x, rx_pcd_fqid=%x:%x\n", fqids[0], fqids[2], fqids[4], fqids[5]);
	if (!fqids[0]) {
		netdev_err(ndev, "failed to get rx_err_fqid\n");
		rc = -EINVAL;
		goto err_rx_cfg;
	}
	if (!fqids[2]) {
		netdev_err(ndev, "failed to get rx_def_fqid\n");
		rc = -EINVAL;
		goto err_rx_cfg;
	}
	if (!fqids[4] && fqids[5]) {
		netdev_err(ndev, "failed to get rx_pcd_fqid\n");
		rc = -EINVAL;
		goto err_rx_cfg;
	}
	if (!(netdev->rx_err_fq = dpaa_fq_init(ndev, fqids[0], 1, INV_FQID, netdev->rx_ch, dpaa_rx_err_dqrr))) {
		netdev_err(ndev, "failed to init rx_err_fq\n");
		rc = -ENODEV;
		goto err_rx_err_fq;
	}
	if (!(netdev->rx_def_fq = dpaa_fq_init(ndev, fqids[2], 1, INV_FQID, netdev->rx_ch, dpaa_rx_def_dqrr))) {
		netdev_err(ndev, "failed to init rx_def_fq\n");
		rc = -ENOMEM;
		goto err_rx_def_fq;
	}
	if (fqids[5] && !(netdev->rx_pcd_fqs = dpaa_fq_init(ndev, fqids[4], fqids[5], INV_FQID, netdev->rx_ch, dpaa_rx_def_dqrr))) {
		netdev_err(ndev, "failed to init rx_pcd_fqs\n");
		rc = -ENOMEM;
		goto err_rx_pcd_fqs;
	}
	netdev->rx_pcd_fq_nr = fqids[5];

	if ((rc = of_property_read_u32_array(dev->of_node, "fsl,qman-frame-queues-tx", fqids, 4))) {
		netdev_err(ndev, "failed to get property \"fsl,qman-frame-queues-tx\"\n");
		goto err_tx_cfg;
	}
	netdev_dbg(ndev, "tx_err_fqid=%x\n", fqids[0]);
	if (!fqids[0]) {
		netdev_err(ndev, "failed to get tx_err_fqid\n");
		rc = -EINVAL;
		goto err_tx_cfg;
	}
	if (use_tx_conf) {
		netdev_dbg(ndev, "tx_conf_fqid=%x\n", fqids[2]);
		if (!fqids[2]) {
			netdev_err(ndev, "failed to get tx_conf_fqid\n");
			rc = -EINVAL;
			goto err_tx_cfg;
		}
	} else {
		fqids[2] = INV_FQID;
	}
	if (!(netdev->tx_err_fq = dpaa_fq_init(ndev, fqids[0], 1, INV_FQID, netdev->rx_ch, dpaa_tx_err_dqrr))) {
		netdev_err(ndev, "failed to init tx_err_fq\n");
		rc = -ENODEV;
		goto err_tx_err_fq;
	}
	if (use_tx_conf && !(netdev->tx_conf_fq = dpaa_fq_init(ndev, fqids[2], 1, INV_FQID, netdev->rx_ch, dpaa_tx_conf_dqrr))) {
		netdev_err(ndev, "failed to init tx_conf_fq\n");
		rc = -ENODEV;
		goto err_tx_conf_fq;
	}
	channel = fm_get_tx_port_channel(mdev->port_dev[TX]);
	if (!(netdev->tx_fqs = dpaa_fq_init(ndev, INV_FQID, ndev->real_num_tx_queues, fqids[2], channel, NULL))) {
		netdev_err(ndev, "failed to init tx_fqs\n");
		rc = -ENODEV;
		goto err_tx_fqs;
	}
	netdev_dbg(ndev, "tx_fqids=%x:%x\n", netdev->tx_fqs[0].fq.fqid, ndev->real_num_tx_queues);

	pdev = of_phy_attach(ndev, mdev->phy_node, 0, mdev->phy_if);
	if (IS_ERR_OR_NULL(pdev)) {
		rc = pdev ? PTR_ERR(pdev) : -ENODEV;
		netdev_err(ndev, "failed to attach to phy\n");
		goto err_attach;
	}
	mdev->phy_dev = pdev;
	pdev->supported &= mdev->if_support;
	pdev->supported |= SUPPORTED_Pause | SUPPORTED_Asym_Pause;
	pdev->advertising = pdev->supported;

	dpaa_netdev_bind(netdev);

	list_add_tail(&netdev->node, &dpaa_eth_priv_list);
ok:
	return 0;

err_attach:
	dpaa_fq_clean(ndev, netdev->tx_fqs, ndev->real_num_tx_queues);
err_tx_fqs:
	if (use_tx_conf) {
		dpaa_fq_clean(ndev, netdev->tx_conf_fq, 1);
	}
err_tx_conf_fq:
	dpaa_fq_clean(ndev, netdev->tx_err_fq, 1);
err_tx_err_fq:
err_tx_cfg:
	if (netdev->rx_pcd_fqs) {
		dpaa_fq_clean(ndev, netdev->rx_pcd_fqs, netdev->rx_pcd_fq_nr);
	}
err_rx_pcd_fqs:
	dpaa_fq_clean(ndev, netdev->rx_def_fq, 1);
err_rx_def_fq:
	dpaa_fq_clean(ndev, netdev->rx_err_fq, 1);
err_rx_err_fq:
err_rx_cfg:
	if (!use_tx_conf) {
		dpaa_bpool_clean(ndev, netdev->tx_drain_bp);
	}
err_tx_drain_bp:
	dpaa_bpool_clean(ndev, netdev->rx_bp);
err_rx_bp:
err_bp_check:
	devm_kfree(dev, netdev->dpa_bp);
err_bp_probe:
	qman_release_pool(netdev->rx_ch);
err_alloc_ch:
	dummy_netdev_del(ndev);
err:
	return rc;
}

static void dpaa_netdev_del(dpaa_ndev_t *netdev)
{
	struct net_device *ndev;

	ndev = netdev->ndev;
	list_del(&netdev->node);

	phy_disconnect(netdev->mdev->phy_dev);

	dpaa_netdev_unbind(netdev);

	dpaa_fq_clean(ndev, netdev->tx_fqs, ndev->real_num_tx_queues);
	if (use_tx_conf) {
		dpaa_fq_clean(ndev, netdev->tx_conf_fq, 1);
	}
	dpaa_fq_clean(ndev, netdev->tx_err_fq, 1);
	if (netdev->rx_pcd_fqs) {
		dpaa_fq_clean(ndev, netdev->rx_pcd_fqs, netdev->rx_pcd_fq_nr);
	}
	dpaa_fq_clean(ndev, netdev->rx_def_fq, 1);
	dpaa_fq_clean(ndev, netdev->rx_err_fq, 1);
	if (!use_tx_conf) {
		dpaa_bpool_clean(ndev, netdev->tx_drain_bp);
	}
	dpaa_bpool_clean(ndev, netdev->rx_bp);
	devm_kfree(ndev->dev.parent, netdev->dpa_bp);
	qman_release_pool(netdev->rx_ch);
	dummy_netdev_del(ndev);
}

static int __init dpaa_init(void)
{
	int rc;
	unsigned int i, cpu;
	struct device *dev;
	struct device_node *eth_node;
	dpaa_ndev_t *netdev, *tmp;
	struct {
		void **fn;
		const char *name;
	} ksyms_table[] = {
#define KSYM_TBL_ENTRY(x)	{(void **)&ksym_##x, #x}
		KSYM_TBL_ENTRY(qm_get_unused_portal),
		KSYM_TBL_ENTRY(qm_put_unused_portal),
		KSYM_TBL_ENTRY(bm_get_unused_portal),
		KSYM_TBL_ENTRY(bm_put_unused_portal),
	};

	if ((rc = mtrace_init())) {
		goto err;
	}
#ifdef CONFIG_FSL_QMAN_FQ_LOOKUP
	if ((rc = qman_setup_fq_lookup_table(1024))) {
		goto err_setup_table;
	}
#endif
	for (i = 0; i < ARRAY_SIZE(ksyms_table); i++) {
		if (!(*ksyms_table[i].fn = (void *)kallsyms_lookup_name(ksyms_table[i].name))) {
			pr_err("Failed to get address of \"%s\"\n", ksyms_table[i].name);
			rc = -EFAULT;
			goto err_lookup_syms;
		}
	}

	if ((rc = on_each_cpu(affine_qportal_acquire, NULL, 1))) {
		goto err_qportal_acquire;
	}
	for_each_online_cpu(cpu) {
		if (!per_cpu_ptr(&cpu_qportal_infos, cpu)->cfg) {
			rc = -ENODEV;
			goto err_qportal_acquire;
		}
	}
	for_each_online_cpu(cpu) {
		if ((rc = cpu_qportal_create(cpu))) {
			goto err_qportal_create;
		}
	}

	if ((rc = on_each_cpu(affine_bportal_acquire, NULL, 1))) {
		goto err_bportal_acquire;
	}
	for_each_online_cpu(cpu) {
		if (!per_cpu_ptr(&cpu_bportal_infos, cpu)->cfg) {
			rc = -ENODEV;
			goto err_bportal_acquire;
		}
	}
	for_each_online_cpu(cpu) {
		if ((rc = cpu_bportal_create(cpu))) {
			goto err_bportal_create;
		}
	}

	for_each_compatible_node(eth_node, NULL, "fsl,dpa-ethernet-init") {
		if ((dev = bus_find_device(&platform_bus_type, NULL, eth_node, dpaa_eth_proxy_match))) {
			if ((rc = dpaa_netdev_add(dev))) {
				dev_err(dev, "failed to add netdev\n");
				goto err_netdev_add;
			}
		}
	}

	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		if ((rc = dpaa_netdev_start(netdev))) {
			netdev_err(netdev->ndev, "failed to start netdev\n");
			goto err_netdev_start;
		}
	}

	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		if ((rc = dummy_netdev_notify(netdev->ndev, NETDEV_UP, &dpaa_ndev_ops))) {
			netdev_err(netdev->ndev, "failed to notify netdev\n");
			goto err_netdev_notify;
		}
	}

	return 0;

err_netdev_notify:
	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		dummy_netdev_notify(netdev->ndev, NETDEV_GOING_DOWN, &dpaa_ndev_ops);
	}
err_netdev_start:
	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		dpaa_netdev_stop(netdev);
	}
	/* Waitting for on-the-fly frames finish */
	msleep(MSEC_PER_SEC);
	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		dummy_netdev_notify(netdev->ndev, NETDEV_DOWN, NULL);
	}
err_netdev_add:
	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		dpaa_netdev_del(netdev);
	}
err_bportal_create:
	on_each_cpu(cpu_bportal_destroy, NULL, 1);
err_bportal_acquire:
	on_each_cpu(affine_bportal_release, NULL, 1);
err_qportal_create:
	on_each_cpu(cpu_qportal_destroy, NULL, 1);
err_qportal_acquire:
	on_each_cpu(affine_qportal_release, NULL, 1);
err_lookup_syms:
	qman_clean_fq_lookup_table();
err_setup_table:
	mtrace_finish();
err:
	return rc;
}

static void __exit dpaa_exit(void)
{
	dpaa_ndev_t *netdev, *tmp;

	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		dummy_netdev_notify(netdev->ndev, NETDEV_GOING_DOWN, NULL);
	}

	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		dpaa_netdev_stop(netdev);
	}

	/* Waitting for on-the-fly frames finish */
	msleep(MSEC_PER_SEC);
	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		dummy_netdev_notify(netdev->ndev, NETDEV_DOWN, NULL);
	}

	list_for_each_entry_safe(netdev, tmp, &dpaa_eth_priv_list, node) {
		dpaa_netdev_del(netdev);
	}

	on_each_cpu(cpu_bportal_destroy, NULL, 1);
	on_each_cpu(affine_bportal_release, NULL, 1);

	on_each_cpu(cpu_qportal_destroy, NULL, 1);
	on_each_cpu(affine_qportal_release, NULL, 1);

	qman_clean_fq_lookup_table();

	mtrace_finish();
}

module_init(dpaa_init);
module_exit(dpaa_exit);

MODULE_LICENSE("GPL");
