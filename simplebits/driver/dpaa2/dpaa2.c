/*
 * Copyright (C) 2017
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	dpaa2.c
 * @brief	DPAA2 ethernet driver for simplebit
 */

#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/kallsyms.h>
#include <linux/etherdevice.h>

#include "netdev.h"
#include "worker.h"
#include "mc.h"
#include "mc-sys.h"
#include "mc-private.h"
#include "qbman.h"
#include "dpni.h"
#include "dpcon.h"
#include "dpbp.h"
#include "fsl_dpio.h"

#include "mtrace.h"

#define DPAA2_DPA_BP_SZ		2048
#define DPAA2_DPNI_MAX_FRM_SZ	1536
#define DPAA2_DPNI_DATA_ALIGN	256

#define DEFINE_KSYM_PTR(x)	typeof(x) *ksym_##x

struct dpaa2_fq;
typedef void (*qbman_cb_dqrr_t)(struct qbman_swp *, struct dpaa2_fq *,
				const struct dpaa2_dq *);

typedef struct dpio_dev {
	struct dpio_attr attr;
	struct fsl_mc_device *mdev;
	struct list_head node;
} dpio_dev_t;

typedef struct dpcon_dev {
	__percpu uint8_t *ch_idx;
	struct dpcon_attr attr;
	struct fsl_mc_device *mdev;
	struct list_head node;
} dpcon_dev_t;

typedef struct dpbp_dev {
	struct dpbp_attr attr;
	struct fsl_mc_device *mdev;
	struct list_head node;
} dpbp_dev_t;

typedef struct dpaa2_fq {
	uint16_t qdid;
	struct dpni_queue_id qid;
	struct net_device *ndev;
	qbman_cb_dqrr_t dqrr;
} ____cacheline_aligned dpaa2_fq_t;

typedef struct dpni_dev {
	struct dpni_attr attr;
	struct fsl_mc_device *mdev;
} dpni_dev_t;

typedef struct dpaa2_io_info {
	struct qbman_swp *swp;
	dpio_dev_t *dpio;
} dpaa2_io_info_t;

typedef struct dpaa2_ndev {
	uint8_t ch_idx;
	struct net_device *ndev;
	dpcon_dev_t *dpcon;
	dpaa2_fq_t *rx_fq, *tx_fqs, *tx_conf_fq;
	dpbp_dev_t *rx_dpbp, *tx_drain_dpbp;
	dpni_dev_t *dpni;
	struct list_head node;
} dpaa2_ndev_t;

static DEFINE_KSYM_PTR(dpio_open);
static DEFINE_KSYM_PTR(dpio_close);
static DEFINE_KSYM_PTR(dpio_enable);
static DEFINE_KSYM_PTR(dpio_disable);
static DEFINE_KSYM_PTR(dpio_reset);
static DEFINE_KSYM_PTR(dpio_set_stashing_destination);
static DEFINE_KSYM_PTR(dpio_get_attributes);
static DEFINE_KSYM_PTR(dpio_add_static_dequeue_channel);
static DEFINE_KSYM_PTR(dpio_remove_static_dequeue_channel);
static DEFINE_KSYM_PTR(dpni_open);
static DEFINE_KSYM_PTR(dpni_close);
static DEFINE_KSYM_PTR(dpni_enable);
static DEFINE_KSYM_PTR(dpni_disable);
static DEFINE_KSYM_PTR(dpni_reset);
static DEFINE_KSYM_PTR(dpni_get_attributes);
static DEFINE_KSYM_PTR(dpni_set_buffer_layout);
static DEFINE_KSYM_PTR(dpni_set_link_cfg);
static DEFINE_KSYM_PTR(dpni_set_tx_confirmation_mode);
static DEFINE_KSYM_PTR(dpni_set_max_frame_length);
static DEFINE_KSYM_PTR(dpni_set_unicast_promisc);
static DEFINE_KSYM_PTR(dpni_set_multicast_promisc);
static DEFINE_KSYM_PTR(dpni_set_pools);
static DEFINE_KSYM_PTR(dpni_get_queue);
static DEFINE_KSYM_PTR(dpni_set_queue);
static DEFINE_KSYM_PTR(dpni_get_qdid);

static bool use_tx_conf = false;
static unsigned long skb_buf_nr = 2048;
static struct fsl_mc_device *dprc_mdev;

static LIST_HEAD(dpio_dev_list);
static LIST_HEAD(dpcon_dev_list);
static LIST_HEAD(dpbp_dev_list);
static LIST_HEAD(dpni_dev_list);
static DEFINE_MUTEX(dpio_dev_list_lock);
static DEFINE_MUTEX(dpcon_dev_list_lock);
static DEFINE_MUTEX(dpbp_dev_list_lock);
static DEFINE_MUTEX(dpni_dev_list_lock);
static DEFINE_PER_CPU(dpaa2_io_info_t, cpu_dpaa2_io_infos);

module_param_named(tx_conf, use_tx_conf, bool, S_IRUGO);
MODULE_PARM_DESC(tx_conf, "Use tx confirm");

module_param_named(bufs, skb_buf_nr, ulong, S_IRUGO);
MODULE_PARM_DESC(bufs, "Number of skb buffers");

static struct qbman_swp *dpaa2_qbman_swp_create(unsigned int cpu, dpio_dev_t *dpio)
{
	struct qbman_swp *swp;
	struct fsl_mc_device *mdev;
	struct qbman_swp_desc *desc;

	mdev = dpio->mdev;

	if (!(desc = kzalloc(sizeof(*desc), GFP_KERNEL))) {
		dev_err(&mdev->dev, "failed to alloc memory\n");
		goto err;
	}

	if (ksym_dpio_open(dprc_mdev->mc_io, 0, mdev->obj_desc.id, &mdev->mc_handle)) {
		dev_err(&mdev->dev, "failed to open dpio\n");
		goto err_open;
	}

	if (ksym_dpio_reset(dprc_mdev->mc_io, 0, mdev->mc_handle)) {
		dev_err(&mdev->dev, "failed to reset dpio\n");
		goto err_reset;
	}

	if (ksym_dpio_get_attributes(dprc_mdev->mc_io, 0, mdev->mc_handle, &dpio->attr)) {
		dev_err(&mdev->dev, "failed to get attrs\n");
		goto err_get_attr;
	}
	desc->qman_version = dpio->attr.qbman_version;

	if (ksym_dpio_enable(dprc_mdev->mc_io, 0, mdev->mc_handle)) {
		dev_err(&mdev->dev, "failed to enable dpio\n");
		goto err_enable;
	}

	desc->cena_bar = ioremap_cache_ns(mdev->regions[0].start, resource_size(&mdev->regions[0]));
	if (!(desc->cena_bar)) {
		dev_err(&mdev->dev, "failed to map cena region\n");
		goto err_map_cena;
	}

	desc->cinh_bar = ioremap(mdev->regions[1].start, resource_size(&mdev->regions[1]));
	if (!(desc->cinh_bar)) {
		dev_err(&mdev->dev, "failed to map cinh region\n");
		goto err_map_cinh;
	}

	if (!(swp = qbman_swp_init(desc))) {
		dev_err(&mdev->dev, "failed to init sw portal\n");
		goto err_swp_init;
	}

	return swp;

err_swp_init:
	iounmap(desc->cinh_bar);
err_map_cinh:
	iounmap(desc->cena_bar);
err_map_cena:
	ksym_dpio_disable(dprc_mdev->mc_io, 0, mdev->mc_handle);
err_enable:
err_get_attr:
err_reset:
	ksym_dpio_close(dprc_mdev->mc_io, 0, mdev->mc_handle);
err_open:
	kfree(desc);
err:
	return NULL;
}

static void dpaa2_qbman_swp_destroy(struct qbman_swp *swp, dpio_dev_t *dpio)
{
	struct fsl_mc_device *mdev;
	const struct qbman_swp_desc *desc;

	mdev = dpio->mdev;
	desc = qbman_swp_get_desc(swp);

	qbman_swp_finish(swp);
	iounmap(desc->cinh_bar);
	iounmap(desc->cena_bar);
	ksym_dpio_disable(dprc_mdev->mc_io, 0, mdev->mc_handle);
	ksym_dpio_close(dprc_mdev->mc_io, 0, mdev->mc_handle);

	kfree(desc);
}

static int cpu_qbman_swp_acquire(unsigned int cpu)
{
	dpaa2_io_info_t *info;

	BUG_ON(!mutex_is_locked(&dpio_dev_list_lock));

	info = per_cpu_ptr(&cpu_dpaa2_io_infos, cpu);
	if (!(info->dpio = list_first_entry_or_null(&dpio_dev_list, dpio_dev_t, node))) {
		pr_err("CPU %u: failed to get dpio\n", cpu);
		goto err;
	}
	list_del(&info->dpio->node);

	return 0;
err:
	return -ENODEV;
}

static void cpu_qbman_swp_release(unsigned int cpu)
{
	dpaa2_io_info_t *info;

	info = per_cpu_ptr(&cpu_dpaa2_io_infos, cpu);
	if (info->dpio) {
		BUG_ON(!mutex_is_locked(&dpio_dev_list_lock));
		list_add_tail(&info->dpio->node, &dpio_dev_list);
	}
}

static int cpu_qbman_swp_create(unsigned int cpu)
{
	int rc;
	dpaa2_io_info_t *info;

	info = per_cpu_ptr(&cpu_dpaa2_io_infos, cpu);
	if (!(info->swp = dpaa2_qbman_swp_create(cpu, info->dpio))) {
		pr_err("CPU %u: failed to create qbman swp\n", cpu);
		rc = -ENODEV;
		goto err;
	}

	return 0;
err:
	return rc;
}

static void cpu_qbman_swp_destroy(unsigned int cpu)
{
	dpaa2_io_info_t *info;

	info = per_cpu_ptr(&cpu_dpaa2_io_infos, cpu);
	if ((info->swp)) {
		dpaa2_qbman_swp_destroy(info->swp, info->dpio);
	}
}

static int __dpaa2_dprc_obj_remove(struct device *dev, void *data)
{
	struct fsl_mc_device *mdev;

	mdev = to_fsl_mc_device(dev);
	if (!strcmp(mdev->obj_desc.type, data)) {
		fsl_mc_device_remove(mdev);
	}

	return 0;
}

static int dpaa2_dprc_obj_add(const char *type, const char *override)
{
	int i, rc, nr_objs;
	struct dprc_obj_desc desc;
	struct fsl_mc_device *mdev;

	if ((rc = dprc_get_obj_count(dprc_mdev->mc_io, 0, dprc_mdev->mc_handle, &nr_objs))) {
		dev_err(&dprc_mdev->dev, "failed to get object count\n");
		goto err;
	}

	for (i = 0; i < nr_objs; i++) {
		dprc_get_obj(dprc_mdev->mc_io, 0, dprc_mdev->mc_handle, i, &desc);
		if (!strcmp(type, desc.type)) {
			if ((rc = fsl_mc_device_add(&desc, NULL, &dprc_mdev->dev, override, &mdev))) {
				dev_err(&dprc_mdev->dev, "failed to add device \"%s.%d\"\n", desc.type, desc.id);
				goto err_add;
			}
		}
	}

	return 0;
err_add:
	device_for_each_child(&dprc_mdev->dev, (void *)type, __dpaa2_dprc_obj_remove);
err:
	return rc;
}

static void dpaa2_dprc_obj_remove(const char *type)
{
	device_for_each_child(&dprc_mdev->dev, (void *)type, __dpaa2_dprc_obj_remove);
}

static int dpaa2_dprc_probe(struct fsl_mc_device *mdev)
{
	int rc;
	uint32_t size;
	phys_addr_t paddr;

	if (strcmp(mdev->obj_desc.type, "dprc")) {
		rc = -EINVAL;
		goto err;
	}

	if (dprc_mdev) {
		dev_err(&mdev->dev, "Only one dprc supported\n");
		rc = -EBUSY;
		goto err;
	}

	paddr = mdev->regions[0].start;
	size = resource_size(&mdev->regions[0]);
	if ((rc = fsl_create_mc_io(&mdev->dev, paddr, size, NULL, 0, &mdev->mc_io))) {
		dev_err(&mdev->dev, "failed to create mc_io\n");
		goto err;
	}
	dprc_mdev = mdev;
	dprc_mdev->mc_io = mdev->mc_io;

	if ((rc = dprc_open(mdev->mc_io, 0, mdev->obj_desc.id, &mdev->mc_handle))) {
		dev_err(&mdev->dev, "failed to open dprc\n");
		goto err_open;
	}

	return 0;

err_open:
	fsl_destroy_mc_io(mdev->mc_io);
	mdev->mc_io = NULL;
err:
	return rc;
}

static int dpaa2_dprc_remove(struct fsl_mc_device *mdev)
{
	if (mdev != dprc_mdev) {
		goto err;
	}

	dprc_close(mdev->mc_io, 0, mdev->mc_handle);

	fsl_destroy_mc_io(mdev->mc_io);

	return 0;
err:
	return -ENODEV;
}

static struct fsl_mc_driver dpaa2_dprc_driver = {
	.driver = {
		.name = KBUILD_MODNAME,
		.owner = THIS_MODULE,
	},
	.probe = dpaa2_dprc_probe,
	.remove = dpaa2_dprc_remove,
	.match_id_table = NULL,
};

static int dpaa2_dpio_probe(struct fsl_mc_device *mdev)
{
	int rc;
	dpio_dev_t *dpio;

	if (strcmp(mdev->obj_desc.type, "dpio")) {
		rc = -EINVAL;
		goto err;
	}

	if (!(dpio = kzalloc(sizeof(*dpio), GFP_KERNEL))) {
		dev_err(&mdev->dev, "failed to alloc memory\n");
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&dpio->node);
	dpio->mdev = mdev;

	mutex_lock(&dpio_dev_list_lock);
	list_add_tail(&dpio->node, &dpio_dev_list);
	mutex_unlock(&dpio_dev_list_lock);

	dev_dbg(&mdev->dev, "probed\n");

	return 0;
err:
	return rc;
}

static int dpaa2_dpio_remove(struct fsl_mc_device *mdev)
{
	int rc;
	dpio_dev_t *dpio, *tmp;

	if (strcmp(mdev->obj_desc.type, "dpio")) {
		rc = -EINVAL;
		goto err;
	}

	mutex_lock(&dpio_dev_list_lock);
	list_for_each_entry_safe(dpio, tmp, &dpio_dev_list, node) {
		if (dpio->mdev == mdev) {
			list_del(&dpio->node);
			dev_dbg(&mdev->dev, "removed\n");
			kfree(dpio);
			mutex_unlock(&dpio_dev_list_lock);
			goto ok;
		}
	}

	dev_err(&mdev->dev, "device is busy\n");
	mutex_unlock(&dpio_dev_list_lock);
	rc = -EBUSY;
err:
	return rc;
ok:
	return 0;
}

static struct fsl_mc_driver dpaa2_dpio_driver = {
	.driver = {
		.name = KBUILD_MODNAME "-dpio",
		.owner = THIS_MODULE,
	},
	.probe = dpaa2_dpio_probe,
	.remove = dpaa2_dpio_remove,
	.match_id_table = NULL,
};

static int dpaa2_dpcon_probe(struct fsl_mc_device *mdev)
{
	int rc;
	dpcon_dev_t *dpcon;

	if (strcmp(mdev->obj_desc.type, "dpcon")) {
		rc = -EINVAL;
		goto err;
	}

	if (!(dpcon = kzalloc(sizeof(*dpcon), GFP_KERNEL))) {
		pr_err("%s(): failed to alloc memory\n", __func__);
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&dpcon->node);
	dpcon->mdev = mdev;

	mutex_lock(&dpcon_dev_list_lock);
	list_add_tail(&dpcon->node, &dpcon_dev_list);
	mutex_unlock(&dpcon_dev_list_lock);

	dev_dbg(&mdev->dev, "probed\n");

	return 0;
err:
	return rc;
}

static int dpaa2_dpcon_remove(struct fsl_mc_device *mdev)
{
	int rc;
	dpcon_dev_t *dpcon, *tmp;

	if (strcmp(mdev->obj_desc.type, "dpcon")) {
		rc = -EINVAL;
		goto err;
	}

	mutex_lock(&dpcon_dev_list_lock);
	list_for_each_entry_safe(dpcon, tmp, &dpcon_dev_list, node) {
		if (dpcon->mdev == mdev) {
			list_del(&dpcon->node);
			dev_dbg(&mdev->dev, "removed\n");
			kfree(dpcon);
			mutex_unlock(&dpcon_dev_list_lock);
			goto ok;
		}
	}

	dev_err(&mdev->dev, "device is busy\n");
	mutex_unlock(&dpcon_dev_list_lock);
	rc = -EBUSY;
err:
	return rc;
ok:
	return 0;
}

static struct fsl_mc_driver dpaa2_dpcon_driver = {
	.driver = {
		.name = KBUILD_MODNAME "-dpcon",
		.owner = THIS_MODULE,
	},
	.probe = dpaa2_dpcon_probe,
	.remove = dpaa2_dpcon_remove,
	.match_id_table = NULL,
};

static int dpaa2_dpbp_probe(struct fsl_mc_device *mdev)
{
	int rc;
	dpbp_dev_t *dpbp;

	if (strcmp(mdev->obj_desc.type, "dpbp")) {
		rc = -EINVAL;
		goto err;
	}

	if (!(dpbp = kzalloc(sizeof(*dpbp), GFP_KERNEL))) {
		pr_err("%s(): failed to alloc memory\n", __func__);
		rc = -ENOMEM;
		goto err;
	}

	INIT_LIST_HEAD(&dpbp->node);
	dpbp->mdev = mdev;

	mutex_lock(&dpbp_dev_list_lock);
	list_add_tail(&dpbp->node, &dpbp_dev_list);
	mutex_unlock(&dpbp_dev_list_lock);

	dev_dbg(&mdev->dev, "probed\n");

	return 0;
err:
	return rc;
}

static int dpaa2_dpbp_remove(struct fsl_mc_device *mdev)
{
	int rc;
	dpbp_dev_t *dpbp, *tmp;

	if (strcmp(mdev->obj_desc.type, "dpbp")) {
		rc = -EINVAL;
		goto err;
	}

	mutex_lock(&dpbp_dev_list_lock);
	list_for_each_entry_safe(dpbp, tmp, &dpbp_dev_list, node) {
		if (dpbp->mdev == mdev) {
			list_del(&dpbp->node);
			dev_dbg(&mdev->dev, "removed\n");
			kfree(dpbp);
			mutex_unlock(&dpbp_dev_list_lock);
			goto ok;
		}
	}

	dev_err(&mdev->dev, "device is busy\n");
	mutex_unlock(&dpbp_dev_list_lock);
	rc = -EBUSY;
err:
	return rc;
ok:
	return 0;
}

static struct fsl_mc_driver dpaa2_dpbp_driver = {
	.driver = {
		.name = KBUILD_MODNAME "-dpbp",
		.owner = THIS_MODULE,
	},
	.probe = dpaa2_dpbp_probe,
	.remove = dpaa2_dpbp_remove,
	.match_id_table = NULL,
};

static int dpaa2_start_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	dma_addr_t baddr;
	dpaa2_fq_t *fq;
	unsigned int txq;
	dpaa2_ndev_t *netdev;
	struct sk_buff **skbh;
	struct dpaa2_fd fd = {};
	struct qbman_swp *swp;
	struct qbman_eq_desc ed;

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
	fq = &netdev->tx_fqs[txq];
	dpaa2_fd_set_addr(&fd, baddr);
	dpaa2_fd_set_len(&fd, skb->len);
	dpaa2_fd_set_format(&fd, dpaa2_fd_single);
	if (!use_tx_conf) {
		dpaa2_fd_set_bpid(&fd, netdev->tx_drain_dpbp->attr.bpid);
	}
	qbman_eq_desc_clear(&ed);
	qbman_eq_desc_set_no_orp(&ed, 0);
	qbman_eq_desc_set_response(&ed, 0, 0);
	qbman_eq_desc_set_fq(&ed, fq->qid.fqid);
	qbman_eq_desc_set_qd(&ed, fq->qdid, fq->qid.qdbin, 0);
	swp = this_cpu_ptr(&cpu_dpaa2_io_infos)->swp;
	if (mtrace_skb_add(skb)) {
		goto err;
	}
	if (qbman_swp_enqueue(swp, &ed, (struct qbman_fd *)&fd)) {
		mtrace_skb_del(skb);
		goto err;
	}

	return NETDEV_TX_OK;
err:
	return NETDEV_TX_BUSY;
}

static struct net_device_ops dpaa2_netdev_ops = {
	.ndo_start_xmit = dpaa2_start_xmit,
};

static void qbman_poll_dqrr(struct qbman_swp *swp, unsigned int limit)
{
	int i;
	dpaa2_fq_t *fq;
	const struct dpaa2_dq *dq;

	for (i = 0; i < limit; i++) {
		if (!(dq = qbman_swp_dqrr_next(swp))) {
			break;
		}
		fq = (dpaa2_fq_t *)dpaa2_dq_fqd_ctx(dq);
		fq->dqrr(swp, fq, dq);
		qbman_swp_dqrr_consume(swp, dq);
	}
}

static void dpaa2_netdev_poll(struct net_device *ndev, unsigned int tx_budget, unsigned int rx_budget, bool stride)
{
	int i, ret;
	bool fold;
	uint64_t bufs[7];
	dma_addr_t baddr;
	dpaa2_ndev_t *netdev;
	unsigned int n;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	struct qbman_swp *swp;

	swp = this_cpu_ptr(&cpu_dpaa2_io_infos)->swp;
	qbman_poll_dqrr(swp, rx_budget);

	if (use_tx_conf || !tx_budget) {
		goto end;
	}

	netdev = netdev_priv(ndev);
	dev = ndev->dev.parent;
	n = min(tx_budget, 7u);
	fold = false;
	while (tx_budget) {
		n = min(tx_budget, n);
		n = fold ? n / 2 : n;
		if (!n) {
			break;
		}
		if ((ret = qbman_swp_acquire(swp, netdev->tx_drain_dpbp->attr.bpid, bufs, n)) != n) {
			BUG_ON(ret > 0);
			if (stride) {
				break;
			} else {
				fold = true;
				continue;
			}
		}
		for (i = 0; i < n; i++) {
			baddr = bufs[i];
			skbh = phys_to_virt(dma_to_phys(dev, baddr));
			skbh--;
			skb = *skbh;
			dev_kfree_skb(skb);
		}
		tx_budget -= n;
	}
end:
	return;
}

static netdev_priv_ops_t dpaa2_ndev_ops = {
	.netdev_poll = dpaa2_netdev_poll,
};

static dpcon_dev_t *dpaa2_dpcon_init(struct net_device *ndev)
{
	dpcon_dev_t *dpcon;

	mutex_lock(&dpcon_dev_list_lock);
	if (!(dpcon = list_first_entry_or_null(&dpcon_dev_list, dpcon_dev_t, node))) {
		netdev_err(ndev, "failed to get dpcon\n");
		mutex_unlock(&dpcon_dev_list_lock);
		goto err;
	}
	list_del(&dpcon->node);
	mutex_unlock(&dpcon_dev_list_lock);

	if (!(dpcon->ch_idx = alloc_percpu(uint8_t))) {
		netdev_err(ndev, "failed to alloc memory\n");
		goto err_alloc;
	}

	if ((dpcon_open(dprc_mdev->mc_io, 0, dpcon->mdev->obj_desc.id, &dpcon->mdev->mc_handle))) {
		netdev_err(ndev, "failed to open dpcon\n");
		goto err_open;
	}

	if ((dpcon_reset(dprc_mdev->mc_io, 0, dpcon->mdev->mc_handle))) {
		netdev_err(ndev, "failed to open dpcon\n");
		goto err_reset;
	}

	if ((dpcon_get_attributes(dprc_mdev->mc_io, 0, dpcon->mdev->mc_handle, &dpcon->attr))) {
		netdev_err(ndev, "failed to get dpcon attrs\n");
		goto err_get_attr;
	}
	dev_dbg(&dpcon->mdev->dev, "id=%d, qbman_ch_id=%u\n", dpcon->attr.id, dpcon->attr.qbman_ch_id);

	if ((dpcon_enable(dprc_mdev->mc_io, 0, dpcon->mdev->mc_handle))) {
		netdev_err(ndev, "failed to enable dpcon\n");
		goto err_enable;
	}

	return dpcon;

err_enable:
err_get_attr:
err_reset:
	dpcon_close(dprc_mdev->mc_io, 0, dpcon->mdev->mc_handle);
err_open:
	free_percpu(dpcon->ch_idx);
err_alloc:
	mutex_lock(&dpcon_dev_list_lock);
	list_add_tail(&dpcon->node, &dpcon_dev_list);
	mutex_unlock(&dpcon_dev_list_lock);
err:
	return NULL;
}

static void dpaa2_dpcon_clean(struct net_device *ndev, dpcon_dev_t *dpcon)
{
	dpcon_disable(dprc_mdev->mc_io, 0, dpcon->mdev->mc_handle);
	dpcon_close(dprc_mdev->mc_io, 0, dpcon->mdev->mc_handle);
	free_percpu(dpcon->ch_idx);

	mutex_lock(&dpcon_dev_list_lock);
	list_add_tail(&dpcon->node, &dpcon_dev_list);
	mutex_unlock(&dpcon_dev_list_lock);
}

static dpbp_dev_t *dpaa2_dpbp_init(struct net_device *ndev, size_t sz, unsigned long nr)
{
	int i, rc, ret;
	uint64_t bufs[7];
	dpbp_dev_t *dpbp;
	dma_addr_t baddr;
	unsigned long cnt;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	struct qbman_swp *swp;
	struct qbman_release_desc rd;

	mutex_lock(&dpbp_dev_list_lock);
	if (!(dpbp = list_first_entry_or_null(&dpbp_dev_list, dpbp_dev_t, node))) {
		netdev_err(ndev, "failed to get dpbp\n");
		mutex_unlock(&dpbp_dev_list_lock);
		goto err;
	}
	list_del(&dpbp->node);
	mutex_unlock(&dpbp_dev_list_lock);

	if ((dpbp_open(dprc_mdev->mc_io, 0, dpbp->mdev->obj_desc.id, &dpbp->mdev->mc_handle))) {
		netdev_err(ndev, "failed to open dpbp\n");
		goto err_open;
	}

	if ((dpbp_reset(dprc_mdev->mc_io, 0, dpbp->mdev->mc_handle))) {
		netdev_err(ndev, "failed to open dpbp\n");
		goto err_reset;
	}

	if ((dpbp_get_attributes(dprc_mdev->mc_io, 0, dpbp->mdev->mc_handle, &dpbp->attr))) {
		netdev_err(ndev, "failed to get dpbp attrs\n");
		goto err_get_attr;
	}

	if ((dpbp_enable(dprc_mdev->mc_io, 0, dpbp->mdev->mc_handle))) {
		netdev_err(ndev, "failed to enable dpbp\n");
		goto err_enable;
	}

	swp = this_cpu_ptr(&cpu_dpaa2_io_infos)->swp;
	cnt = 0;
	ret = 7;
	do {
		if (ret == 7) {
			ret = qbman_swp_acquire(swp, dpbp->attr.bpid, bufs, 7);
		}
		if (ret < 7) {
			ret = qbman_swp_acquire(swp, dpbp->attr.bpid, bufs, 1);
		}
	} while (ret > 0);

	if (cnt) {
		netdev_warn(ndev, "dpbp %u: drained %lu bufs\n", dpbp->attr.bpid, cnt);
	}

	dev = ndev->dev.parent;
	qbman_release_desc_clear(&rd);
	qbman_release_desc_set_bpid(&rd, dpbp->attr.bpid);
	for (cnt = 0; cnt < nr;) {
		ret = nr - cnt;
		ret =min(ret, 7);
		memset(bufs, 0, sizeof(bufs[0]) * ret);
		for (i = 0; i < ret; i++) {
			if (!(skb = __netdev_alloc_skb(ndev, sz, GFP_KERNEL | GFP_DMA))
			||  (skb_headroom(skb) < NET_SKB_PAD)) {
				while (i--) {
					baddr = bufs[i];
					skbh = phys_to_virt(dma_to_phys(dev, baddr));
					skbh--;
					skb = *skbh;
					dev_kfree_skb(skb);
				}
				goto err_alloc;
			}
			skbh = (void *)skb->data;
			skbh--;
			*skbh = skb;
			baddr = phys_to_dma(dev, virt_to_phys(skb->data));
			BUG_ON(!baddr);
			bufs[i] = baddr;
		}

		do {
			rc = qbman_swp_release(swp, &rd, bufs, ret);
		} while (rc == -EBUSY);
		BUG_ON(rc);
		cnt += ret;
	}

	if (cnt) {
		netdev_info(ndev, "dpbp %u: released %lu bufs\n", dpbp->attr.bpid, cnt);
	}

	return dpbp;

err_alloc:
	ret = 7;
	do {
		if (ret == 7) {
			ret = qbman_swp_acquire(swp, dpbp->attr.bpid, bufs, 7);
		}
		if (ret < 7) {
			ret = qbman_swp_acquire(swp, dpbp->attr.bpid, bufs, 1);
		}
		for (i = 0; i < ret; i++) {
			baddr = bufs[i];
			skbh = phys_to_virt(dma_to_phys(dev, baddr));
			skbh--;
			skb = *skbh;
			dev_kfree_skb(skb);
		}
	} while (ret > 0);
err_enable:
err_get_attr:
err_reset:
	dpbp_close(dprc_mdev->mc_io, 0, dpbp->mdev->mc_handle);
err_open:
	mutex_lock(&dpbp_dev_list_lock);
	list_add_tail(&dpbp->node, &dpbp_dev_list);
	mutex_unlock(&dpbp_dev_list_lock);
err:
	return NULL;
}

static void dpaa2_dpbp_clean(struct net_device *ndev, dpbp_dev_t *dpbp)
{
	int i, ret;
	uint64_t bufs[7];
	dma_addr_t baddr;
	unsigned long cnt;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	struct qbman_swp *swp;

	dev = ndev->dev.parent;
	swp = this_cpu_ptr(&cpu_dpaa2_io_infos)->swp;
	cnt = 0;
	ret = 7;
	do {
		if (ret == 7) {
			ret = qbman_swp_acquire(swp, dpbp->attr.bpid, bufs, 7);
		}
		if (ret < 7) {
			ret = qbman_swp_acquire(swp, dpbp->attr.bpid, bufs, 1);
		}
		for (i = 0; i < ret; i++) {
			baddr = bufs[i];
			skbh = phys_to_virt(dma_to_phys(dev, baddr));
			skbh--;
			skb = *skbh;
			dev_kfree_skb(skb);
		}
		cnt += (ret > 0) ? ret : 0;
	} while (ret > 0);

	if (cnt) {
		netdev_info(ndev, "dpbp %u: drained %lu bufs\n", dpbp->attr.bpid, cnt);
	}

	dpbp_disable(dprc_mdev->mc_io, 0, dpbp->mdev->mc_handle);
	dpbp_close(dprc_mdev->mc_io, 0, dpbp->mdev->mc_handle);

	mutex_lock(&dpbp_dev_list_lock);
	list_add_tail(&dpbp->node, &dpbp_dev_list);
	mutex_unlock(&dpbp_dev_list_lock);
}

static dpni_dev_t *dpaa2_dpni_init(struct net_device *ndev, struct fsl_mc_device *mdev)
{
	dpni_dev_t *dpni;
	struct dpni_link_cfg cfg = {};
	struct dpni_buffer_layout layout;
	enum dpni_confirmation_mode mode;

	if (!(dpni = kzalloc(sizeof(*dpni), GFP_KERNEL))) {
		netdev_err(ndev, "failed to alloc memory\n");
		goto err;
	}
	dpni->mdev = mdev;

	if ((ksym_dpni_open(dprc_mdev->mc_io, 0, dpni->mdev->obj_desc.id, &dpni->mdev->mc_handle))) {
		netdev_err(ndev, "failed to open dpni\n");
		goto err_open;
	}

	if ((ksym_dpni_reset(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle))) {
		netdev_err(ndev, "failed to reset dpni\n");
		goto err_reset;
	}

	if ((ksym_dpni_get_attributes(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, &dpni->attr))) {
		netdev_err(ndev, "failed to get attrs\n");
		goto err_get_attr;
	}

	if (dpni->attr.num_queues < ndev->real_num_tx_queues) {
		netdev_err(ndev, "invalid setting of num_queues\n");
		goto err_num_queues;
	}

	if ((ksym_dpni_set_max_frame_length(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, DPAA2_DPNI_MAX_FRM_SZ))) {
		netdev_err(ndev, "failed to set max frame length\n");
		goto err_max_frm;
	}

	memset(&layout, 0, sizeof(layout));
	layout.data_align = DPAA2_DPNI_DATA_ALIGN;
	layout.options = DPNI_BUF_LAYOUT_OPT_DATA_ALIGN;
	if ((ksym_dpni_set_buffer_layout(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, DPNI_QUEUE_RX, &layout))) {
		netdev_err(ndev, "failed to set rx buffer layout\n");
		goto err_buf_layout;
	}

	memset(&layout, 0, sizeof(layout));
	if ((ksym_dpni_set_buffer_layout(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, DPNI_QUEUE_TX, &layout))) {
		netdev_err(ndev, "failed to set tx buffer layout\n");
		goto err_buf_layout;
	}

	memset(&layout, 0, sizeof(layout));
	if ((ksym_dpni_set_buffer_layout(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, DPNI_QUEUE_TX_CONFIRM, &layout))) {
		netdev_err(ndev, "failed to set tx confirm buffer layout\n");
		goto err_buf_layout;
	}
	mode = use_tx_conf ? DPNI_CONF_AFFINE : DPNI_CONF_DISABLE;
	if ((ksym_dpni_set_tx_confirmation_mode(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, mode))) {
		netdev_err(ndev, "failed to set tx confirm mode\n");
		goto err_tx_conf_mode;
	}

	if ((ksym_dpni_set_unicast_promisc(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, 1))) {
		netdev_err(ndev, "failed to enable unicast promiscuous\n");
		goto err_promisc;
	}

	if ((ksym_dpni_set_multicast_promisc(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, 1))) {
		netdev_err(ndev, "failed to enable multicast promiscuous\n");
		goto err_promisc;
	}

	cfg.options = DPNI_LINK_OPT_AUTONEG;
	if ((ksym_dpni_set_link_cfg(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle, &cfg))) {
		netdev_err(ndev, "failed to set link cfg\n");
		goto err_link_cfg;
	}

	return dpni;

err_link_cfg:
err_promisc:
err_tx_conf_mode:
err_buf_layout:
err_max_frm:
err_num_queues:
err_get_attr:
err_reset:
	ksym_dpni_close(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle);
err_open:
	kfree(dpni);
err:
	return NULL;
}

static void dpaa2_dpni_clean(struct net_device *ndev, dpni_dev_t *dpni)
{
	ksym_dpni_close(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle);

	kfree(dpni);
}

static int dpaa2_dpni_set_dpbp(struct net_device *ndev, dpbp_dev_t *dpbp, size_t sz)
{
	int rc;
	struct fsl_mc_device *mdev;
	struct dpni_pools_cfg params = {};

	mdev = to_fsl_mc_device(ndev->dev.parent);

	params.num_dpbp = 1;
	params.pools[0].dpbp_id = dpbp->attr.bpid;
	params.pools[0].backup_pool = 0;
	params.pools[0].buffer_size = sz;
	if ((rc = ksym_dpni_set_pools(dprc_mdev->mc_io, 0, mdev->mc_handle, &params))) {
		netdev_err(ndev, "failed to set pools\n");
		goto err;
	}

	return 0;
err:
	return rc;
}

static void dpaa2_recycle_skb(struct qbman_swp *swp, struct net_device *ndev,
			      struct sk_buff *skb, dma_addr_t baddr)
{
	int rc;
	uint64_t buf;
	dpaa2_ndev_t *netdev;
	struct sk_buff **skbh;
	struct qbman_release_desc rd;

	BUG_ON(atomic_read(&skb->users) != 1);

	skb->data = skb->head + NET_SKB_PAD;
	skb_reset_tail_pointer(skb);
	skb->len = 0;
	skbh = (void *)skb->data;
	skbh--;
	skb = *skbh;
	netdev = netdev_priv(ndev);
	buf = baddr;
	qbman_release_desc_clear(&rd);
	qbman_release_desc_set_bpid(&rd, netdev->rx_dpbp->attr.bpid);
	do {
		rc = qbman_swp_release(swp, &rd, &buf, 1);
	} while (rc == -EBUSY);

	BUG_ON(rc);
}

static void dpaa2_rx_dqrr(struct qbman_swp *swp, struct dpaa2_fq *fq,
			  const struct dpaa2_dq *dq)
{
	dma_addr_t baddr;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	struct net_device *ndev;
	const struct dpaa2_fd *fd;

	fd = (const struct dpaa2_fd *)dpaa2_dq_fd(dq);
	ndev= fq->ndev;
	dev = ndev->dev.parent;
	baddr = dpaa2_fd_get_addr(fd);
	skbh = phys_to_virt(dma_to_phys(dev, baddr));
	skbh--;
	skb = *skbh;
	skb_reserve(skb, dpaa2_fd_get_offset(fd));
	skb_put(skb, dpaa2_fd_get_len(fd));
	skb_reset_mac_header(skb);
	skb_pull(skb, ETH_HLEN);
	dummy_netdev_receive(skb, ndev);

	dpaa2_recycle_skb(swp, ndev, skb, baddr);
}

static void dpaa2_tx_conf_dqrr(struct qbman_swp *swp, struct dpaa2_fq *fq,
			       const struct dpaa2_dq *dq)
{
	dma_addr_t baddr;
	struct device *dev;
	struct sk_buff *skb, **skbh;
	const struct dpaa2_fd *fd;

	fd = (const struct dpaa2_fd *)dpaa2_dq_fd(dq);
	dev = fq->ndev->dev.parent;
	baddr = dpaa2_fd_get_addr(fd);
	skbh = phys_to_virt(dma_to_phys(dev, baddr));
	skbh--;
	skb = *skbh;
	dev_kfree_skb(skb);
}

static int dpaa2_netdev_fqs_init(dpaa2_ndev_t *netdev)
{
	int i, rc;
	uint8_t q_opt = DPNI_QUEUE_OPT_USER_CTX | DPNI_QUEUE_OPT_DEST;
	dpaa2_fq_t *fq;
	dpni_dev_t *dpni;
	struct qbman_swp *swp;
	struct dpni_queue q;
	struct net_device *ndev;

	ndev = netdev->ndev;
	dpni = netdev->dpni;

	if (!(netdev->rx_fq = kzalloc(sizeof(*netdev->rx_fq), GFP_KERNEL))) {
		netdev_err(ndev, "failed to alloc dev memory\n");
		rc = -ENOMEM;
		goto err;
	}
	fq = netdev->rx_fq;
	fq->ndev = ndev;
	fq->dqrr = dpaa2_rx_dqrr;

	if ((rc = ksym_dpni_get_queue(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle,
				      DPNI_QUEUE_RX, 0, 0, &q, &fq->qid))) {
		netdev_err(ndev, "failed to get rx queue\n");
		goto err_get_rxq;
	}
	netdev_dbg(ndev, "rx_fqid=%x, rx_qdbin=%x\n", fq->qid.fqid, fq->qid.qdbin);

	swp = this_cpu_ptr(&cpu_dpaa2_io_infos)->swp;
	if ((rc = qbman_swp_fq_schedule(swp, fq->qid.fqid))) {
		netdev_err(ndev, "failed to schedule fq\n");
		goto err_sched_rxq;
	}

	memset(&q, 0, sizeof(q));
	q.destination.id = netdev->dpcon->attr.id;
	q.destination.type = DPNI_DEST_DPCON;
	q.destination.priority = 1;
	q.user_context = (uint64_t)fq;
	if ((rc = ksym_dpni_set_queue(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle,
				      DPNI_QUEUE_RX, 0, 0, q_opt, &q))) {
		netdev_err(ndev, "failed to set rx queue\n");
		goto err_set_rxq;
	}

	if (!(netdev->tx_fqs = kzalloc(sizeof(*netdev->tx_fqs) * ndev->real_num_tx_queues, GFP_KERNEL))) {
		netdev_err(ndev, "failed to alloc dev memory\n");
		rc = -ENOMEM;
		goto err_alloc_txq;
	}

	for (i = 0; i < ndev->real_num_tx_queues; i++) {
		fq = &netdev->tx_fqs[i];
		fq->ndev = ndev;
		memset(&q, 0, sizeof(q));
		if ((rc = ksym_dpni_get_queue(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle,
					      DPNI_QUEUE_TX, 0, i, &q, &fq->qid))) {
			netdev_err(ndev, "failed to get tx queue\n");
			goto err_get_txq;
		}
		if ((rc = ksym_dpni_get_qdid(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle,
					      DPNI_QUEUE_TX, &fq->qdid))) {
			netdev_err(ndev, "failed to get tx qdid\n");
			goto err_get_txqd;
		}
	}
	fq = &netdev->tx_fqs[0];
	netdev_dbg(ndev, "tx_qdid=%x, tx_qdbin=%x:%x\n", fq->qdid, fq->qid.qdbin, ndev->real_num_tx_queues);

	if (!use_tx_conf) {
		goto ok;
	}

	if (!(netdev->tx_conf_fq = kzalloc(sizeof(*netdev->tx_conf_fq), GFP_KERNEL))) {
		netdev_err(ndev, "failed to alloc dev memory\n");
		rc = -ENOMEM;
		goto err_alloc_txcq;
	}
	fq = netdev->tx_conf_fq;
	fq->ndev = ndev;
	fq->dqrr = dpaa2_tx_conf_dqrr;

	if ((rc = ksym_dpni_get_queue(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle,
				      DPNI_QUEUE_TX_CONFIRM, 0, 0, &q, &fq->qid))) {
		netdev_err(ndev, "failed to get tx_conf queue\n");
		goto err_get_txcq;
	}
	netdev_dbg(ndev, "tx_conf_fqid=%x, tx_conf_qdbin=%x\n", fq->qid.fqid, fq->qid.qdbin);
	memset(&q, 0, sizeof(q));
	q.destination.id = netdev->dpcon->attr.id;
	q.destination.type = DPNI_DEST_DPCON;
	q.destination.priority = 0;
	q.user_context = (uint64_t)fq;
	if ((rc = ksym_dpni_set_queue(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle,
				      DPNI_QUEUE_TX_CONFIRM, 0, 0, q_opt, &q))) {
		netdev_err(ndev, "failed to set tx_conf queue\n");
		goto err_set_txcq;
	}
ok:
	return 0;

err_set_txcq:
err_get_txcq:
	kfree(netdev->tx_conf_fq);
err_alloc_txcq:
err_get_txqd:
err_get_txq:
	kfree(netdev->tx_fqs);
err_alloc_txq:
err_set_rxq:
err_sched_rxq:
err_get_rxq:
	kfree(netdev->rx_fq);
err:
	return rc;
}

static void dpaa2_netdev_fqs_clean(dpaa2_ndev_t *netdev)
{
	if (use_tx_conf) {
		kfree(netdev->tx_conf_fq);
	}
	kfree(netdev->tx_fqs);
	kfree(netdev->rx_fq);
}

static void dpaa2_netdev_bind(dpaa2_ndev_t *netdev)
{
	uint8_t *ch_idx;
	unsigned int cpu;
	cpumask_t cpumask;
	dpaa2_io_info_t *info;

	get_worker_cpumask(&cpumask);

	for_each_cpu(cpu, &cpumask) {
		info = per_cpu_ptr(&cpu_dpaa2_io_infos, cpu);
		ch_idx = per_cpu_ptr(netdev->dpcon->ch_idx, cpu);
		if ((ksym_dpio_add_static_dequeue_channel(dprc_mdev->mc_io, 0, info->dpio->mdev->mc_handle,
							       netdev->dpcon->attr.id, ch_idx))) {
			netdev_err(netdev->ndev, "failed to add static dequeue channel\n");
			BUG();
		}
		qbman_swp_push_set(info->swp, *ch_idx, true);
	}
}

static void dpaa2_netdev_unbind(dpaa2_ndev_t *netdev)
{
	uint8_t *ch_idx;
	unsigned int cpu;
	cpumask_t cpumask;
	dpaa2_io_info_t *info;

	get_worker_cpumask(&cpumask);

	for_each_cpu(cpu, &cpumask) {
		info = per_cpu_ptr(&cpu_dpaa2_io_infos, cpu);
		ch_idx = per_cpu_ptr(netdev->dpcon->ch_idx, cpu);
		qbman_swp_push_set(info->swp, *ch_idx, false);
		ksym_dpio_remove_static_dequeue_channel(dprc_mdev->mc_io, 0, info->dpio->mdev->mc_handle,
							netdev->dpcon->attr.id);
	}
}

static int dpaa2_netdev_start(dpaa2_ndev_t *netdev)
{
	int rc;
	dpni_dev_t *dpni;

	dpni = netdev->dpni;
	if ((rc = ksym_dpni_enable(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle))) {
		netdev_err(netdev->ndev, "failed to enable dpni\n");
		goto err;
	}

	return 0;
err:
	return rc;
}

static void dpaa2_netdev_stop(dpaa2_ndev_t *netdev)
{
	dpni_dev_t *dpni;

	dpni = netdev->dpni;
	ksym_dpni_disable(dprc_mdev->mc_io, 0, dpni->mdev->mc_handle);
}

static int dpaa2_netdev_probe(struct fsl_mc_device *mdev)
{
	int rc;
	dpaa2_ndev_t *netdev;
	struct net_device *ndev = NULL;

	if (strcmp(mdev->obj_desc.type, "dpni")) {
		rc = -EINVAL;
		goto err;
	}

	if (!netdev_in_filter(dev_name(&mdev->dev))) {
		goto ok;
	}

	if (!(ndev = dummy_netdev_add(sizeof(*netdev), use_tx_conf ? 1 : nr_cpu_ids))) {
		dev_err(&mdev->dev, "failed to alloc memory\n");
		rc = -ENOMEM;
		goto err;
	}
	SET_NETDEV_DEV(ndev, &mdev->dev);
	ndev->netdev_ops = &dpaa2_netdev_ops;
	dev_set_drvdata(&mdev->dev, ndev);
	ndev->features |= NETIF_F_LLTX;
	ndev->priv_flags |= IFF_TX_SKB_SHARING;
	memcpy(ndev->name, dev_name(&mdev->dev), sizeof(ndev->name));
	netdev = netdev_priv(ndev);
	INIT_LIST_HEAD(&netdev->node);
	netdev->ndev = ndev;

	if (!(netdev->dpcon = dpaa2_dpcon_init(ndev))) {
		netdev_err(ndev, "failed to init dpcon\n");
		rc = -ENODEV;
		goto err_dpcon_init;
	}

	if (!(netdev->rx_dpbp = dpaa2_dpbp_init(ndev, DPAA2_DPA_BP_SZ, skb_buf_nr))) {
		netdev_err(ndev, "failed to init rx_dpbp\n");
		rc = -ENODEV;
		goto err_rx_dpbp_init;
	}

	if (!use_tx_conf && !(netdev->tx_drain_dpbp = dpaa2_dpbp_init(ndev, 0, 0))) {
		netdev_err(ndev, "failed to init tx_drain_dpbp\n");
		rc = -ENODEV;
		goto err_tx_drain_dpbp_init;
	}

	if (!(netdev->dpni = dpaa2_dpni_init(ndev, mdev))) {
		netdev_err(ndev, "failed to init dpni\n");
		rc = -ENODEV;
		goto err_dpni_init;
	}

	if ((rc = dpaa2_dpni_set_dpbp(ndev, netdev->rx_dpbp, DPAA2_DPA_BP_SZ))) {
		netdev_err(ndev, "failed to set rx_dpbp for dpni\n");
		goto err_set_dpbp;
	}

	if ((rc = dpaa2_netdev_fqs_init(netdev))) {
		netdev_err(ndev, "failed to init fqs\n");
		goto err_flow_init;
	}

	dpaa2_netdev_bind(netdev);

	mutex_lock(&dpni_dev_list_lock);
	list_add_tail(&netdev->node, &dpni_dev_list);
	mutex_unlock(&dpni_dev_list_lock);

	dev_dbg(&mdev->dev, "probed\n");
ok:
	return 0;

err_flow_init:
err_set_dpbp:
	dpaa2_dpni_clean(ndev, netdev->dpni);
err_dpni_init:
	if (!use_tx_conf) {
		dpaa2_dpbp_clean(ndev, netdev->tx_drain_dpbp);
	}
err_tx_drain_dpbp_init:
	dpaa2_dpbp_clean(ndev, netdev->rx_dpbp);
err_rx_dpbp_init:
	dpaa2_dpcon_clean(ndev, netdev->dpcon);
err_dpcon_init:
	dummy_netdev_del(ndev);
err:
	return rc;
}

static int dpaa2_netdev_remove(struct fsl_mc_device *mdev)
{
	int rc;
	dpcon_dev_t *dpcon;
	dpaa2_ndev_t *netdev;
	struct net_device *ndev;

	if (strcmp(mdev->obj_desc.type, "dpni")) {
		rc = -EINVAL;
		goto err;
	}

	if (!netdev_in_filter(dev_name(&mdev->dev))) {
		goto ok;
	}

	ndev = dev_get_drvdata(&mdev->dev);
	netdev = netdev_priv(ndev);
	dpcon = netdev->dpcon;

	mutex_lock(&dpni_dev_list_lock);
	list_del(&netdev->node);
	mutex_unlock(&dpni_dev_list_lock);

	dpaa2_netdev_unbind(netdev);

	dpaa2_netdev_fqs_clean(netdev);

	dpaa2_dpni_clean(ndev, netdev->dpni);

	if (!use_tx_conf) {
		dpaa2_dpbp_clean(ndev, netdev->tx_drain_dpbp);
	}

	dpaa2_dpbp_clean(ndev, netdev->rx_dpbp);

	dpaa2_dpcon_clean(ndev, netdev->dpcon);

	dummy_netdev_del(ndev);

	dev_dbg(&mdev->dev, "removed\n");
ok:
	return 0;
err:
	return rc;
}

static struct fsl_mc_driver dpaa2_netdev_driver = {
	.driver = {
		.name = KBUILD_MODNAME "-dpni",
		.owner = THIS_MODULE,
	},
	.probe = dpaa2_netdev_probe,
	.remove = dpaa2_netdev_remove,
	.match_id_table = NULL,
};

static int __init dpaa2_init(void)
{
	int rc;
	unsigned int i, cpu;
	dpaa2_ndev_t *netdev, *tmp;
	struct {
		void **fn;
		const char *name;
	} ksyms_table[] = {
#define KSYM_TBL_ENTRY(x)	{(void **)&ksym##_##x, #x}
		KSYM_TBL_ENTRY(dpio_open),
		KSYM_TBL_ENTRY(dpio_close),
		KSYM_TBL_ENTRY(dpio_enable),
		KSYM_TBL_ENTRY(dpio_disable),
		KSYM_TBL_ENTRY(dpio_reset),
		KSYM_TBL_ENTRY(dpio_set_stashing_destination),
		KSYM_TBL_ENTRY(dpio_get_attributes),
		KSYM_TBL_ENTRY(dpio_add_static_dequeue_channel),
		KSYM_TBL_ENTRY(dpio_remove_static_dequeue_channel),
		KSYM_TBL_ENTRY(dpni_open),
		KSYM_TBL_ENTRY(dpni_close),
		KSYM_TBL_ENTRY(dpni_enable),
		KSYM_TBL_ENTRY(dpni_disable),
		KSYM_TBL_ENTRY(dpni_reset),
		KSYM_TBL_ENTRY(dpni_get_attributes),
		KSYM_TBL_ENTRY(dpni_set_buffer_layout),
		KSYM_TBL_ENTRY(dpni_set_link_cfg),
		KSYM_TBL_ENTRY(dpni_set_tx_confirmation_mode),
		KSYM_TBL_ENTRY(dpni_set_max_frame_length),
		KSYM_TBL_ENTRY(dpni_set_unicast_promisc),
		KSYM_TBL_ENTRY(dpni_set_multicast_promisc),
		KSYM_TBL_ENTRY(dpni_set_pools),
		KSYM_TBL_ENTRY(dpni_get_queue),
		KSYM_TBL_ENTRY(dpni_set_queue),
		KSYM_TBL_ENTRY(dpni_get_qdid),
	};

	if ((rc = mtrace_init())) {
		goto err;
	}

	for (i = 0; i < ARRAY_SIZE(ksyms_table); i++) {
		if (!(*ksyms_table[i].fn = (void *)kallsyms_lookup_name(ksyms_table[i].name))) {
			pr_err("Failed to get address of \"%s\"\n", ksyms_table[i].name);
			rc = -EFAULT;
			goto err;
		}
	}

	if ((rc = fsl_mc_driver_register(&dpaa2_dprc_driver))) {
		goto err_dprc_drv_reg;
	}

	if ((rc = fsl_mc_driver_register(&dpaa2_dpio_driver))) {
		goto err_dpio_drv_reg;
	}

	if ((rc = fsl_mc_driver_register(&dpaa2_dpcon_driver))) {
		goto err_dpcon_drv_reg;
	}

	if ((rc = fsl_mc_driver_register(&dpaa2_dpbp_driver))) {
		goto err_dpbp_drv_reg;
	}

	if ((rc = fsl_mc_driver_register(&dpaa2_netdev_driver))) {
		goto err_netdev_drv_reg;
	}

	if (!dprc_mdev) {
		pr_err("No dprc for \"" KBUILD_MODNAME "\" probed \n");
		rc = -ENODEV;
		goto err_no_dprc;
	}

	if ((rc = dpaa2_dprc_obj_add("dpio", KBUILD_MODNAME "-dpio"))) {
		goto err_scan_dpio;
	}

	if ((rc = dpaa2_dprc_obj_add("dpcon", KBUILD_MODNAME "-dpcon"))) {
		goto err_scan_dpcon;
	}

	if ((rc = dpaa2_dprc_obj_add("dpbp", KBUILD_MODNAME "-dpbp"))) {
		goto err_scan_dpbp;
	}

	mutex_lock(&dpio_dev_list_lock);
	for_each_online_cpu(cpu) {
		if ((rc = cpu_qbman_swp_acquire(cpu))) {
			mutex_unlock(&dpio_dev_list_lock);
			goto err_swp_acquire;
		}
	}
	mutex_unlock(&dpio_dev_list_lock);

	for_each_online_cpu(cpu) {
		if ((rc = cpu_qbman_swp_create(cpu))) {
			goto err_swp_create;
		}
	}

	if ((rc = dpaa2_dprc_obj_add("dpni", KBUILD_MODNAME "-dpni"))) {
		goto err_scan_dpni;
	}

	mutex_lock(&dpni_dev_list_lock);
	list_for_each_entry_safe(netdev, tmp, &dpni_dev_list, node) {
		if ((rc = dpaa2_netdev_start(netdev))) {
			netdev_err(netdev->ndev, "failed to start netdev\n");
			mutex_unlock(&dpni_dev_list_lock);
			goto err_netdev_start;
		}
	}

	list_for_each_entry_safe(netdev, tmp, &dpni_dev_list, node) {
		if ((rc = dummy_netdev_notify(netdev->ndev, NETDEV_UP, &dpaa2_ndev_ops))) {
			netdev_err(netdev->ndev, "failed to notify netdev\n");
			mutex_unlock(&dpni_dev_list_lock);
			goto err_netdev_notify;
		}
	}
	mutex_unlock(&dpni_dev_list_lock);

	return 0;

err_netdev_notify:
	list_for_each_entry_safe(netdev, tmp, &dpni_dev_list, node) {
		dummy_netdev_notify(netdev->ndev, NETDEV_GOING_DOWN, &dpaa2_ndev_ops);
	}
err_netdev_start:
	list_for_each_entry_safe(netdev, tmp, &dpni_dev_list, node) {
		dpaa2_netdev_stop(netdev);
	}
	/* Waitting for on-the-fly frames finish */
	msleep(MSEC_PER_SEC);
	list_for_each_entry_safe(netdev, tmp, &dpni_dev_list, node) {
		dummy_netdev_notify(netdev->ndev, NETDEV_DOWN, NULL);
	}
	dpaa2_dprc_obj_remove("dpni");
err_scan_dpni:
err_swp_create:
	for_each_online_cpu(cpu) {
		cpu_qbman_swp_destroy(cpu);
	}
err_swp_acquire:
	mutex_lock(&dpio_dev_list_lock);
	for_each_online_cpu(cpu) {
		cpu_qbman_swp_release(cpu);
	}
	mutex_unlock(&dpio_dev_list_lock);
	dpaa2_dprc_obj_remove("dpbp");
err_scan_dpbp:
	dpaa2_dprc_obj_remove("dpcon");
err_scan_dpcon:
	dpaa2_dprc_obj_remove("dpio");
err_no_dprc:
err_scan_dpio:
	fsl_mc_driver_unregister(&dpaa2_netdev_driver);
err_netdev_drv_reg:
	fsl_mc_driver_unregister(&dpaa2_dpbp_driver);
err_dpbp_drv_reg:
	fsl_mc_driver_unregister(&dpaa2_dpcon_driver);
err_dpcon_drv_reg:
	fsl_mc_driver_unregister(&dpaa2_dpio_driver);
err_dpio_drv_reg:
	fsl_mc_driver_unregister(&dpaa2_dprc_driver);
err_dprc_drv_reg:
	mtrace_finish();
err:
	return rc;
}

static void __exit dpaa2_exit(void)
{
	unsigned int cpu;
	dpaa2_ndev_t *netdev, *tmp;

	list_for_each_entry_safe(netdev, tmp, &dpni_dev_list, node) {
		dummy_netdev_notify(netdev->ndev, NETDEV_GOING_DOWN, &dpaa2_ndev_ops);
	}

	list_for_each_entry_safe(netdev, tmp, &dpni_dev_list, node) {
		dpaa2_netdev_stop(netdev);
	}

	/* Waitting for on-the-fly frames finish */
	msleep(MSEC_PER_SEC);
	list_for_each_entry_safe(netdev, tmp, &dpni_dev_list, node) {
		dummy_netdev_notify(netdev->ndev, NETDEV_DOWN, NULL);
	}

	dpaa2_dprc_obj_remove("dpni");

	for_each_online_cpu(cpu) {
		cpu_qbman_swp_destroy(cpu);
	}

	mutex_lock(&dpio_dev_list_lock);
	for_each_online_cpu(cpu) {
		cpu_qbman_swp_release(cpu);
	}
	mutex_unlock(&dpio_dev_list_lock);

	dpaa2_dprc_obj_remove("dpbp");

	dpaa2_dprc_obj_remove("dpcon");

	dpaa2_dprc_obj_remove("dpio");

	fsl_mc_driver_unregister(&dpaa2_netdev_driver);

	fsl_mc_driver_unregister(&dpaa2_dpbp_driver);

	fsl_mc_driver_unregister(&dpaa2_dpcon_driver);

	fsl_mc_driver_unregister(&dpaa2_dpio_driver);

	fsl_mc_driver_unregister(&dpaa2_dprc_driver);

	mtrace_finish();
}

module_init(dpaa2_init);
module_exit(dpaa2_exit);

MODULE_LICENSE("GPL");
