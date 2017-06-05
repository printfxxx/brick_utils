/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	worker.c
 * @brief	Worker thread implementation
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/cpu.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/if_ether.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/udp.h>

#include "worker.h"
#include "netdev.h"
#include "cmd.h"
#include "compat.h"

#include "mtrace.h"

#define IDLE_THRESHOLD	8

typedef struct tx_desc {
	void *pkt;
	unsigned int sz, nr, inc_off, inc_sz;
	unsigned long long inc_step;
} tx_desc_t;

typedef int (worker_op_handler_t)(worker_t *worker, worker_op_t *op);

static char *worker_cpus;
static cpumask_t worker_cpumask;
static DEFINE_PER_CPU(worker_t, all_worker);
static plat_time_t pt_stride_timeout;

module_param_named(cpus, worker_cpus, charp, S_IRUGO);
MODULE_PARM_DESC(cpus, "Worker cpus list");

static void traffic_poll(netdev_pcpu_t *pcpu, unsigned int limit);

static void netdev_poll(netdev_t *netdev, unsigned int limit, plat_time_t pt_last_tx)
{
	bool stride;
	netdev_priv_ops_t *priv_ops;

	if ((priv_ops = netdev->priv_ops)) {
		stride = !!((plat_time_get() - pt_last_tx) < pt_stride_timeout);
		priv_ops->netdev_poll(netdev->ndev, limit, stride);
	}
}

static void flow_control_update(netdev_pcpu_t *pcpu)
{
	uint64_t ns;

	if (pcpu->ps_limit) {
		if (pcpu->burst_sz > pcpu->ps_limit) {
			pcpu->burst_sz = pcpu->ps_limit;
		}
		ns = (uint64_t)NSEC_PER_SEC * pcpu->burst_sz;
		ns = div64_u64(ns + (pcpu->ps_limit >> 1), pcpu->ps_limit);
		pcpu->pt_period = nsec_to_plat_time(ns);
		pcpu->burst_remain = pcpu->burst_sz;
		pcpu->pt_next = plat_time_get();
	}
}

static int worker_op_handler_worker(worker_t *worker, worker_op_t *op)
{
	netdev_pcpu_t *pcpu, *pcpu_tmp;
	proto_handle_t *handle;

	handle = op->args[0];

	pr_debug("Worker %u: get status\n", worker->cpu);

	list_for_each_entry_safe(pcpu, pcpu_tmp, &worker->netdev_pcpu_list, node) {
		cmd_pr_info(handle, "[%s]\n", netdev_name(pcpu->netdev->ndev));
		cmd_pr_info(handle, "byte_mode=%d\n", pcpu->byte_mode);
		cmd_pr_info(handle, "pool=%u/%u\n", ring_used_nr(&pcpu->ring), ring_size(&pcpu->ring));
		cmd_pr_info(handle, "qlen=%u\n", pcpu->qlen);
		cmd_pr_info(handle, "burst_sz=%u\n", pcpu->burst_sz);
		cmd_pr_info(handle, "budget=%u\n", pcpu->budget);
		cmd_pr_info(handle, "ps_limit=%llu\n", pcpu->ps_limit);
		cmd_pr_info(handle, "pkt_cnt=%llu\n", pcpu->pkt_cnt);
		if (pcpu->pkt_cnt) {
			cmd_pr_info(handle, "pkt_remain=%llu\n", pcpu->pkt_remain);
		}
		cmd_pr_info(handle, "\n");
	}

	return 0;
}

static int worker_op_handler_bind(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];

	pr_debug("Worker %u: \"%s\" bind\n",
		 worker->cpu, netdev_name(netdev->ndev));

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (pcpu->netdev) {
		rc = -EBUSY;
		goto err;
	}

	memset(pcpu, 0, sizeof(*pcpu));
	pcpu->netdev = netdev;
	pcpu->qlen = 128;
	pcpu->burst_sz = 1;
	pcpu->budget = 64;
	ring_init(&pcpu->ring, 0);
	seqcount_init(&pcpu->tx_stats_seq);
	seqcount_init(&pcpu->rx_stats_seq);
	INIT_LIST_HEAD(&pcpu->node);
	pcpu->lock_bitmap = kzalloc(BITS_TO_LONGS(netdev->ndev->real_num_tx_queues), GFP_KERNEL);
	if (!pcpu->lock_bitmap) {
		pr_err("%s(): failed to alloc memory\n", __func__);
		rc = -ENOMEM;
		goto err;
	}

	local_bh_disable();
	list_add_tail(&pcpu->node, &worker->netdev_pcpu_list);
	local_bh_enable();

	return 0;
err:
	memset(pcpu, 0, sizeof(*pcpu));
	return rc;
}

static int worker_op_handler_unbind(worker_t *worker, worker_op_t *op)
{
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];

	pr_debug("Worker %u: \"%s\" unbind\n",
		 worker->cpu, netdev_name(netdev->ndev));

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		goto end;
	}

	local_bh_disable();
	list_del(&pcpu->node);
	local_bh_enable();

	while (ring_used_nr(&pcpu->ring)) {
		dev_kfree_skb(pcpu->pool[ring_tail(&pcpu->ring)]);
		ring_pull(&pcpu->ring, 1);
	}

	kfree(pcpu->user);
	kfree(pcpu->pool);
	kfree(pcpu->lock_bitmap);
end:
	memset(pcpu, 0, sizeof(*pcpu));
	return 0;
}

static int worker_op_handler_start(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];

	pr_debug("Worker %u: \"%s\" start\n",
		 worker->cpu, netdev_name(netdev->ndev));

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	pcpu->pkt_remain = max(pcpu->pkt_cnt, 1ull);
	pcpu->burst_remain = pcpu->burst_sz;
	pcpu->pt_next = 0;
	pcpu->tx_pkts = pcpu->tx_bytes = 0;
	pcpu->rx_pkts = pcpu->rx_bytes = 0;
	pcpu->tx_head = pcpu->tx_tail = 0;
	pcpu->pt_last_tx = 0;
	pcpu->start = true;

	return 0;
err:
	return rc;
}

static int worker_op_handler_stop(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];

	pr_debug("Worker %u: %s stop\n",
		 worker->cpu, netdev_name(netdev->ndev));

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (!pcpu->start) {
		goto ok;
	}

	pcpu->pkt_remain = 0;
	while (pcpu->tx_used) {
		netdev_poll(netdev, pcpu->tx_used, 0);
		traffic_poll(pcpu, pcpu->tx_used);
	}
	pcpu->start = false;
ok:
	return 0;
err:
	return rc;
}

static int worker_op_handler_free(worker_t *worker, worker_op_t *op)
{
	netdev_t *netdev;
	netdev_pcpu_t *pcpu, *tmp;

	pr_debug("Worker %u: free\n", worker->cpu);

	list_for_each_entry_safe(pcpu, tmp, &worker->netdev_pcpu_list, node) {
		netdev = pcpu->netdev;
		op->args[0] = netdev;
		worker_op_handler_unbind(worker, op);
	}

	return 0;
}

static int worker_op_handler_clear(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];

	pr_debug("Worker %u: clear \"%s\" statistics\n",
		 worker->cpu, netdev_name(netdev->ndev));

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	pcpu->tx_pkts = pcpu->tx_bytes = 0;
	pcpu->rx_pkts = pcpu->rx_bytes = 0;

	return 0;
err:
	return rc;
}

static int worker_op_handler_byte_mode(worker_t *worker, worker_op_t *op)
{
	int rc;
	uint32_t mode;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];
	get_arg(mode, op->args[1]);
	mode = !!mode;

	pr_debug("Worker %u: set \"%s\" byte mode to %d\n",
		 worker->cpu, netdev_name(netdev->ndev), mode);

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	pcpu->byte_mode = mode;

	return 0;
err:
	return rc;
}

static int worker_op_handler_pool_sz(worker_t *worker, worker_op_t *op)
{
	int rc, *user = NULL;
	ring_t ring;
	uint32_t sz;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;
	struct sk_buff *skb, **pool = NULL;

	netdev = op->args[0];
	get_arg(sz, op->args[1]);

	pr_debug("Worker %u: set \"%s\" pool size to %u\n",
		 worker->cpu, netdev_name(netdev->ndev), sz);

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	ring_init(&ring, sz);

	if (sz) {
		if (!(pool = kzalloc(sizeof(*pool) * sz, GFP_KERNEL))
		||  !(user = kzalloc(sizeof(*user) * sz, GFP_KERNEL))) {
			pr_err("%s(): failed to alloc memory\n", __func__);
			rc = -ENOMEM;
			goto err;
		}
	}

	while (ring_used_nr(&pcpu->ring)) {
		skb = pcpu->pool[ring_tail(&pcpu->ring)];
		if (ring_free_nr(&ring)) {
			pool[ring_head(&ring)] = skb;
			ring_push(&ring, 1);
		} else {
			dev_kfree_skb(skb);
		}
		ring_pull(&pcpu->ring, 1);
	}
	kfree(pcpu->user);
	kfree(pcpu->pool);
	pcpu->user = user;
	pcpu->pool = pool;
	pcpu->ring = ring;

	return 0;
err:
	kfree(user);
	kfree(pool);
	return rc;
}

static int worker_op_handler_qlen(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	uint32_t qlen;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];
	get_arg(qlen, op->args[1]);

	pr_debug("Worker %u: set \"%s\" queue length to %u\n",
		 worker->cpu, netdev_name(netdev->ndev), qlen);

	if (!qlen) {
		rc = -EINVAL;
		goto err;
	}

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	pcpu->qlen = qlen;

	return 0;
err:
	return rc;
}

static int worker_op_handler_burst_sz(worker_t *worker, worker_op_t *op)
{
	int rc;
	uint32_t sz;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];
	get_arg(sz, op->args[1]);

	pr_debug("Worker %u: set \"%s\" burst size to %u\n",
		 worker->cpu, netdev_name(netdev->ndev), sz);

	if (!sz) {
		rc = -EINVAL;
		goto err;
	}

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	pcpu->burst_sz = sz;
	flow_control_update(pcpu);

	return 0;
err:
	return rc;
}

static int worker_op_handler_budget(worker_t *worker, worker_op_t *op)
{
	int rc;
	uint32_t budget;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];
	get_arg(budget, op->args[1]);

	pr_debug("Worker %u: set \"%s\" traffic poll budget to %u\n",
		 worker->cpu, netdev_name(netdev->ndev), budget);

	if (!budget) {
		rc = -EINVAL;
		goto err;
	}

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	pcpu->budget = budget;

	return 0;
err:
	return rc;
}

static int worker_op_handler_ps_limit(worker_t *worker, worker_op_t *op)
{
	int rc;
	uint64_t limit;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];
	get_arg(limit, op->args[1]);

	pr_debug("Worker %u: set \"%s\" per-second limit to %llu\n",
		 worker->cpu, netdev_name(netdev->ndev), limit);

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	pcpu->ps_limit = limit;
	flow_control_update(pcpu);

	return 0;
err:
	return rc;
}

static int worker_op_handler_pkt_cnt(worker_t *worker, worker_op_t *op)
{
	int rc;
	uint64_t cnt;
	netdev_t *netdev;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];
	get_arg(cnt, op->args[1]);

	pr_debug("Worker %u: set \"%s\" packet count to %llu\n",
		 worker->cpu, netdev_name(netdev->ndev), cnt);

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	pcpu->pkt_cnt = cnt;
	pcpu->pkt_remain = max_t(uint64_t, pcpu->pkt_cnt, 1);

	return 0;
err:
	return rc;
}

static int worker_op_handler_add_skb(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	unsigned int i, n = 0;
	netdev_pcpu_t *pcpu;
	struct sk_buff *skb;
	proto_rxd_t *rxd;
	proto_handle_t *handle;

	netdev = op->args[0];
	handle = op->args[1];
	rxd = op->args[2];

	pr_debug("Worker %u: add skbs of \"%s\"\n",
		 worker->cpu, netdev_name(netdev->ndev));

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	while (1) {
		if ((rc = proto_recv(handle, rxd)) < 0) {
			goto err;
		}
		if (!rxd->hdr.length) {
			break;
		}
		if (!ring_free_nr(&pcpu->ring)) {
			rc = -ENOMEM;
			goto err;
		}
		if (!(skb = __netdev_alloc_skb(netdev->ndev, rxd->hdr.length, GFP_KERNEL | GFP_DMA))) {
			pr_err("%s(): failed to alloc skb\n", __func__);
			rc = -ENOMEM;
			goto err;
		}
		skb_reset_mac_header(skb);
		skb_set_queue_mapping(skb, 0);
		memcpy(skb->data, rxd->buf, rxd->hdr.length);
		skb_put(skb, rxd->hdr.length);
		pcpu->pool[ring_head(&pcpu->ring)] = skb;
		ring_push(&pcpu->ring, 1);
		n++;
	}

	return 0;
err:
	while (n--) {
		ring_push_cancel(&pcpu->ring, 1);
		i = ring_head(&pcpu->ring);
		dev_kfree_skb(pcpu->pool[i]);
		pcpu->pool[i] = NULL;
	}
	return rc;
}

static int worker_op_handler_del_skb(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	unsigned int i;
	netdev_pcpu_t *pcpu;

	netdev = op->args[0];

	pr_debug("Worker %u: delete skbs of \"%s\"\n",
		 worker->cpu, netdev_name(netdev->ndev));

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	while (ring_used_nr(&pcpu->ring)) {
		ring_push_cancel(&pcpu->ring, 1);
		i = ring_head(&pcpu->ring);
		dev_kfree_skb(pcpu->pool[i]);
		pcpu->pool[i] = NULL;
	}

	return 0;
err:
	return rc;
}

static int worker_op_handler_skb_txq(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	uint32_t txq, nr;
	unsigned int i;
	netdev_pcpu_t *pcpu;
	struct sk_buff *skb;

	netdev = op->args[0];
	get_arg(txq, op->args[1]);
	get_arg(nr, op->args[2]);

	pr_debug("Worker %u: set \"%s\" skb txq mapping to %u:%u\n",
		 worker->cpu, netdev_name(netdev->ndev), txq, nr);

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (txq >= netdev->ndev->real_num_tx_queues) {
		rc = -EINVAL;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	for (i = 0; (i < nr) && (i < ring_used_nr(&pcpu->ring)); i++) {
		skb = pcpu->pool[ring_tail_next(&pcpu->ring, i)];
		skb_set_queue_mapping(skb, (txq + i) % netdev->ndev->real_num_tx_queues);
	}

	return 0;
err:
	return rc;
}

static int worker_op_handler_dump_skb(worker_t *worker, worker_op_t *op)
{
	int rc;
	netdev_t *netdev;
	unsigned int i;
	netdev_pcpu_t *pcpu;
	struct sk_buff *skb;
	proto_txd_t txd;
	proto_handle_t *handle;

	netdev = op->args[0];
	handle = op->args[1];

	pr_debug("Worker %u: dump skbs of \"%s\"\n",
		 worker->cpu, netdev_name(netdev->ndev));

	pcpu = per_cpu_ptr(netdev->pcpu, worker->cpu);
	if (!pcpu->netdev) {
		rc = -ENODEV;
		goto err;
	}

	if (pcpu->start) {
		rc = -EBUSY;
		goto err;
	}

	for (i = 0; i < ring_used_nr(&pcpu->ring); i++) {
		skb = pcpu->pool[ring_tail_next(&pcpu->ring, i)];
		txd.iov[0].iov_base = skb->data;
		txd.iov[0].iov_len = skb->len;
		txd.hdr.magic = MAGIC_PRIV;
		txd.num = 1;
		if ((rc = proto_send(handle, &txd)) < 0) {
			goto err;
		}
	}

	txd.hdr.magic = MAGIC_PRIV;
	txd.num = 0;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	return 0;
err:
	return rc;
}

static worker_op_handler_t *worker_op_handler[WORKER_OP_MAXIMUM] = {
	[WORKER_OP_WORKER]    = worker_op_handler_worker,
	[WORKER_OP_BIND]      = worker_op_handler_bind,
	[WORKER_OP_UNBIND]    = worker_op_handler_unbind,
	[WORKER_OP_START]     = worker_op_handler_start,
	[WORKER_OP_STOP]      = worker_op_handler_stop,
	[WORKER_OP_FREE]      = worker_op_handler_free,
	[WORKER_OP_CLEAR]     = worker_op_handler_clear,
	[WORKER_OP_BYTE_MODE] = worker_op_handler_byte_mode,
	[WORKER_OP_QLEN]      = worker_op_handler_qlen,
	[WORKER_OP_POOL_SZ]   = worker_op_handler_pool_sz,
	[WORKER_OP_BURST_SZ]  = worker_op_handler_burst_sz,
	[WORKER_OP_BUDGET]    = worker_op_handler_budget,
	[WORKER_OP_PS_LIMIT]  = worker_op_handler_ps_limit,
	[WORKER_OP_PKT_CNT]   = worker_op_handler_pkt_cnt,
	[WORKER_OP_ADD_SKB]   = worker_op_handler_add_skb,
	[WORKER_OP_DEL_SKB]   = worker_op_handler_del_skb,
	[WORKER_OP_SKB_TXQ]   = worker_op_handler_skb_txq,
	[WORKER_OP_DUMP_SKB]  = worker_op_handler_dump_skb,
};

static void worker_op_process(worker_t *worker, worker_op_t *op)
{
	if ((op->opcode < WORKER_OP_MAXIMUM) && (worker_op_handler[op->opcode])) {
		worker->op_resp = worker_op_handler[op->opcode](worker, op);
	} else {
		worker->op_resp = -EINVAL;
	}
}

/**
 * @brief	Post a command to specified worker
 */
int worker_op_post(worker_op_t *op)
{
	int rc;
	bool parallel;
	worker_t *worker;
	unsigned int cpu;

	if (!cpumask_subset(&op->cpumask, cpu_online_mask)) {
		rc = -ENODEV;
		goto err;
	}

	pr_debug("Post op 0x%x\n", op->opcode);
	parallel = !!(op->opcode & WORKER_OP_F_PARALLEL);
	op->opcode &= ~WORKER_OP_F_PARALLEL;

	rc = 0;
	if (parallel) {
		for_each_cpu(cpu, &op->cpumask) {
			worker = worker_get(cpu);
			mutex_lock(&worker->op_lock);
			worker->op_resp = -EIO;
			smp_wmb();
			atomic_long_set(&worker->op, (long)op);
			smp_wmb();
			if (!cpumask_test_cpu(cpu, &worker_cpumask)) {
				wake_up_process(worker->th);
			}
		}

		for_each_cpu(cpu, &op->cpumask) {
			worker = worker_get(cpu);
			wait_event(worker->resp_wq, !atomic_long_read(&worker->op));
			rc = rc ? : worker->op_resp;
			mutex_unlock(&worker->op_lock);
		}
	} else {
		for_each_cpu(cpu, &op->cpumask) {
			worker = worker_get(cpu);
			mutex_lock(&worker->op_lock);
			worker->op_resp = -EIO;
			smp_wmb();
			atomic_long_set(&worker->op, (long)op);
			smp_wmb();
			if (!cpumask_test_cpu(cpu, &worker_cpumask)) {
				wake_up_process(worker->th);
			}
			wait_event(worker->resp_wq, !atomic_long_read(&worker->op));
			rc = rc ? : worker->op_resp;
			mutex_unlock(&worker->op_lock);
		}
	}

	if (rc) {
		goto err;
	}

	return 0;
err:
	return rc;
}

static void worker_op_finish(worker_t *worker, worker_op_t *op)
{
	pr_debug("Worker %u: post finish for op %u\n", worker->cpu, op->opcode);

	atomic_long_set(&worker->op, 0);

	wake_up(&worker->resp_wq);
}

static int cmd_parse_cpumask(const char *str, cpumask_t *cpumask,
			     proto_handle_t *handle)
{
	int rc;

	if (!strcmp(str, "all")) {
		get_worker_cpumask(cpumask);
		goto ok;
	}

	cpumask_clear(cpumask);
	if (cpulist_parse(str, cpumask)
	||  !cpumask_subset(cpumask, &worker_cpumask)
	||  !cpumask_subset(cpumask, cpu_online_mask)) {
		rc = -EINVAL;
		goto err;
	}
ok:
	return 0;
err:
	if (handle) {
		cmd_pr_err(handle, "ERR: invalid cpu \"%s\"\n", str);
	}
	return rc;
}

static int cmd_parse_netdev(const char *str, netdev_t **netdev,
			    proto_handle_t *handle)
{
	int rc;
	struct list_head *list;

	list = netdev_list_acquire_read();

	if (!(*netdev = netdev_find_by_name(list, str))) {
		rc = -ENODEV;
		goto err;
	}

	rc = 0;
err:
	netdev_list_release_read(list);
	if (rc && handle) {
		cmd_pr_err(handle, "ERR: invalid netdev \"%s\"\n", str);
	}
	return rc;
}

static int worker_cmd_worker(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	worker_t *worker;
	const char *arg_cpus;
	worker_op_t op;
	unsigned int cpu;

	rxd->len = rxd->hdr.length;
	arg_cpus = proto_get_str(&rxd->buf, &rxd->len);

	if (!arg_cpus) {
		if ((rc = cmd_parse_cpumask("all", &op.cpumask, handle))) {
			goto err;
		}
		for_each_cpu(cpu, &op.cpumask) {
			worker = worker_get(cpu);
			if (IS_ERR_OR_NULL(worker->th)) {
				continue;
			}
			cmd_pr_info(handle, "worker %u\n", worker->cpu);
		}
	} else {
		op.opcode = WORKER_OP_WORKER;
		op.args[0] = handle;
		if ((rc = cmd_parse_cpumask(arg_cpus, &op.cpumask, handle))
		||  (rc = worker_op_post(&op))) {
			goto err;
		}
	}

	return 0;
err:
	return rc;
}

static int worker_cmd_cpu_dev(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	const char *arg_cpus, *arg_dev;
	proto_rxd_t r;
	worker_op_t op;

	r = *rxd;
	r.len = r.hdr.length;
	if (!(arg_cpus = proto_get_str(&r.buf, &r.len))
	||  !(arg_dev = proto_get_str(&r.buf, &r.len))) {
		rc = -EINVAL;
		goto err;
	}

	op.opcode = param;
	op.args[1] = handle;
	op.args[2] = rxd;
	if ((rc = cmd_parse_cpumask(arg_cpus, &op.cpumask, handle))
	||  (rc = cmd_parse_netdev(arg_dev, (netdev_t **)&op.args[0], handle))
	||  (rc = worker_op_post(&op))) {
		goto err;
	}

	return 0;
err:
	return rc;
}

static int worker_cmd_cpu_dev_u32(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	uint32_t u32;
	const char *arg_cpus, *arg_dev;
	proto_rxd_t r;
	worker_op_t op;

	r = *rxd;
	r.len = r.hdr.length;
	if (!(arg_cpus = proto_get_str(&r.buf, &r.len))
	||  !(arg_dev = proto_get_str(&r.buf, &r.len))
	||  (proto_get_uint32(&r.buf, &r.len, &u32) < 0)) {
		rc = -EINVAL;
		goto err;
	}

	op.opcode = param;
	set_arg(op.args[1], u32);
	op.args[2] = handle;
	op.args[3] = rxd;
	if ((rc = cmd_parse_cpumask(arg_cpus, &op.cpumask, handle))
	||  (rc = cmd_parse_netdev(arg_dev, (netdev_t **)&op.args[0], handle))
	||  (rc = worker_op_post(&op))) {
		goto err;
	}

	return 0;
err:
	return rc;
}

static int worker_cmd_cpu_dev_u64(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	uint64_t u64;
	const char *arg_cpus, *arg_dev;
	proto_rxd_t r;
	worker_op_t op;

	r = *rxd;
	r.len = r.hdr.length;
	if (!(arg_cpus = proto_get_str(&r.buf, &r.len))
	||  !(arg_dev = proto_get_str(&r.buf, &r.len))
	||  (proto_get_uint64(&r.buf, &r.len, &u64) < 0)) {
		rc = -EINVAL;
		goto err;
	}

	op.opcode = param;
	set_arg(op.args[1], u64);
	op.args[2] = handle;
	op.args[3] = rxd;
	if ((rc = cmd_parse_cpumask(arg_cpus, &op.cpumask, handle))
	||  (rc = cmd_parse_netdev(arg_dev, (netdev_t **)&op.args[0], handle))
	||  (rc = worker_op_post(&op))) {
		goto err;
	}

	return 0;
err:
	return rc;
}

static int worker_cmd_cpu_dev_u32_u32(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	uint32_t u32[2];
	const char *arg_cpus, *arg_dev;
	proto_rxd_t r;
	worker_op_t op;

	r = *rxd;
	r.len = r.hdr.length;
	if (!(arg_cpus = proto_get_str(&r.buf, &r.len))
	||  !(arg_dev = proto_get_str(&r.buf, &r.len))
	||  (proto_get_uint32(&r.buf, &r.len, &u32[0]) < 0)
	||  (proto_get_uint32(&r.buf, &r.len, &u32[1]) < 0)) {
		rc = -EINVAL;
		goto err;
	}

	op.opcode = param;
	set_arg(op.args[1], u32[0]);
	set_arg(op.args[2], u32[1]);
	op.args[3] = handle;
	op.args[4] = rxd;
	if ((rc = cmd_parse_cpumask(arg_cpus, &op.cpumask, handle))
	||  (rc = cmd_parse_netdev(arg_dev, (netdev_t **)&op.args[0], handle))
	||  (rc = worker_op_post(&op))) {
		goto err;
	}

	return 0;
err:
	return rc;
}

enum {
	PROTO_L1_MAC = 0,
	PROTO_L2_ETH,
	PROTO_L3_IPV4,
	PROTO_L4_UDP,
};

static cmd_t worker_cmd[WORKER_ID_MAX] = {
	[WORKER_ID_WORKER]    = {worker_cmd_worker,          0},
	[WORKER_ID_BYTE_MODE] = {worker_cmd_cpu_dev_u32,     WORKER_OP_BYTE_MODE},
	[WORKER_ID_QLEN]      = {worker_cmd_cpu_dev_u32,     WORKER_OP_QLEN},
	[WORKER_ID_POOL_SZ]   = {worker_cmd_cpu_dev_u32,     WORKER_OP_POOL_SZ},
	[WORKER_ID_BURST_SZ]  = {worker_cmd_cpu_dev_u32,     WORKER_OP_BURST_SZ},
	[WORKER_ID_BUDGET]    = {worker_cmd_cpu_dev_u32,     WORKER_OP_BUDGET},
	[WORKER_ID_PS_LIMIT]  = {worker_cmd_cpu_dev_u64,     WORKER_OP_PS_LIMIT},
	[WORKER_ID_PKT_CNT]   = {worker_cmd_cpu_dev_u64,     WORKER_OP_PKT_CNT},
	[WORKER_ID_ADD_SKB]   = {worker_cmd_cpu_dev,         WORKER_OP_ADD_SKB},
	[WORKER_ID_DEL_SKB]   = {worker_cmd_cpu_dev,         WORKER_OP_DEL_SKB},
	[WORKER_ID_SKB_TXQ]   = {worker_cmd_cpu_dev_u32_u32, WORKER_OP_SKB_TXQ},
	[WORKER_ID_DUMP_SKB]  = {worker_cmd_cpu_dev,         WORKER_OP_DUMP_SKB},
};

static int worker_cmd_fn(proto_handle_t *handle, proto_rxd_t *desc, unsigned long param)
{
	int rc;
	uint8_t id = param;
	cmd_fn_t *fn;

	if (id >= WORKER_ID_MAX) {
		rc = -EINVAL;
		goto err;
	}

	if (!(fn = worker_cmd[id].fn)) {
		rc = -ENOSYS;
		goto err;
	}

	return fn(handle, desc, worker_cmd[id].param);
err:
	return rc;
}

worker_t *worker_get(unsigned int cpu)
{
	return per_cpu_ptr(&all_worker, cpu);
}

void get_worker_cpumask(struct cpumask *cpumask)
{
	cpumask_copy(cpumask, &worker_cpumask);
}
EXPORT_SYMBOL(get_worker_cpumask);

static void calc_burst_remain(netdev_pcpu_t *pcpu)
{
	plat_time_t now;

	if (pcpu->burst_remain <= 0) {
		now = plat_time_get();
		if (unlikely(now >= pcpu->pt_next)) {
			pcpu->burst_remain += pcpu->burst_sz;
			pcpu->pt_next = now + pcpu->pt_period;
		}
	}
}

static void traffic_poll(netdev_pcpu_t *pcpu, unsigned int limit)
{
	int *user;
	uint64_t pkts, bytes;
	unsigned int nr, tx_used;
	struct sk_buff *skb;

	nr = ring_used_nr(&pcpu->ring);
	pkts = pcpu->tx_pkts;
	bytes = pcpu->tx_bytes;
	tx_used = pcpu->tx_used;
	while (tx_used && limit) {
		skb = pcpu->pool[pcpu->tx_tail];
		user = &pcpu->user[pcpu->tx_tail];
		if (unlikely(*user < atomic_read(&skb->users))) {
			break;
		}
		*user -= 1;
		tx_used -= 1;
		limit -= 1;
		pkts += 1;
		bytes += skb->len;
		pcpu->tx_tail = _ring_add(pcpu->tx_tail, 1, nr);
	}

	if (likely(tx_used < pcpu->tx_used)) {
		if (pcpu->netdev->priv_ops) {
			pcpu->pt_last_tx = plat_time_get();
		}
		pcpu->tx_used = tx_used;
		raw_write_seqcount_begin(&pcpu->tx_stats_seq);
		pcpu->tx_pkts = pkts;
		pcpu->tx_bytes = bytes;
		raw_write_seqcount_end(&pcpu->tx_stats_seq);
	}
}

/**
 * @brief	Run traffic on each netdev in worker thread
 */
static void traffic_run(netdev_pcpu_t *pcpu)
{
	int *user;
	netdev_t *netdev;
	unsigned int n, txq, lock_nr = 0;
	struct sk_buff *skb;
	struct net_device *ndev;
	struct netdev_queue *tx_queue;
	netdev_tx_t (*xmit)(struct sk_buff *, struct net_device *);
	netdev_priv_ops_t *priv_ops;

	calc_burst_remain(pcpu);

	netdev = pcpu->netdev;
	ndev = netdev->ndev;
	xmit = netdev->ops->ndo_start_xmit;
	priv_ops = netdev->priv_ops;
	n = ring_used_nr(&pcpu->ring);

	if (!(ndev->features & NETIF_F_LLTX)) {
		local_bh_disable();
	}

	while (n && pcpu->pkt_remain && (pcpu->burst_remain > 0)
	   &&  (pcpu->tx_used < pcpu->qlen)) {
		skb = pcpu->pool[pcpu->tx_head];
		user = &pcpu->user[pcpu->tx_head];
		txq = skb_get_queue_mapping(skb);
		tx_queue = netdev_get_tx_queue(ndev, txq);
		if (!(ndev->features & NETIF_F_LLTX) && !test_bit(txq, pcpu->lock_bitmap)) {
			if (!__netif_tx_trylock(tx_queue)) {
				break;
			}
			__set_bit(txq, pcpu->lock_bitmap);
			lock_nr++;
		}
		skb_get(skb);
		if (netif_xmit_frozen_or_stopped(tx_queue)
		||  (*xmit)(skb, ndev) != NETDEV_TX_OK) {
			atomic_dec(&skb->users);
			break;
		}
		*user += 1;
		pcpu->tx_used += 1;
		pcpu->tx_head = _ring_add(pcpu->tx_head, 1, n);
		pcpu->pkt_remain -= !!pcpu->pkt_cnt;
		if (pcpu->ps_limit) {
			pcpu->burst_remain -= pcpu->byte_mode ? skb->len : 1;
		}
	}

	if (!(ndev->features & NETIF_F_LLTX)) {
		for (txq = 0; lock_nr && (txq < ndev->real_num_tx_queues); txq++) {
			if (__test_and_clear_bit(txq, pcpu->lock_bitmap)) {
				tx_queue = netdev_get_tx_queue(ndev, txq);
				txq_trans_update(tx_queue);
				__netif_tx_unlock(tx_queue);
				lock_nr--;
			}
		}
	}

	if (!(ndev->features & NETIF_F_LLTX)) {
		local_bh_enable();
	}
}

static int worker_fn(void *arg)
{
	worker_t *worker = arg;
	worker_op_t *op;
	netdev_pcpu_t *pcpu, *pcpu_tmp;

	atomic_long_set(&worker->op, 0);

	while (1) {
		if (kthread_should_stop() && list_empty(&worker->netdev_pcpu_list)) {
			break;
		}
		list_for_each_entry_safe(pcpu, pcpu_tmp, &worker->netdev_pcpu_list, node) {
			netdev_poll(pcpu->netdev, pcpu->budget, pcpu->pt_last_tx);
			if (!pcpu->start) {
				continue;
			}
			traffic_run(pcpu);
			traffic_poll(pcpu, pcpu->budget);
		}

		if (unlikely(!cpumask_test_cpu(worker->cpu, &worker_cpumask))) {
			set_current_state(TASK_INTERRUPTIBLE);
			schedule();
		}

		if (unlikely(op = (worker_op_t *)atomic_long_read(&worker->op))) {
			pr_debug("Worker %u: receive op %x\n", worker->cpu, op->opcode);
			worker_op_process(worker, op);
			worker_op_finish(worker, op);
		}

		if (unlikely(need_resched())) {
			schedule();
		}
	}

	return 0;
}

static int worker_init(unsigned int cpu)
{
	int rc;
	worker_t *worker;

	worker = per_cpu_ptr(&all_worker, cpu);
	memset(worker, 0, sizeof(*worker));

	worker->cpu = cpu;
	atomic_long_set(&worker->op, 1);
	init_waitqueue_head(&worker->op_wq);
	init_waitqueue_head(&worker->resp_wq);
	mutex_init(&worker->op_lock);
	INIT_LIST_HEAD(&worker->netdev_pcpu_list);

	worker->th = kthread_create(worker_fn, worker, "worker%u", worker->cpu);
	if (IS_ERR(worker->th)) {
		pr_err("Failed to create \"worker %u\"\n", worker->cpu);
		rc = PTR_ERR(worker->th);
		goto err;
	}
	set_user_nice(worker->th, -5);
	kthread_bind(worker->th, worker->cpu);
	wake_up_process(worker->th);

	while (atomic_long_read(&worker->op)) {
		schedule();
	}

	return 0;
err:
	worker->th = NULL;
	return rc;
}

static void worker_cleanup(unsigned int cpu)
{
	worker_t *worker;

	worker = per_cpu_ptr(&all_worker, cpu);

	if (!IS_ERR_OR_NULL(worker->th)) {
		set_tsk_thread_flag(worker->th, TIF_SIGPENDING);
		kthread_stop(worker->th);
		worker->th = NULL;
	}
}

__init int worker_init_all(void)
{
	int rc;
	unsigned int cpu;

	pt_stride_timeout = nsec_to_plat_time(10000);

	if (worker_cpus) {
		if (cpulist_parse(worker_cpus, &worker_cpumask)
		||  cpumask_empty(&worker_cpumask)
		||  !cpumask_subset(&worker_cpumask, cpu_online_mask)) {
			pr_err("Invalid parameter of \"worker_cpus\"\n");
			rc = -EINVAL;
			goto err;
		}
	} else {
		cpumask_copy(&worker_cpumask, cpu_online_mask);
	}

	for_each_online_cpu(cpu) {
		if ((rc = worker_init(cpu))) {
			goto err;
		}
	}

	if ((rc = cmd_fn_register(MAGIC_WORKER, worker_cmd_fn))) {
		pr_err("Failed to register command functions\n");
		goto err;
	}

	return 0;
err:
	for_each_online_cpu(cpu) {
		worker_cleanup(cpu);
	}
	return rc;
}

void worker_cleanup_all(void)
{
	worker_op_t op;
	unsigned int cpu;

	op.opcode = WORKER_OP_FREE;
	cpumask_copy(&op.cpumask, cpu_online_mask);
	worker_op_post(&op);

	for_each_online_cpu(cpu) {
		worker_cleanup(cpu);
	}
}
