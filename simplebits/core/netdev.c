/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	netdev.c
 * @brief	Net device control and result show
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/ctype.h>
#include <linux/kthread.h>
#include <linux/rtnetlink.h>
#include <linux/etherdevice.h>

#include "netdev.h"
#include "compat.h"
#include "cmd.h"

#include "mtrace.h"

static char *netdev_filter;
static LIST_HEAD(netdev_list);
static DEFINE_MUTEX(netdev_list_lock);
static struct task_struct *stats_th;

module_param_named(devs, netdev_filter, charp, S_IRUGO);
MODULE_PARM_DESC(devs, "Net device filter");

static int netdev_hook_xmit(struct sk_buff *skb, struct net_device *ndev)
{
	notrace_dev_kfree_skb(skb);

	return NETDEV_TX_OK;
}

static int netdev_receive(struct sk_buff *skb, struct net_device *ndev,
			  struct packet_type *pt, struct net_device *orig_dev)
{
#ifdef MTRACE
	if (mtrace_skb_add(skb)) {
		notrace_kfree_skb(skb);
		return 0;
	}
#endif
	skb->protocol = htons(ETH_P_LOOP);
	dummy_netdev_receive(skb, ndev);
	kfree_skb(skb);

	return 0;
}

static netdev_t *netdev_find(const struct net_device *find)
{
	netdev_t *netdev, *tmp;

	BUG_ON(!mutex_is_locked(&netdev_list_lock));

	list_for_each_entry_safe(netdev, tmp, &netdev_list, node) {
		if ((netdev->ndev == find)) {
			return netdev;
		}
	}

	return NULL;
}

static netdev_t *netdev_find_by_name(const char *name)
{
	netdev_t *netdev, *tmp;

	BUG_ON(!mutex_is_locked(&netdev_list_lock));

	list_for_each_entry_safe(netdev, tmp, &netdev_list, node) {
		if (!strcmp(netdev_name(netdev->ndev), name)) {
			return netdev;
		}
	}

	return NULL;
}

static int netdev_add(struct net_device *add, netdev_priv_ops_t *ops)
{
	int rc;
	netdev_t *netdev;
	worker_op_t op;

	BUG_ON(!mutex_is_locked(&netdev_list_lock));

	if (!(netdev = kzalloc(sizeof(*netdev), GFP_KERNEL))
	||  !(netdev->pcpu = alloc_percpu(netdev_pcpu_t))) {
		pr_err("%s(): failed to alloc memory\n", __func__);
		rc = -ENOMEM;
		goto err;
	}

	netdev->ndev = add;
	netdev->priv_ops = ops;
	mutex_init(&netdev->lock);
	seqcount_init(&netdev->stats_seq);

	op.opcode = WORKER_OP_BIND;
	cpumask_copy(&op.cpumask, cpu_online_mask);
	op.args[0] = netdev;
	if ((rc = worker_op_post(&op))) {
		goto err;
	}

	INIT_LIST_HEAD(&netdev->node);
	list_add_tail(&netdev->node, &netdev_list);

	return 0;
err:
	if (netdev) {
		free_percpu(netdev->pcpu);
		kfree(netdev);
	}
	return rc;
}

static void netdev_del(netdev_t *netdev)
{
	worker_op_t op;
	struct net_device *ndev;

	ndev = netdev->ndev;
	list_del(&netdev->node);

	op.opcode = WORKER_OP_UNBIND | WORKER_OP_F_PARALLEL;
	cpumask_copy(&op.cpumask, cpu_online_mask);
	op.args[0] = netdev;
	worker_op_post(&op);

	free_percpu(netdev->pcpu);
	kfree(netdev);
}

static int netdev_attach(netdev_t *netdev)
{
	int rc;
	unsigned int flags;
	struct net_device *ndev = NULL;

	ASSERT_RTNL();

	mutex_lock(&netdev->lock);
	if (netdev->attach) {
		netdev_err(netdev->ndev, "already attached\n");
		rc = -EBUSY;
		mutex_unlock(&netdev->lock);
		goto err;
	}

	ndev = netdev->ndev;

	if (!netdev->priv_ops) {
		netif_tx_lock_bh(ndev);
		netdev->hook = *ndev->netdev_ops;
		netdev->hook.ndo_start_xmit = netdev_hook_xmit;
		netdev->ops = ndev->netdev_ops;
		ndev->netdev_ops = &netdev->hook;
		netif_tx_unlock_bh(ndev);
		if (ndev->features & NETIF_F_GRO) {
			ndev->features &= ~NETIF_F_GRO;
			netdev_features_change(ndev);
			netdev->ndev_ch_flags |= NDEV_CH_F_GRO;
		}
		netdev->pt.type = htons(ETH_P_ALL);
		netdev->pt.func = netdev_receive;
		netdev->pt.dev = ndev;
		dev_add_pack(&netdev->pt);
		flags = dev_get_flags(ndev);
		if (!(flags & IFF_PROMISC)) {
			if ((rc = dev_change_flags(ndev, flags | IFF_PROMISC))) {
				netdev_err(ndev, "failed to enable promiscuous mode\n");
				mutex_unlock(&netdev->lock);
				goto err_change;
			}
			netdev->ndev_ch_flags |= NDEV_CH_F_PROMISC;
		}
	} else {
		netdev->ops = ndev->netdev_ops;
	}

	netdev->attach = true;
	mutex_unlock(&netdev->lock);
	return 0;

err_change:
	dev_remove_pack(&netdev->pt);
	if (netdev->ndev_ch_flags & NDEV_CH_F_GRO) {
		ndev->features |= NETIF_F_GRO;
		netdev_features_change(ndev);
	}
err:
	return rc;
}

static void netdev_detach(netdev_t *netdev)
{
	struct net_device *ndev;

	ASSERT_RTNL();

	mutex_lock(&netdev->lock);
	if (!netdev->attach) {
		goto end;
	}

	if (!netdev->priv_ops) {
		ndev = netdev->ndev;
		netif_tx_lock_bh(ndev);
		ndev->netdev_ops = netdev->ops;
		netif_tx_unlock_bh(ndev);
		if (netdev->ndev_ch_flags & NDEV_CH_F_PROMISC) {
			dev_change_flags(ndev, dev_get_flags(ndev) & ~IFF_PROMISC);
		}
		dev_remove_pack(&netdev->pt);
		if (netdev->ndev_ch_flags & NDEV_CH_F_GRO) {
			ndev->features |= NETIF_F_GRO;
			netdev_features_change(ndev);
		}
	}

	netdev->attach = false;
end:
	mutex_unlock(&netdev->lock);
}

static int netdev_clear(netdev_t *netdev)
{
	int rc;
	worker_op_t op;

	mutex_lock(&netdev->lock);

	op.opcode = WORKER_OP_CLEAR;
	cpumask_copy(&op.cpumask, cpu_online_mask);
	op.args[0] = netdev;

	rc = worker_op_post(&op);

	netdev->tx_pkts = netdev->tx_bytes = 0;
	netdev->rx_pkts = netdev->rx_bytes = 0;
	netdev->tx_pps_rt = netdev->tx_Bps_rt = netdev->tx_bps_rt = 0;
	netdev->rx_pps_rt = netdev->rx_Bps_rt = netdev->rx_bps_rt = 0;
	netdev->time_start = netdev->time_stop = netdev->time_prev = ktime_get();

	mutex_unlock(&netdev->lock);

	return rc;
}

static int __netdev_notifier(struct net_device *ndev, unsigned long event,
			     void *arg)
{
	int rc;
	netdev_t *netdev;
	worker_op_t op;
	unsigned long priv_flags;

#ifdef NET_DEVICE_EXTENDED_SIZE
	priv_flags = netdev_extended(ndev)->ext_priv_flags;
#else
	priv_flags = ndev->priv_flags;
#endif
	if (!net_eq(dev_net(ndev), &init_net)
	||  !(priv_flags & IFF_TX_SKB_SHARING)) {
		rc = 0;
		goto ok;
	}

	switch (event) {
	case NETDEV_UP:
		rc = 0;
		mutex_lock(&netdev_list_lock);
		if (netdev_in_filter(netdev_name(ndev))
		&&  !(netdev = netdev_find(ndev))) {
			rc = netdev_add(ndev, arg);
		}
		mutex_unlock(&netdev_list_lock);
		if (rc) {
			goto err;
		}
		break;

	case NETDEV_GOING_DOWN:
		mutex_lock(&netdev_list_lock);
		if (netdev_in_filter(netdev_name(ndev))
		&&  (netdev = netdev_find(ndev))) {
			mutex_lock(&netdev->lock);
			op.opcode = WORKER_OP_STOP | WORKER_OP_F_PARALLEL;
			cpumask_copy(&op.cpumask, cpu_online_mask);
			op.args[0] = netdev;
			worker_op_post(&op);
			mutex_unlock(&netdev->lock);
		}
		mutex_unlock(&netdev_list_lock);
		break;

	case NETDEV_DOWN:
		mutex_lock(&netdev_list_lock);
		if (netdev_in_filter(netdev_name(ndev))
		&&  (netdev = netdev_find(ndev))) {
			netdev_detach(netdev);
			netdev_del(netdev);
		}
		mutex_unlock(&netdev_list_lock);
		break;

	default:
		break;
	}

	rc = 0;
	goto ok;
err:
ok:
	return notifier_from_errno(rc);
}

static int netdev_notifier(struct notifier_block *block,
			   unsigned long event, void *ptr)
{
	struct net_device *ndev;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(3, 11, 0)
	ndev = netdev_notifier_info_to_dev(ptr);
#else
	ndev = ptr;
#endif
	return __netdev_notifier(ndev, event, NULL);
}

static struct notifier_block netdev_notifier_block = {
	.notifier_call = netdev_notifier
};

static int netdev_cmd_netdev(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	netdev_t *netdev, *tmp;
	const char *arg_netdev;

	rxd->len = rxd->hdr.length;
	arg_netdev = proto_get_str(&rxd->buf, &rxd->len);

	mutex_lock(&netdev_list_lock);

	if (!arg_netdev) {
		list_for_each_entry_safe(netdev, tmp, &netdev_list, node) {
			mutex_lock(&netdev->lock);
			cmd_pr_info(handle, "%s%s%s\n", netdev_name(netdev->ndev),
				    netdev->priv_ops ? " [priv]": "", netdev->attach ? " [attach]" : "");
			mutex_unlock(&netdev->lock);
		}
	} else {
		if (!(netdev = netdev_find_by_name(arg_netdev))) {
			cmd_pr_err(handle, "ERR: netdev \"%s\" not found\n", arg_netdev);
			rc = -ENODEV;
			mutex_unlock(&netdev_list_lock);
			goto err;
		}
		rc = 0;
		mutex_lock(&netdev->lock);
		if (netdev->attach) {
			cmd_pr_info(handle, "txq_nr=%d\n", netdev->ndev->real_num_tx_queues);
		} else {
			cmd_pr_err(handle, "ERR: netdev \"%s\" not attached\n", arg_netdev);
			rc = -ENODEV;
			mutex_unlock(&netdev->lock);
			mutex_unlock(&netdev_list_lock);
			goto err;
		}
		mutex_unlock(&netdev->lock);
	}

	mutex_unlock(&netdev_list_lock);
	return 0;
err:
	return rc;
}

static int netdev_cmd_start(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	netdev_t *netdev;
	const char *arg_netdev;
	worker_op_t op;

	rxd->len = rxd->hdr.length;
	if (!(arg_netdev = proto_get_str(&rxd->buf, &rxd->len))) {
		rc = -EINVAL;
		goto err;
	}

	mutex_lock(&netdev_list_lock);

	if (!(netdev = netdev_find_by_name(arg_netdev))) {
		cmd_pr_err(handle, "ERR: netdev \"%s\" not found\n", arg_netdev);
		rc = -ENODEV;
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	mutex_lock(&netdev->lock);

	if (!netdev->attach) {
		cmd_pr_err(handle, "ERR: netdev \"%s\" not attached\n", arg_netdev);
		rc = -ENODEV;
		mutex_unlock(&netdev->lock);
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	if (netdev->start) {
		rc = -EBUSY;
		mutex_unlock(&netdev->lock);
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	op.opcode = WORKER_OP_START | WORKER_OP_F_PARALLEL;
	get_worker_cpumask(&op.cpumask);
	op.args[0] = netdev;
	if ((rc = worker_op_post(&op))) {
		mutex_unlock(&netdev->lock);
		mutex_unlock(&netdev_list_lock);
		goto err_post;
	}

	netdev->time_start = ktime_get();
	netdev->start = true;

	mutex_unlock(&netdev->lock);
	mutex_unlock(&netdev_list_lock);
	return 0;

err_post:
	op.opcode = WORKER_OP_STOP | WORKER_OP_F_PARALLEL;
	get_worker_cpumask(&op.cpumask);
	op.args[0] = netdev;
	worker_op_post(&op);
err:
	return rc;
}

static int netdev_cmd_stop(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	netdev_t *netdev;
	const char *arg_netdev;
	worker_op_t op;

	rxd->len = rxd->hdr.length;
	if (!(arg_netdev = proto_get_str(&rxd->buf, &rxd->len))) {
		rc = -EINVAL;
		goto err;
	}

	mutex_lock(&netdev_list_lock);

	if (!(netdev = netdev_find_by_name(arg_netdev))) {
		cmd_pr_err(handle, "ERR: netdev \"%s\" not found\n", arg_netdev);
		rc = -ENODEV;
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	mutex_lock(&netdev->lock);

	if (!netdev->start) {
		goto ok;
	}

	op.opcode = WORKER_OP_STOP | WORKER_OP_F_PARALLEL;
	get_worker_cpumask(&op.cpumask);
	op.args[0] = netdev;
	if ((rc = worker_op_post(&op))) {
		mutex_unlock(&netdev->lock);
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	netdev->time_stop = ktime_get();
	netdev->start = false;
ok:
	mutex_unlock(&netdev->lock);
	mutex_unlock(&netdev_list_lock);
	return 0;
err:
	return rc;
}

static int netdev_cmd_clear(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	netdev_t *netdev;
	const char *arg_netdev;

	rxd->len = rxd->hdr.length;
	if (!(arg_netdev = proto_get_str(&rxd->buf, &rxd->len))) {
		rc = -EINVAL;
		goto err;
	}

	mutex_lock(&netdev_list_lock);

	if (!(netdev = netdev_find_by_name(arg_netdev))) {
		cmd_pr_err(handle, "ERR: netdev \"%s\" not found\n", arg_netdev);
		rc = -ENODEV;
		mutex_unlock(&netdev_list_lock);
		goto err;
	}
	if (!netdev->attach) {
		cmd_pr_err(handle, "ERR: netdev \"%s\" not attached\n", arg_netdev);
		rc = -ENODEV;
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	if ((rc = netdev_clear(netdev))) {
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	mutex_unlock(&netdev_list_lock);
	return 0;
err:
	return rc;
}

static uint64_t calc_per_sec_value(uint64_t val, int64_t ns)
{
	uint64_t mul;

	if (val < (U64_MAX / NSEC_PER_SEC)) {
		mul = NSEC_PER_SEC;
	} else if (val < (U64_MAX / USEC_PER_SEC)) {
		mul = USEC_PER_SEC;
		ns = div64_u64(ns, NSEC_PER_SEC / USEC_PER_SEC);
	} else if (val < (U64_MAX / MSEC_PER_SEC)) {
		mul = MSEC_PER_SEC;
		ns = div64_u64(ns, NSEC_PER_SEC / MSEC_PER_SEC);
	} else {
		mul = 1;
		ns = div64_u64(ns, NSEC_PER_SEC);
	}

	if (ns <= 0) {
		return 0;
	}

	return div64_u64((val * mul) + (ns >> 1), ns);
}

static void thousands_grouping_ull(proto_handle_t *handle, uint64_t val)
{
	uint32_t rem;
	uint64_t g, m, k;

	g = div_u64_rem(val, 1000000000u, &rem);
	m = div_u64_rem(rem, 1000000u, &rem);
	k = div_u64_rem(rem, 1000u, &rem);

	if (g) {
		cmd_pr_info(handle, "%llu,%03llu,%03llu,%03u", g, m, k, rem);
	} else if (m) {
		cmd_pr_info(handle, "%llu,%03llu,%03u", m, k, rem);
	} else if (k) {
		cmd_pr_info(handle, "%llu,%03u", k, rem);
	} else {
		cmd_pr_info(handle, "%u", rem);
	}
}

static void netdev_cmd_stats_single(proto_handle_t *handle, netdev_t *netdev)
{
	int64_t ns;
	unsigned seq;
	uint64_t tx_pkts, tx_bytes, rx_pkts, rx_bytes,
		 tx_pps, tx_Bps, tx_bps, rx_pps, rx_Bps, rx_bps;
	cpumask_t cpumask;

	get_worker_cpumask(&cpumask);

	cmd_pr_info(handle, "{%s}\n", netdev_name(netdev->ndev));

	do {
		seq = raw_read_seqcount_begin(&netdev->stats_seq);
		tx_pkts = netdev->tx_pkts;
		tx_bytes = netdev->tx_bytes;
		rx_pkts = netdev->rx_pkts;
		rx_bytes = netdev->rx_bytes;
		tx_pps = netdev->tx_pps_rt;
		tx_Bps = netdev->tx_Bps_rt;
		tx_bps = netdev->tx_bps_rt;
		rx_pps = netdev->rx_pps_rt;
		rx_Bps = netdev->rx_Bps_rt;
		rx_bps = netdev->rx_bps_rt;
	} while (read_seqcount_retry(&netdev->stats_seq, seq));

	cmd_pr_info(handle, "[stats]\n<tx> pkts=");
	thousands_grouping_ull(handle, tx_pkts);
	cmd_pr_info(handle, ", bytes=");
	thousands_grouping_ull(handle, tx_bytes);
	cmd_pr_info(handle, "\n<rx> pkts=");
	thousands_grouping_ull(handle, rx_pkts);
	cmd_pr_info(handle, ", bytes=");
	thousands_grouping_ull(handle, rx_bytes);
	cmd_pr_info(handle, "\n");

	cmd_pr_info(handle, "[rt]\n<tx> pps=");
	thousands_grouping_ull(handle, tx_pps);
	cmd_pr_info(handle, ", Bps=");
	thousands_grouping_ull(handle, tx_Bps);
	cmd_pr_info(handle, ", bps=");
	thousands_grouping_ull(handle, tx_bps);
	cmd_pr_info(handle, "\n<rx> pps=");
	thousands_grouping_ull(handle, rx_pps);
	cmd_pr_info(handle, ", Bps=");
	thousands_grouping_ull(handle, rx_Bps);
	cmd_pr_info(handle, ", bps=");
	thousands_grouping_ull(handle, rx_bps);
	cmd_pr_info(handle, "\n");

	cmd_pr_info(handle, "[avg]\n");
	if (!netdev->start) {
		ns = ktime_to_ns(ktime_sub(netdev->time_stop, netdev->time_start));
		do {
			seq = raw_read_seqcount_begin(&netdev->stats_seq);
			tx_pkts = netdev->tx_pkts - netdev->tx_pkts_prev;
			tx_bytes = netdev->tx_bytes - netdev->tx_bytes_prev;
			rx_pkts = netdev->rx_pkts - netdev->rx_pkts_prev;
			rx_bytes = netdev->rx_bytes - netdev->rx_bytes_prev;
		} while (read_seqcount_retry(&netdev->stats_seq, seq));
		tx_pps = calc_per_sec_value(tx_pkts, ns);
		tx_Bps = calc_per_sec_value(tx_bytes, ns);
		tx_bps = calc_per_sec_value(tx_pkts * 24 * 8 + tx_bytes * 8, ns);
		rx_pps = calc_per_sec_value(rx_pkts, ns);
		rx_Bps = calc_per_sec_value(rx_bytes, ns);
		rx_bps = calc_per_sec_value(rx_pkts * 24 * 8 + rx_bytes * 8, ns);
		cmd_pr_info(handle, "<tx>\npps=");
		thousands_grouping_ull(handle, tx_pps);
		cmd_pr_info(handle, ", Bps=");
		thousands_grouping_ull(handle, tx_Bps);
		cmd_pr_info(handle, ", bps=");
		thousands_grouping_ull(handle, tx_bps);
		cmd_pr_info(handle, "\n<rx>\npps=");
		thousands_grouping_ull(handle, rx_pps);
		cmd_pr_info(handle, ", Bps=");
		thousands_grouping_ull(handle, rx_Bps);
		cmd_pr_info(handle, ", bps=");
		thousands_grouping_ull(handle, rx_bps);
		cmd_pr_info(handle, "\n");
	} else {
		cmd_pr_info(handle, "<tx> ...\n<rx> ...\n");
	}

	return;
}

static int netdev_cmd_stats(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	netdev_t *netdev, *tmp;

	mutex_lock(&netdev_list_lock);

	list_for_each_entry_safe(netdev, tmp, &netdev_list, node) {
		mutex_lock(&netdev->lock);
		if (netdev->attach) {
			netdev_cmd_stats_single(handle, netdev);
		}
		mutex_unlock(&netdev->lock);
	}

	mutex_unlock(&netdev_list_lock);

	return 0;
}

static int netdev_cmd_attach(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	netdev_t *netdev;
	const char *arg_netdev;

	rxd->len = rxd->hdr.length;
	if (!(arg_netdev = proto_get_str(&rxd->buf, &rxd->len))) {
		rc = -EINVAL;
		goto err;
	}

	mutex_lock(&netdev_list_lock);

	if (!(netdev = netdev_find_by_name(arg_netdev))) {
		rc = -ENODEV;
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	rtnl_lock();
	rc = netdev_attach(netdev);
	rtnl_unlock();

	if (rc || (rc = netdev_clear(netdev))) {
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	mutex_unlock(&netdev_list_lock);
	return 0;
err:
	return rc;
}

static int netdev_cmd_detach(proto_handle_t *handle, proto_rxd_t *rxd, unsigned long param)
{
	int rc;
	netdev_t *netdev;
	const char *arg_netdev;
	proto_rxd_t _rxd;

	_rxd = *rxd;
	if ((rc = netdev_cmd_stop(handle, &_rxd, 0))) {
		goto err;
	}

	rxd->len = rxd->hdr.length;
	if (!(arg_netdev = proto_get_str(&rxd->buf, &rxd->len))) {
		rc = -EINVAL;
		goto err;
	}

	mutex_lock(&netdev_list_lock);
	if (!(netdev = netdev_find_by_name(arg_netdev))) {
		rc = -ENODEV;
		mutex_unlock(&netdev_list_lock);
		goto err;
	}

	rtnl_lock();
	netdev_detach(netdev);
	rtnl_unlock();

	mutex_unlock(&netdev_list_lock);
	return 0;
err:
	return rc;
}

static cmd_t netdev_cmd[WORKER_ID_MAX] = {
	[NETDEV_ID_NETDEV] = {netdev_cmd_netdev, 0},
	[NETDEV_ID_START]  = {netdev_cmd_start,  0},
	[NETDEV_ID_STOP]   = {netdev_cmd_stop,   0},
	[NETDEV_ID_CLEAR]  = {netdev_cmd_clear,  0},
	[NETDEV_ID_STATS]  = {netdev_cmd_stats,  0},
	[NETDEV_ID_ATTACH] = {netdev_cmd_attach, 0},
	[NETDEV_ID_DETACH] = {netdev_cmd_detach, 0},
};

static int netdev_cmd_fn(proto_handle_t *handle, proto_rxd_t *desc, unsigned long param)
{
	int rc;
	uint8_t id = param;
	cmd_fn_t *fn;

	if (id >= WORKER_ID_MAX) {
		rc = -EINVAL;
		goto err;
	}

	if (!(fn = netdev_cmd[id].fn)) {
		rc = -ENOSYS;
		goto err;
	}

	return fn(handle, desc, netdev_cmd[id].param);
err:
	return rc;
}

static void netdev_update_stats(netdev_t *netdev, int64_t ns)
{
	unsigned seq;
	uint64_t pkts, bytes, tx_pkts, tx_bytes, rx_pkts, rx_bytes,
		 tx_pps, tx_Bps, tx_bps, rx_pps, rx_Bps, rx_bps;
	cpumask_t cpumask;
	unsigned int cpu;
	const netdev_pcpu_t *pcpu;

	if (ns <= 0) {
		return;
	}

	get_worker_cpumask(&cpumask);

	tx_pkts = netdev->tx_pkts_prev;
	tx_bytes = netdev->tx_bytes_prev;
	rx_pkts = netdev->rx_pkts_prev;
	rx_bytes = netdev->rx_bytes_prev;

	for_each_cpu(cpu, &cpumask) {
		pcpu = per_cpu_ptr(netdev->pcpu, cpu);
		do {
			seq = raw_read_seqcount_begin(&pcpu->tx_stats_seq);
			pkts = pcpu->tx_pkts;
			bytes = pcpu->tx_bytes;
		} while (read_seqcount_retry(&pcpu->tx_stats_seq, seq));
		tx_pkts += pkts;
		tx_bytes += bytes;
		do {
			seq = raw_read_seqcount_begin(&pcpu->rx_stats_seq);
			pkts = pcpu->rx_pkts;
			bytes = pcpu->rx_bytes;
		} while (read_seqcount_retry(&pcpu->rx_stats_seq, seq));
		rx_pkts += pkts;
		rx_bytes += bytes;
	}

	pkts = tx_pkts - netdev->tx_pkts;
	bytes = tx_bytes - netdev->tx_bytes;
	tx_pps = calc_per_sec_value(pkts, ns);
	tx_Bps = calc_per_sec_value(bytes, ns);
	tx_bps = calc_per_sec_value(pkts * 24 * 8 + bytes * 8, ns);
	pkts = rx_pkts - netdev->rx_pkts;
	bytes = rx_bytes - netdev->rx_bytes;
	rx_pps = calc_per_sec_value(pkts, ns);
	rx_Bps = calc_per_sec_value(bytes, ns);
	rx_bps = calc_per_sec_value(pkts * 24 * 8 + bytes * 8, ns);

	raw_write_seqcount_begin(&netdev->stats_seq);
	netdev->tx_pkts = tx_pkts;
	netdev->tx_bytes = tx_bytes;
	netdev->rx_pkts = rx_pkts;
	netdev->rx_bytes = rx_bytes;
	netdev->tx_pps_rt = tx_pps;
	netdev->tx_Bps_rt = tx_Bps;
	netdev->tx_bps_rt = tx_bps;
	netdev->rx_pps_rt = rx_pps;
	netdev->rx_Bps_rt = rx_Bps;
	netdev->rx_bps_rt = rx_bps;
	raw_write_seqcount_end(&netdev->stats_seq);
}

static int netdev_stats_fn(void *arg)
{
	int64_t ns;
	ktime_t prev, now;
	netdev_t *netdev, *tmp;

	while (!kthread_should_stop()) {
		if (unlikely(need_resched())) {
			schedule();
		}
		prev = ktime_get();
		msleep_interruptible(MSEC_PER_SEC);
		mutex_lock(&netdev_list_lock);
		list_for_each_entry_safe(netdev, tmp, &netdev_list, node) {
			mutex_lock(&netdev->lock);
			if (netdev->attach) {
				now = ktime_get();
				ns = ktime_to_ns(ktime_sub(now, prev));
				netdev_update_stats(netdev, ns);
			}
			mutex_unlock(&netdev->lock);
		}
		mutex_unlock(&netdev_list_lock);
	}

	return 0;
}

int __init netdev_add_all(void)
{
	int rc;
	netdev_t *netdev, *tmp;

	if ((rc = register_netdevice_notifier(&netdev_notifier_block))) {
		pr_err("Failed to register netdevice notifier\n");
		goto err;
	}

	if ((rc = cmd_fn_register(MAGIC_NETDEV, netdev_cmd_fn))) {
		pr_err("Failed to register command functions\n");
		goto err;
	}

	/* Start a thread to update statistics */
	stats_th = kthread_run(netdev_stats_fn, NULL, "netdev_stats");
	if (IS_ERR(stats_th)) {
		pr_err("Failed to create netdev_stats kthread\n");
		rc = PTR_ERR(stats_th);
		goto err;
	}
	set_user_nice(stats_th, -10);

	return 0;
err:
	rtnl_lock();
	mutex_lock(&netdev_list_lock);

	list_for_each_entry_safe(netdev, tmp, &netdev_list, node) {
		netdev_detach(netdev);
		netdev_del(netdev);
	}

	mutex_unlock(&netdev_list_lock);
	rtnl_unlock();
	return rc;
}

void netdev_del_all(void)
{
	netdev_t *netdev, *tmp;

	set_tsk_thread_flag(stats_th, TIF_SIGPENDING);
	kthread_stop(stats_th);

	unregister_netdevice_notifier(&netdev_notifier_block);

	rtnl_lock();
	mutex_lock(&netdev_list_lock);

	list_for_each_entry_safe(netdev, tmp, &netdev_list, node) {
		netdev_detach(netdev);
		netdev_del(netdev);
	}

	mutex_unlock(&netdev_list_lock);
	rtnl_unlock();
}

/**
 * @brief	find netdev by given specified name
 */
netdev_t *netdev_get_by_name(const char *name)
{
	netdev_t *netdev;

	mutex_lock(&netdev_list_lock);

	netdev = netdev_find_by_name(name);

	mutex_unlock(&netdev_list_lock);

	return netdev;
}

/**
 * @brief	Return if netdev in filter list
 */
bool netdev_in_filter(const char *name)
{
	char *s, *str, *dup = NULL;
	size_t n;

	if (!netdev_filter) {
		goto ok;
	}

	n = strlen(netdev_filter) + 1;
	if (!(dup = kmalloc(n, GFP_KERNEL))) {
		pr_err("%s(): failed to alloc memory\n", __func__);
		goto err;
	}
	memcpy(dup, netdev_filter, n);

	str = dup;
	while (str) {
		s = strsep(&str, ",");
		if (!strcmp(s, name)) {
			goto ok;
		}
	}
err:
	kfree(dup);
	return false;
ok:
	kfree(dup);
	return true;
}
EXPORT_SYMBOL(netdev_in_filter);

/**
 * @brief	Allocate a net_device instance for private device
 */
struct net_device *dummy_netdev_add(int sizeof_priv, unsigned int count)
{
	struct net_device *ndev;

	if (!(ndev = alloc_etherdev_mq(sizeof_priv, count))) {
		goto err;
	}
	ndev->reg_state = NETREG_REGISTERED;

	return ndev;
err:
	return NULL;
}
EXPORT_SYMBOL(dummy_netdev_add);

/**
 * @brief	Free dummy net_device instance
 */
void dummy_netdev_del(struct net_device *ndev)
{
	ndev->reg_state = NETREG_UNINITIALIZED;
	free_netdev(ndev);
}
EXPORT_SYMBOL(dummy_netdev_del);

/**
 * @brief	Receive handler. This routine should be called in private driver after receive frames
 */
void dummy_netdev_receive(struct sk_buff *skb, struct net_device *ndev)
{
	worker_t *worker;
	netdev_t *netdev = NULL;
	netdev_pcpu_t *pcpu, *tmp;

	worker = worker_get(smp_processor_id());

	list_for_each_entry_safe(pcpu, tmp, &worker->netdev_pcpu_list, node) {
		if (pcpu->netdev->ndev == ndev) {
			netdev = pcpu->netdev;
			break;
		}
	}

	if (!netdev || !pcpu->start) {
		goto end;
	}

	raw_write_seqcount_begin(&pcpu->rx_stats_seq);
	pcpu->rx_pkts++;
	pcpu->rx_bytes += skb->len + ETH_HLEN;
	raw_write_seqcount_end(&pcpu->rx_stats_seq);
end:
	return;
}
EXPORT_SYMBOL(dummy_netdev_receive);

/**
 * @brief	Post a netdev event
 */
int dummy_netdev_notify(struct net_device *ndev, unsigned long event, void *arg)
{
	int rc;

	rtnl_lock();
	rc = __netdev_notifier(ndev, event, arg);
	rtnl_unlock();

	return notifier_to_errno(rc);
}
EXPORT_SYMBOL(dummy_netdev_notify);
