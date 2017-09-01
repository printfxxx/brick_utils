/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	netdev.h
 * @brief	Header file for netdev
 */

#ifndef _NETDEV_H_
#define _NETDEV_H_

#include <linux/netdevice.h>
#include <linux/skbuff.h>
#include <linux/mutex.h>
#include <linux/ktime.h>

#include "time.h"
#include "worker.h"
#include "ring.h"

typedef struct netdev_pcpu {
	bool start, byte_mode;
	struct netdev *netdev;
	ring_t ring;
	int *user;
	struct sk_buff **pool;
	plat_time_t pt_period, pt_next, pt_last_tx;
	uint32_t burst_sz, budget;
	int64_t burst_remain;
	uint64_t tx_pkts, tx_bytes, rx_pkts, rx_bytes,
		 pkt_cnt, pkt_remain, ps_limit;
	unsigned int tx_head, tx_tail, tx_used, qlen;
	unsigned long *lock_bitmap;
	seqcount_t tx_stats_seq, rx_stats_seq;
	struct list_head node;
} netdev_pcpu_t;

typedef struct netdev_priv_ops {
	void (*netdev_poll)(struct net_device *, unsigned int, unsigned int, bool);
} netdev_priv_ops_t;

typedef struct netdev {
	bool attach, start;
	struct net_device *ndev;
	netdev_priv_ops_t *priv_ops;
	unsigned int ndev_ch_flags;
#define NDEV_CH_F_GRO		0x01
#define NDEV_CH_F_PROMISC	0x02
	struct net_device_ops hook;
	const struct net_device_ops *ops;
	struct packet_type pt;
	uint64_t tx_pkts_prev, tx_bytes_prev,
		 rx_pkts_prev, rx_bytes_prev,
		 tx_pkts, tx_bytes, rx_pkts, rx_bytes,
		 tx_pps_rt, tx_Bps_rt, tx_bps_rt,
		 rx_pps_rt, rx_Bps_rt, rx_bps_rt;
	ktime_t time_start, time_stop, time_prev;
	seqcount_t stats_seq;
	__percpu netdev_pcpu_t *pcpu;
	struct mutex lock;
	struct list_head node;
} netdev_t;

int __init netdev_add_all(void);
void netdev_del_all(void);

bool netdev_in_filter(const char *name);
netdev_t *netdev_get_by_name(const char *name);
struct net_device *dummy_netdev_add(int sizeof_priv, unsigned int count);
void dummy_netdev_del(struct net_device *ndev);
void dummy_netdev_receive(struct sk_buff *skb, struct net_device *ndev);
int dummy_netdev_notify(struct net_device *ndev, unsigned long event, void *arg);

#endif	/* _NETDEV_H_ */
