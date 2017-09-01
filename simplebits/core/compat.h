/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	compat.h
 * @brief	Compatible kernel APIs implementation
 */

#ifndef _COMPAT_H_
#define _COMPAT_H_

#include <linux/version.h>
#include <linux/netdevice.h>

#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 28)
#define for_each_cpu(cpu, cpumask)	for_each_cpu_mask(cpu, (*cpumask))
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 3, 0)
static inline bool netif_xmit_frozen_or_stopped(const struct netdev_queue *dev_queue)
{
	return (netif_tx_queue_stopped(dev_queue) || netif_tx_queue_frozen(dev_queue));
}
#endif

#if LINUX_VERSION_CODE < KERNEL_VERSION(3, 13, 0)
#define raw_read_seqcount_begin(s)	read_seqcount_begin(s)
#define raw_write_seqcount_begin(s)	write_seqcount_begin(s)
#define raw_write_seqcount_end(s)	write_seqcount_end(s)
#endif

#ifndef U64_MAX
#define U64_MAX		((u64)(~0ULL))
#endif

#ifndef S64_MAX
#define S64_MAX		((s64)(U64_MAX >> 1))
#endif

#endif	/* _COMPAT_H_ */
