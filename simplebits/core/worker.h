/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	worker.h
 * @brief	Header file for worker
 */

#ifndef _WORKER_H_
#define _WORKER_H_

#include <linux/mutex.h>
#include <linux/cpumask.h>

enum {
	WORKER_OP_WORKER,		/* Get worker status */
	WORKER_OP_BIND,			/* Bind netdev to worker */
	WORKER_OP_UNBIND,		/* Unbind netdev from worker */
	WORKER_OP_START,		/* Start traffic on netdev */
	WORKER_OP_STOP,			/* Stop traffic on netdev */
	WORKER_OP_FREE,			/* Unbind all netdev from worker */
	WORKER_OP_CLEAR,		/* Clear netdev statistics */
	WORKER_OP_BYTE_MODE,		/* Set to byte mode */
	WORKER_OP_QLEN,			/* Set queue length */
	WORKER_OP_POOL_SZ,		/* Set pool size */
	WORKER_OP_BURST_SZ,		/* Set burst size */
	WORKER_OP_BUDGET,		/* Set traffic poll budget */
	WORKER_OP_PS_LIMIT,		/* Set per-second limit */
	WORKER_OP_PKT_CNT,		/* Set packets count */
	WORKER_OP_ADD_SKB,		/* Add skbs */
	WORKER_OP_DEL_SKB,		/* Delete skbs */
	WORKER_OP_SKB_TXQ,		/* Set txq mapping of skbs */
	WORKER_OP_DUMP_SKB,		/* Dump skbs */
	WORKER_OP_MAXIMUM,
#define WORKER_OP_F_PARALLEL	0x80000000
};

typedef struct worker {
	unsigned int cpu;
	atomic_long_t op;
	int op_resp;
	struct task_struct *th;
	struct list_head netdev_pcpu_list;
	wait_queue_head_t op_wq, resp_wq;
	struct mutex op_lock;
} worker_t;

typedef struct worker_op {
	unsigned int opcode;
	cpumask_t cpumask;
#define get_arg(var, ptr)	do { var = *((typeof(var) *)(ptr)); } while (0)
#define set_arg(ptr, var)	do { ptr = (typeof(ptr))&var; } while (0)
	void *args[6];
} worker_op_t;

int worker_op_post(worker_op_t *op);
worker_t *worker_get(unsigned int cpu);
void get_worker_cpumask(struct cpumask *cpumask);
__init int worker_init_all(void);
void worker_cleanup_all(void);

#endif	/* _WORKER_H_ */
