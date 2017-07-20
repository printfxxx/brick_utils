/*
 * Copyright (C) 2016
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	qman.h
 * @brief	Header file for qman driver
 */

#ifndef _QMAN_H_
#define _QMAN_H_

#define affine_portals			__affine_portals
#define qman_setup_fq_lookup_table	__qman_setup_fq_lookup_table
#define qman_create_portal		__qman_create_portal
#define qman_create_affine_portal	__qman_create_affine_portal
#define qman_destroy_portal		__qman_destroy_portal
#define qman_destroy_affine_portal	__qman_destroy_affine_portal
#define qman_irqsource_remove		__qman_irqsource_remove
#define qman_p_poll_dqrr		__qman_p_poll_dqrr
#define qman_poll_dqrr			__qman_poll_dqrr
#define qman_p_static_dequeue_add	__qman_p_static_dequeue_add
#define qman_static_dequeue_add		__qman_static_dequeue_add
#define qman_p_static_dequeue_del	__qman_p_static_dequeue_del
#define qman_static_dequeue_del		__qman_static_dequeue_del
#define qman_create_fq			__qman_create_fq
#define qman_destroy_fq			__qman_destroy_fq
#define qman_init_fq			__qman_init_fq
#define qman_retire_fq			__qman_retire_fq
#define qman_oos_fq			__qman_oos_fq
#define qman_p_volatile_dequeue		__qman_p_volatile_dequeue
#define qman_volatile_dequeue		__qman_volatile_dequeue
#define qman_p_enqueue			__qman_p_enqueue
#define qman_enqueue			__qman_enqueue

#include <linux/fsl_qman.h>

#include "qman_low.h"

int qman_setup_fq_lookup_table(size_t num_entries);
void qman_clean_fq_lookup_table(void);

#endif	/* _QMAN_H_ */
