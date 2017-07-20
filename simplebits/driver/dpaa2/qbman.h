/*
 * Copyright (C) 2017
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	qbman.h
 * @brief	Header file for qbman driver
 */

#ifndef _QBMAN_H_
#define _QBMAN_H_

#define qbman_swp_init			__qbman_swp_init
#define qbman_swp_finish		__qbman_swp_finish
#define qbman_swp_get_desc		__qbman_swp_get_desc
#define qbman_swp_mc_start		__qbman_swp_mc_start
#define qbman_swp_mc_submit		__qbman_swp_mc_submit
#define qbman_swp_mc_result		__qbman_swp_mc_result
#define qbman_eq_desc_clear		__qbman_eq_desc_clear
#define qbman_eq_desc_set_no_orp	__qbman_eq_desc_set_no_orp
#define qbman_eq_desc_set_response	__qbman_eq_desc_set_response
#define qbman_eq_desc_set_fq		__qbman_eq_desc_set_fq
#define qbman_eq_desc_set_qd		__qbman_eq_desc_set_qd
#define qbman_swp_enqueue		__qbman_swp_enqueue
#define qbman_swp_push_get		__qbman_swp_push_get
#define qbman_swp_push_set		__qbman_swp_push_set
#define qbman_swp_dqrr_next		__qbman_swp_dqrr_next
#define qbman_swp_dqrr_consume		__qbman_swp_dqrr_consume
#define dpaa2_dq_flags			__dpaa2_dq_flags
#define dpaa2_dq_fqd_ctx		__dpaa2_dq_fqd_ctx
#define dpaa2_dq_fd			__dpaa2_dq_fd
#define qbman_release_desc_clear	__qbman_release_desc_clear
#define qbman_release_desc_set_bpid	__qbman_release_desc_set_bpid
#define qbman_swp_release		__qbman_swp_release
#define qbman_swp_acquire		__qbman_swp_acquire
#define qbman_swp_fq_schedule		__qbman_swp_fq_schedule

#include "qbman_portal.h"
#include "fsl_dpaa2_fd.h"

#endif	/* _QBMAN_H_ */
