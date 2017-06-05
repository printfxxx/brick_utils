/*
 * Copyright (C) 2016
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	bman.h
 * @brief	Header file for bman driver
 */

#ifndef _BMAN_H_
#define _BMAN_H_

#include "bman_low.h"

#define bman_create_portal		__bman_create_portal
#define bman_create_affine_portal	__bman_create_affine_portal
#define bman_destroy_portal		__bman_destroy_portal
#define bman_destroy_affine_portal	__bman_destroy_affine_portal
#define bman_new_pool			__bman_new_pool
#define bman_free_pool			__bman_free_pool
#define bman_release			__bman_release
#define bman_acquire			__bman_acquire
#define bman_shutdown_pool		__bman_shutdown_pool

struct bman_pool;
struct bman_portal;

struct bman_portal *bman_create_portal(
				       struct bman_portal *portal,
				       const struct bm_portal_config *config);
struct bman_portal *bman_create_affine_portal(
			const struct bm_portal_config *config);
void bman_destroy_portal(struct bman_portal *bm);
void bman_destroy_affine_portal(const struct bm_portal_config *config);
struct bman_pool *bman_new_pool(const struct bman_pool_params *params);
void bman_free_pool(struct bman_pool *pool);
int bman_release(struct bman_pool *pool, const struct bm_buffer *bufs, u8 num,
			u32 flags);
int bman_acquire(struct bman_pool *pool, struct bm_buffer *bufs, u8 num,
			u32 flags);
int bman_shutdown_pool(u32 bpid);

#endif	/* _BMAN_H_ */
