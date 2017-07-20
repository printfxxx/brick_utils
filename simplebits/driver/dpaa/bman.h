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

#define bman_create_portal		__bman_create_portal
#define bman_create_affine_portal	__bman_create_affine_portal
#define bman_destroy_portal		__bman_destroy_portal
#define bman_destroy_affine_portal	__bman_destroy_affine_portal
#define bman_new_pool			__bman_new_pool
#define bman_free_pool			__bman_free_pool
#define bman_release			__bman_release
#define bman_acquire			__bman_acquire
#define bman_shutdown_pool		__bman_shutdown_pool

#include "bman_low.h"

#endif	/* _BMAN_H_ */
