/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	time.c
 * @brief	Time API implementation for each platform
 */

#ifdef PLATFORM_TIME

#include <linux/kernel.h>
#include <linux/math64.h>

#include "time.h"

#if defined(QORIQ)
#include <asm/machdep.h>

static uint64_t plat_time_mul_mhz;

int plat_time_init(void)
{
	if (!(plat_time_mul_mhz = div_u64(ppc_proc_freq + 500000, 1000000))) {
		goto err;
	}

	pr_debug("plat_time_mul_mhz=%llu\n", plat_time_mul_mhz);

	return 0;
err:
	return -EINVAL;
}

plat_time_t plat_time_get(void)
{
	uint32_t hi, lo, chk;

	do {
		hi = mfspr(SPRN_ATBU);
		lo = mfspr(SPRN_ATBL);
		chk = mfspr(SPRN_ATBU);
	} while (unlikely(hi != chk));

	return (plat_time_t)(((uint64_t)hi << 32) | (uint64_t)lo);
}

plat_time_t nsec_to_plat_time(uint64_t ns)
{
	return (plat_time_t)div64_u64(ns * plat_time_mul_mhz + 500, 1000);
}

uint64_t plat_time_to_nsec(plat_time_t time)
{
	return div64_u64(time * 1000 + (plat_time_mul_mhz >> 1), plat_time_mul_mhz);
}
#elif defined(LAYERSCAPE)
#include <asm/arch_timer.h>

static uint64_t plat_time_mul_mhz;

int plat_time_init(void)
{
	if (!(plat_time_mul_mhz = div_u64(arch_timer_get_cntfrq() + 500000, 1000000))) {
		goto err;
	}

	pr_debug("plat_time_mul_mhz=%llu\n", plat_time_mul_mhz);

	return 0;
err:
	return -EINVAL;
}

plat_time_t plat_time_get(void)
{
	return (plat_time_t)arch_counter_get_cntvct();
}

plat_time_t nsec_to_plat_time(uint64_t ns)
{
	return (plat_time_t)div64_u64(ns * plat_time_mul_mhz + 500, 1000);
}

uint64_t plat_time_to_nsec(plat_time_t time)
{
	return div64_u64(time * 1000 + (plat_time_mul_mhz >> 1), plat_time_mul_mhz);
}
#else
#error unknown platform
#endif

#endif	/* PLATFORM_TIME */
