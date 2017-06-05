/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	main.c
 * @brief	Main source file
 */

#include <linux/init.h>
#include <linux/module.h>

#include "cmd.h"
#include "worker.h"
#include "netdev.h"
#include "time.h"

#include "mtrace.h"

static int __init sb_init(void)
{
	int rc;

	if ((rc = mtrace_init())) {
		goto err;
	}

	if ((rc = plat_time_init())) {
		goto err;
	}

	if ((rc = cmd_init())) {
		goto err_cmd_init;
	}

	if ((rc = worker_init_all())) {
		goto err_worker_init;
	}

	if ((rc = netdev_add_all())) {
		goto err_netdev_add;
	}

	return 0;

err_netdev_add:
	worker_cleanup_all();
err_worker_init:
	cmd_finish();
err_cmd_init:
	mtrace_finish();
err:
	return rc;
}

static void __exit sb_exit(void)
{
	netdev_del_all();
	worker_cleanup_all();
	cmd_finish();
	mtrace_finish();
}

module_init(sb_init);
module_exit(sb_exit);

MODULE_LICENSE("GPL");
