/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	cmd.h
 * @brief	Header file for cmd server
 */

#ifndef _CMD_H_
#define _CMD_H_

#include <linux/net.h>

#include "proto.h"

typedef int (cmd_fn_t)(proto_handle_t *handle, proto_rxd_t *desc, unsigned long param);

typedef struct cmd {
	cmd_fn_t *fn;
	unsigned long param;
} cmd_t;

int __init cmd_init(void);
void cmd_finish(void);
int cmd_fn_register(int magic, cmd_fn_t *fn);
__printf(2, 3) int cmd_pr_info(proto_handle_t *handle, const char *fmt, ...);
__printf(2, 3) int cmd_pr_err(proto_handle_t *handle, const char *fmt, ...);
__printf(3, 0) int cmd_vprintf(proto_handle_t *handle, int channel, const char *fmt, va_list args);

#endif	/* _CMD_H_ */
