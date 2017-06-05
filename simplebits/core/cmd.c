/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	cmd.c
 * @brief	Command server
 */

#include <linux/init.h>
#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/net.h>
#include <linux/in.h>
#include <net/sock.h>

#include "cmd.h"
#include "proto.h"

enum {
	PROTO_STATE_CONNECT,
	PROTO_STATE_CMD_ID_0,
	PROTO_STATE_CMD_ID_1,
	PROTO_STATE_HDR,
	PROTO_STATE_DATA,
	PROTO_STATE_DONE,
};

static int cmd_port = 1234;
static cmd_fn_t *cmd_fn[MAGIC_MAX];
static struct socket *cmd_sock;
static struct task_struct *cmd_th;

module_param_named(port, cmd_port, int, S_IRUGO);
MODULE_PARM_DESC(port, "command server listen port");

static void sock_shutdown_and_release(struct socket *sock)
{
	uint8_t cmd_buf[256];
	struct kvec iov;
	struct msghdr msg;

	kernel_sock_shutdown(sock, SHUT_WR);

	while (1) {
		iov.iov_base = cmd_buf;
		iov.iov_len = sizeof(cmd_buf);
		memset(&msg, 0, sizeof(msg));
		if (kernel_recvmsg(sock, &msg, &iov, 1, iov.iov_len, 0) <= 0) {
			break;
		}
	}

	kernel_sock_shutdown(sock, SHUT_RD);
	sock_release(sock);
}

static ssize_t cmd_ops_sendmsg(proto_sock_t sock, proto_iovec_t *iov, size_t num, int flags)
{
	int i;
	size_t size = 0;
	struct msghdr msg = {};

	for (i = 0; i < num; i++) {
		size += iov[i].iov_len;
	}
	msg.msg_flags = flags;

	return kernel_sendmsg(sock, &msg, iov, num, size);
}

static ssize_t cmd_ops_recv(proto_sock_t sock, void *buf, size_t len, int flags)
{
	struct kvec iov = {};
	struct msghdr msg = {};

	iov.iov_base = buf;
	iov.iov_len = len;

	return kernel_recvmsg(sock, &msg, &iov, 1, len, flags);
}

static int cmd_server_fn(void *arg)
{
	int rc, ret;
	void *buf;
	size_t len;
	uint8_t magic, id;
	proto_rxd_t rxd;
	struct socket *sock;
	proto_handle_t handle = {};

	if (!(buf = kmalloc(PROTO_BUF_MAX, GFP_KERNEL))) {
		pr_err("%s(): failed to alloc memory\n", __func__);
		rc = -ENOMEM;
		goto err;
	}
	len = PROTO_BUF_MAX;
	handle.sendmsg = cmd_ops_sendmsg;
	handle.recv = cmd_ops_recv;

	while (!kthread_should_stop()) {
		if ((rc = kernel_accept(cmd_sock, &sock, 0)) < 0) {
			if (rc == -ERESTARTSYS) {
				continue;
			}
			pr_err("Failed to accept cmd socket\n");
			goto err;
		}
		handle.sock = sock;
		handle.io_err = false;
		while (1) {
			rxd.buf = buf;
			rxd.len = len;
			if ((rc = proto_recv(&handle, &rxd)) < 0) {
				if (handle.io_err) {
					sock_shutdown_and_release(sock);
					break;
				} else {
					continue;
				}
			}
			magic = rxd.hdr.magic;
			id = rxd.hdr.id;
			pr_debug("CMD: magic=%u, id=%u, length=%u\n", rxd.hdr.magic, rxd.hdr.id, rxd.hdr.length);
			if ((magic < MAGIC_MAX) && (cmd_fn[magic])) {
				ret = cmd_fn[magic](&handle, &rxd, id);
				if (handle.io_err) {
					sock_shutdown_and_release(sock);
					break;
				}
			} else if (magic == MAGIC_PRIV) {
				continue;
			} else {
				ret = ENOSYS;
			}
			if (ret < 0) {
				ret = -ret;
			}
			if ((rc = proto_send_ret_code(&handle, ret)) < 0) {
				if (handle.io_err) {
					sock_shutdown_and_release(sock);
					break;
				} else {
					continue;
				}
			}
		}
	}

	rc = 0;
	goto ok;
err:
	kfree(buf);
	while (!kthread_should_stop()) {
		set_current_state(TASK_INTERRUPTIBLE);
		schedule();
	}
ok:
	return rc;
}

int __init cmd_init(void)
{
	int rc, val;
	struct sockaddr_in sin = {};

	if ((rc = __sock_create(&init_net, AF_INET, SOCK_STREAM, 0, &cmd_sock, 1)) < 0) {
		pr_err("Failed to create cmd socket\n");
		goto err;
	}

	val = 1;
	if ((rc = kernel_setsockopt(cmd_sock, SOL_SOCKET, SO_REUSEADDR,
				    (char *)&val, sizeof(val))) < 0) {
		pr_err("Failed to set cmd socket options\n");
		goto err;
	}

	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = htonl(INADDR_ANY);
	sin.sin_port = htons(cmd_port);
	if ((rc = kernel_bind(cmd_sock, (struct sockaddr *)&sin, sizeof(sin))) < 0) {
		pr_err("Failed to bind to cmd socket\n");
		goto err;
	}

	if ((rc = kernel_listen(cmd_sock, 1)) < 0) {
		pr_err("Failed to listen cmd socket\n");
		goto err;
	}

	if (IS_ERR(cmd_th = kthread_run(cmd_server_fn, NULL, "cmd_server"))) {
		pr_err("Failed to create cmd server kthread\n");
		rc = PTR_ERR(cmd_th);
		goto err;
	}
	set_user_nice(cmd_th, -15);

	rc = 0;
	goto ok;
err:
	if (cmd_sock) {
		sock_shutdown_and_release(cmd_sock);
		cmd_sock = NULL;
	}
ok:
	return rc;
}

void cmd_finish(void)
{
	if (!IS_ERR_OR_NULL(cmd_th)) {
		set_tsk_thread_flag(cmd_th, TIF_SIGPENDING);
		kthread_stop(cmd_th);
		cmd_th = NULL;
	}
	if (cmd_sock) {
		sock_shutdown_and_release(cmd_sock);
		cmd_sock = NULL;
	}
}

int cmd_fn_register(int magic, cmd_fn_t *fn)
{
	int rc;

	if ((magic < 0) || (magic >= MAGIC_MAX) || !fn) {
		rc = -EINVAL;
		goto err;
	}

	if (cmd_fn[magic]) {
		rc = -EEXIST;
		goto err;
	}

	cmd_fn[magic] = fn;

	return 0;
err:
	return rc;
}

int cmd_vprintf(proto_handle_t *handle, int channel, const char *fmt, va_list args)
{
	int rc;
	size_t sz;
	uint8_t buf[512];
	proto_txd_t txd;

	sz = vsnprintf(buf, sizeof(buf), fmt, args);
	txd.iov[0].iov_base = buf;
	txd.iov[0].iov_len = min_t(size_t, sz, sizeof(buf) - 1);
	txd.num = 1;
	txd.hdr.magic = MAGIC_MSG;
	txd.hdr.id = channel;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	return 0;
err:
	return rc;
}

int cmd_pr_info(proto_handle_t *handle, const char *fmt, ...)
{
	int rc;
	va_list args;

	va_start(args, fmt);
	rc = cmd_vprintf(handle, MSG_ID_STDOUT, fmt, args);
	va_end(args);

	return rc;
}

int cmd_pr_err(proto_handle_t *handle, const char *fmt, ...)
{
	int rc;
	va_list args;

	va_start(args, fmt);
	rc = cmd_vprintf(handle, MSG_ID_STDERR, fmt, args);
	va_end(args);

	return rc;
}
