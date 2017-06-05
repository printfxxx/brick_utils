/*
 * Copyright (C) 2014
 *
 * Brick Yang <printfxxx@163.com>
 *
 * This program is free software. You can redistribute it and/or
 * modify it as you like.
 */

/**
 * @file	cli.c
 * @brief	Simplebits command line tools
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
#include <errno.h>
#include <netdb.h>
#include <ctype.h>
#include <fcntl.h>
#include <pcap.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/if_ether.h>

#include "proto.h"

#include "mtrace.h"

#ifndef ARRAY_SIZE
#define ARRAY_SIZE(arr)		(sizeof(arr) / sizeof((arr)[0]))
#endif

#ifndef offsetof
#define offsetof(type, member)	((size_t)&((type *)0)->member)
#endif

struct cmd_param;
typedef struct cmd_param cmd_param_t;

typedef int (cmd_fn_t)(proto_handle_t *handle, int argc, const char *argv[], cmd_param_t *param);

typedef struct cmd {
	const char *name, *help;
	uint8_t magic, id;
	cmd_fn_t *fn;
} cmd_t;

struct cmd_param {
	cmd_t *cmd;
	void *buf;
	size_t len;
};

static int cmd_process_std_resp(proto_handle_t *handle, proto_rxd_t *rxd, int *ret)
{
	int fd, rc;

	while (1) {
		if ((rc = proto_recv(handle, rxd)) < 0) {
			goto err;
		}
		switch (rxd->hdr.magic) {
		case MAGIC_MSG:
			if (rxd->hdr.id == MSG_ID_STDOUT) {
				fd = STDOUT_FILENO;
			} else if (rxd->hdr.id == MSG_ID_STDERR) {
				fd = STDERR_FILENO;
			} else {
				rc = -EINVAL;
				goto err;
			}
			write(fd, rxd->buf, rxd->hdr.length);
			break;
		case MAGIC_RET_CODE:
			*ret = rxd->hdr.id;
			rc = 1;
			goto ok;
		default:
			rc = 0;
			goto ok;
		}
	}
ok:
err:
	return rc;
}

static int cmd_handler_no_arg(proto_handle_t *handle, int argc, const char *argv[],
			      cmd_param_t *param)
{
	int rc, ret;
	proto_txd_t txd;
	proto_rxd_t rxd;

	if (argc != 1) {
		rc = -EINVAL;
		goto err;
	}

	txd.num = 0;
	txd.hdr.magic = param->cmd->magic;
	txd.hdr.id = param->cmd->id;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	return ret;
err:
	return rc;
}

static int cmd_handler_str(proto_handle_t *handle, int argc, const char *argv[],
			   cmd_param_t *param)
{
	int rc, ret;
	proto_txd_t txd;
	proto_rxd_t rxd;

	if (argc != 2) {
		rc = -EINVAL;
		goto err;
	}

	txd.iov[0].iov_base = (void *)argv[1];
	txd.iov[0].iov_len = strlen(argv[1]) + 1;
	txd.num = 1;
	txd.hdr.magic = param->cmd->magic;
	txd.hdr.id = param->cmd->id;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	return ret;
err:
	return rc;
}

static int cmd_handler_str_str(proto_handle_t *handle, int argc, const char *argv[],
			       cmd_param_t *param)
{
	int rc, ret;
	proto_txd_t txd;
	proto_rxd_t rxd;

	if (argc != 3) {
		rc = -EINVAL;
		goto err;
	}

	txd.iov[0].iov_base = (void *)argv[1];
	txd.iov[0].iov_len = strlen(argv[1]) + 1;
	txd.iov[1].iov_base = (void *)argv[2];
	txd.iov[1].iov_len = strlen(argv[2]) + 1;
	txd.num = 2;
	txd.hdr.magic = param->cmd->magic;
	txd.hdr.id = param->cmd->id;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	return ret;
err:
	return rc;
}

static int cmd_handler_str_str_u32(proto_handle_t *handle, int argc, const char *argv[],
				   cmd_param_t *param)
{
	int rc, ret;
	__be32 be32;
	proto_txd_t txd;
	proto_rxd_t rxd;

	if (argc != 4) {
		rc = -EINVAL;
		goto err;
	}

	txd.iov[0].iov_base = (void *)argv[1];
	txd.iov[0].iov_len = strlen(argv[1]) + 1;
	txd.iov[1].iov_base = (void *)argv[2];
	txd.iov[1].iov_len = strlen(argv[2]) + 1;
	be32 = strtoul(argv[3], NULL, 0);
	be32 = __cpu_to_be32(be32);
	txd.iov[2].iov_base = &be32;
	txd.iov[2].iov_len = sizeof(be32);
	txd.num = 3;
	txd.hdr.magic = param->cmd->magic;
	txd.hdr.id = param->cmd->id;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	return ret;
err:
	return rc;
}

static int cmd_handler_str_str_u64(proto_handle_t *handle, int argc, const char *argv[],
				   cmd_param_t *param)
{
	int rc, ret;
	__be64 be64;
	proto_txd_t txd;
	proto_rxd_t rxd;

	if (argc != 4) {
		rc = -EINVAL;
		goto err;
	}

	txd.iov[0].iov_base = (void *)argv[1];
	txd.iov[0].iov_len = strlen(argv[1]) + 1;
	txd.iov[1].iov_base = (void *)argv[2];
	txd.iov[1].iov_len = strlen(argv[2]) + 1;
	be64 = strtoull(argv[3], NULL, 0);
	be64 = __cpu_to_be64(be64);
	txd.iov[2].iov_base = &be64;
	txd.iov[2].iov_len = sizeof(be64);
	txd.num = 3;
	txd.hdr.magic = param->cmd->magic;
	txd.hdr.id = param->cmd->id;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	return ret;
err:
	return rc;
}

static int cmd_handler_no_arg_or_str(proto_handle_t *handle, int argc, const char *argv[],
				     cmd_param_t *param)
{
	switch (argc) {
	case 1:
		return cmd_handler_no_arg(handle, argc, argv, param);
	case 2:
		return cmd_handler_str(handle, argc, argv, param);
	default:
		return -EINVAL;
	}
}

enum {
	PROTO_L1_MAC = 0,
	PROTO_L2_ETH,
	PROTO_L3_IPV4,
	PROTO_L4_UDP,
};

typedef struct tx_desc {
	void *pkt;
	uint32_t sz, nr, inc_off, inc_sz;
	uint64_t inc_step;
} tx_desc_t;

static uint16_t ipv4_csum_calc(const void *buf, size_t len)
{
	uint32_t acc;
	uint16_t src;
	const uint8_t *p;

	acc = 0;
	p = buf;
	while (len > 1) {
		src = (*p++) << 8;
		src |= (*p++);
		acc += src;
		len -= 2;
	}

	if (len > 0) {
		src = (*p) << 8;
		acc += src;
	}

	acc = (acc >> 16) + (acc & 0x0000fffful);
	if ((acc & 0xffff0000ul) != 0) {
		acc = (acc >> 16) + (acc & 0x0000fffful);
	}

	return (uint16_t)acc;
}

static uint64_t be_bytes_to_cpu(const void *src, size_t sz)
{
	__be64 be64 = 0;

	assert(sz <= sizeof(be64));
	memcpy((void *)&be64 + sizeof(be64) - sz, src, sz);

	return __be64_to_cpu(be64);
}

static void cpu_to_be_bytes(void *dst, uint64_t u64, size_t sz)
{
	__be64 be64;

	assert(sz <= sizeof(u64));
	be64 = __cpu_to_be64(u64);

	memcpy(dst, (const void *)&be64 + sizeof(be64) - sz, sz);
}

static int cmd_handler_add_skb(proto_handle_t *handle, int argc, const char *argv[],
			       cmd_param_t *param)
{
	int rc, ret;
	char *s, *str, *dup = NULL;
	uint16_t u16;
	uint32_t hlen = 0, data_begin = 0, data_end = 0;
	uint64_t u64, inc_base;
	tx_desc_t desc = {};
	proto_txd_t txd;
	proto_rxd_t rxd;
	unsigned int i, j, k, proto_bits = 0;
	struct iphdr iphdr = {};
	struct ethhdr ethhdr = {};
	struct udphdr udphdr = {};
	struct {
		const char *name;
		void *hdr;
		uint32_t sz, off;
	} *p, proto[] = {
		[PROTO_L1_MAC]  = {"mac",  &ethhdr, ETH_ALEN * 2},
		[PROTO_L2_ETH]  = {"eth",  &ethhdr, sizeof(struct ethhdr)},
		[PROTO_L3_IPV4] = {"ipv4", &iphdr,  sizeof(struct iphdr)},
		[PROTO_L4_UDP]  = {"udp",  &udphdr, sizeof(struct udphdr)}
	};
	struct {
		const char *name;
		unsigned int off, sz;
	} *f, field[] = {
		{"mac.dst",   offsetof(struct ethhdr, h_dest),   sizeof(ethhdr.h_dest)},
		{"mac.src",   offsetof(struct ethhdr, h_source), sizeof(ethhdr.h_source)},
		{"eth.dst",   offsetof(struct ethhdr, h_dest),   sizeof(ethhdr.h_dest)},
		{"eth.src",   offsetof(struct ethhdr, h_source), sizeof(ethhdr.h_source)},
		{"eth.proto", offsetof(struct ethhdr, h_proto),  sizeof(ethhdr.h_proto)},
		{"ipv4.src",  offsetof(struct iphdr, saddr),     sizeof(iphdr.saddr)},
		{"ipv4.dst",  offsetof(struct iphdr, daddr),     sizeof(iphdr.daddr)},
		{"udp.src",   offsetof(struct udphdr, source),   sizeof(udphdr.source)},
		{"udp.dst",   offsetof(struct udphdr, dest),     sizeof(udphdr.dest)},
	};

	if (argc < 5) {
		fprintf(stderr, "ERR: invalid argument for \"%s\"\n", argv[0]);
		rc = -EINVAL;
		goto err;
	}

	strtoul(argv[1], &s, 0);
	if (*s) {
		fprintf(stderr, "ERR: invalid cpu \"%s\"\n", argv[1]);
		rc = -EINVAL;
		goto err;
	}

	desc.sz = strtoul(argv[3], NULL, 0);
	if (desc.sz < ETH_ZLEN) {
		fprintf(stderr, "ERR: invalid packet size %u\n", desc.sz);
		rc = -EINVAL;
		goto err;
	}

	if (!(dup = strdup(argv[4]))) {
		fprintf(stderr, "ERR: failed to duplicate string\n");
		rc = -errno;
		goto err;
	}
	str = dup;
	while (str) {
		s = strsep(&str, "+");
		for (i = 0; i < ARRAY_SIZE(proto); i++) {
			if (strcmp(s, proto[i].name)) {
				continue;
			}
			if ((proto_bits & (1 << i))) {
				fprintf(stderr, "ERR: proto \"%s\" already selected\n", s);
				rc = EINVAL;
				goto err;
			}
			proto[i].off = hlen;
			hlen += proto[i].sz;
			proto_bits |= 1 << i;
			break;
		}
		if (i >= ARRAY_SIZE(proto)) {
			fprintf(stderr, "ERR: unknown proto \"%s\"\n", s);
			rc = -EINVAL;
			goto err;
		}
	}
	free(dup);
	dup = NULL;

	if (desc.sz < hlen) {
		fprintf(stderr, "ERR: packet size %u shorter than header size %u\n", desc.sz, hlen);
		rc = -EINVAL;
		goto err;
	}

	if ((proto_bits & (1 << PROTO_L2_ETH))
	&&  (proto_bits & (1 << PROTO_L3_IPV4))) {
		ethhdr.h_proto = htons(ETH_P_IP);
	}
	if (proto_bits & (1 << PROTO_L3_IPV4)) {
		iphdr.version = IPVERSION;
		iphdr.ihl = sizeof(iphdr) >> 2;
		u16 = desc.sz - proto[PROTO_L3_IPV4].off;
		iphdr.tot_len = htons(u16);
	}
	if ((proto_bits & (1 << PROTO_L3_IPV4))
	&&  (proto_bits & (1 << PROTO_L4_UDP))) {
		iphdr.protocol = IPPROTO_UDP;
	}
	if (proto_bits & (1 << PROTO_L4_UDP)) {
		u16 = desc.sz - proto[PROTO_L4_UDP].off;
		udphdr.len = htons(u16);
	}

	for (i = 5; i < argc; i++) {
		if (!(dup = strdup(argv[i]))) {
			fprintf(stderr, "ERR: failed to duplicate string\n");
			rc = -errno;
			goto err;
		}
		str = dup;
		s = strsep(&str, "=");
		if (!str) {
			fprintf(stderr, "ERR: bad expression \"%s\"\n", s);
			rc = -EINVAL;
			goto err;
		}

		if (!strcmp(s, "data")) {
			s = strsep(&str, "-");
			data_begin = strtoul(s, NULL, 0) & 0xff;
			if (!str) {
				data_end = data_begin;
				continue;
			}
			data_end = strtoul(str, NULL, 0) & 0xff;
			continue;
		}

		for (j = 0; j < ARRAY_SIZE(field); j++) {
			if (strcmp(s, field[j].name)) {
				continue;
			}
			f = &field[j];
			*strpbrk(s, ".") = '\0';
			for (k = 0; k < ARRAY_SIZE(proto); k++) {
				if (strcmp(s, proto[k].name)) {
					continue;
				}
				p = &proto[k];
				break;
			}
			if (k >= ARRAY_SIZE(proto)) {
				fprintf(stderr, "ERR: unknown protocol \"%s\"\n", s);
				rc = -EINVAL;
				goto err;
			}
			if (!(proto_bits & (1 << k))) {
				fprintf(stderr, "ERR: protocol \"%s\" not select\n", p->name);
				rc = -EINVAL;
				goto err;
			}
			s = strsep(&str, ":");
			u64 = strtoull(s, NULL, 0);
			cpu_to_be_bytes(p->hdr + f->off, u64, f->sz);
			if (!str) {
				break;
			}
			if (desc.nr) {
				fprintf(stderr, "ERR: multi-range is not supported\n");
				rc = EINVAL;
				goto err;
			}
			s = strsep(&str, ":");
			desc.nr = strtoul(s, NULL, 0);
			desc.nr = desc.nr ? : 1;
			desc.inc_step = 1;
			desc.inc_off = p->off + f->off;
			desc.inc_sz = f->sz;
			if (!str) {
				break;
			}
			desc.inc_step = strtoull(str, NULL, 0);
			break;
		}
		if (j >= ARRAY_SIZE(field)) {
			fprintf(stderr, "ERR: unknown field \"%s\"\n", str);
			rc = -EINVAL;
			goto err;
		}
		free(dup);
		dup = NULL;
	}

	if (!(desc.pkt = malloc(desc.sz))) {
		fprintf(stderr, "ERR: failed to alloc memory\n");
		rc = -errno;
		goto err;
	}
	memset(desc.pkt, 0, desc.sz);

	for (i = 0; i < ARRAY_SIZE(proto); i++) {
		if ((1 << i) & proto_bits) {
			memcpy(desc.pkt + proto[i].off, proto[i].hdr, proto[i].sz);
		}
	}
	if (data_begin || data_end) {
		j = data_begin;
		for (i = hlen; i < desc.sz; i++) {
			((uint8_t *)desc.pkt)[i] = j;
			if (j == data_end) {
				j = data_begin;
			} else {
				j = (j + 1) & 0xff;
			}
		}
	}

	desc.nr = desc.nr ? : 1;
	inc_base = be_bytes_to_cpu(desc.pkt + desc.inc_off, desc.inc_sz);

	txd.iov[0].iov_base = (void *)argv[1];
	txd.iov[0].iov_len = strlen(argv[1]) + 1;
	txd.iov[1].iov_base = (void *)argv[2];
	txd.iov[1].iov_len = strlen(argv[2]) + 1;
	txd.num = 2;
	txd.hdr.magic = MAGIC_WORKER;
	txd.hdr.id = WORKER_ID_ADD_SKB;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	for (i = 0; i < desc.nr; i++) {
		u64 = inc_base + desc.inc_step * i;
		cpu_to_be_bytes(desc.pkt + desc.inc_off, u64, desc.inc_sz);
		if (proto_bits & (1 << PROTO_L3_IPV4)) {
			struct iphdr *iph = desc.pkt + proto[PROTO_L3_IPV4].off;
			iph->check = 0;
			iph->check = ipv4_csum_calc(iph, sizeof(*iph));
			iph->check = ~htons(iph->check);
		}
		txd.iov[0].iov_base = desc.pkt;
		txd.iov[0].iov_len = desc.sz;
		txd.hdr.magic = MAGIC_PRIV;
		txd.num = 1;
		if ((rc = proto_send(handle, &txd)) < 0) {
			goto err;
		}
	}

	txd.hdr.magic = MAGIC_PRIV;
	txd.num = 0;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	rc = ret;
	goto ok;
err:
ok:
	free(dup);
	free(desc.pkt);

	return rc;
}

static int cmd_handler_skb_txq(proto_handle_t *handle, int argc, const char *argv[],
			       cmd_param_t *param)
{
	int rc, ret;
	char *s, *str, *dup = NULL;
	__be32 txq, nr = 0;
	proto_txd_t txd;
	proto_rxd_t rxd;

	if (argc != 4) {
		rc = -EINVAL;
		goto err;
	}

	if (!(dup = strdup(argv[3]))) {
		fprintf(stderr, "ERR: failed to duplicate string\n");
		rc = -errno;
		goto err;
	}
	str = dup;
	s = strsep(&str, ":");
	txq = strtoul(s, NULL, 0);
	txq = __cpu_to_be32(txq);
	if (str) {
		nr = strtoul(str, NULL, 0);
	}
	nr = nr ? : 1;
	nr = __cpu_to_be32(nr);

	txd.iov[0].iov_base = (void *)argv[1];
	txd.iov[0].iov_len = strlen(argv[1]) + 1;
	txd.iov[1].iov_base = (void *)argv[2];
	txd.iov[1].iov_len = strlen(argv[2]) + 1;
	txd.iov[2].iov_base = &txq;
	txd.iov[2].iov_len = sizeof(txq);
	txd.iov[3].iov_base = &nr;
	txd.iov[3].iov_len = sizeof(nr);
	txd.num = 4;
	txd.hdr.magic = param->cmd->magic;
	txd.hdr.id = param->cmd->id;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	rc = ret;
	goto ok;
err:
ok:
	free(dup);
	return rc;
}

static int cmd_handler_load_skb(proto_handle_t *handle, int argc, const char *argv[],
				cmd_param_t *param)
{
	int rc, ret;
	char *s, err_buf[PCAP_ERRBUF_SIZE];
	pcap_t *pcap = NULL;
	proto_txd_t txd;
	proto_rxd_t rxd;
	const u_char *pkt;
	struct pcap_pkthdr hdr;

	if (argc < 4) {
		fprintf(stderr, "ERR: invalid argument for \"%s\"\n", argv[0]);
		rc = -EINVAL;
		goto err;
	}

	strtoul(argv[1], &s, 0);
	if (*s) {
		fprintf(stderr, "ERR: invalid cpu \"%s\"\n", argv[1]);
		rc = -EINVAL;
		goto err;
	}

	if (!(pcap = pcap_open_offline(argv[3], err_buf))) {
		fprintf(stderr, "ERR: failed to open file \"%s\"\n", argv[3]);
		rc = -ENOENT;
		goto err;
	}

	txd.iov[0].iov_base = (void *)argv[1];
	txd.iov[0].iov_len = strlen(argv[1]) + 1;
	txd.iov[1].iov_base = (void *)argv[2];
	txd.iov[1].iov_len = strlen(argv[2]) + 1;
	txd.num = 2;
	txd.hdr.magic = MAGIC_WORKER;
	txd.hdr.id = WORKER_ID_ADD_SKB;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	while ((pkt = pcap_next(pcap, &hdr))) {
		txd.iov[0].iov_base = (void *)pkt;
		txd.iov[0].iov_len = hdr.len;
		txd.hdr.magic = MAGIC_PRIV;
		txd.num = 1;
		if ((rc = proto_send(handle, &txd)) < 0) {
			goto err;
		}
	}

	txd.hdr.magic = MAGIC_PRIV;
	txd.num = 0;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	rc = ret;
	goto ok;
err:
ok:
	if (pcap) {
		pcap_close(pcap);
	}

	return rc;
}

static int cmd_handler_save_skb(proto_handle_t *handle, int argc, const char *argv[],
				cmd_param_t *param)
{
	int rc, ret;
	char *s;
	pcap_t *pcap = NULL;
	proto_txd_t txd;
	proto_rxd_t rxd;
	pcap_dumper_t *dump = NULL;
	struct pcap_pkthdr hdr;

	if (argc < 4) {
		fprintf(stderr, "ERR: invalid argument for \"%s\"\n", argv[0]);
		rc = -EINVAL;
		goto err;
	}

	strtoul(argv[1], &s, 0);
	if (*s) {
		fprintf(stderr, "ERR: invalid cpu \"%s\"\n", argv[1]);
		rc = -EINVAL;
		goto err;
	}

	if (!(pcap = pcap_open_dead(DLT_EN10MB, 0x40000))) {
		rc = -ENOMEM;
		goto err;
	}
	if (!(dump = pcap_dump_open(pcap, argv[3]))) {
		fprintf(stderr, "ERR: failed to open file \"%s\"\n", argv[3]);
		rc = -EPERM;
		goto err;
	}

	txd.iov[0].iov_base = (void *)argv[1];
	txd.iov[0].iov_len = strlen(argv[1]) + 1;
	txd.iov[1].iov_base = (void *)argv[2];
	txd.iov[1].iov_len = strlen(argv[2]) + 1;
	txd.num = 2;
	txd.hdr.magic = MAGIC_WORKER;
	txd.hdr.id = param->cmd->id;
	if ((rc = proto_send(handle, &txd)) < 0) {
		goto err;
	}

	while (1) {
		rxd.buf = param->buf;
		rxd.len = param->len;
		if ((rc = proto_recv(handle, &rxd)) < 0) {
			goto err;
		}
		if (!rxd.hdr.length) {
			break;
		}
		hdr.ts = (struct timeval){};
		hdr.len = rxd.hdr.length;
		hdr.caplen = rxd.hdr.length;
		pcap_dump((u_char *)dump, &hdr, rxd.buf);
	}

	rxd.buf = param->buf;
	rxd.len = param->len;
	while (!(rc = cmd_process_std_resp(handle, &rxd, &ret))) {
		continue;
	}

	if (rc < 0) {
		goto err;
	}

	rc = ret;
	goto ok;
err:
ok:
	if (dump) {
		pcap_dump_close(dump);
	}
	if (pcap) {
		pcap_close(pcap);
	}

	return rc;
}

static cmd_t cmd_tbl[] = {
	{"worker",    "Get worker list or status of worker\n"
	              "%s %s < cpu >\n",
	              MAGIC_WORKER, WORKER_ID_WORKER, cmd_handler_no_arg_or_str},
	{"byte_mode", "Set byte mode of netdev\n"
	              "%s %s [ cpu ] [ netdev ]\n",
	              MAGIC_WORKER, WORKER_ID_BYTE_MODE, cmd_handler_str_str_u32},
	{"qlen",      "Set queue length\n"
	              "%s %s [ cpu ] [ netdev ] [ qlen ]\n",
	              MAGIC_WORKER, WORKER_ID_QLEN, cmd_handler_str_str_u32},
	{"pool_sz",   "Set pool size\n"
	              "%s %s [ cpu ] [ netdev ] [ sz ]\n",
	              MAGIC_WORKER, WORKER_ID_POOL_SZ, cmd_handler_str_str_u32},
	{"burst_sz",  "Set burst bytes size\n"
	              "%s %s [ cpu ] [ netdev ] [ sz ]\n",
	              MAGIC_WORKER, WORKER_ID_BURST_SZ, cmd_handler_str_str_u32},
	{"budget",    "Set traffic poll budget\n"
	              "%s %s [ cpu ] [ netdev ] [ budget ]\n",
	              MAGIC_WORKER, WORKER_ID_BUDGET, cmd_handler_str_str_u32},
	{"ps_limit",  "Set per-second limit\n"
	              "%s %s [ cpu ] [ netdev ] [ limit ]\n",
	              MAGIC_WORKER, WORKER_ID_PS_LIMIT, cmd_handler_str_str_u64},
	{"pkt_cnt",   "Set packets count\n"
	              "%s %s [ cpu ] [ netdev ] [ count ]\n",
	              MAGIC_WORKER, WORKER_ID_PKT_CNT,  cmd_handler_str_str_u64},
	{"add_skb",   "add skbs\n"
	              "%s %s [ cpu ] [ netdev ] [ sz ] [ proto ] < ... >\n",
	              0, 0, cmd_handler_add_skb},
	{"del_skb",   "Delete skbs\n"
	              "%s %s [ cpu ] [ netdev ]\n",
	              MAGIC_WORKER, WORKER_ID_DEL_SKB, cmd_handler_str_str},
	{"skb_txq",   "Set txq mapping of skbs\n"
	              "%s %s [ cpu ] [ netdev ] [ txq ] < nr >\n",
	              MAGIC_WORKER, WORKER_ID_SKB_TXQ, cmd_handler_skb_txq},
	{"load_skb",  "Load skbs from pcap file\n"
	              "%s %s [ cpu ] [ netdev ] [ filename ]\n",
	              0, 0, cmd_handler_load_skb},
	{"save_skb",  "save skbs to pcap file\n"
	              "%s %s [ cpu ] [ netdev ] [ filename ]\n",
	              0, WORKER_ID_DUMP_SKB, cmd_handler_save_skb},
	{"netdev",    "Get netdev list or status of netdev\n"
	              "%s %s < netdev >\n",
	              MAGIC_NETDEV, NETDEV_ID_NETDEV, cmd_handler_no_arg_or_str},
	{"start",     "Start traffic on netdev\n"
	              "%s %s [ netdev ]\n",
	              MAGIC_NETDEV, NETDEV_ID_START, cmd_handler_str},
	{"stop",      "Stop traffic on netdev\n"
	              "%s %s [ netdev ]\n",
	              MAGIC_NETDEV, NETDEV_ID_STOP, cmd_handler_str},
	{"clear",     "Clear statistics of netdev\n"
	              "%s %s [ netdev ]\n",
	              MAGIC_NETDEV, NETDEV_ID_CLEAR, cmd_handler_str},
	{"stats",     "Get statistics of all netdev\n"
	              "%s %s\n",
	              MAGIC_NETDEV, NETDEV_ID_STATS, cmd_handler_no_arg},
	{"attach",    "Attach netdev\n"
	              "%s %s [ netdev ]\n",
	              MAGIC_NETDEV, NETDEV_ID_ATTACH, cmd_handler_str},
	{"detach",    "Detach netdev\n"
	              "%s %s [ netdev ]\n",
	              MAGIC_NETDEV, NETDEV_ID_DETACH, cmd_handler_str},
};

static int process_cmd_from_arg(proto_handle_t *handle, int argc, const char *argv[])
{
	int i, rc;
	cmd_param_t param = {};

	if (!(param.buf = malloc(PROTO_BUF_MAX))) {
		fprintf(stderr, "ERR: failed to alloc memory\n");
		rc = -errno;
		goto err;
	}
	param.len = PROTO_BUF_MAX;

	for (i = 0; i <= ARRAY_SIZE(cmd_tbl); i++) {
		if (!strcmp(argv[0], cmd_tbl[i].name)) {
			param.cmd = &cmd_tbl[i];
			break;
		}
	}

	if (!param.cmd) {
		fprintf(stderr, "ERR: command \"%s\" not found\n", argv[0]);
		rc = -EINVAL;
		goto err;
	}

	if ((rc = param.cmd->fn(handle, argc, argv, &param))) {
		goto err;
	}
	goto ok;
ok:
err:
	free(param.buf);
	return rc;
}

static void show_help(void)
{
	int i;

	printf("SimpleBits CLI\n");
	printf("Usage:\n");
	printf("sb_cli [ -h server ip ] [ -p server port] commands...\n");
	printf("Default server ip: 127.0.0.1\n");
	printf("Default server port: 1234\n");
	printf("\nCommands:\n");

	for (i = 0; i < ARRAY_SIZE(cmd_tbl); i++) {
		printf(cmd_tbl[i].help, "sb_cli", cmd_tbl[i].name);
		printf("\n");
	}
}

static ssize_t cmd_ops_sendmsg(proto_sock_t sock, proto_iovec_t *iov, size_t num, int flags)
{
	ssize_t ret;
	struct msghdr msg = {};

	msg.msg_iov = iov;
	msg.msg_iovlen = num;

	if ((ret = sendmsg(sock, &msg, 0)) < 0) {
		return -errno;
	} else {
		return ret;
	}
}

static ssize_t cmd_ops_recv(proto_sock_t sock, void *buf, size_t len, int flags)
{
	ssize_t ret;

	if ((ret = recv(sock, buf, len, flags)) < 0) {
		return -errno;
	} else {
		return ret;
	}
}

int main(int argc, const char *argv[])
{
	int i, rc, sockfd = -1;
	char *s, *ip_env;
	uint16_t port = 1234;
	const char *ip = "127.0.0.1";
	proto_handle_t handle = {};
	struct sockaddr_in sin;

	mtrace_init();

	if ((ip_env = getenv("SB_IP"))) {
		s = strsep(&ip_env, ":");
		if (strlen(s)) {
			ip = s;
		}
		if (ip_env) {
			port = strtoul(ip_env, NULL, 0);
		}
	}

	for (i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "-h")) {
			if (++i == argc) {
				show_help();
				rc = EINVAL;
				goto err;
			}
			ip = argv[i];
		} else if (!strcmp(argv[i], "-p")) {
			if (++i == argc) {
				show_help();
				rc = EINVAL;
				goto err;
			}
			port = strtoul(argv[i], NULL, 0);
		} else {
			break;
		}
	}

	handle.sendmsg = cmd_ops_sendmsg;
	handle.recv = cmd_ops_recv;

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_addr.s_addr = inet_addr(ip);
	sin.sin_port = htons(port);

	if ((sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP)) < 0) {
		fprintf(stderr, "ERR: failed to create socket\n");
		rc = errno;
		goto err;
	}

	if (connect(sockfd, (struct sockaddr *)&sin, sizeof(struct sockaddr)) < 0) {
		fprintf(stderr, "ERR: failed to connect socket\n");
		rc = errno;
		goto err;
	}

	handle.sock = sockfd;
	handle.io_err = false;

	if (i >= argc) {
		show_help();
		rc = EINVAL;
		goto err;
	}

	rc = process_cmd_from_arg(&handle, argc - i, &argv[i]);
	rc = rc < 0 ? -rc : rc;
	if (rc) {
		fprintf(stderr, "ERR: %s\n", strerror(rc));
		goto err;
	}

	rc = 0;
	goto ok;
ok:
err:
	if (sockfd >= 0) {
		shutdown(sockfd, SHUT_RDWR);
		close(sockfd);
	}

	mtrace_finish();

	return rc;
}
