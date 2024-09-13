// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <string.h>
#include <bpf/bpf_endian.h>
#include "mem.h"
#include "hmac.h"
#include "header_parser.h"

#define MAX_IPH_SIZE 60
#define MAX_ALLOWED_SIZE 1442

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, hmac_sha256_ctx);
} ctx_map SEC(".maps");

typedef struct flow
{
	__be32 src_addr;
	__be32 dst_addr;
	__be16 src_port;
	__be16 dst_port;
} flow_t;

typedef struct keys
{
	__u8 padding_key[KEY_SIZE];
	__u8 dummy_packet_key[KEY_SIZE];
} keys_t;

struct tlshdr
{
	__u8 type;
	__be16 version;
	__be16 length;
} __attribute__((packed));

struct hdr
{
	struct ethhdr *eth;
	struct iphdr *ip;
	struct tcphdr *tcp;
	struct tlshdr *tls;
};

struct
{
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, flow_t);
	__type(value, keys_t);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} clients_map SEC(".maps");

static __always_inline __u16 csum_fold(__u32 csum)
{
	csum = (csum & 0xffff) + (csum >> 16);
	csum = (csum & 0xffff) + (csum >> 16);
	return (__u16)~csum;
}

static __always_inline __u16 csum_tcpudp_magic(__u32 saddr, __u32 daddr,
											   __u32 len, __u8 proto,
											   __u32 csum)
{
	__u64 s = csum;

	s += (__u32)saddr;
	s += (__u32)daddr;
#if __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
	s += proto + len;
#elif __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
	s += (proto + len) << 8;
#else
#error Unknown endian
#endif
	s = (s & 0xffffffff) + (s >> 32);
	s = (s & 0xffffffff) + (s >> 32);

	return csum_fold((__u32)s);
}

/*
static __always_inline void *manage_ipv4_checksums(void *data, void *data_end, __u16 cut_len)
{

	__u32 ip_len;
	struct iphdr *ip_v4 = (struct iphdr *)data;

	if (data + IPV4_MIN_HLEN > data_end)
	{
		bpf_printk("No IP packet\n");
		return NULL;
	}

	ip_len = ip_v4->ihl << 2;

	ip_len = ip_len & 0x3F;

	ip_v4->tot_len = bpf_htons(bpf_ntohs(ip_v4->tot_len) - cut_len);

	ip_v4->check = 0;

	if (data + 60 > data_end) // TODO: correggo guardando se ci sono opzioni iterativamente
		return NULL;

	__s64 csum = bpf_csum_diff(0, 0, data, ip_len, 0);

	if (csum < 0)
	{
		bpf_printk("csum < 0");
		return NULL;
	}

	csum = csum_fold(csum);

	ip_v4->check = csum;

	data += ip_len;

	struct tcphdr *tcp = (struct tcphdr *)data;

	if (data + TCP_MIN_HLEN > data_end)
		return NULL;

	__u16 tcp_len = bpf_ntohl(ip_v4->tot_len) - ip_len;

	tcp->check = 0;

	if (data + tcp_len > data_end)
		return NULL;

	tcp_len = tcp_len & 0xFFF;

	if(tcp_len > 0xFFF){
		bpf_printk("data + tcp_len > data_end");
		return NULL;
	}

	__u32 csum_tcp = bpf_csum_diff(0, 0, (u32 *)tcp, tcp_len, 0);

	if (csum_tcp < 0)
	{
		bpf_printk("csum_tcp < 0");
		return NULL;
	}

	csum_tcp = csum_tcpudp_magic(ip_v4->saddr, ip_v4->daddr, tcp_len, IPPROTO_TCP, csum_tcp);

	tcp->check = csum_tcp;

	bpf_printk("tcp_hlen: %u", tcp_len);

	return (void *)((long)data + (long)ip_len);
}
*/

static __always_inline struct tlshdr* parse_tls(struct xdp_md *ctx, __u8 tls_offset)
{
	struct tlshdr *tls = NULL;
	if(tls_offset == 54)
		tls = ptr_at(ctx, 54, sizeof(struct tlshdr));
	else if (tls_offset == 58)
		tls = ptr_at(ctx, 58, sizeof(struct tlshdr));
	else if (tls_offset == 62)
		tls = ptr_at(ctx, 62, sizeof(struct tlshdr));
	else if (tls_offset == 66)
	    tls = ptr_at(ctx, 66, sizeof(struct tlshdr));
	else if (tls_offset == 70)
		tls = ptr_at(ctx, 70, sizeof(struct tlshdr));
	else if (tls_offset == 74)
		tls = ptr_at(ctx, 74, sizeof(struct tlshdr));
	else if (tls_offset == 78)
		tls = ptr_at(ctx, 78, sizeof(struct tlshdr));
	else if (tls_offset == 82)
		tls = ptr_at(ctx, 82, sizeof(struct tlshdr));
	else if (tls_offset == 86)
		tls = ptr_at(ctx, 86, sizeof(struct tlshdr));
	else if (tls_offset == 90)
		tls = ptr_at(ctx, 90, sizeof(struct tlshdr));
	else if(tls_offset == 94)
		tls = ptr_at(ctx, 94, sizeof(struct tlshdr));
	else if(tls_offset == 98)
		tls = ptr_at(ctx, 98, sizeof(struct tlshdr));
	else if(tls_offset == 102)
		tls = ptr_at(ctx, 102, sizeof(struct tlshdr));
	else if(tls_offset == 106)
		tls = ptr_at(ctx, 106, sizeof(struct tlshdr));
	else if(tls_offset == 110)
		tls = ptr_at(ctx, 110, sizeof(struct tlshdr));
	else if(tls_offset == 114)
		tls = ptr_at(ctx, 114, sizeof(struct tlshdr));
	else if(tls_offset == 118)
		tls = ptr_at(ctx, 118, sizeof(struct tlshdr));
	else if(tls_offset == 122)
		tls = ptr_at(ctx, 122, sizeof(struct tlshdr));
	else if(tls_offset == 126)
		tls = ptr_at(ctx, 126, sizeof(struct tlshdr));
	else if(tls_offset == 130)
		tls = ptr_at(ctx, 130, sizeof(struct tlshdr));
	else if(tls_offset == 134)
		tls = ptr_at(ctx, 134, sizeof(struct tlshdr));
	else 
		tls = NULL;

	return tls;

}

static __always_inline int get_headers(struct xdp_md *ctx, struct hdr *hdr)
{
	__u8 ip_len;

	hdr->eth = parse_ethernet(ctx);
	if (!hdr->eth)
		return 0;

	hdr->ip = parse_ip(ctx);
	if (!hdr->ip)
		return 0;
	ip_len = hdr->ip->ihl << 2;
	ip_len = ip_len & 0x3F;

	hdr->tcp = parse_tcp(ctx, ip_len);
	if (!hdr->tcp)
		return 0;

	hdr->tls = parse_tls(ctx, ETH_HLEN + ip_len + hdr->tcp->doff * 4);
	if (!hdr->tls)
		return 0;

	return 1;
}

static __always_inline int is_dummy_packet(struct xdp_md *ctx, hmac_sha256_ctx *hmac_ctx, __u8 *dummy_packet_key)
{
	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 packet_len = ctx->data_end - ctx->data;
	int hmac_message_offset = (packet_len - (MESSAGE_SIZE + SHA256_DIGEST_SIZE)) & 0xFFF;
	__u8 hmac[SHA256_DIGEST_SIZE];

	if (hmac_message_offset < 0)
		return 0;

	data = (void *)((long)data + (long)hmac_message_offset);

	if (data + MESSAGE_SIZE > data_end)
		return 0;

	hmac_sha256(hmac_ctx, dummy_packet_key, data, hmac, SHA256_DIGEST_SIZE);

	data += MESSAGE_SIZE;

	if (data + SHA256_DIGEST_SIZE > data_end)
		return 0;

	if (memcmp(hmac, data, SHA256_DIGEST_SIZE) == 0)
		return 1;

	return 0;
}

static __always_inline __u16 get_padding_len(struct xdp_md *ctx, hmac_sha256_ctx *hmac_ctx, __u8 *padding_key)
{
	// PADDING MANAGEMENT (5*MESSAGE_SIZE bytes is the maximum padding size)

	void *data = (void *)(long)ctx->data;
	void *data_end = (void *)(long)ctx->data_end;
	__u16 packet_len = ctx->data_end - ctx->data;
	int hmac_message_offset = (packet_len - SHA256_DIGEST_SIZE) & 0xFFF;
	void *message = (void *)((long)data + (long)hmac_message_offset);
	void *hmac_candidate;
	__u8 hmac[SHA256_DIGEST_SIZE];
	__u8 i;

#pragma unroll
	for (i = 0; i < 5; i++)
	{
		hmac_message_offset -= MESSAGE_SIZE; // se l'unita minima del padding scende cambio la logica, la prima volta retrocedo di message, poi di "unit"

		hmac_message_offset = hmac_message_offset & 0xFFF;

		hmac_candidate = message;

		message = ptr_at(ctx, hmac_message_offset, MESSAGE_SIZE);

		if (!message)
			break;

		hmac_sha256(hmac_ctx, padding_key, message, hmac, SHA256_DIGEST_SIZE);

		if (hmac_candidate + SHA256_DIGEST_SIZE > data_end)
			break;

		if (memcmp(hmac, hmac_candidate, SHA256_DIGEST_SIZE) != 0)
			break;

	}

	return i * MESSAGE_SIZE;
}

static __always_inline int update_ipv4_len(struct iphdr *ip, struct xdp_md *ctx, int diff)
{
	void *data_end = (void *)(long)ctx->data_end;
	__u16 ip_len = ip->ihl << 2;

	ip->tot_len = bpf_htons(bpf_ntohs(ip->tot_len) - diff);

	if ((void *)ip + MAX_IPH_SIZE > data_end)
		return 0;

	ip->check = 0;
	__s64 csum = bpf_csum_diff(0, 0, (void *)ip, ip_len, 0);
	if (csum < 0)
		return 0;

	csum = csum_fold(csum);
	ip->check = csum;

	return 1;
}

__attribute__((__always_inline__)) static inline __u16 csum_fold_helper(
	__u64 csum)
{
	int i;
#pragma unroll
	for (i = 0; i < 4; i++)
	{
		if (csum >> 16)
			csum = (csum & 0xffff) + (csum >> 16);
	}
	return ~csum;
}

static __always_inline int
ipv4_l4_csum(void *data_start, int data_size, __u64 *csum, struct iphdr *iph, struct xdp_md *ctx)
{
	__u32 tmp = 0;
	*csum = bpf_csum_diff(0, 0, data_start, data_size, *csum);
	*csum = bpf_csum_diff(0, 0, &iph->saddr, sizeof(__be32), *csum);
	*csum = bpf_csum_diff(0, 0, &iph->daddr, sizeof(__be32), *csum);
	tmp = __builtin_bswap32((__u32)(iph->protocol));
	*csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
	tmp = __builtin_bswap32((__u32)(data_size));
	*csum = bpf_csum_diff(0, 0, &tmp, sizeof(__u32), *csum);
	*csum = csum_fold_helper(*csum);
	return 1;
}

static __always_inline int update_tcp_checksum(struct tcphdr *tcp, struct iphdr *ip, struct xdp_md *ctx, int diff)
{
	void *data_end = (void *)(long)ctx->data_end;
	void *data = (void *)(long)ctx->data;
	__u16 ip_len = ip->ihl << 2;
	__u16 tcp_len = bpf_ntohs(ip->tot_len) - ip_len;
	__u64 csum = 0;

	tcp->check = 0;
	tcp = parse_tcp(ctx, ip_len);
	if (!tcp)
		return 0;
	if (data + MAX_ALLOWED_SIZE > data_end)
		return 0;

	//bpf_printk("ip_len: %u", ip_len);
	if (tcp_len > MAX_ALLOWED_SIZE - 74)
		return 0;

	s64 csum_tcp = bpf_csum_diff(0, 0, tcp, tcp_len - tcp_len % 4, 0);
	//bpf_printk("csum_tcp: %d", csum_tcp);

	if (csum_tcp < 0)
		return 0;

	u8 last_bytes[4] = {0, 0, 0, 0};
	void *a = (void *)((long)tcp + (long)(tcp_len - tcp_len % 4));
	if (a + 4 > data_end)
		return 0;
	for (int i = 0; i < 4 && i < tcp_len % 4; i++)
	{
		last_bytes[i] = *(u8 *)(a + i);
	}
	csum_tcp = bpf_csum_diff(0, 0, last_bytes, 4, csum_tcp);
	if (csum_tcp < 0)
		return 0;

	csum_tcp = csum_tcpudp_magic(ip->saddr, ip->daddr, tcp_len, IPPROTO_TCP, csum_tcp);

	tcp->check = csum_tcp;

	return 1;
}

SEC("xdp")
int xdp_parser_func(struct xdp_md *ctx)
{
	struct hdr hdr;
	flow_t fl;
	__u32 ctx_map_key = 0;
	hmac_sha256_ctx *hmac_ctx;
	keys_t *keys;
	__u32 packet_len = ctx->data_end - ctx->data;
	__u64 csum = 0;

	if (!get_headers(ctx, &hdr))
		return XDP_PASS;

	fl = (flow_t){
		.src_addr = bpf_ntohl(hdr.ip->saddr),
		.dst_addr = bpf_ntohl(hdr.ip->daddr),
		.src_port = bpf_ntohs(hdr.tcp->source),
		.dst_port = bpf_ntohs(hdr.tcp->dest)};

	keys = bpf_map_lookup_elem(&clients_map, &fl);
	if (!keys)
	{
		// bpf_printk("ip_src: %u, ip_dst: %u, port_src: %u, port_dts: %u", fl.src_addr, fl.dst_addr, bpf_ntohs(hdr.tcp->source), bpf_ntohs(hdr.tcp->dest));
		return XDP_PASS;
	}


	
	bpf_printk("tls");
	// bpf_printk("Packet len: %u", packet_len);

	hmac_ctx = bpf_map_lookup_elem(&ctx_map, &ctx_map_key);
	if (!hmac_ctx)
		return XDP_PASS;

	if (is_dummy_packet(ctx, hmac_ctx, &(keys->dummy_packet_key))) // ANZI CHE DROPPARE DOVREI TRASFORMARE IL PACCHETTO IN UN ACK E MANDARLO INDIETRO
		return XDP_DROP;

	// bpf_printk("Packet len: %u", packet_len);

	__u16 padding_len = get_padding_len(ctx, hmac_ctx, &(keys->padding_key));
	if (padding_len == 0)
		return XDP_PASS;

	// bpf_printk("ccc");

	if (bpf_xdp_adjust_tail(ctx, MAX_ALLOWED_SIZE - packet_len) < 0)
	{
		bpf_printk("Error adjusting tail: %d", padding_len);
		return XDP_PASS;
	}

	if (!get_headers(ctx, &hdr))
		return XDP_ABORTED;

	bpf_printk("aaa");

	if (!update_ipv4_len(hdr.ip, ctx, padding_len))
		return XDP_ABORTED;

	bpf_printk("bbb");
	
	if((void*)hdr.tls + sizeof(struct tlshdr) > (void*)ctx->data_end)
		return XDP_ABORTED;

	hdr.tls->length = bpf_htons(bpf_ntohs(hdr.tls->length) - padding_len);
	bpf_printk("tls_len: %x", hdr.tls->version);

	if (!update_tcp_checksum(hdr.tcp, hdr.ip, ctx, padding_len))
		return XDP_ABORTED;
	
	bpf_printk("ccc");

	if (bpf_xdp_adjust_tail(ctx, -(MAX_ALLOWED_SIZE - packet_len + padding_len)) < 0)
		return XDP_ABORTED;

	bpf_printk("sssss");

	return XDP_PASS;
}

char __license[] SEC("license") = "GPL";
