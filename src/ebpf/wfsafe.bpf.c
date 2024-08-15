// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
#include <bpf/bpf_endian.h>
#include "wfsafe.h"

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPV4_MIN_HLEN 20
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define TCP_MIN_HLEN 20
#define MESSAGE_SIZE 32
#define KEY_SIZE 32

#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memcmp(dest, src, n) __builtin_memcmp((dest), (src), (n))

/****************************** MACROS ******************************/
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

struct
{
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, HMAC_SHA256_CTX);
} ctx_map SEC(".maps");


typedef struct flow {
	__be32 src_addr;
	__be32 dst_addr;
	__be16 src_port;
	__be16 dst_port;
} flow_t;

typedef struct keys {
    __u8 padding_key[KEY_SIZE];
    __u8 dummy_packet_key[KEY_SIZE];
} keys_t;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, flow_t);
	__type(value, keys_t);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} clients_map SEC(".maps");

/**************************** VARIABLES *****************************/
static const __u32 k[SHA256_BLOCK_SIZE] = {
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};

/*********************** FUNCTION DEFINITIONS ***********************/
static inline void sha256_transform(SHA256_CTX *ctx, const __u8 *data)
{

	__u32 a, b, c, d, e, f, g, h, i, j, t1, t2, m[SHA256_BLOCK_SIZE];

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < SHA256_BLOCK_SIZE; ++i)
		m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

	a = ctx->state[0];
	b = ctx->state[1];
	c = ctx->state[2];
	d = ctx->state[3];
	e = ctx->state[4];
	f = ctx->state[5];
	g = ctx->state[6];
	h = ctx->state[7];

	for (i = 0; i < SHA256_BLOCK_SIZE; ++i)
	{
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
		t2 = EP0(a) + MAJ(a, b, c);
		h = g;
		g = f;
		f = e;
		e = d + t1;
		d = c;
		c = b;
		b = a;
		a = t1 + t2;
	}

	ctx->state[0] += a;
	ctx->state[1] += b;
	ctx->state[2] += c;
	ctx->state[3] += d;
	ctx->state[4] += e;
	ctx->state[5] += f;
	ctx->state[6] += g;
	ctx->state[7] += h;
}

static inline void sha256_init(SHA256_CTX *ctx)
{
	ctx->datalen = 0;
	ctx->bitlen = 0;
	ctx->state[0] = 0x6a09e667;
	ctx->state[1] = 0xbb67ae85;
	ctx->state[2] = 0x3c6ef372;
	ctx->state[3] = 0xa54ff53a;
	ctx->state[4] = 0x510e527f;
	ctx->state[5] = 0x9b05688c;
	ctx->state[6] = 0x1f83d9ab;
	ctx->state[7] = 0x5be0cd19;
}

// static inline void sha256_update(SHA256_CTX *ctx, const __u8 *x, size_t xlen, const __u8 *y, size_t ylen)
static inline void sha256_update(SHA256_CTX *ctx, const __u8 *x, const __u8 *y)
{
	size_t i;

	memcpy(ctx->data, x, SHA256_BLOCK_SIZE);
	sha256_transform(ctx, ctx->data);
	ctx->bitlen += 512;
	memcpy(ctx->data, y, MESSAGE_SIZE);
	ctx->datalen = MESSAGE_SIZE;

}



static inline void sha256_final(SHA256_CTX *ctx, __u8 hash[])
{

	ctx->data[MESSAGE_SIZE] = 0x80;
	memset(ctx->data + MESSAGE_SIZE + 1, 0, 56 - MESSAGE_SIZE - 1);

	// Append to the padding the total message's length in bits and transform.
	ctx->bitlen += ctx->datalen * 8;
	ctx->data[63] = ctx->bitlen;
	ctx->data[62] = ctx->bitlen >> 8;
	ctx->data[61] = ctx->bitlen >> 16;
	ctx->data[60] = ctx->bitlen >> 24;
	ctx->data[59] = ctx->bitlen >> 32;
	ctx->data[58] = ctx->bitlen >> 40;
	ctx->data[57] = ctx->bitlen >> 48;
	ctx->data[56] = ctx->bitlen >> 56;
	sha256_transform(ctx, ctx->data);

	// Since this implementation uses little endian byte ordering and SHA uses big endian,
	// reverse all the bytes when copying the final state to the output hash.
	for (__u8 i = 0; i < 4; ++i)
	{
		hash[i] = (ctx->state[0] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 4] = (ctx->state[1] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 8] = (ctx->state[2] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 12] = (ctx->state[3] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 16] = (ctx->state[4] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 20] = (ctx->state[5] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 24] = (ctx->state[6] >> (24 - i * 8)) & 0x000000ff;
		hash[i + 28] = (ctx->state[7] >> (24 - i * 8)) & 0x000000ff;
	}
}

static inline void hmac_sha256(
	HMAC_SHA256_CTX *ctx,
	const __u8 *key,
	const void *data,
	__u8 *out,
	const size_t outlen)
{

	size_t sz;
	int i;
	SHA256_CTX *sha_ctx = &(ctx->sha256_ctx);

	memcpy(ctx->k, key, KEY_SIZE);
	memset((ctx->k) + KEY_SIZE, 0, SHA256_BLOCK_SIZE - KEY_SIZE);

	for (i = 0; i < SHA256_BLOCK_SIZE; i++)
	{
		ctx->k_ipad[i] = 0x36 ^ ctx->k[i];
		ctx->k_opad[i] = 0x5c ^ ctx->k[i];
	}

	// Perform HMAC algorithm: ( https://tools.ietf.org/html/rfc2104 )
	//      `H(K XOR opad, H(K XOR ipad, data))`
	sha256_init(sha_ctx);
	sha256_update(sha_ctx, ctx->k_ipad, data);
	sha256_final(sha_ctx, ctx->ihash);
	
	
	sha256_init(sha_ctx);
	sha256_update(sha_ctx, ctx->k_opad, ctx->ihash);
	sha256_final(sha_ctx, ctx->ohash);


	sz = (outlen > SHA256_DIGEST_SIZE) ? SHA256_DIGEST_SIZE : outlen;

	memcpy(out, ctx->ohash, sz);
}



static inline int ip_is_fragment(struct iphdr *iph)
{
	return bpf_ntohs(iph->frag_off) & (IP_MF | IP_OFFSET);
}

static inline void* manage_ethernet(void* data, void* data_end)
{
	struct ethhdr *eth = data;

	if (data + ETH_HLEN > data_end)
	{
		return NULL;
	}

	if(bpf_htons(eth->h_proto) != ETH_P_IP)
	{
		return NULL;
	}

	return data + ETH_HLEN;
}



static inline void* manage_ipv4(void* data, void* data_end, flow_t *fl)
{

	__u8 ip_len;
	struct iphdr *ip_v4 = (struct iphdr *) data;

	if (data + IPV4_MIN_HLEN > data_end)
	{
		bpf_printk("No IP packet\n");
		return NULL;
	}

	ip_len = ip_v4->ihl << 2;

	if (data + ip_len > data_end)
		return NULL;

	if (ip_is_fragment(ip_v4))
	{
		bpf_printk("Fragmented IP packet\n");
		return NULL;
	}

	if (ip_v4->protocol != IPPROTO_TCP)
	{
		bpf_printk("No TCP packet\n");
		return NULL;
	}

	fl->src_addr = bpf_ntohl(ip_v4->saddr);
	fl->dst_addr = bpf_ntohl(ip_v4->daddr);

	return (void*) ((long)data + (long)ip_len);
}

static inline __u8 manage_tcp(void* data, void* data_end, flow_t *fl)
{
	struct tcphdr *tcp = (struct tcphdr *) data;
	__u16 tcp_hlen;

	if (data + TCP_MIN_HLEN > data_end)
		return 0;

	fl->src_port = bpf_ntohs(tcp->source);
	fl->dst_port = bpf_ntohs(tcp->dest);

	return 1;
	//return data + tcp_hlen;
}

__attribute__((no_stack_protector))
SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void*) (long)ctx->data;
    __u8 hmac[SHA256_DIGEST_SIZE];
    HMAC_SHA256_CTX *hmac_ctx;
	struct so_event *e;
	keys_t *keys;
	struct flow fl;
    __u32 packet_len;
	int hmac_message_offset;
	__u32 dummy_hmac_offset;

	//l2 management
	data = manage_ethernet(data, data_end);
	if (!data)
		return XDP_PASS;

	//l3 management
	data = manage_ipv4(data, data_end, &fl);
	if(!data)
		return XDP_PASS;

	//l4 management
	if(!manage_tcp(data, data_end, &fl))
		return XDP_PASS;

	//retrieve secret key
	keys = bpf_map_lookup_elem(&clients_map, &fl);

	//check if ip is registered
	if (!keys)
	{
		//bpf_printk("IP not registered\n");
    	return XDP_PASS;
	}

	hmac_ctx = bpf_map_lookup_elem(&ctx_map, &fl);
	if (!hmac_ctx)
	{
		return XDP_PASS;
	}

	packet_len = ctx->data_end - ctx->data;

	/*if(packet_len < MESSAGE_SIZE + SHA256_DIGEST_SIZE)
	{
		return XDP_PASS;
	}*/

	hmac_message_offset = packet_len - (MESSAGE_SIZE + SHA256_DIGEST_SIZE);
	

	data = (void*) (long)ctx->data;

	data = (void*)((long) data + (long)hmac_message_offset);

	//
	if(data + MESSAGE_SIZE > data_end || hmac_message_offset < 0)
	{
		return XDP_PASS;
	}
	{
		return XDP_PASS;
	}	


    hmac_sha256(hmac_ctx, keys->dummy_packet_key, data, hmac, SHA256_DIGEST_SIZE);


    data += SHA256_DIGEST_SIZE;

   	if(data + SHA256_DIGEST_SIZE > data_end)
	{
		return XDP_PASS;
	}


    if (memcmp(hmac, data, SHA256_DIGEST_SIZE) == 0)
    {
        return XDP_DROP;
    }

    
	return XDP_PASS;
}


char __license[] SEC("license") = "GPL";
