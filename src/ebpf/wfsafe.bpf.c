// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2020 Facebook */

#include "vmlinux.h"
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <string.h>

#define ETH_HLEN 14
#define ETH_P_IP 0x0800
#define IPV4_MIN_HLEN 20
#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF
#define TCP_MIN_HLEN 20
#define SHA256_BLOCK_SIZE 64
#define SHA256_DIGEST_SIZE 32

#define ROTR(x, n) ((x >> n) | (x << (32 - n)))
#define SHR(x, n) (x >> n)

#define CH(x, y, z) ((x & y) ^ (~x & z))
#define MAJ(x, y, z) ((x & y) ^ (x & z) ^ (y & z))
#define EP0(x) (ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define EP1(x) (ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define SIG0(x) (ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define SIG1(x) (ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

typedef struct flow {
	__be32 src_addr;
	__be32 dst_addr;
	__be16 src_port;
	__be16 dst_port;
} flow_t;

typedef struct keys {
    __u8 padding_key[32];
    __u8 dummy_packet_key[32];
} keys_t;

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 8192);
	__type(key, flow_t);
	__type(value, keys_t);
	__uint(pinning, LIBBPF_PIN_BY_NAME);
} clients_map SEC(".maps");

/*
static const __u32 k[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
    0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
    0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
    0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
    0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
    0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
    0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
    0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
    0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

struct sha256_ctx {
    __u32 state[8];
    __u64 count;
    __u8 buffer[64];
};

static inline void sha256_transform(struct sha256_ctx *ctx, const __u8 data[])
{
	__u32 a, b, c, d, e, f, g, h, i, j, t1, t2, m[64];

    for (i = 0, j = 0; i < 16; ++i, j += 4)
        m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
    for (; i < 64; ++i)
        m[i] = SIG1(m[i - 2]) + m[i - 7] + SIG0(m[i - 15]) + m[i - 16];

    a = ctx->state[0];
    b = ctx->state[1];
    c = ctx->state[2];
    d = ctx->state[3];
    e = ctx->state[4];
    f = ctx->state[5];
    g = ctx->state[6];
    h = ctx->state[7];

    for (i = 0; i < 64; ++i) {
        t1 = h + EP1(e) + CH(e, f, g) + k[i] + m[i];
        t2 = EP0(a) + MAJ(a, b, c);
        h = g;
        g = f;
        f = e;
        e = d + t1;
        d = c;
        c = b;
        b = a;
        a = t2 + t1;
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

static inline void sha256_init(struct sha256_ctx *ctx)
{
    ctx->state[0] = 0x6a09e667;
    ctx->state[1] = 0xbb67ae85;
    ctx->state[2] = 0x3c6ef372;
    ctx->state[3] = 0xa54ff53a;
    ctx->state[4] = 0x510e527f;
    ctx->state[5] = 0x9b05688c;
    ctx->state[6] = 0x1f83d9ab;
    ctx->state[7] = 0x5be0cd19;
    ctx->count = 0;
}

static inline void sha256_update(struct sha256_ctx *ctx, const __u8 *data, __u16 len)
{
    __u16 i, j;

    j = ctx->count & 63;
    ctx->count += len;
    for (i = 0; i < len; ++i) {
        ctx->buffer[j++] = data[i];
        if (j == 64) {
            sha256_transform(ctx, ctx->buffer);
            j = 0;
        }
    }
}

__attribute__((no_stack_protector))
static inline void sha256_final(struct sha256_ctx *ctx, __u8 hash[32])
{
    __u32 i;
    __u8 finalcount[8];

    for (i = 0; i < 8; ++i)
        finalcount[i] = (ctx->count >> ((7 - i) * 8)) & 255;
    sha256_update(ctx, (__u8 *)"\200", 1);
    for (i = 0; i < 63 && (ctx->count & 63) != 56; i++)
        sha256_update(ctx, (__u8 *)"\0", 1);
    sha256_update(ctx, finalcount, 8);
    for (i = 0; i < 8; ++i) {
        hash[i * 4] = (ctx->state[i] >> 24) & 255;
        hash[i * 4 + 1] = (ctx->state[i] >> 16) & 255;
        hash[i * 4 + 2] = (ctx->state[i] >> 8) & 255;
        hash[i * 4 + 3] = ctx->state[i] & 255;
    }
}

// Implementazione HMAC-SHA256
static inline void hmac_sha256(const __u8 *key, __u16 key_len, const __u8 *data, __u16 data_len, __u8 *hmac)
{

    __u8 k_ipad[SHA256_BLOCK_SIZE];
    __u8 k_opad[SHA256_BLOCK_SIZE];
    __u8 tk[SHA256_DIGEST_SIZE];
    struct sha256_ctx ctx;
    __u32 i;


    if (key_len > SHA256_BLOCK_SIZE) {
        sha256_init(&ctx);
        sha256_update(&ctx, key, key_len);
        sha256_final(&ctx, tk);
        key = tk;
        key_len = SHA256_DIGEST_SIZE;
    }

    // Inizializzazione manuale di k_ipad e k_opad a zero
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] = 0;
        k_opad[i] = 0;
    }


    // Copia manuale della chiave in k_ipad e k_opad
    for (i = 0; i < key_len; i++) {
        k_ipad[i] = key[i];
        k_opad[i] = key[i];
    }


    // XOR con i valori specifici
    for (i = 0; i < SHA256_BLOCK_SIZE; i++) {
        k_ipad[i] ^= 0x36;
        k_opad[i] ^= 0x5c;
    }

    sha256_init(&ctx);
    sha256_update(&ctx, k_ipad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, data, data_len);
    sha256_final(&ctx, hmac);

    sha256_init(&ctx);
    sha256_update(&ctx, k_opad, SHA256_BLOCK_SIZE);
    sha256_update(&ctx, hmac, SHA256_DIGEST_SIZE);
    sha256_final(&ctx, hmac);
}
*/

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

	return data + ip_len;
}

static inline void* manage_tcp(void* data, void* data_end, flow_t *fl)
{
	struct tcphdr *tcp = (struct tcphdr *) data;
	__u16 tcp_hlen;

	if (data + TCP_MIN_HLEN > data_end)
		return NULL;

	fl->src_port = bpf_ntohs(tcp->source);
	fl->dst_port = bpf_ntohs(tcp->dest);

	return data + tcp_hlen;
}

__attribute__((no_stack_protector))
SEC("xdp")
int  xdp_parser_func(struct xdp_md *ctx)
{
	void *data_end = (void *) (long) ctx->data_end;
	void *data = (void*) (long)ctx->data;
	struct so_event *e;
	keys_t *keys;
	struct flow fl;

	/*__u8 secret_key_test[32] = {0xc, 0x1, 0x2, 0x3, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7, 0x8, 0x9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7};
	__u8 hmac[SHA256_DIGEST_SIZE];
	char message[] = "Hello, World!";

	// Compute the HMAC

	hmac_sha256(secret_key_test, 32, (const __u8 *)message, 10, hmac);

    // Print the HMAC for debugging purposes
    bpf_printk("HMAC: ");
    for (int i = 0; i < SHA256_DIGEST_SIZE; i++) {
        bpf_printk("%02x", hmac[i]);
    }
    bpf_printk("\n");*/

	//l2 management
	data = manage_ethernet(data, data_end);
	if (!data)
		return XDP_PASS;

	//l3 management
	data = manage_ipv4(data, data_end, &fl);
	if(!data)
		return XDP_PASS;

	//l4 management
	data = manage_tcp(data, data_end, &fl);
	if(!data)
		return XDP_PASS;

	//retrieve secret key
	keys = bpf_map_lookup_elem(&clients_map, &fl);

	//check if ip is registered
	if (!keys)
	{
		bpf_printk("IP not registered\n");
    	return XDP_PASS;
	}


	return XDP_PASS;
}


char __license[] SEC("license") = "GPL";
