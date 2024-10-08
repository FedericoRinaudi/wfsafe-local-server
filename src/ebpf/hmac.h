#ifndef __HMAC_H
#define __HMAC_H

#define SHA256_DIGEST_SIZE 32      
#define SHA256_BLOCK_SIZE 64
#define MESSAGE_SIZE 32
#define KEY_SIZE 32

typedef struct {
	__u8 data[SHA256_BLOCK_SIZE];
	__u32 datalen;
	unsigned long long bitlen;
	__u32 state[8];
	__u32 m[SHA256_BLOCK_SIZE];
} sha256_ctx;

typedef struct {
	sha256_ctx sha256_ctx;
	__u8 k[SHA256_BLOCK_SIZE];
  	__u8 k_ipad[SHA256_BLOCK_SIZE];
  	__u8 k_opad[SHA256_BLOCK_SIZE];
  	__u8 ihash[SHA256_DIGEST_SIZE];
  	__u8 ohash[SHA256_DIGEST_SIZE];
} hmac_sha256_ctx;

#include "vmlinux.h"
#include "hmac.h"
#include "mem.h"


/****************************** MACROS ******************************/
#define ROTLEFT(a, b) (((a) << (b)) | ((a) >> (32 - (b))))
#define ROTRIGHT(a, b) (((a) >> (b)) | ((a) << (32 - (b))))

#define CH(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define MAJ(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define EP0(x) (ROTRIGHT(x, 2) ^ ROTRIGHT(x, 13) ^ ROTRIGHT(x, 22))
#define EP1(x) (ROTRIGHT(x, 6) ^ ROTRIGHT(x, 11) ^ ROTRIGHT(x, 25))
#define SIG0(x) (ROTRIGHT(x, 7) ^ ROTRIGHT(x, 18) ^ ((x) >> 3))
#define SIG1(x) (ROTRIGHT(x, 17) ^ ROTRIGHT(x, 19) ^ ((x) >> 10))

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
static __always_inline void sha256_transform(sha256_ctx *ctx, const __u8 *data)
{

	__u32 a, b, c, d, e, f, g, h, i, j, t1, t2;

	for (i = 0, j = 0; i < 16; ++i, j += 4)
		ctx->m[i] = (data[j] << 24) | (data[j + 1] << 16) | (data[j + 2] << 8) | (data[j + 3]);
	for (; i < SHA256_BLOCK_SIZE; ++i)
		ctx->m[i] = SIG1(ctx->m[i - 2]) + ctx->m[i - 7] + SIG0(ctx->m[i - 15]) + ctx->m[i - 16];

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
		t1 = h + EP1(e) + CH(e, f, g) + k[i] + ctx->m[i];
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

static __always_inline void sha256_init(sha256_ctx *ctx)
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

static __always_inline void sha256_update(sha256_ctx *ctx, const __u8 *x, const __u8 *y)
{
	size_t i;

	memcpy(ctx->data, x, SHA256_BLOCK_SIZE);
	sha256_transform(ctx, ctx->data);
	ctx->bitlen += 512;
	memcpy(ctx->data, y, MESSAGE_SIZE);
	ctx->datalen = MESSAGE_SIZE;
}

static __always_inline void sha256_final(sha256_ctx *ctx, __u8 hash[])
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

static __always_inline void hmac_sha256(
	hmac_sha256_ctx *ctx,
	const __u8 *key,
	const void *message,
	__u8 *out,
	const size_t outlen)
{

	size_t sz;
	int i;
	sha256_ctx *sha_ctx = &(ctx->sha256_ctx);

	memcpy(ctx->k, key, KEY_SIZE);
	memset((ctx->k) + KEY_SIZE, 0, SHA256_BLOCK_SIZE - KEY_SIZE);

	for (i = 0; i < SHA256_BLOCK_SIZE; i++)
	{
		ctx->k_ipad[i] = 0x36 ^ ctx->k[i];
		ctx->k_opad[i] = 0x5c ^ ctx->k[i];
	}

	sha256_init(sha_ctx);
	sha256_update(sha_ctx, ctx->k_ipad, message);
	sha256_final(sha_ctx, ctx->ihash);

	sha256_init(sha_ctx);
	sha256_update(sha_ctx, ctx->k_opad, ctx->ihash);
	sha256_final(sha_ctx, ctx->ohash);

	sz = (outlen > SHA256_DIGEST_SIZE) ? SHA256_DIGEST_SIZE : outlen;

	memcpy(out, ctx->ohash, sz);
}

#endif