/* SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause) */
/* Copyright (c) 2020 Facebook */
#ifndef __WFSAFE_H
#define __WFSAFE_H


#define SHA256_DIGEST_SIZE 32      
#define SHA256_BLOCK_SIZE 64

typedef struct {
	__u8 data[SHA256_BLOCK_SIZE];
	__u32 datalen;
	unsigned long long bitlen;
	__u32 state[8];
} SHA256_CTX ;

typedef struct {
	SHA256_CTX sha256_ctx;
	uint8_t k[SHA256_BLOCK_SIZE];
  	uint8_t k_ipad[SHA256_BLOCK_SIZE];
  	uint8_t k_opad[SHA256_BLOCK_SIZE];
  	uint8_t ihash[SHA256_DIGEST_SIZE];
  	uint8_t ohash[SHA256_DIGEST_SIZE];
} HMAC_SHA256_CTX ;

#endif /* __BOOTSTRAP_H */
