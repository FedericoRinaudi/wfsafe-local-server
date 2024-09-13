#ifndef __BUILTIN_H
#define __BUILTIN_H

#define IP_MF 0x2000
#define IP_OFFSET 0x1FFF

#include "vmlinux.h"

#define memset(dest, c, n) __builtin_memset((dest), (c), (n))
#define memcpy(dest, src, n) __builtin_memcpy((dest), (src), (n))
#define memcmp(dest, src, n) __builtin_memcmp((dest), (src), (n))

static __always_inline void *ptr_at(struct xdp_md *ctx, size_t offset, size_t len)
{
	void *out;
	void *start = (void *)(long)ctx->data;
	void *end = (void *)(long)ctx->data_end;

	if (start + offset + len > end)
	{
		return NULL; // Errore
	}

	out = (void *)(start + offset);
	return out; // Successo
}

#endif
