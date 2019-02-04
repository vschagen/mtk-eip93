// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#ifndef _SHA_H_
#define _SHA_H_

#include <crypto/scatterwalk.h>
#include <crypto/sha.h>

#include "eip93-common.h"
#include "eip93-core.h"

#define MTK_SHA_MAX_BLOCKSIZE		SHA256_BLOCK_SIZE
#define MTK_SHA_MAX_DIGESTSIZE		SHA256_DIGEST_SIZE

struct mtk_ahash_ctx {
	struct mtk_context base;
	struct mtk_device *mtk;

	u32 alg;

	u32 ipad[SHA256_DIGEST_SIZE / sizeof(u32)];
	u32 opad[SHA256_DIGEST_SIZE / sizeof(u32)];
};

struct mtk_ahash_req {
	bool last_req;
	bool finish;
	bool hmac;
	bool needs_inv;
	int	flags;

	int nents;
	dma_addr_t	result_dma;

	u32 digest;

	u8 state_sz;    /* expected sate size, only set once */
	u32 state[SHA256_DIGEST_SIZE / sizeof(u32)];

	u64 len[2];
	u64 processed[2];

	u8 cache[SHA256_BLOCK_SIZE] __aligned(sizeof(u32));
	dma_addr_t	cache_dma;
	unsigned int cache_sz;

	u8 cache_next[SHA256_BLOCK_SIZE] __aligned(sizeof(u32));
};

struct mtk_ahash_export_state {
	u64 len;
	u64 processed;

	u32 state[SHA256_DIGEST_SIZE / sizeof(u32)];
	u8 cache[SHA256_BLOCK_SIZE];
};

#endif /* _SHA_H_ */
