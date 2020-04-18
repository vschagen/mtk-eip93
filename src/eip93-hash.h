// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#ifndef _SHA_H_
#define _SHA_H_

#include <crypto/hmac.h>
#include <crypto/md5.h>
#include <crypto/scatterwalk.h>
#include <crypto/sha.h>

#include "eip93-common.h"
#include "eip93-core.h"

#define MTK_SHA_MAX_BLOCKSIZE		SHA256_BLOCK_SIZE
#define MTK_SHA_MAX_DIGESTSIZE		SHA256_DIGEST_SIZE
#define HASH_CACHE_SIZE			SHA256_BLOCK_SIZE

extern struct mtk_alg_tamplate mtk_alg_sha1;
extern struct mtk_alg_template mtk_alg_sha224;
extern struct mtk_alg_template mtk_alg_sha256;
extern struct mtk_alg_template mtk_alg_hmac_sha1;
extern struct mtk_alg_template mtk_alg_hmac_sha224;
extern struct mtk_alg_template mtk_alg_hmac_sha256;

struct mtk_ahash_ctx {
	struct mtk_context	base;
	struct mtk_device	*mtk;
	int			flags;
	struct crypto_shash 	*shash; /* TODO change to ahash */
	u32			ipad[SHA256_DIGEST_SIZE / sizeof(u32)];
	u32			opad[SHA256_DIGEST_SIZE / sizeof(u32)];
};

struct mtk_ahash_rctx {
	bool			last_req;
	bool			finish;
	bool 			hmac;
	bool			hmac_zlen;
	bool			len_is_le;
	bool			not_first;
	int			flags;

	int			nents;
	u8			*result;
	dma_addr_t		result_dma;
	struct saRecord_s	*saRecord;
	dma_addr_t		saRecord_dma;
	struct saState_s	*saState;
	dma_addr_t		saState_dma;

	u32			digest;
	u8			digest_sz;
	u8 			block_sz;    /* block size, only set once */
	u8 			state_sz;    /* expected state size, only set once */
	u32			state[SHA256_DIGEST_SIZE / sizeof(u32)];

	u64			len;
	u64			processed;

	u8			cache[HASH_CACHE_SIZE] __aligned(sizeof(u32));
	dma_addr_t		cache_dma;
	unsigned int		cache_sz;

	u8			cache_next[HASH_CACHE_SIZE] __aligned(sizeof(u32));
};

struct mtk_ahash_export_state {
	u64			len;
	u64			processed;

	u8			digest;
	u8			state[SHA256_DIGEST_SIZE];
	u8			cache[SHA256_BLOCK_SIZE];
};

#endif /* _SHA_H_ */
