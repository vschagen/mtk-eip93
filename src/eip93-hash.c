/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include <linux/device.h>
#include <linux/dmapool.h>
#include <linux/interrupt.h>
#include <crypto/internal/hash.h>

#include "eip93-common.h"
#include "eip93-core.h"
#include "eip93-hash.h"
#include "eip93-ring.h"

/* crypto hw padding constant for first operation */
#define SHA_PADDING		64
#define SHA_PADDING_MASK	(SHA_PADDING - 1)


static inline u64 mtk_queue_len(struct mtk_ahash_req *req)
{
	if (req->len[1] > req->processed[1])
		return 0xffffffff - (req->len[0] - req->processed[0]);

	return req->len[0] - req->processed[0];
}
static int mtk_ahash_handle_result(struct mtk_device *mtk,
				  struct crypto_async_request *async,
				  bool *should_complete, int *ret)

{
	struct eip93_desciptor *rdesc;
	struct ahash_request *areq = ahash_request_cast(async);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(areq);
	struct mtk_ahash_req *sreq = ahash_request_ctx(areq);
	int cache_len, result_sz = sreq->state_sz;

	*ret = 0;

	rdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].rdr);
	if (IS_ERR(rdesc)) {
		dev_err(mtk->dev,
			"hash: result: could not retrieve the result descriptor\n");
		*ret = PTR_ERR(rdesc);
	} else if (rdesc->peCrtlStat.bits.errStatus) {
		dev_err(mtk->dev,
			"hash: result: result descriptor error (%d)\n",
			rdesc->peCrtlStat.bits.errStatus);
		*ret = -EINVAL;
	}

/*	safexcel_complete(priv, ring);

	if (sreq->nents) {
		dma_unmap_sg(priv->dev, areq->src, sreq->nents, DMA_TO_DEVICE);
		sreq->nents = 0;
	}

	if (sreq->result_dma) {
		dma_unmap_sg(priv->dev, areq->src, sreq->nents, DMA_TO_DEVICE);
		sreq->result_dma = 0;
	}
*/
	if (sreq->finish) {
		memcpy(areq->result, sreq->state,
				crypto_ahash_digestsize(ahash));
	}

	cache_len = mtk_queued_len(sreq);
	if (cache_len)
		memcpy(sreq->cache, sreq->cache_next, cache_len);

	*should_complete = true;

	return 1;
}

static int mtk_ahash_send(struct crypto_async_request *async,
				   struct mtk_request *request,
				   int *commands, int *results)
{
	struct ahash_request *areq = ahash_request_cast(async);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(areq);
	struct mtk_ahash_req *req = ahash_request_ctx(areq);
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));
	struct mtk_crypto_priv *priv = ctx->priv;
	struct eip93_descriptor *cdesc, *first_cdesc = NULL;
	struct eip93_descriptor *rdesc;
	struct scatterlist *sg;
	int i, queued, len, cache_len, extra, n_cdesc = 0, ret = 0;

	queued = len = req->len - req->processed;
	if (queued <= crypto_ahash_blocksize(ahash))
		cache_len = queued;
	else
		cache_len = queued - areq->nbytes;

	if (!req->last_req) {
		/* If this is not the last request and the queued data does not
		 * fit into full blocks, cache it for the next send() call.
		 */
		extra = queued & (crypto_ahash_blocksize(ahash) - 1);
		if (!extra)
			/* If this is not the last request and the queued data
			 * is a multiple of a block, cache the last one for now.
			 */
			extra = crypto_ahash_blocksize(ahash);

		if (extra) {
			sg_pcopy_to_buffer(areq->src, sg_nents(areq->src),
					   req->cache_next, extra,
					   areq->nbytes - extra);

			queued -= extra;
			len -= extra;

			if (!queued) {
				*commands = 0;
				*results = 0;
				return 0;
			}
		}
	}

	/* Add a command descriptor for the cached data, if any */
	if (cache_len) {
		req->cache_dma = kzalloc(cache_len, EIP197_GFP_FLAGS(*async));
		if (!ctx->base.cache) {
			ret = -ENOMEM;
			goto unlock;
		}
		memcpy(ctx->base.cache, req->cache, cache_len);
		ctx->base.cache_dma = dma_map_single(priv->dev, ctx->base.cache,
						     cache_len, DMA_TO_DEVICE);
		if (dma_mapping_error(priv->dev, ctx->base.cache_dma)) {
			ret = -EINVAL;
			goto free_cache;
		}

		ctx->base.cache_sz = cache_len;
		first_cdesc = mtk_add_cdesc(mtk, ctx->base.cache_dma,
							Result.base, saRecord.base, saState.base,
							cache_len, 0);

		if (IS_ERR(first_cdesc)) {
			ret = PTR_ERR(first_cdesc);
			goto unmap_cache;
		}
		rdesc = mtk_add_rdesc(mtk);
		n_cdesc++;

		queued -= cache_len;
		if (!queued)
			goto send_command;
	}

	/* Now handle the current ahash request buffer(s) */
	req->nents = dma_map_sg(priv->dev, areq->src,
				sg_nents_for_len(areq->src, areq->nbytes),
				DMA_TO_DEVICE);
	if (!req->nents) {
		ret = -ENOMEM;
		goto cdesc_rollback;
	}

	for_each_sg(areq->src, sg, req->nents, i) {
		int sglen = sg_dma_len(sg);

		/* Do not overflow the request */
		if (queued - sglen < 0)
			sglen = queued;

		cdesc = mtk_add_cdesc(mtk, sg_dma_address(sg), Result.base,
						saRecord.base, saState.base, sglen, 0);
		if (IS_ERR(cdesc)) {
			ret = PTR_ERR(cdesc);
			goto cdesc_rollback;
		}
		rdesc = mtk_add_rdesc(mtk);

		n_cdesc++;

		if (n_cdesc == 1)
			first_cdesc = cdesc;

		queued -= sglen;
		if (!queued)
			break;
	}

send_command:

	spin_unlock_bh(&priv->ring[ring].egress_lock);

	req->processed += len;
	request->req = &areq->base;

	*commands = n_cdesc;
	*results = 1;
	return 0;

unmap_result:

unmap_sg:

cdesc_rollback:
	for (i = 0; i < n_cdesc; i++)
		mtk_ring_rollback_wptr(priv, &priv->ring[ring].cdr);
unmap_cache:
	if (req->bcache_dma) {
		dma_unmap_single(priv->dev, ctx->base.cache_dma,
				 ctx->base.cache_sz, DMA_TO_DEVICE);
		req->cache_sz = 0;
	}

	return ret;
}

static int mtk_ahash_enqueue(struct ahash_request *areq)
{
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));
	struct mtk_ahash_req *req = ahash_request_ctx(areq);
	struct mtk_crypto_priv *priv = ctx->priv;
	int ret, ring;


	spin_lock_bh(&mtk->ring[0].queue_lock);
	ret = crypto_enqueue_request(&mtk->ring[0].queue, &areq->base);
	spin_unlock_bh(&mtk->ring[0].queue_lock);

	queue_work(mtk->ring[0].workqueue, &mtk->ring[0].work_data.work);

	return ret;
}

static int mtk_ahash_cache(struct ahash_request *areq)
{
	struct mtk_ahash_req *req = ahash_request_ctx(areq);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(areq);
	int queued, cache_len;

	cache_len = req->len - areq->nbytes - req->processed;
	queued = req->len - req->processed;

	/*
	 * In case there isn't enough bytes to proceed (less than a
	 * block size), cache the data until we have enough.
	 */
	if (cache_len + areq->nbytes <= crypto_ahash_blocksize(ahash)) {
		sg_pcopy_to_buffer(areq->src, sg_nents(areq->src),
				   req->cache + cache_len,
				   areq->nbytes, 0);
		return areq->nbytes;
	}

	/* We could'nt cache all the data */
	return -E2BIG;
}

static int mtk_ahash_update(struct ahash_request *areq)
{
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));
	struct mtk_ahash_req *req = ahash_request_ctx(areq);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(areq);

	/* If the request is 0 length, do nothing */
	if (!areq->nbytes)
		return 0;

	req->len += areq->nbytes;

	mtk_ahash_cache(areq);

	/*
	 * We're not doing partial updates when performing an hmac request.
	 * Everything will be handled by the final() call.
	 */
	if (ctx->digest == )
		return 0;

	if (req->hmac)
		return mtk_ahash_enqueue(areq);

	if (!req->last_req &&
	    req->len - req->processed > crypto_ahash_blocksize(ahash))
		return safexcel_ahash_enqueue(areq);

	return 0;
}

static int mtk_ahash_final(struct ahash_request *areq)
{
	struct mtk_ahash_req *req = ahash_request_ctx(areq);
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));

	req->last_req = true;
	req->finish = true;

	/* If we have an overall 0 length request */
	if (!(req->len + areq->nbytes)) {
		if (IS_SHA1(req->flags))
			memcpy(areq->result, sha1_zero_message_hash,
			       SHA1_DIGEST_SIZE);
		else if (IS_SHA224(req->flags))
			memcpy(areq->result, sha224_zero_message_hash,
			       SHA224_DIGEST_SIZE);
		else if (IS_SHA256(req->flags))
			memcpy(areq->result, sha256_zero_message_hash,
			       SHA256_DIGEST_SIZE);
		return 0;
	}

	return mtk_ahash_enqueue(areq);
}

static int mtk_ahash_finup(struct ahash_request *areq)
{
	struct mtk_ahash_req *req = ahash_request_ctx(areq);

	req->last_req = true;
	req->finish = true;

	mtk_ahash_update(areq);
	return mtk_ahash_final(areq);
}

static int mtk_ahash_export(struct ahash_request *areq, void *out)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(areq);
	struct mtk_ahash_req *req = ahash_request_ctx(areq);
	struct mtk_ahash_export_state *export = out;

	export->len = req->len;
	export->processed = req->processed;

	memcpy(export->state, req->state, req->state_sz);
	memset(export->cache, 0, crypto_ahash_blocksize(ahash));
	memcpy(export->cache, req->cache, crypto_ahash_blocksize(ahash));

	return 0;
}

static int mtk_ahash_import(struct ahash_request *areq, const void *in)
{
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(areq);
	struct mtk_ahash_req *req = ahash_request_ctx(areq);
	const struct mtk_ahash_export_state *export = in;
	int ret;

	ret = crypto_ahash_init(areq);
	if (ret)
		return ret;

	req->len = export->len;
	req->processed = export->processed;

	memcpy(req->cache, export->cache, crypto_ahash_blocksize(ahash));
	memcpy(req->state, export->state, req->state_sz);

	return 0;
}

/* EIP93 can only authenticate with the Hash of the key */
static int mtk_hmac_setkey(struct crypto_ahash *tfm, const u8 *key,
			  u32 keylen)
{
	struct mtk_ahash_ctx *tctx = crypto_ahash_ctx(tfm);
	size_t bs = crypto_shash_blocksize(ctx->shash);
	size_t ds = crypto_shash_digestsize(ctx->shash);
	int err, i;

	SHASH_DESC_ON_STACK(shash, ctx->shash);

	shash->tfm = ctx->shash;
	shash->flags = crypto_shash_get_flags(ctx->shash) &
		       CRYPTO_TFM_REQ_MAY_SLEEP;

	if (keylen > bs) {
		err = crypto_shash_digest(shash, key, keylen, bctx->ipad);
		if (err)
			return err;
		keylen = ds;
	} else {
		memcpy(ctx->ipad, key, keylen);
	}

	memset(ctx->ipad + keylen, 0, bs - keylen);
	memcpy(ctx->opad, ctx->ipad, bs);

	for (i = 0; i < bs; i++) {
		ctx->ipad[i] ^= HMAC_IPAD_VALUE;
		ctx->opad[i] ^= HMAC_OPAD_VALUE;
	}

	return 0;
}

static int mtk_ahash_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_ahash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct ahash_alg *alg = __crypto_ahash_alg(tfm->__crt_alg) 
	struct mtk_alg_template *tmpl = container_of(alg,
			     struct mtk_alg_template, alg.ahash);
	struct mtk_device*mtk = tmpl->mtk;
	unsigned long flags = tmpl->flags;
	char *alg_base;

	ctx->mtk = mtk;
	ctx->base.send = mtk_ahash_send;
	ctx->base.handle_result = mtk_ahash_handle_result;

	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct mtk_ahash_req));

	if IS_HMAC(flags) {
		if IS_HASH_SHA1(flags)
			alg_base = "sha1";
		if IS_HASH_SHA224(flags)
			alg_base = "sha224";
		if IS_HASH_SHA256(flags)
			alg_base = "sha256";

		ctx->shash = crypto_alloc_shash(alg_base, 0,
					CRYPTO_ALG_NEED_FALLBACK);
		if (IS_ERR(ctx->shash)) {
			dev_err(mtk->dev,
				"base driver %s could not be loaded.\n", alg_base);
			return PTR_ERR(ctx->shash);
		}
	}
	return 0;
}

static int mtk_ahash_init(struct ahash_request *areq)
{
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));
	struct mtk_ahash_req *req = ahash_request_ctx(areq);

	memset(req, 0, sizeof(*req));

	
	ctx->alg = CONTEXT_CONTROL_CRYPTO_ALG_SHA1;
	ctx->digest = CONTEXT_CONTROL_DIGEST_PRECOMPUTED;
	req->state_sz = SHA1_DIGEST_SIZE;

	return 0;
}

static int mtk_ahash_digest(struct ahash_request *areq)
{
	int ret = mtk_ahash_init(areq);

	if (ret)
		return ret;

	return mtk_ahash_finup(areq);
}

static void mtk_ahash_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_ahash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_device *mtk = ctx->mtk;
	int ret;

}

struct mtk_ahash_result {
	struct completion completion;
	int error;
};

static void mtk_ahash_complete(struct crypto_async_request *req, int error)
{
	struct mtk_ahash_result *result = req->data;

	if (error == -EINPROGRESS)
		return;

	result->error = error;
	complete(&result->completion);
}


struct mtk_alg_template mtk_alg_sha1 = {
	.type = MTK_ALG_TYPE_AHASH,
	.flags = MTK_HASH_SHA1,
	.alg.ahash = {
		.init = mtk_ahash_init,
		.update = mtk_ahash_update,
		.final = mtk_ahash_final,
		.finup = mtk_ahash_finup,
		.digest = mtk_ahash_digest,
		.export = mtk_ahash_export,
		.import = mtk_ahash_import,
		.halg = {
			.digestsize = SHA1_DIGEST_SIZE,
			.statesize = sizeof(struct mtk_ahash_export_state),
			.base = {
				.cra_name = "sha1",
				.cra_driver_name = "eip93-sha1",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
				.cra_blocksize = SHA1_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct mtk_ahash_ctx),
				.cra_init = mtk_ahash_cra_init,
				.cra_exit = mtk_ahash_cra_exit,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct mtk_alg_template mtk_alg_sha224 = {
	.type = MTK_ALG_TYPE_AHASH,
	.flags = MTK_HASH_SHA224,
	.alg.ahash = {
		.init = mtk_ahash_init,
		.update = mtk_ahash_update,
		.final = mtk_ahash_final,
		.finup = mtk_ahash_finup,
		.digest= mtk_ahash_digest,
		.export = mtk_ahash_export,
		.import = mtk_ahash_import,
		.halg = {
			.digestsize = SHA224_DIGEST_SIZE,
			.statesize = sizeof(struct mtk_ahash_export_state),
			.base = {
				.cra_name = "sha224",
				.cra_driver_name = "eip93-sha224",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
				.cra_blocksize = SHA224_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct mtk_ahash_ctx),
				.cra_init = mtk_ahash_cra_init,
				.cra_exit = mtk_ahash_cra_exit,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct mtk_alg_template mtk_alg_sha256 = {
	.type = MTK_ALG_TYPE_AHASH,
	.flags = MTK_HASH_SHA256,
	.alg.ahash = {
		.init = mtk_ahash_init,
		.update = mtk_ahash_update,
		.final = mtk_ahash_final,
		.finup = mtk_ahash_finup,
		.digest= mtk_ahash_digest,
		.export = mtk_ahash_export,
		.import = mtk_ahash_import,
		.halg = {
			.digestsize = SHA256_DIGEST_SIZE,
			.statesize = sizeof(struct mtk_ahash_export_state),
			.base = {
				.cra_name = "sha256",
				.cra_driver_name = "eip93-sha256",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
				.cra_blocksize = SHA256_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct mtk_ahash_ctx),
				.cra_init = mtk_ahash_cra_init,
				.cra_exit = mtk_ahash_cra_exit,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct mtk_alg_template mtk_alg_hmac_sha1 = {
	.type = MTK_ALG_TYPE_AHASH,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1,
	.alg.ahash = {
		.init = mtk_ahash_init,
		.update = mtk_ahash_update,
		.final = mtk_ahash_final,
		.finup = mtk_ahash_finup,
		.digest= mtk_ahash_digest,
		.setkey = mtk_hmac_setkey,
		.export = mtk_ahash_export,
		.import = mtk_ahash_import,
		.halg = {
			.digestsize = SHA1_DIGEST_SIZE,
			.statesize = sizeof(struct mtk_ahash_export_state),
			.base = {
				.cra_name = "hmac(sha1)",
				.cra_driver_name = "eip93-hmac-sha1",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
				.cra_blocksize = SHA1_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct mtk_ahash_ctx),
				.cra_init = mtk_ahash_cra_init,
				.cra_exit = mtk_ahash_cra_exit,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct mtk_alg_template mtk_alg_hmac_sha224 = {
	.type = MTK_ALG_TYPE_AHASH,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA224,
	.alg.ahash = {
		.init = mtk_ahash_init,
		.update = mtk_ahash_update,
		.final = mtk_ahash_final,
		.finup = mtk_ahash_finup,
		.digest= mtk_ahash_digest,
		.setkey = mtk_hmac_setkey,
		.export = mtk_ahash_export,
		.import = mtk_ahash_import,
		.halg = {
			.digestsize = SHA224_DIGEST_SIZE,
			.statesize = sizeof(struct mtk_ahash_export_state),
			.base = {
				.cra_name = "hmac(sha224)",
				.cra_driver_name = "eip93-hmac-sha224",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
				.cra_blocksize = SHA224_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct mtk_ahash_ctx),
				.cra_init = mtk_ahash_cra_init,
				.cra_exit = mtk_ahash_cra_exit,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

struct mtk_alg_template mtk_alg_hmac_sha256 = {
	.type = MTK_ALG_TYPE_AHASH,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256,
	.alg.ahash = {
		.init = mtk_ahash_init,
		.update = mtk_ahash_update,
		.final = mtk_ahash_final,
		.finup = mtk_ahash_finup,
		.digest= mtk_ahash_digest,
		.setkey = mtk_hmac_setkey,
		.export = mtk_ahash_export,
		.import = mtk_ahash_import,
		.halg = {
			.digestsize = SHA1_DIGEST_SIZE,
			.statesize = sizeof(struct mtk_ahash_export_state),
			.base = {
				.cra_name = "hmac(sha256)",
				.cra_driver_name = "eip93-hmac-sha256",
				.cra_priority = 300,
				.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
				.cra_blocksize = SHA1_BLOCK_SIZE,
				.cra_ctxsize = sizeof(struct mtk_ahash_ctx),
				.cra_init = mtk_ahash_cra_init,
				.cra_exit = mtk_ahash_cra_exit,
				.cra_module = THIS_MODULE,
			},
		},
	},
};

