/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include <crypto/internal/hash.h>

#include "eip93-common.h"
#include "eip93-core.h"
#include "eip93-hash.h"
#include "eip93-ring.h"

/* crypto hw padding constant for first operation */
#define SHA_PADDING		64
#define SHA_PADDING_MASK	(SHA_PADDING - 1)

static inline u64 mtk_queued_len(struct mtk_ahash_rctx *req)
{
	return req->len - req->processed;
}

static int mtk_ahash_handle_result(struct mtk_device *mtk,
				  struct crypto_async_request *async,
				  bool *should_complete, int *ret)
{
	struct eip93_descriptor_s *rdesc, *cdesc;
	struct ahash_request *areq = ahash_request_cast(async);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(areq);
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(ahash);
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);
	u64 cache_len;

	*ret = 0;

	rdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].rdr);
	if (IS_ERR(rdesc)) {
		dev_err(mtk->dev,
			"hash: result: could not retrieve result descriptor\n");
		*ret = PTR_ERR(rdesc);
	} else if (rdesc->peCrtlStat.bits.errStatus) {
		dev_err(mtk->dev,
			"hash: result: result descriptor error (%d)\n",
			rdesc->peCrtlStat.bits.errStatus);
		*ret = -EINVAL;
	}

	//safexcel_complete(priv, ring);
	//Handle cdesc;


	if (rctx->nents) {
		dma_unmap_sg(mtk->dev, areq->src, rctx->nents, DMA_TO_DEVICE);
		rctx->nents = 0;
	}

	if (rctx->result_dma) {
		dma_unmap_single(mtk->dev, rctx->result_dma, rctx->digest_sz,
				 DMA_FROM_DEVICE);
		rctx->result_dma = 0;
	}

	if (rctx->cache_dma) {
		dma_unmap_single(mtk->dev, rctx->cache_dma, rctx->cache_sz,
				 DMA_TO_DEVICE);
		rctx->cache_dma = 0;
		rctx->cache_sz = 0;
	}

	if (rctx->finish) {
		if (rctx->hmac &&
		    (rctx->digest != CONTEXT_CONTROL_DIGEST_HMAC)) {
			/* Faking HMAC using hash - need to do outer hash */
			memcpy(rctx->cache, rctx->state,
			       crypto_ahash_digestsize(ahash));

			memcpy(rctx->state, ctx->opad, rctx->digest_sz);

			rctx->len = rctx->block_sz +
				    crypto_ahash_digestsize(ahash);
			rctx->processed = rctx->block_sz;
			rctx->hmac = 0;

			areq->nbytes = 0;
			mtk_ahash_enqueue(areq);

			*should_complete = false; /* Not done yet */
			return 1;
		}

		memcpy(areq->result, rctx->state,
			       crypto_ahash_digestsize(ahash));

	}

	cache_len = mtk_queued_len(rctx);
	if (cache_len)
		memcpy(rctx->cache, rctx->cache_next, cache_len);

	*should_complete = true;

	return 1;
}

static int mtk_ahash_send(struct crypto_async_request *async,
			  int *commands, int *results)
{
	struct ahash_request *areq = ahash_request_cast(async);
	struct crypto_ahash *ahash = crypto_ahash_reqtfm(areq);
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));
	struct mtk_device *mtk = ctx->mtk;
	struct eip93_descriptor *cdesc, *first_cdesc = NULL;
	struct eip93_descriptor *rdesc;
	struct scatterlist *sg;
	int i, cache_len, extra, n_cdesc = 0, ret = 0;
	u64 queued, len;

	queued = mtk_queued_len(rctx);
	if (queued <= HASH_CACHE_SIZE)
		cache_len = queued;
	else
		cache_len = queued - areq->nbytes;

	if (!rctx->finish && !rctx->last_req) {
		/* If this is not the last request and the queued data does not
		 * fit into full cache blocks, cache it for the next send call.
		 */
		extra = queued & (HASH_CACHE_SIZE - 1);

		/* If this is not the last request and the queued data
		 * is a multiple of a block, cache the last one for now.
		 */
		if (!extra)
			extra = HASH_CACHE_SIZE;

		sg_pcopy_to_buffer(areq->src, sg_nents(areq->src),
				   rctx->cache_next, extra,
				   areq->nbytes - extra);

		queued -= extra;

		if (!queued) {
			*commands = 0;
			*results = 0;
			return 0;
		}

		extra = 0;
	}
	len = queued;
	/* Add a command descriptor for the cached data, if any */
	if (cache_len) {
		rctx->cache_dma = dma_map_single(mtk->dev, rctx->cache,
						cache_len, DMA_TO_DEVICE);
		if (dma_mapping_error(mtk->dev, rctx->cache_dma))
			return -EINVAL;

		rctx->cache_sz = cache_len;
		first_cdesc = mtk_add_cdesc(priv, ring, 1,
						 (cache_len == len),
						 rctx->cache_dma, cache_len,
						 len, ctx->base.ctxr_dma);
		if (IS_ERR(first_cdesc)) {
			ret = PTR_ERR(first_cdesc);
			goto unmap_cache;
		}
		n_cdesc++;

		queued -= cache_len;
		if (!queued)
			goto send_command;
	}

	/* Now handle the current ahash request buffer(s) */
	rctx->nents = dma_map_sg(mtk->dev, areq->src,
				sg_nents_for_len(areq->src, areq->nbytes),
				DMA_TO_DEVICE);
	if (!req->nents) {
		ret = -ENOMEM;
		goto cdesc_rollback;
	}

	for_each_sg(areq->src, sg, rctx->nents, i) {
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
	/* Setup the context options */
	safexcel_context_control(ctx, req, first_cdesc);

	/* Add the token */
	safexcel_hash_token(first_cdesc, len, req->digest_sz, ctx->cbcmac);

	req->result_dma = dma_map_single(priv->dev, req->state, req->digest_sz,
				 DMA_FROM_DEVICE);
	if (dma_mapping_error(priv->dev, req->result_dma)) {
		ret = -EINVAL;
		goto unmap_sg;
	}

	/* Add a result descriptor */
	rdesc = mtk_add_rdesc(mtk);
	if (IS_ERR(rdesc)) {
		ret = PTR_ERR(rdesc);
		goto unmap_result;
	}

	// use buf[dd]
	//mtk_rdr_req_set(mtk, ring, rdesc, &areq->base);

	rctx->processed += len - extra;

	*commands = n_cdesc;
	*results = 1;
	return 0;

unmap_result:
	dma_unmap_single(mtk->dev, rctx->result_dma, rctx->digest_sz,
		 DMA_FROM_DEVICE);
unmap_sg:
	if (rctx->nents) {
		dma_unmap_sg(mtk->dev, areq->src, rctx->nents, DMA_TO_DEVICE);
		rctx->nents = 0;
	}
cdesc_rollback:
	for (i = 0; i < n_cdesc; i++)
		mtk_ring_rollback_wptr(mtk, &mtk->ring[0].cdr);
unmap_cache:
	if (rctx->cache_dma) {
		dma_unmap_single(mtk->dev, rctx->cache_dma, rctx->cache_sz,
			 	DMA_TO_DEVICE);
		rctx->cache_dma = 0;
		rctx->cache_sz = 0;
	}

	return ret;
}

static int mtk_ahash_enqueue(struct ahash_request *areq)
{
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);
	struct mtk_device *mtk = ctx->mtk;
	int ret, ring;

	spin_lock_bh(&mtk->ring[0].queue_lock);
	ret = crypto_enqueue_request(&mtk->ring[0].queue, &areq->base);
	spin_unlock_bh(&mtk->ring[0].queue_lock);

	rctx->not_first = true;

	queue_work(mtk->ring[0].workqueue, &mtk->ring[0].work_dequeue.work);

	return ret;
}

static int mtk_ahash_cache(struct ahash_request *areq)
{
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);
	u64 cache_len;

	/* cache_len: everything accepted by the driver but not sent yet,
	 * tot sz handled by update() - last req sz - tot sz handled by send()
	 */
	cache_len = mtk_queued_len(rctx);

	/*
	 * In case there isn't enough bytes to proceed (less than a
	 * block size), cache the data until we have enough.
	 */
	if (cache_len + areq->nbytes <= HASH_CACHE_SIZE) {
		sg_pcopy_to_buffer(areq->src, sg_nents(areq->src),
				   rctx->cache + cache_len,
				   areq->nbytes, 0);
		return 0;
	}

	/* We couldn't cache all the data */
	return -E2BIG;
}

static int mtk_ahash_update(struct ahash_request *areq)
{
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);
	int ret;

	/* If the request is 0 length, do nothing */
	if (!areq->nbytes)
		return 0;

	/* Add request to the cache if it fits */
	ret = mtk_ahash_cache(areq);

	/* Update total request length */
	rctx->len += areq->nbytes;

	/* If not all data could fit into the cache, go process the excess.
	 * Also go process immediately for an HMAC IV precompute, which
	 * will never be finished at all, but needs to be processed anyway.
	 */
	if ((ret && !rctx->finish) || rctx->last_req)
		return mtk_ahash_enqueue(areq);

	return 0;
}

static int mtk_ahash_final(struct ahash_request *areq)
{
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));

	rctx->last_req = true;
	rctx->finish = true;

	if (unlikely(!rctx->len && !areq->nbytes)) {
		/*
		 * If we have an overall 0 length *hash* request:
		 * The HW cannot do 0 length hash, so we provide the correct
		 * result directly here.
		 */
		if (IS_HASH_SHA1(rctx->flags))
			memcpy(areq->result, sha1_zero_message_hash,
			       SHA1_DIGEST_SIZE);
		else if (IS_HASH_SHA224(rctx->flags))
			memcpy(areq->result, sha224_zero_message_hash,
			       SHA224_DIGEST_SIZE);
		else if (IS_HASH_SHA256(rctx->flags))
			memcpy(areq->result, sha256_zero_message_hash,
			       SHA256_DIGEST_SIZE);
		return 0;
	} else if (unlikely(IS_HMAC(rctx->flags) &&
			    (rctx->len == rctx->block_sz) &&
			    !areq->nbytes)) {
		/*
		 * If we have an overall 0 length *HMAC* request:
		 * For HMAC, we need to finalize the inner digest
		 * and then perform the outer hash.
		 */

		/* generate pad block in the cache */
		/* start with a hash block of all zeroes */
		memset(rctx->cache, 0, rctx->block_sz);
		/* set the first byte to 0x80 to 'append a 1 bit' */
		rctx->cache[0] = 0x80;
		/* add the length in bits in the last 2 bytes */
		if (rctx->len_is_le) {
			/* Little endian length word (e.g. MD5) */
			rctx->cache[rctx->block_sz-8] = (rctx->block_sz << 3) &
						      255;
			rctx->cache[rctx->block_sz-7] = (rctx->block_sz >> 5);
		} else {
			/* Big endian length word (e.g. any SHA) */
			rctx->cache[rctx->block_sz-2] = (rctx->block_sz >> 5);
			rctx->cache[rctx->block_sz-1] = (rctx->block_sz << 3) &
						      255;
		}
		rctx->len += rctx->block_sz; /* plus 1 hash block */

		/* Set special zero-length HMAC flag */
		rctx->hmac_zlen = true;

		/* Finalize HMAC */
		rctx->digest = CONTEXT_CONTROL_DIGEST_HMAC;
	} else if (rctx->hmac) {
		/* Finalize HMAC */
		rctx->digest = CONTEXT_CONTROL_DIGEST_HMAC;
	}

	return mtk_ahash_enqueue(areq);
}

static int mtk_ahash_finup(struct ahash_request *areq)
{
	struct mtk_ahash_rctx *req = ahash_request_ctx(areq);

	req->last_req = true;
	req->finish = true;

	mtk_ahash_update(areq);
	return mtk_ahash_final(areq);
}

static int mtk_ahash_export(struct ahash_request *areq, void *out)
{
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);
	struct mtk_ahash_export_state *export = out;

	export->len = rctx->len;
	export->processed = rctx->processed;

	export->digest = rctx->digest;

	memcpy(export->state, rctx->state, rctx->state_sz);
	memcpy(export->cache, rctx->cache, HASH_CACHE_SIZE);

	return 0;
}

static int mtk_ahash_import(struct ahash_request *areq, const void *in)
{
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);
	const struct mtk_ahash_export_state *export = in;
	int ret;

	ret = crypto_ahash_init(areq);
	if (ret)
		return ret;

	rctx->len = export->len;
	rctx->processed = export->processed;

	rctx->digest = export->digest;

	memcpy(rctx->cache, export->cache, HASH_CACHE_SIZE);
	memcpy(rctx->state, export->state, rctx->state_sz);

	return 0;
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

static int mtk_hmac_init_pad(struct ahash_request *areq,
				  unsigned int blocksize, const u8 *key,
				  unsigned int keylen, u8 *ipad, u8 *opad)
{
	struct mtk_ahash_result result;
	struct scatterlist sg;
	int ret, i;
	u8 *keydup;

	keydup = kmemdup(key, keylen, GFP_KERNEL);
	if (!keydup)
		return -ENOMEM;

	ahash_request_set_callback(areq, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   mtk_ahash_complete, &result);
	sg_init_one(&sg, keydup, keylen);
	ahash_request_set_crypt(areq, &sg, ipad, keylen);
	init_completion(&result.completion);

	ret = crypto_ahash_digest(areq);
	if (ret == -EINPROGRESS || ret == -EBUSY) {
		wait_for_completion_interruptible(&result.completion);
		ret = result.error;
	}

	/* Avoid leaking */
	memzero_explicit(keydup, keylen);
	kfree(keydup);

	if (ret)
		return ret;

	keylen = crypto_ahash_digestsize(crypto_ahash_reqtfm(areq));

	memset(ipad + keylen, 0, blocksize - keylen);
	memcpy(opad, ipad, blocksize);

	for (i = 0; i < blocksize; i++) {
		ipad[i] ^= HMAC_IPAD_VALUE;
		opad[i] ^= HMAC_OPAD_VALUE;
	}

	return 0;
}

static int mtk_hmac_init_iv(struct ahash_request *areq,
				 unsigned int blocksize, u8 *pad, void *state)
{
	struct mtk_ahash_result result;
	struct mtk_ahash_rctx *rctx;
	struct scatterlist sg;
	int ret;

	ahash_request_set_callback(areq, CRYPTO_TFM_REQ_MAY_BACKLOG,
				   mtk_ahash_complete, &result);
	sg_init_one(&sg, pad, blocksize);
	ahash_request_set_crypt(areq, &sg, pad, blocksize);
	init_completion(&result.completion);

	ret = crypto_ahash_init(areq);
	if (ret)
		return ret;

	rctx = ahash_request_ctx(areq);
	rctx->hmac = true;
	rctx->last_req = true;

	ret = crypto_ahash_update(areq);
	if (ret && ret != -EINPROGRESS && ret != -EBUSY)
		return ret;

	wait_for_completion_interruptible(&result.completion);
	if (result.error)
		return result.error;

	return crypto_ahash_export(areq, state);
}

int mtk_hmac_setkey(const char *alg, const u8 *key, unsigned int keylen,
			 void *istate, void *ostate)
{
	struct ahash_request *areq;
	struct crypto_ahash *tfm;
	unsigned int blocksize;
	u8 *ipad, *opad;
	int ret;

	tfm = crypto_alloc_ahash(alg, 0, 0);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	areq = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!areq) {
		ret = -ENOMEM;
		goto free_ahash;
	}

	crypto_ahash_clear_flags(tfm, ~0);
	blocksize = crypto_tfm_alg_blocksize(crypto_ahash_tfm(tfm));

	ipad = kcalloc(2, blocksize, GFP_KERNEL);
	if (!ipad) {
		ret = -ENOMEM;
		goto free_request;
	}

	opad = ipad + blocksize;

	ret = mtk_hmac_init_pad(areq, blocksize, key, keylen, ipad, opad);
	if (ret)
		goto free_ipad;

	ret = mtk_hmac_init_iv(areq, blocksize, ipad, istate);
	if (ret)
		goto free_ipad;

	ret = mtk_hmac_init_iv(areq, blocksize, opad, ostate);

free_ipad:
	kfree(ipad);
free_request:
	ahash_request_free(areq);
free_ahash:
	crypto_free_ahash(tfm);

	return ret;
}

static int mtk_hmac_alg_setkey(struct crypto_ahash *tfm, const u8 *key,
				    unsigned int keylen, const char *alg,
				    unsigned int state_sz)
{
	struct mtk_ahash_ctx *ctx = crypto_tfm_ctx(crypto_ahash_tfm(tfm));
	struct mtk_device *mtk = ctx->mtk;
	struct mtk_ahash_export_state istate, ostate;
	int ret;

	ret = mtk_hmac_setkey(alg, key, keylen, &istate, &ostate);
	if (ret)
		return ret;

	memcpy(ctx->ipad, &istate.state, state_sz);
	memcpy(ctx->opad, &ostate.state, state_sz);

	return 0;
}

static int mtk_ahash_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_ahash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl =
		container_of(__crypto_ahash_alg(tfm->__crt_alg),
				struct mtk_alg_template, alg.ahash);
	struct mtk_device *mtk = tmpl->mtk;
	unsigned long flags = tmpl->flags;
	char *alg_base;

	ctx->mtk = mtk;
	ctx->flags = flags;

	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct mtk_ahash_rctx));

	ctx->base.send = mtk_ahash_send;
	ctx->base.handle_result = mtk_ahash_handle_result;

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

static int mtk_hmac_sha1_setkey(struct crypto_ahash *tfm, const u8 *key,
				     unsigned int keylen)
{
	return mtk_hmac_alg_setkey(tfm, key, keylen, "eip93-sha1",
					SHA1_DIGEST_SIZE);
}

static int mtk_hmac_sha224_setkey(struct crypto_ahash *tfm, const u8 *key,
				     unsigned int keylen)
{
	return mtk_hmac_alg_setkey(tfm, key, keylen, "eip93-sha224",
					SHA1_DIGEST_SIZE);
}

static int mtk_hmac_sha256_setkey(struct crypto_ahash *tfm, const u8 *key,
				     unsigned int keylen)
{
	return mtk_hmac_alg_setkey(tfm, key, keylen, "eip93-sha256",
					SHA1_DIGEST_SIZE);
}

static int mtk_ahash_init(struct ahash_request *areq)
{
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));
	struct mtk_device *mtk = ctx->mtk;
	struct mtk_ahash_rctx *rctx = ahash_request_ctx(areq);

	memset(rctx, 0, sizeof(*rctx));
	rctx->flags = ctx->flags;
	rctx->saRecord = dma_zalloc_coherent(mtk->dev,
				sizeof(struct saRecord_s),
				&rctx->saRecord_dma, GFP_KERNEL);

	if (!rctx->saRecord) {
		dev_err(mtk->dev, "Ahash RCTX dma_alloc for saRecord failed\n");
		return -ENOMEM;
	}

	rctx->saState = dma_zalloc_coherent(mtk->dev,
				sizeof(struct saState_s),
				&rctx->saState_dma, GFP_KERNEL);

	if (!rctx->saState) {
		dev_err(mtk->dev, "Ahash RCTX dma_alloc for saState failed\n");
		return -ENOMEM;
	}

	rctx->result = devm_kzalloc(mtk->dev, SHA256_DIGEST_SIZE, GFP_KERNEL);

	rctx->result_dma = (u32)dma_map_single(mtk->dev, (void *)rctx->result,
				SHA256_DIGEST_SIZE, DMA_FROM_DEVICE);
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

	crypto_free_shash(ctx->shash);
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
		.setkey = mtk_hmac_sha1_setkey,
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
		.setkey = mtk_hmac_sha224_setkey,
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
		.setkey = mtk_hmac_sha256_setkey,
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
