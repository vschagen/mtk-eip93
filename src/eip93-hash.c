// SPDX-License-Identifier: GPL-2.0
/*
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

static LIST_HEAD(ahash_algs);

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
		first_cdesc = mtk_add_cdesc(priv, ring, 1,
						 (cache_len == len),
						 ctx->base.cache_dma,
						 cache_len, len,
						 ctx->base.ctxr_dma);
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

		cdesc = mtk_add_cdesc(priv, ring, !n_cdesc,
					   !(queued - sglen), sg_dma_address(sg),
					   sglen, len, ctx->base.ctxr_dma);
		if (IS_ERR(cdesc)) {
			ret = PTR_ERR(cdesc);
			goto cdesc_rollback;
		}
		n_cdesc++;

		if (n_cdesc == 1)
			first_cdesc = cdesc;

		queued -= sglen;
		if (!queued)
			break;
	}

send_command:
	/* Setup the context options */
	safexcel_context_control(ctx, req, first_cdesc, req->state_sz,
				 crypto_ahash_blocksize(ahash));

	/* Add the token */
	safexcel_hash_token(first_cdesc, len, req->state_sz);

	ctx->base.result_dma = dma_map_single(priv->dev, areq->result,
					      req->state_sz, DMA_FROM_DEVICE);
	if (dma_mapping_error(priv->dev, ctx->base.result_dma)) {
		ret = -EINVAL;
		goto cdesc_rollback;
	}

	/* Add a result descriptor */
	rdesc = safexcel_add_rdesc(priv, ring, 1, 1, ctx->base.result_dma,
				   req->state_sz);
	if (IS_ERR(rdesc)) {
		ret = PTR_ERR(rdesc);
		goto cdesc_rollback;
	}

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

/*
	req->needs_inv = false;

	if (req->processed && ctx->digest == CONTEXT_CONTROL_DIGEST_PRECOMPUTED)
		ctx->base.needs_inv = safexcel_ahash_needs_inv_get(areq);

	if (ctx->base.ctxr) {
		if (ctx->base.needs_inv) {
			ctx->base.needs_inv = false;
			req->needs_inv = true;
		}
	} else {
		ctx->base.ring = safexcel_select_ring(priv);
		ctx->base.ctxr = dma_pool_zalloc(priv->context_pool,
						 EIP197_GFP_FLAGS(areq->base),
						 &ctx->base.ctxr_dma);
		if (!ctx->base.ctxr)
			return -ENOMEM;
	}

	ring = ctx->base.ring;
*/
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
	if (ctx->digest == CONTEXT_CONTROL_DIGEST_HMAC)
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

static int mtk_ahash_cra_init(struct crypto_tfm *tfm)
{
	struct safexcel_ahash_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = to_cipher_tmpl(tfm);
	struct mtk_device *mtk = tmpl->mtk;
	struct mtk_context_record *ctxr;
/*
	struct safexcel_alg_template *tmpl =
		container_of(__crypto_ahash_alg(tfm->__crt_alg),
			     struct safexcel_alg_template, alg.ahash);
*/
	ctx->mtk = mtk;
	ctx->base.send = mtk_ahash_send;
	ctx->base.handle_result = mtk_ahash_handle_result;

	crypto_ahash_set_reqsize(__crypto_ahash_cast(tfm),
				 sizeof(struct safexcel_ahash_req));
	return 0;
}

static int mtk_ahash_init(struct ahash_request *areq)
{
	struct mtk_ahash_ctx *ctx = crypto_ahash_ctx(crypto_ahash_reqtfm(areq));
	struct mtk_ahash_req *req = ahash_request_ctx(areq);

	memset(req, 0, sizeof(*req));

	
/*   hardware can init SHAx_Hx values!

	req->state[0] = SHA1_H0;
	req->state[1] = SHA1_H1;
	req->state[2] = SHA1_H2;
	req->state[3] = SHA1_H3;
	req->state[4] = SHA1_H4;

	ctx->alg = CONTEXT_CONTROL_CRYPTO_ALG_SHA1;
	ctx->digest = CONTEXT_CONTROL_DIGEST_PRECOMPUTED;
	req->state_sz = SHA1_DIGEST_SIZE;
*/
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

	/* context not allocated, skip invalidation */
	if (!ctx->base.ctxr)
		return;

	ret = safexcel_ahash_exit_inv(tfm);
	if (ret)
		dev_warn(mtk->dev, "hash: invalidation error %d\n", ret);
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

	if (keylen <= blocksize) {
		memcpy(ipad, key, keylen);
	} else {
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
	}

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
	struct mtk_ahash_req *req;
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

	req = ahash_request_ctx(areq);
	req->hmac = true;
	req->last_req = true;

	ret = crypto_ahash_update(areq);
	if (ret && ret != -EINPROGRESS)
		return ret;

	wait_for_completion_interruptible(&result.completion);
	if (result.error)
		return result.error;

	return crypto_ahash_export(areq, state);
}

static int mtk_hmac_setkey(const char *alg, const u8 *key,
				unsigned int keylen, void *istate, void *ostate)
{
	struct ahash_request *areq;
	struct crypto_ahash *tfm;
	unsigned int blocksize;
	u8 *ipad, *opad;
	int ret;

	tfm = crypto_alloc_ahash(alg, CRYPTO_ALG_TYPE_AHASH,
				 CRYPTO_ALG_TYPE_AHASH_MASK);
	if (IS_ERR(tfm))
		return PTR_ERR(tfm);

	areq = ahash_request_alloc(tfm, GFP_KERNEL);
	if (!areq) {
		ret = -ENOMEM;
		goto free_ahash;
	}

	crypto_ahash_clear_flags(tfm, ~0);
	blocksize = crypto_tfm_alg_blocksize(crypto_ahash_tfm(tfm));

	ipad = kzalloc(2 * blocksize, GFP_KERNEL);
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

static int safexcel_hmac_sha1_setkey(struct crypto_ahash *tfm, const u8 *key,
				     unsigned int keylen)
{
	struct safexcel_ahash_ctx *ctx = crypto_tfm_ctx(crypto_ahash_tfm(tfm));
	struct safexcel_ahash_export_state istate, ostate;
	int ret, i;

	ret = safexcel_hmac_setkey("safexcel-sha1", key, keylen, &istate, &ostate);
	if (ret)
		return ret;

	for (i = 0; i < SHA1_DIGEST_SIZE / sizeof(u32); i++) {
		if (ctx->ipad[i] != le32_to_cpu(istate.state[i]) ||
		    ctx->opad[i] != le32_to_cpu(ostate.state[i])) {
			ctx->base.needs_inv = true;
			break;
		}
	}

	memcpy(ctx->ipad, &istate.state, SHA1_DIGEST_SIZE);
	memcpy(ctx->opad, &ostate.state, SHA1_DIGEST_SIZE);

	return 0;
}

struct mtk_ahash_def {
	unsigned long flags;
	const char *name;
	const char *drv_name;
	unsigned int digestsize;
	unsigned int blocksize;
	unsigned int statesize;
	const u32 *std_iv;
};

static const struct mtk_ahash_def ahash_def[] = {
	{
		.flags		= MTK_HASH_SHA1,
		.name		= "sha1",
		.drv_name	= "eip93-sha1",
		.digestsize	= SHA1_DIGEST_SIZE,
		.blocksize	= SHA1_BLOCK_SIZE,
		.statesize	= sizeof(struct sha1_state),
		.std_iv		= std_iv_sha1,
	},
	{
		.flags		= MTK_HASH_SHA256,
		.name		= "sha256",
		.drv_name	= "eip93-sha256",
		.digestsize	= SHA256_DIGEST_SIZE,
		.blocksize	= SHA256_BLOCK_SIZE,
		.statesize	= sizeof(struct sha256_state),
		.std_iv		= std_iv_sha256,
	},
	{
		.flags		= MTK_HASH_SHA1 || MTK_HMAC,
		.name		= "hmac(sha1)",
		.drv_name	= "eip93-hmac-sha1",
		.digestsize	= SHA1_DIGEST_SIZE,
		.blocksize	= SHA1_BLOCK_SIZE,
		.statesize	= sizeof(struct sha1_state),
		.std_iv		= std_iv_sha1,
	},
	{
		.flags		= MTK_HASH_SHA224 | MTK_HMAC,
		.name		= "hmac(sha224)",
		.drv_name	= "eip93-hmac-sha224",
		.digestsize	= SHA1_DIGEST_SIZE,
		.blocksize	= SHA1_BLOCK_SIZE,
		.statesize	= sizeof(struct sha224_state),
		.std_iv		= std_iv_sha1,
	},
	{
		.flags		= MTK_HASH_SHA256 | MTK_HMAC,
		.name		= "hmac(sha256)",
		.drv_name	= "eip93-hmac-sha256",
		.digestsize	= SHA256_DIGEST_SIZE,
		.blocksize	= SHA256_BLOCK_SIZE,
		.statesize	= sizeof(struct sha256_state),
		.std_iv		= std_iv_sha256,
	},
};

static int mtk_ahash_register_one(const struct mtk_ahash_def *def,
				  struct mtk_device *mtk)
{
	struct mtk_alg_template *tmpl;
	struct ahash_alg *alg;
	struct crypto_alg *base;
	int ret;

	tmpl = kzalloc(sizeof(*tmpl), GFP_KERNEL);
	if (!tmpl)
		return -ENOMEM;

	tmpl->std_iv = def->std_iv;

	alg = &tmpl->alg.ahash;
	alg->init = mtk_ahash_init;
	alg->update = mtk_ahash_update;
	alg->final = mtk_ahash_final;
	alg->digest = mtk_ahash_digest;
	alg->export = mtk_ahash_export;
	alg->import = mtk_ahash_import;
	if (IS_HMAC(def->flags))
		alg->setkey = mtk_hmac_setkey;
	alg->halg.digestsize = def->digestsize;
	alg->halg.statesize = def->statesize;

	base = &alg->halg.base;
	base->cra_blocksize = def->blocksize;
	base->cra_priority = 300;
	base->cra_flags = CRYPTO_ALG_ASYNC;
	base->cra_ctxsize = sizeof(struct mtk_ahash_ctx);
	base->cra_alignmask = 0;
	base->cra_module = THIS_MODULE;
	base->cra_init = mtk_ahash_cra_init;
	INIT_LIST_HEAD(&base->cra_list);

	snprintf(base->cra_name, CRYPTO_MAX_ALG_NAME, "%s", def->name);
	snprintf(base->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
		 def->drv_name);

	INIT_LIST_HEAD(&tmpl->entry);
	tmpl->crypto_alg_type = CRYPTO_ALG_TYPE_AHASH;
	tmpl->alg_flags = def->flags;
	tmpl->mtk = mtk;

	ret = crypto_register_ahash(alg);
	if (ret) {
		kfree(tmpl);
		dev_err(mtk->dev, "%s registration failed\n", base->cra_name);
		return ret;
	}

	list_add_tail(&tmpl->entry, &ahash_algs);
	dev_dbg(mtk->dev, "%s is registered\n", base->cra_name);
	return 0;
}

static void mtk_ahash_unregister(struct mtk_device *mtk)
{
	struct mtk_alg_template *tmpl, *n;

	list_for_each_entry_safe(tmpl, n, &ahash_algs, entry) {
		crypto_unregister_ahash(&tmpl->alg.ahash);
		list_del(&tmpl->entry);
		kfree(tmpl);
	}
}

static int mtk_ahash_register(struct mtk_device *mtk)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(ahash_def); i++) {
		ret = mtk_ahash_register_one(&ahash_def[i], mtk);
		if (ret)
			goto err;
	}

	return 0;
err:
	mtk_ahash_unregister(mtk);
	return ret;
}

