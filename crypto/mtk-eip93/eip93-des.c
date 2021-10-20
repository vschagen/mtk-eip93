// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include <crypto/internal/des.h>
#include <linux/dma-mapping.h>

#include "eip93-common.h"
#include "eip93-main.h"
#include "eip93-cipher.h"
#include "eip93-regs.h"

/* Crypto skcipher API functions */
static int mtk_des_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_crypto_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
					sizeof(struct mtk_cipher_reqctx));

	memset(ctx, 0, sizeof(*ctx));

	ctx->mtk = tmpl->mtk;
	ctx->type = tmpl->type;

	ctx->sa_in = kzalloc(sizeof(struct saRecord_s), GFP_KERNEL);
	if (!ctx->sa_in)
		return -ENOMEM;

	ctx->sa_base_in = dma_map_single(ctx->mtk->dev, ctx->sa_in,
				sizeof(struct saRecord_s), DMA_TO_DEVICE);

	ctx->sa_out = kzalloc(sizeof(struct saRecord_s), GFP_KERNEL);
	if (!ctx->sa_out)
		return -ENOMEM;

	ctx->sa_base_out = dma_map_single(ctx->mtk->dev, ctx->sa_out,
				sizeof(struct saRecord_s), DMA_TO_DEVICE);
	return 0;
}

static void mtk_des_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_crypto_ctx *ctx = crypto_tfm_ctx(tfm);

	dma_unmap_single(ctx->mtk->dev, ctx->sa_base_in,
			sizeof(struct saRecord_s), DMA_TO_DEVICE);
	dma_unmap_single(ctx->mtk->dev, ctx->sa_base_out,
			sizeof(struct saRecord_s), DMA_TO_DEVICE);

	kfree(ctx->sa_in);
	kfree(ctx->sa_out);
}

static int mtk_des_setkey(struct crypto_skcipher *ctfm, const u8 *key,
				 unsigned int len)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct mtk_crypto_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);
	struct saRecord_s *saRecord = ctx->sa_out;
	int sa_size = sizeof(struct saRecord_s);
	unsigned long flags = tmpl->flags;
	unsigned int keylen = len;
	int err;

	if (!key || !keylen)
		return -EINVAL;

	switch ((flags & MTK_ALG_MASK)) {
	case MTK_ALG_DES:
		ctx->blksize = DES_BLOCK_SIZE;
		err = verify_skcipher_des_key(ctfm, key);
		break;
	case MTK_ALG_3DES:
		ctx->blksize = DES3_EDE_BLOCK_SIZE;
		err = verify_skcipher_des3_key(ctfm, key);
	}

	if (err)
		return err;

	dma_unmap_single(ctx->mtk->dev, ctx->sa_base_in, sa_size,
								DMA_TO_DEVICE);
	dma_unmap_single(ctx->mtk->dev, ctx->sa_base_out, sa_size,
								DMA_TO_DEVICE);

	mtk_set_saRecord(saRecord, keylen, flags);

	memset(saRecord->saKey + keylen, 0, 32 - keylen);
	memcpy(saRecord->saKey, key, keylen);

	saRecord->saCmd0.bits.direction = 0;

	memcpy(ctx->sa_in, saRecord, sa_size);
	ctx->sa_in->saCmd0.bits.direction = 1;

	ctx->sa_base_out = dma_map_single(ctx->mtk->dev, ctx->sa_out, sa_size,
								DMA_TO_DEVICE);

	ctx->sa_base_in = dma_map_single(ctx->mtk->dev, ctx->sa_in, sa_size,
								DMA_TO_DEVICE);
	return 0;
}

static int mtk_des_crypt(struct skcipher_request *req)
{
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct crypto_async_request *async = &req->base;
	struct mtk_crypto_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct crypto_skcipher *skcipher = crypto_skcipher_reqtfm(req);

#ifdef CONFIG_CRYPTO_DEV_EIP93_POLL
	struct mtk_device *mtk = ctx->mtk;
#endif

	if (!req->cryptlen)
		return 0;

	rctx->assoclen = 0;
	rctx->textsize = req->cryptlen;
	rctx->authsize = 0;
	rctx->sg_src = req->src;
	rctx->sg_dst = req->dst;
	rctx->ivsize = crypto_skcipher_ivsize(skcipher);
	rctx->blksize = ctx->blksize;
	if (!IS_ECB(rctx->flags))
		rctx->flags |= MTK_DESC_DMA_IV;

	return mtk_skcipher_send_req(async);
}

static int mtk_des_encrypt(struct skcipher_request *req)
{
	struct mtk_crypto_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct mtk_alg_template *tmpl = container_of(req->base.tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_ENCRYPT;
	rctx->saRecord_base = ctx->sa_base_out;

	return mtk_des_crypt(req);
}

static int mtk_des_decrypt(struct skcipher_request *req)
{
	struct mtk_crypto_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct mtk_alg_template *tmpl = container_of(req->base.tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_DECRYPT;
	rctx->saRecord_base = ctx->sa_base_in;

	return mtk_des_crypt(req);
}

/* Available algorithms in this module */

struct mtk_alg_template mtk_alg_ecb_des = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_ECB | MTK_ALG_DES,
	.alg.skcipher = {
		.setkey = mtk_des_setkey,
		.encrypt = mtk_des_encrypt,
		.decrypt = mtk_des_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize	= 0,
		.base = {
			.cra_name = "ecb(des)",
			.cra_driver_name = "ebc(des-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_crypto_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_des_cra_init,
			.cra_exit = mtk_des_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_cbc_des = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CBC | MTK_ALG_DES,
	.alg.skcipher = {
		.setkey = mtk_des_setkey,
		.encrypt = mtk_des_encrypt,
		.decrypt = mtk_des_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize	= DES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des)",
			.cra_driver_name = "cbc(des-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_crypto_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_des_cra_init,
			.cra_exit = mtk_des_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_ecb_des3_ede = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_ECB | MTK_ALG_3DES,
	.alg.skcipher = {
		.setkey = mtk_des_setkey,
		.encrypt = mtk_des_encrypt,
		.decrypt = mtk_des_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize	= 0,
		.base = {
			.cra_name = "ecb(des3_ede)",
			.cra_driver_name = "ecb(des3_ede-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_crypto_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_des_cra_init,
			.cra_exit = mtk_des_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_cbc_des3_ede = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CBC | MTK_ALG_3DES,
	.alg.skcipher = {
		.setkey = mtk_des_setkey,
		.encrypt = mtk_des_encrypt,
		.decrypt = mtk_des_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize	= DES3_EDE_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des3_ede)",
			.cra_driver_name = "cbc(des3_ede-eip93)",
			.cra_priority = MTK_CRA_PRIORITY,
			.cra_flags = CRYPTO_ALG_ASYNC |
					CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_crypto_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_des_cra_init,
			.cra_exit = mtk_des_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
