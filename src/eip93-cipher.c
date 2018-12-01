/*
 * Copyright (c) 2018 Richard van Schagen. All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 */
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <crypto/aes.h>
#include <crypto/des.h>
#include <crypto/internal/skcipher.h>

#include "common-eip93.h"
#include "eip93-cipher.h"
#include "regs-eip93.h"

#define WORDSWAP(a)     	((((a)>>24)&0xff) | (((a)>>8)&0xff00) |	(((a)<<8)&0xff0000) | (((a)<<24)&0xff000000))

static LIST_HEAD(ablkcipher_algs);

// get one request from finished queue

void mtk_cipher_req_done(struct mtk_device *mtk, int ctr)
{
	struct ablkcipher_request *req = NULL;
	struct eip93DescpHandler_s *rd;
	struct mtk_dma_rec *rec;
	unsigned long flags;	

	rd = &mtk->rd[ctr];
	rec = &mtk->rec[ctr];
	req = (struct ablkcipher_request *)rec->req;

	if (req) {
		rec->flags = 0;
//		spin_lock_irqsave(&mtk->lock, flags);
		mtk->count--;
//		spin_unlock_irqrestore(&mtk->lock, flags);
		req->base.complete(&req->base, 0);
	}
}

int mtk_cipher_setkey(struct crypto_ablkcipher *ablk, const u8 *key,
				 unsigned int keylen)
{
	struct crypto_tfm *tfm = crypto_ablkcipher_tfm(ablk);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	unsigned long flags = to_cipher_tmpl(tfm)->alg_flags;
	int ret;

	if (!key || !keylen)
		return -EINVAL;

	if (IS_AES(flags)) {
		switch (keylen) {
		case AES_KEYSIZE_128:
		case AES_KEYSIZE_192:
		case AES_KEYSIZE_256:
			break;
		default:
			goto fallback;
		}
	}
	if (IS_DES(flags)) {
		if (keylen != DES_KEY_SIZE)
			return -EINVAL;
	}
	if (IS_3DES(flags)) {
		if (keylen != DES3_EDE_KEY_SIZE)
			return -EINVAL;
	}
	ctx->keylen = keylen;
	memcpy(ctx->key, key, keylen);

	return 0;
fallback:
	ret = crypto_skcipher_setkey(ctx->fallback, key, keylen);
	if (!ret)
		ctx->keylen = keylen;
	return ret;
}

int mtk_scatter_combine(struct mtk_device *mtk, struct scatterlist *sgsrc,
		struct scatterlist *sgdst, int nbytes)
{
	struct mtk_dma_rec *rec;
	unsigned int remainin, remainout;
	int offsetin = 0;
	int offsetout = 0;
	unsigned int n, len;
	struct page *spage, *dpage;
	unsigned int soff, doff;
	unsigned int ssize, dsize;
	dma_addr_t saddr, daddr;
	bool nextin = false;
	bool nextout = false;
	int ctr;
	int count = 0;

	n = nbytes;
	spage = sg_page(sgsrc);
	soff = sgsrc->offset;
	remainin = min(sgsrc->length, n);
	ssize = remainin;
	saddr = dma_map_page(mtk->dev, spage, soff, remainin, DMA_TO_DEVICE);

	dpage = sg_page(sgdst);
	doff = sgdst->offset;
	remainout = min(sgdst->length, n);
	dsize = remainout;
	daddr = dma_map_page(mtk->dev, dpage, doff, remainout, DMA_FROM_DEVICE);

	ctr = mtk->rec_rear_idx;

	while (n) {
		if (nextin) {
			sgsrc++;
			spage = sg_page(sgsrc);
			soff = sgsrc->offset;
			remainin = min(sgsrc->length, n);
			if (remainin == 0)
				continue;
			saddr = dma_map_page(mtk->dev, spage, soff, remainin,
				DMA_BIDIRECTIONAL);
			ssize = remainin;
			offsetin = 0;
			nextin = false;
		}

		if (nextout) {
			sgdst++;
			dpage = sg_page(sgdst);
			doff = sgdst->offset;
			remainout = min(sgdst->length, n);
			if (remainout == 0)
				continue;
			daddr = dma_map_page(mtk->dev, dpage, doff, remainout,
				DMA_BIDIRECTIONAL);
			dsize = remainout;
			offsetout = 0;
			nextout = false;
		}
		rec = &mtk->rec[ctr];
		rec->srcDma = (saddr + offsetin);
		rec->dstDma = (daddr + offsetout);
		rec->saddr = saddr;
		rec->daddr = daddr;
		rec->ssize = ssize;
		rec->dsize = dsize;
		if (remainin == remainout) {
			len = remainin;
			nextin = true;
			nextout = true;
		} else if (remainin < remainout) {
			len = remainin;
			offsetout += len;
			remainout -= len;
			nextin = true;
		} else {
			len = remainout;
			offsetin += len;
			remainin -= len;
			nextout = true;
		}
		n -= len;
		rec->dmaLen = len;
		count++;
		ctr = (ctr + 1) % MTK_RING_SIZE;
		dev_dbg(mtk->dev, "[%d] SrcAd: %08x, DstAd %08x Len: %d\n", 
			ctr, rec->srcDma, rec->dstDma, rec->dmaLen);
	}
	return count;
}

int mtk_cipher_xmit(struct mtk_device *mtk, struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_cipher_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	struct mtk_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
	struct eip93DescpHandler_s *cd;
	struct mtk_dma_rec *rec;
	u32 aesKeyLen;
	u32 ctr = 0, count, i, errVal, spi = 0;
	saRecord_t *saRecord;
	saState_t *saState;
	dma_addr_t saPhyAddr, statePhyAddr;
	int LoopLimiter = 10000;
	unsigned int total;
	uint32_t interrupts = 0;
	unsigned long flags = 0;
	unsigned long GetCount;

	if (!mtk)
		return -ENODEV;

	if (ctx->keylen == AES_KEYSIZE_256)
		aesKeyLen = 4;
	else if (ctx->keylen == AES_KEYSIZE_192)
		aesKeyLen = 3;
	else
		aesKeyLen = 2;

	spin_lock_irqsave(&mtk->lock, flags);

	ctr = mtk->rec_rear_idx;

	/* prepare SA */

	saRecord = &mtk->saRecord[ctr];
	memset(saRecord, 0x00, sizeof(saRecord_t));
	saPhyAddr = mtk->phy_record + (sizeof(saRecord_t) * ctr);

	saState = &mtk->saState[ctr];
	memset(saState, 0x00, sizeof(saState_t));
	statePhyAddr = mtk->phy_state + (sizeof(saState_t) * ctr);

	if IS_ENCRYPT(rctx->flags) {
		saRecord->saCmd0.bits.direction = 0x0; //outbound
	} else {
		saRecord->saCmd0.bits.direction = 0x1; //inbound
	}

	saRecord->saCmd0.bits.ivSource = 0x2;//0x2;Load IV from SaRecord
	saRecord->saCmd0.bits.saveIv = 0x1;//0x1;Save IV to SaRecord
	saRecord->saCmd0.bits.opGroup = 0x0; // basic operation
	saRecord->saCmd0.bits.opCode = 0x0; // protocol
	if IS_DES(rctx->flags) {
		saRecord->saCmd0.bits.cipher = 0x0;
	}
	if IS_3DES(rctx->flags) {
		saRecord->saCmd0.bits.cipher = 0x1;
	}
	if IS_AES(rctx->flags) {
		saRecord->saCmd0.bits.cipher = 0x3;
	}
	saRecord->saCmd0.bits.hash = 15; // hashAlg 15 = NULL;
	saRecord->saCmd0.bits.hdrProc = 0x0; // no header processing
	saRecord->saCmd0.bits.digestLength = 0x0; // digestWord;
	saRecord->saCmd0.bits.padType = 3; // Zero padding
	saRecord->saCmd0.bits.extPad = 0;
	saRecord->saCmd0.bits.scPad = 0; //no padding
	if IS_ECB(rctx->flags)
		saRecord->saCmd1.bits.cipherMode = 0;
	if IS_CBC(rctx->flags)
		saRecord->saCmd1.bits.cipherMode = 1;
	if IS_CTR(rctx->flags)
		saRecord->saCmd1.bits.cipherMode = 2;

	saRecord->saCmd1.bits.hmac = 0; //enHmac no Hmac;

	if IS_AES(rctx->flags)
		saRecord->saCmd1.bits.aesKeyLen = aesKeyLen;

	saRecord->saCmd1.bits.seqNumCheck = 0; // no Seq Num Check

	memcpy(saRecord->saKey, ctx->key, ctx->keylen);

	saRecord->saSpi = 0x0; //WORDSWAP(spi); //esp spi

	saRecord->saSeqNumMask[0] = 0xFFFFFFFF;
	saRecord->saSeqNumMask[1] = 0x0;
	
	if IS_CBC(rctx->flags) {
		if (!req->info)
			memset(saState->stateIv, 0xFF, 16);
		else
			memcpy(saState->stateIv, req->info, 16);
	}

	if IS_CTR(rctx->flags) {
		if (!req->info)
			memset(saState->stateIv, 0xFF, 16);
		else
			memcpy(saState->stateIv, req->info, 16);
	}

	// Create combined scatterlist records
	count = mtk_scatter_combine(mtk, req->src, req->dst, req->nbytes);

	// Create #count Cmd Descriptors

	for (i = 0; i < count; i++) {
		cd = &mtk->cd[ctr];
		memset(cd, 0x00, 32); // clear CDR??
		rec = &mtk->rec[ctr];
		rec->req = (void *)req;
		rec->flags = BIT_1; // (TODO indicate simple "crypto"
		rec->saAddr = (unsigned int)saRecord;
		rec->stateAddr = (unsigned int)saState;
		cd->peCrtlStat.bits.hostReady = 1;
		cd->peCrtlStat.bits.hashFinal = 0;
		cd->peCrtlStat.bits.padCrtlStat = 0; //padCrtlStat; pad boundary
		cd->peCrtlStat.bits.peReady = 0;

		cd->srcAddr = rec->srcDma;
		cd->dstAddr = rec->dstDma;
		cd->saAddr = saPhyAddr;
		cd->stateAddr = statePhyAddr;
		cd->arc4Addr = statePhyAddr;
		cd->peLength.bits.length = (rec->dmaLen) & (BIT_20 - 1);
		cd->peLength.bits.hostReady = 1;
		ctr = (ctr + 1) % MTK_RING_SIZE;
	}
	rec->flags |= BIT_0; // Indicate last
	mtk->rec_rear_idx = ctr;
	mtk->getcount = mtk->getcount + count;
	spin_unlock_irqrestore(&mtk->lock, flags);

	/*
	 * Make sure all data is updated before starting engine.
	 */
	wmb();
	/* Writing new descriptor count starts DMA action */
	writel(count, mtk->base + EIP93_REG_PE_CD_COUNT);

	writel(BIT_0, mtk->base + EIP93_REG_MASK_ENABLE);
	return 0;
fail:
	mtk->rec_front_idx = (mtk->rec_front_idx + 1) % MTK_RING_SIZE;
free_saRecord:
	dma_free_coherent(mtk->dev, sizeof(saRecord_t), saRecord, saPhyAddr);
free_buffer:
	return errVal;
}

int mtk_handle_request(struct mtk_device *mtk, struct ablkcipher_request *req)
{
	struct crypto_ablkcipher *tfm = crypto_ablkcipher_reqtfm(req);
	struct mtk_aes_ctx *ctx = crypto_ablkcipher_ctx(tfm);
	int ret = 0;

	/* assign new request to device */
	ret = sg_nents_for_len(req->dst, req->nbytes);
	if (ret < 0) {
		dev_info(mtk->dev, "Invalid Dst SG\n");
		return ret;
	}

	ret = sg_nents_for_len(req->src, req->nbytes);

	if (ret < 0) {
		dev_info(mtk->dev, "Invalid Src SG\n");
		return ret;
	}

	ret = mtk_cipher_xmit(mtk, req);

	return ret;
}

int mtk_handle_queue(struct mtk_device *mtk, struct ablkcipher_request *req)
{
	unsigned long flags;
	int ret = 0, err;

	spin_lock_irqsave(&mtk->lock, flags);

	if (mtk->count > MTK_QUEUE_LENGTH) {
		spin_unlock_irqrestore(&mtk->lock, flags);
		return -EBUSY;
	}
	ret = -EINPROGRESS;

	if (req) {
		mtk->count = mtk->count + 1;
	}
	spin_unlock_irqrestore(&mtk->lock, flags);

	if (!req)
		return 0;

	err = mtk_handle_request(mtk, req);

	if (err)
		dev_err(mtk->dev, "Error: %d\n", err);

	return ret;
}

int mtk_cipher_crypt(struct ablkcipher_request *req, int encrypt)
{
	struct crypto_tfm *tfm =
			crypto_ablkcipher_tfm(crypto_ablkcipher_reqtfm(req));
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_cipher_reqctx *rctx = ablkcipher_request_ctx(req);
	struct mtk_alg_template *tmpl = to_cipher_tmpl(tfm);
	int ret;

	rctx->flags = tmpl->alg_flags;
	rctx->flags |= encrypt ? MTK_ENCRYPT : MTK_DECRYPT;

/*
	if (IS_AES(rctx->flags) &&
		ctx->keylen != AES_KEYSIZE_128 &&
		ctx->keylen != AES_KEYSIZE_192 &&
		ctx->keylen != AES_KEYSIZE_256) {

		SKCIPHER_REQUEST_ON_STACK(subreq, ctx->fallback);

		skcipher_request_set_tfm(subreq, ctx->fallback);
		skcipher_request_set_callback(subreq, req->base.flags,
					      NULL, NULL);
		skcipher_request_set_crypt(subreq, req->src, req->dst,
					   req->nbytes, req->info);
		if (IS_ENCRYPT(rctx->flags)) 
			ret = crypto_skcipher_encrypt(subreq);
		else
			ret = crypto_skcipher_decrypt(subreq);
		skcipher_request_zero(subreq);
		return ret;
	}
*/
	return mtk_handle_queue(tmpl->mtk, req);
}

int mtk_cipher_encrypt(struct ablkcipher_request *req)
{
	return mtk_cipher_crypt(req, 1);
}

int mtk_cipher_decrypt(struct ablkcipher_request *req)
{
	return mtk_cipher_crypt(req, 0);
}

int mtk_cipher_init(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	memset(ctx, 0, sizeof(*ctx));
	tfm->crt_ablkcipher.reqsize = sizeof(struct mtk_cipher_reqctx);

	ctx->fallback = crypto_alloc_skcipher(crypto_tfm_alg_name(tfm), 0,
					      CRYPTO_ALG_ASYNC |
					      CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);

	return 0;
}

void mtk_cipher_exit(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto_free_skcipher(ctx->fallback);
}

static int
mtk_ablkcipher_async_req_handle(struct crypto_async_request *async_req)
{
	return 0;
}

struct mtk_ablkcipher_def {
	unsigned long flags;
	const char *name;
	const char *drv_name;
	unsigned int blocksize;
	unsigned int ivsize;
	unsigned int min_keysize;
	unsigned int max_keysize;
};

static const struct mtk_ablkcipher_def ablkcipher_def[] = {
	{
		.flags		= MTK_ALG_AES | MTK_MODE_ECB,
		.name		= "ecb(aes)",
		.drv_name	= "ecb-aes-mtk",
		.blocksize	= AES_BLOCK_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_AES | MTK_MODE_CBC,
		.name		= "cbc(aes)",
		.drv_name	= "cbc-aes-mtk",
		.blocksize	= AES_BLOCK_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_AES | MTK_MODE_CTR,
		.name		= "ctr(aes)",
		.drv_name	= "ctr-aes-mtk",
		.blocksize	= AES_BLOCK_SIZE,
		.ivsize		= AES_BLOCK_SIZE,
		.min_keysize	= AES_MIN_KEY_SIZE,
		.max_keysize	= AES_MAX_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_DES | MTK_MODE_ECB,
		.name		= "ecb(des)",
		.drv_name	= "ecb-des-mtk",
		.blocksize	= DES_BLOCK_SIZE,
		.ivsize		= 0,
		.min_keysize	= DES_KEY_SIZE,
		.max_keysize	= DES_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_DES | MTK_MODE_CBC,
		.name		= "cbc(des)",
		.drv_name	= "cbc-des-mtk",
		.blocksize	= DES_BLOCK_SIZE,
		.ivsize		= DES_BLOCK_SIZE,
		.min_keysize	= DES_KEY_SIZE,
		.max_keysize	= DES_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_3DES | MTK_MODE_ECB,
		.name		= "ecb(des3_ede)",
		.drv_name	= "ecb-3des-mtk",
		.blocksize	= DES3_EDE_BLOCK_SIZE,
		.ivsize		= 0,
		.min_keysize	= DES3_EDE_KEY_SIZE,
		.max_keysize	= DES3_EDE_KEY_SIZE,
	},
	{
		.flags		= MTK_ALG_3DES | MTK_MODE_CBC,
		.name		= "cbc(des3_ede)",
		.drv_name	= "cbc-3des-mtk",
		.blocksize	= DES3_EDE_BLOCK_SIZE,
		.ivsize		= DES3_EDE_BLOCK_SIZE,
		.min_keysize	= DES3_EDE_KEY_SIZE,
		.max_keysize	= DES3_EDE_KEY_SIZE,
	},
};
static int mtk_ablkcipher_register_one(const struct mtk_ablkcipher_def *def,
				       struct mtk_device *mtk)
{
	struct mtk_alg_template *tmpl;
	struct crypto_alg *alg;
	int ret;

	tmpl = kzalloc(sizeof(*tmpl), GFP_KERNEL);
	if (!tmpl)
		return -ENOMEM;

	alg = &tmpl->alg.crypto;

	snprintf(alg->cra_name, CRYPTO_MAX_ALG_NAME, "%s", def->name);
	snprintf(alg->cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
		 def->drv_name);

	alg->cra_blocksize = def->blocksize;
	alg->cra_ablkcipher.ivsize = def->ivsize;
	alg->cra_ablkcipher.min_keysize = def->min_keysize;
	alg->cra_ablkcipher.max_keysize = def->max_keysize;
	alg->cra_ablkcipher.setkey = mtk_cipher_setkey;
	alg->cra_ablkcipher.encrypt = mtk_cipher_encrypt;
	alg->cra_ablkcipher.decrypt = mtk_cipher_decrypt;

	alg->cra_priority = 300;
	alg->cra_flags = CRYPTO_ALG_TYPE_ABLKCIPHER | CRYPTO_ALG_ASYNC |
			 CRYPTO_ALG_NEED_FALLBACK;
	alg->cra_ctxsize = sizeof(struct mtk_cipher_ctx);
	alg->cra_alignmask = 0xf;
	alg->cra_type = &crypto_ablkcipher_type;
	alg->cra_module = THIS_MODULE;
	alg->cra_init = mtk_cipher_init;
	alg->cra_exit = mtk_cipher_exit;
	INIT_LIST_HEAD(&alg->cra_list);

	INIT_LIST_HEAD(&tmpl->entry);
	tmpl->crypto_alg_type = CRYPTO_ALG_TYPE_ABLKCIPHER;
	tmpl->alg_flags = def->flags;
	tmpl->mtk = mtk;

	ret = crypto_register_alg(alg);
	if (ret) {
		kfree(tmpl);
		dev_err(mtk->dev, "%s registration failed\n", alg->cra_name);
		return ret;
	}

	list_add_tail(&tmpl->entry, &ablkcipher_algs);
	dev_dbg(mtk->dev, "%s is registered\n", alg->cra_name);
	return 0;
}

static void mtk_ablkcipher_unregister(struct mtk_device *mtk)
{
	struct mtk_alg_template *tmpl, *n;

	list_for_each_entry_safe(tmpl, n, &ablkcipher_algs, entry) {
		crypto_unregister_alg(&tmpl->alg.crypto);
		list_del(&tmpl->entry);
		kfree(tmpl);
	}
}

static int mtk_ablkcipher_register(struct mtk_device *mtk)
{
	int ret, i;

	for (i = 0; i < ARRAY_SIZE(ablkcipher_def); i++) {
		ret = mtk_ablkcipher_register_one(&ablkcipher_def[i], mtk);
		if (ret)
			goto err;
	}

	return 0;
err:
	mtk_ablkcipher_unregister(mtk);
	return ret;
}

const struct mtk_algo_ops ablkcipher_ops = {
	.type = CRYPTO_ALG_TYPE_ABLKCIPHER,
	.register_algs = mtk_ablkcipher_register,
	.unregister_algs = mtk_ablkcipher_unregister,
	.async_req_handle = mtk_ablkcipher_async_req_handle,
};

