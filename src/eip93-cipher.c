// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include <linux/delay.h>
#include <linux/device.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/interrupt.h>
#include <linux/scatterlist.h>
#include <linux/types.h>
#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/authenc.h>
#include <crypto/des.h>
#include <crypto/hmac.h>
#include <crypto/internal/aead.h>
#include <crypto/internal/skcipher.h>
#include <crypto/scatterwalk.h>

#include "eip93-common.h"
#include "eip93-core.h"
#include "eip93-cipher.h"
#include "eip93-regs.h"
#include "eip93-ring.h"

#define WORDSWAP(a)     	((((a)>>24)&0xff) | (((a)>>8)&0xff00) |	(((a)<<8)&0xff0000) | (((a)<<24)&0xff000000))


static void mtk_free_sg_cpy(int cryptlen, struct scatterlist **sg)
{
	int len;

	if (!*sg)
		return;

	len = ALIGN(cryptlen, AES_BLOCK_SIZE);
	free_pages((unsigned long)sg_virt(*sg), get_order(len));

	kfree(*sg);
	*sg = NULL;
}

static inline int mtk_aes_padlen(int len)
{
	len &= AES_BLOCK_SIZE - 1;
	return len ? AES_BLOCK_SIZE - len : 0;
}

static void mtk_sg_copy_buf(void *buf, struct scatterlist *sg,
			    unsigned int cryptlen, int out)
{
	struct scatter_walk walk;

	if (!cryptlen)
		return;

	scatterwalk_start(&walk, sg);
	scatterwalk_copychunks(buf, &walk, cryptlen, out);
	scatterwalk_done(&walk, out, 0);
}

static int mtk_make_sg_cpy(struct scatterlist *src, struct scatterlist **dst,
			int cryptlen)
{
	void *pages;

	*dst = kmalloc(sizeof(**dst), GFP_ATOMIC);
	if (!*dst)
		return -ENOMEM;

	pages = (void *)__get_free_pages(GFP_ATOMIC, get_order(cryptlen));
	if (!pages) {
		kfree(*dst);
		*dst = NULL;
		return -ENOMEM;
	}

	mtk_sg_copy_buf(pages, src, cryptlen, 0);

	sg_init_table(*dst, 1);
	sg_set_buf(*dst, pages, cryptlen);

	return 0;
}

static bool mtk_is_sg_aligned(struct scatterlist *sg, int len, int blocksize)
{
	int nents;

	if (!IS_ALIGNED(len, blocksize))
		return false;

	for (nents = 0; sg; sg = sg_next(sg), ++nents) {
		if (!IS_ALIGNED(sg->offset, sizeof(u32)))
			return false;

		if (sg->offset + sg->length > PAGE_SIZE)
			printk("Cross Page Boundery!");

		if (len <= sg->length) {
			if (!IS_ALIGNED(len, blocksize))
				return false;

			sg->length = len;
			return true;
		}

		if (!IS_ALIGNED(sg->length, blocksize))
			return false;

		len -= sg->length;
	}

	return false;
}

int mtk_skcipher_setkey(struct crypto_skcipher *ctfm, const u8 *key,
				 unsigned int keylen)
{
	struct crypto_tfm *tfm = crypto_skcipher_tfm(ctfm);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);
	unsigned long flags = tmpl->flags;
	u32 tmp[DES_EXPKEY_WORDS];
	int ret = 0;

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
		if (keylen != DES_KEY_SIZE) {
			crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
			return -EINVAL;
		}
		/* test for weak key */
		ret = des_ekey(tmp, key);
		if (!ret && (tfm->crt_flags & CRYPTO_TFM_REQ_WEAK_KEY)) {
			tfm->crt_flags |= CRYPTO_TFM_RES_WEAK_KEY;
			return -EINVAL;
		}
	}

	if (IS_3DES(flags)) {
		if (keylen != DES3_EDE_KEY_SIZE) {
			crypto_skcipher_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
			return -EINVAL;
		}
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

static int mtk_aead_setkey(struct crypto_aead *ctfm, const u8 *key,
			unsigned int len)
{
	struct crypto_tfm *tfm = crypto_aead_tfm(ctfm);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct crypto_authenc_keys keys;
	size_t bs = crypto_shash_blocksize(ctx->shash);
//	size_t ds = crypto_shash_digestsize(ctx->shash);
	int err, i;

	if (crypto_authenc_extractkeys(&keys, key, len) != 0)
		goto badkey;

	if (keys.enckeylen> sizeof(ctx->key))
		goto badkey;

	/* Encryption key */
	ctx->keylen = keys.enckeylen;
	memcpy(ctx->key, keys.enckey, keys.enckeylen);

	/*auth key */
	/* software work-around for now
	 * EIP93 can only authenticate with
	 * hashed keys
	 */
	{
		SHASH_DESC_ON_STACK(shash, ctx->shash);

		shash->tfm = ctx->shash;
		shash->flags = crypto_shash_get_flags(ctx->shash) &
			       CRYPTO_TFM_REQ_MAY_SLEEP;

			err = crypto_shash_digest(shash, keys.authkey,
							keys.authkeylen, ctx->ipad);
			if (err)
				return err;

		memset(ctx->ipad + keys.authkeylen, 0, bs - keys.authkeylen);
		memcpy(ctx->opad, ctx->ipad, bs);
	
		for (i = 0; i < bs; i++) {
			ctx->ipad[i] ^= HMAC_IPAD_VALUE;
			ctx->opad[i] ^= HMAC_OPAD_VALUE;
		}

		return 0;
	}
badkey:
	crypto_aead_set_flags(ctfm, CRYPTO_TFM_RES_BAD_KEY_LEN);
	return -EINVAL;
}

static dma_addr_t mtk_set_saRecord(struct mtk_device *mtk,
			struct mtk_cipher_ctx *ctx, unsigned long flags,
			unsigned int assoclen, unsigned int digestsize)
{
	dma_addr_t ptr;
	int wptr;
	struct saRecord_s *saRecord;

	wptr = mtk_ring_curr_wptr_index(mtk);

	/* prepare SA */
	saRecord = &mtk->saRecord[wptr];
	ptr = mtk->saRecord_base + wptr * sizeof(saRecord_t);

	memset(saRecord, 0x00, sizeof(saRecord_t));

	if IS_ENCRYPT(flags) {
		saRecord->saCmd0.bits.direction = 0x0; //outbound
	} else {
		saRecord->saCmd0.bits.direction = 0x1; //inbound
	}
	saRecord->saCmd0.bits.ivSource = 0x2;//0x2;Load IV from saState

	saRecord->saCmd0.bits.saveIv = 0x1;//0x1;Save IV to saState

	saRecord->saCmd0.bits.opGroup = 0x0; // basic operation
	saRecord->saCmd0.bits.opCode = 0x0; // protocol

	if IS_DES(flags)
		saRecord->saCmd0.bits.cipher = 0x0;

	if IS_3DES(flags)
		saRecord->saCmd0.bits.cipher = 0x1;

	if IS_AES(flags)
		saRecord->saCmd0.bits.cipher = 0x3;

	if IS_HASH(flags)
		saRecord->saCmd0.bits.saveHash = 1;

	saRecord->saCmd0.bits.hash = 15; // hash = NULL

	if IS_HASH_MD5(flags)
		saRecord->saCmd0.bits.hash = 0;

	if IS_HASH_SHA1(flags)
		saRecord->saCmd0.bits.hash = 1;

	if IS_HASH_SHA224(flags)
		saRecord->saCmd0.bits.hash = 2;

	if IS_HASH_SHA256(flags)
		saRecord->saCmd0.bits.hash = 3;

	saRecord->saCmd0.bits.hdrProc = 0x0; // no header processing
	saRecord->saCmd0.bits.padType = 3; // Zero padding
	saRecord->saCmd0.bits.extPad = 0;
	saRecord->saCmd0.bits.scPad = 0; //no padding

	if IS_ECB(flags)
		saRecord->saCmd1.bits.cipherMode = 0;

	if IS_CBC(flags)
		saRecord->saCmd1.bits.cipherMode = 1;

	if IS_CTR(flags)
		saRecord->saCmd1.bits.cipherMode = 2;

	if IS_HMAC(flags) {
		saRecord->saCmd1.bits.hmac = 1;
		memcpy(saRecord->saIDigest, ctx->ipad, 32);
		memcpy(saRecord->saODigest, ctx->opad, 32);
	}

	if IS_AES(flags) {
		if (ctx->keylen == AES_KEYSIZE_256)
			saRecord->saCmd1.bits.aesKeyLen = 4;
		else if (ctx->keylen == AES_KEYSIZE_192)
			saRecord->saCmd1.bits.aesKeyLen = 3;
		else
			saRecord->saCmd1.bits.aesKeyLen = 2;
	}

	saRecord->saCmd1.bits.seqNumCheck = 0; // no Seq Num Check

	saRecord->saCmd1.bits.hashCryptOffset = (assoclen / sizeof(u32));
	saRecord->saCmd0.bits.digestLength = (digestsize / sizeof(u32));

	memcpy(saRecord->saKey, ctx->key, ctx->keylen);

	saRecord->saSpi = 0x0; //WORDSWAP(spi); //esp spi

	saRecord->saSeqNumMask[0] = 0xFFFFFFFF;
	saRecord->saSeqNumMask[1] = 0x0;

	return ptr;
}

int mtk_scatter_combine(struct mtk_device *mtk, dma_addr_t saRecord_base,
			dma_addr_t saState_base, struct scatterlist *sgsrc,
			struct scatterlist *sgdst, int cryptlen, bool complete,
			unsigned int *areq, int *commands, int *results)
{
	struct mtk_dma_rec *rec;
	unsigned int remainin, remainout;
	int offsetin = 0, offsetout = 0;
	unsigned int n, len;
	dma_addr_t saddr, daddr;
	bool nextin = false;
	bool nextout = false;
	struct eip93_descriptor_s *cdesc;
	struct eip93_descriptor_s *rdesc;
	int ndesc_cdr = 0, ndesc_rdr = 0;
	int wptr;

	n = cryptlen;
	remainin = min(sgsrc->length, n);
	remainout = min(sgdst->length, n);

	saddr = dma_map_single(mtk->dev, sg_virt(sgsrc), remainin,
				DMA_TO_DEVICE); //DMA_BIDIRECTIONAL);
	daddr = dma_map_single(mtk->dev, sg_virt(sgdst), remainout,
				DMA_FROM_DEVICE);

	do {
		wptr = mtk_ring_curr_wptr_index(mtk);
		if (nextin) {
			sgsrc++;
			remainin = min(sgsrc->length, n);
			if (remainin == 0)
				continue;

			saddr = dma_map_single(mtk->dev, sg_virt(sgsrc), remainin,
					DMA_TO_DEVICE);
			offsetin = 0;
			nextin = false;
		}

		if (nextout) {
			sgdst++;
			remainout = min(sgdst->length, n);
			if (remainout == 0)
				continue;

			daddr = dma_map_single(mtk->dev, sg_virt(sgdst), remainout,
					DMA_FROM_DEVICE);
			offsetout = 0;
			nextout = false;
		}
		rec = &mtk->ring[0].cdr_dma[wptr];
		rec->srcDma = saddr + offsetin;
		rec->dstDma = daddr + offsetout;
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

		rec->req = areq;
		rec->dmaLen = len;

		cdesc = mtk_add_cdesc(mtk, rec, saRecord_base, saState_base);
		rdesc = mtk_add_rdesc(mtk);

		ndesc_cdr++;
		ndesc_rdr++;
		n -= len;

		dev_dbg(mtk->dev, "[%d]Src:%08x,Len:%d wptr:%d\n", 
			ndesc_cdr, rec->srcDma, rec->dmaLen, wptr);
	} while (n);

	if (complete == true)
		rec->flags |= BIT(0); // Indicate last

	*commands = ndesc_cdr;
	*results = ndesc_rdr;

	return 0;
}


static int mtk_send_req(struct crypto_async_request *base,
			struct mtk_cipher_ctx *ctx,
			struct scatterlist *reqsrc, struct scatterlist *reqdst, 
			 u8 *reqiv, unsigned int cryptlen, unsigned int assoclen,
			unsigned int digestsize, struct mtk_cipher_reqctx *rctx,
			int *commands, int *results)
{
	struct mtk_device *mtk= ctx->mtk;
	int ndesc_cdr = 0, ndesc_rdr = 0, ctr_cdr = 0, ctr_rdr = 0;
	int offset = 0, wptr, err;
	u32 datalen;
	struct scatterlist *src, *src_ctr;
	struct scatterlist *dst, *dst_ctr; 
	struct saState_s *saState;
	dma_addr_t saState_base, saRecord_base;
	u32 start, end, ctr, blocks;
	unsigned long flags;
	bool complete;
	u32 iv[AES_BLOCK_SIZE / sizeof(u32) ];

	datalen = cryptlen + assoclen;
	complete = true;
	flags = rctx->flags;
	wptr = mtk_ring_curr_wptr_index(mtk);

	/* prepare saState */
	saState = &mtk->saState[wptr];
	saState_base = mtk->saState_base + wptr * sizeof(saState_t);
	memset(saState, 0x00, sizeof(saState_t));

	// refresh SA record
	saRecord_base = mtk_set_saRecord(mtk, ctx, flags, assoclen, digestsize);

	// update IV per request
	if (IS_CBC(flags) || IS_CTR(flags)) {
		if (!reqiv)
			memset(saState->stateIv, 0xFF, AES_BLOCK_SIZE);
		else
			memcpy(saState->stateIv, reqiv, AES_BLOCK_SIZE);
			memcpy(iv, reqiv, AES_BLOCK_SIZE);
	}
	if IS_HMAC(flags)
		memcpy(saState->stateIDigest, ctx->ipad, 32);

	err = mtk_is_sg_aligned(reqdst, datalen, AES_BLOCK_SIZE);
	if (!err) {
		rctx->sg_dst = reqdst;
		mtk_make_sg_cpy(rctx->sg_dst, &rctx->sg_dst, datalen);
		dst = rctx->sg_dst;
	} else {
		rctx->sg_dst = NULL;
		dst = reqdst;
	}
	
	err = mtk_is_sg_aligned(reqsrc, datalen, AES_BLOCK_SIZE);
	if (!err) {
		rctx->sg_src = reqsrc;
		mtk_make_sg_cpy(rctx->sg_src, &rctx->sg_src, datalen);
		src = rctx->sg_src;
	} else {
		rctx->sg_src = NULL;
		src = reqsrc;
	}

	if (IS_CTR(rctx->flags) && complete == true) {
		/* Compute data length. */
		blocks = DIV_ROUND_UP(datalen, AES_BLOCK_SIZE);
		ctr = be32_to_cpu(iv[3]);
		/* Check 32bit counter overflow. */
		start = ctr;
		end = start + blocks - 1;
		if (end < start) {
			offset = AES_BLOCK_SIZE * -start;
			/*
			 * Increment the counter manually to cope with the hardware
			 * counter overflow.
			 */
			if (offset < cryptlen) {
				memcpy(iv, reqiv, AES_BLOCK_SIZE);
				ctr |= 0xffffffff;
				iv[3] = cpu_to_be32(ctr);
				crypto_inc((u8 *)iv, AES_BLOCK_SIZE);
				complete = false;
			}
		}
	}

	if (unlikely(complete == false)) {
		src_ctr = src;
		dst_ctr = dst;
		err = mtk_scatter_combine(mtk, saRecord_base,
				saState_base, src, dst,
				offset, complete, (void *)base,
				&ctr_cdr, &ctr_rdr);
		/* Jump to offset. */
		src = scatterwalk_ffwd(rctx->ctr_src, src_ctr, offset);
		dst = ((src_ctr == dst_ctr) ? src :
		       scatterwalk_ffwd(rctx->ctr_dst, dst_ctr, offset));
		/* Set new State */
		wptr = mtk_ring_curr_wptr_index(mtk);
		saState = &mtk->saState[wptr];
		saState_base = mtk->saState_base +wptr * sizeof(saState_t);
		memcpy(saState->stateIv, iv, AES_BLOCK_SIZE);
		datalen -= offset;
		complete = true;
	}

	err = mtk_scatter_combine(mtk, saRecord_base, 
			saState_base, src, dst,
			datalen, complete, (void *)base,
			&ndesc_cdr, &ndesc_rdr);

	*commands = ndesc_cdr + ctr_cdr;
	*results = ndesc_rdr + ctr_rdr;

	return 0;
}

int mtk_skcipher_send(struct crypto_async_request *async,
			int *commands, int *results)
{
	struct skcipher_request *req = skcipher_request_cast(async);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	int err;

	err = mtk_send_req(async, ctx, req->src, req->dst, req->iv,
				req->cryptlen, 0, 0, rctx, commands, results);
	return err;
}

int mtk_aead_send(struct crypto_async_request *async,
			int *commands, int *results)
{
	struct aead_request *req = aead_request_cast(async);
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(req->base.tfm);
	struct crypto_aead *tfm = crypto_aead_reqtfm(req);
	struct mtk_cipher_reqctx *rctx = aead_request_ctx(req);
	int err, digestlen;

	digestlen = crypto_aead_authsize(tfm);

	err = mtk_send_req(async, ctx, req->src, req->dst, req->iv,
				req->cryptlen, req->assoclen, digestlen, rctx,
				commands, results);

	return err;
}

int mtk_req_result(struct mtk_device *mtk, struct mtk_cipher_reqctx *rctx,
		struct scatterlist *reqsrc, struct scatterlist *reqdst,
		unsigned int len, bool *should_complete, int *ret)
{
	struct eip93_descriptor_s *cdesc;
	struct eip93_descriptor_s *rdesc;
	struct mtk_dma_rec *rec;
	int ndesc= 0, rptr, nreq;

	*ret = 0;
	*should_complete = false;

	nreq = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10, 0);

	while (ndesc < nreq) {
		rptr =  mtk_ring_curr_rptr_index(mtk);
		rdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].rdr);
		if (IS_ERR(rdesc)) {
			dev_err(mtk->dev, "cipher: result: error!\n");
			*ret = PTR_ERR(rdesc);
			break;
		}

//		if (likely(!*ret))
			//*ret = mtk_rdesc_check_errors(mtk, rdesc);

			if (rdesc->peCrtlStat.bits.errStatus) {
				dev_err(mtk->dev, "Err: %02x \n",
					rdesc->peCrtlStat.bits.errStatus);
				*ret = -EINVAL;
			}

		cdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].cdr);

		rec = &mtk->ring[0].cdr_dma[rptr];

		dma_unmap_single(mtk->dev, (dma_addr_t)rdesc->srcAddr, rec->dmaLen,
				DMA_TO_DEVICE);

		dma_unmap_single(mtk->dev, (dma_addr_t)rdesc->dstAddr, rec->dmaLen,
				DMA_FROM_DEVICE);

		ndesc++;

		if (rec->flags & BIT(0)) {
				*should_complete = true;
				break;
		}			
	}

	if (*should_complete) {
		if (rctx->sg_dst) {
			dev_dbg(mtk->dev,
				"Copying %d bytes of output data back to original place\n",
				len);
			mtk_sg_copy_buf(sg_virt(rctx->sg_dst), reqdst, len, 1);
			mtk_free_sg_cpy(len, &rctx->sg_dst);
		}

		if (rctx->sg_src) {
			mtk_free_sg_cpy(len, &rctx->sg_src);
		}
	}

	return ndesc;
}

int mtk_skcipher_handle_result(struct mtk_device *mtk,
				struct crypto_async_request *async,
				bool *should_complete,  int *ret)
{
	struct skcipher_request *req = skcipher_request_cast(async);
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	int ndesc;

	ndesc = mtk_req_result(mtk, rctx, req->src, req->dst, req->cryptlen,
				should_complete, ret);

	return ndesc;
}

int mtk_aead_handle_result(struct mtk_device *mtk,
				struct crypto_async_request *async,
				bool *should_complete,  int *ret)
{
	struct aead_request *req = aead_request_cast(async);
	struct mtk_cipher_reqctx *rctx = aead_request_ctx(req);
	int ndesc;

	ndesc = mtk_req_result(mtk, rctx, req->src, req->dst,
			req->cryptlen + req->assoclen, should_complete, ret);

	return ndesc;
}

int mtk_queue_req(struct crypto_async_request *base,
			struct mtk_cipher_reqctx *rctx)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(base->tfm);
	struct mtk_device *mtk = ctx->mtk;
	int ret;

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
					   req->cryptlen, req->iv);
		if (IS_ENCRYPT(rctx->flags)) 
			ret = crypto_skcipher_encrypt(subreq);
		else
			ret = crypto_skcipher_decrypt(subreq);
		skcipher_request_zero(subreq);
		return ret;
	}
*/;

	spin_lock_bh(&mtk->ring[0].queue_lock);
	ret = crypto_enqueue_request(&mtk->ring[0].queue, base);
	spin_unlock_bh(&mtk->ring[0].queue_lock);

	queue_work(mtk->ring[0].workqueue, &mtk->ring[0].work_data.work);

	return -EBUSY;

	return ret;
}

int mtk_skcipher_encrypt(struct skcipher_request *req)
{
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_ENCRYPT;

	return mtk_queue_req(base, rctx);
}

int mtk_skcipher_decrypt(struct skcipher_request *req)
{
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_DECRYPT;

	return mtk_queue_req(base, rctx);
}

int mtk_skcipher_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.skcipher.base);

	memset(ctx, 0, sizeof(*ctx));

	crypto_skcipher_set_reqsize(__crypto_skcipher_cast(tfm),
				sizeof(struct mtk_cipher_reqctx));

	ctx->fallback = crypto_alloc_skcipher(crypto_tfm_alg_name(tfm), 0,
					      CRYPTO_ALG_ASYNC |
					      CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(ctx->fallback))
		return PTR_ERR(ctx->fallback);

	ctx->mtk = tmpl->mtk;
	ctx->base.send = mtk_skcipher_send;
	ctx->base.handle_result = mtk_skcipher_handle_result;

	return 0;
}

void mtk_skcipher_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	crypto_free_skcipher(ctx->fallback);
}

static int mtk_aead_cra_init(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);
	struct mtk_alg_template *tmpl = container_of(tfm->__crt_alg,
				struct mtk_alg_template, alg.aead.base);
	struct mtk_device *mtk = tmpl->mtk;
	unsigned long flags = tmpl->flags;
	char *alg_base;

	ctx->mtk = mtk;

	crypto_aead_set_reqsize(__crypto_aead_cast(tfm),
			sizeof(struct mtk_cipher_reqctx));

	ctx->aead = true;
	ctx->base.send = mtk_aead_send;
	ctx->base.handle_result = mtk_aead_handle_result;
	
	/* software workaround for now */
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

static void mtk_aead_cra_exit(struct crypto_tfm *tfm)
{
	struct mtk_cipher_ctx *ctx = crypto_tfm_ctx(tfm);

	// TODO
}

static int mtk_aead_encrypt(struct aead_request *req)
{
	struct mtk_cipher_reqctx *rctx = aead_request_ctx(req);
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.aead.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_ENCRYPT;

	return mtk_queue_req(base, rctx);
}

static int mtk_aead_decrypt(struct aead_request *req)
{
	struct mtk_cipher_reqctx *rctx = aead_request_ctx(req);	
	struct crypto_async_request *base = &req->base;
	struct mtk_alg_template *tmpl = container_of(base->tfm->__crt_alg,
				struct mtk_alg_template, alg.aead.base);

	rctx->flags = tmpl->flags;
	rctx->flags |= MTK_DECRYPT;

	return mtk_queue_req(base, rctx);
}


/* Available algorithms in this module */

struct mtk_alg_template mtk_alg_ecb_des = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_ECB | MTK_ALG_DES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize	= 0,
		.base = {
			.cra_name = "ecb(des)",
			.cra_driver_name = "eip93-ecb-des",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};
				
struct mtk_alg_template mtk_alg_cbc_des = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CBC | MTK_ALG_DES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = DES_KEY_SIZE,
		.max_keysize = DES_KEY_SIZE,
		.ivsize	= DES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des)",
			.cra_driver_name = "eip93-cbc-des",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_ecb_des3_ede = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_ECB | MTK_ALG_3DES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize	= 0,
		.base = {
			.cra_name = "ecb(des3_ede)",
			.cra_driver_name = "eip93-ecb-des3_ede",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_cbc_des3_ede = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CBC | MTK_ALG_3DES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = DES3_EDE_KEY_SIZE,
		.max_keysize = DES3_EDE_KEY_SIZE,
		.ivsize	= DES3_EDE_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(des3_ede)",
			.cra_driver_name = "eip93-cbc-des3_ede",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = DES3_EDE_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_ecb_aes = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_ECB | MTK_ALG_AES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize	= 0,
		.base = {
			.cra_name = "ecb(aes)",
			.cra_driver_name = "eip93-ecb-aes",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_cbc_aes = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CBC | MTK_ALG_AES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize	= AES_BLOCK_SIZE,
		.base = {
			.cra_name = "cbc(aes)",
			.cra_driver_name = "eip93-cbc-aes",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_ctr_aes = {
	.type = MTK_ALG_TYPE_SKCIPHER,
	.flags = MTK_MODE_CTR | MTK_ALG_AES,
	.alg.skcipher = {
		.setkey = mtk_skcipher_setkey,
		.encrypt = mtk_skcipher_encrypt,
		.decrypt = mtk_skcipher_decrypt,
		.min_keysize = AES_MIN_KEY_SIZE,
		.max_keysize = AES_MAX_KEY_SIZE,
		.ivsize	= AES_BLOCK_SIZE,
		.base = {
			.cra_name = "ctr(aes)",
			.cra_driver_name = "eip93-ctr-aes",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_skcipher_cra_init,
			.cra_exit = mtk_skcipher_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha1_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA1 | MTK_MODE_CBC | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.maxauthsize = SHA1_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha1),cbc(aes))",
			.cra_driver_name = "eip93-authenc-hmac-sha1-cbc-aes",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha224_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA224 | MTK_MODE_CBC | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.maxauthsize = SHA224_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha224),cbc(aes))",
			.cra_driver_name = "eip93-authenc-hmac-sha224-cbc-aes",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

struct mtk_alg_template mtk_alg_authenc_hmac_sha256_cbc_aes = {
	.type = MTK_ALG_TYPE_AEAD,
	.flags = MTK_HASH_HMAC | MTK_HASH_SHA256| MTK_MODE_CBC | MTK_ALG_AES,
	.alg.aead = {
		.setkey = mtk_aead_setkey,
		.encrypt = mtk_aead_encrypt,
		.decrypt = mtk_aead_decrypt,
		.ivsize	= AES_BLOCK_SIZE,
		.maxauthsize = SHA256_DIGEST_SIZE,
		.base = {
			.cra_name = "authenc(hmac(sha256),cbc(aes))",
			.cra_driver_name = "eip93-authenc-hmac-sha256-cbc-aes",
			.cra_priority = 300,
			.cra_flags = CRYPTO_ALG_ASYNC | CRYPTO_ALG_KERN_DRIVER_ONLY,
			.cra_blocksize = AES_BLOCK_SIZE,
			.cra_ctxsize = sizeof(struct mtk_cipher_ctx),
			.cra_alignmask = 0xf,
			.cra_init = mtk_aead_cra_init,
			.cra_exit = mtk_aead_cra_exit,
			.cra_module = THIS_MODULE,
		},
	},
};

