/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#define DEBUG 1

#include <crypto/aead.h>
#include <crypto/aes.h>
#include <crypto/authenc.h>
#include <crypto/ctr.h>
#include <crypto/hmac.h>
#include <crypto/md5.h>
#include <crypto/null.h>
#include <crypto/scatterwalk.h>
#include <crypto/sha.h>

#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/moduleparam.h>
#include <linux/scatterlist.h>
#include <linux/types.h>

#ifdef CONFIG_EIP93_AES
#include "eip93-aes.h"
#endif
#ifdef CONFIG_EIP93_DES
#include "eip93-des.h"
#endif
#ifdef CONFIG_EIP93_AEAD
#include "eip93-aead.h"
#endif
#include "eip93-common.h"
#include "eip93-main.h"
#include "eip93-cipher.h"
#include "eip93-regs.h"
#include "eip93-ring.h"

static inline void mtk_free_sg_cpy(const int len, struct scatterlist **sg)
{
	if (!*sg || !len)
		return;

	free_pages((unsigned long)sg_virt(*sg), get_order(len));
	kfree(*sg);
	*sg = NULL;
}

static inline int mtk_make_sg_cpy(struct mtk_device *mtk, struct scatterlist *src,
		struct scatterlist **dst, const int len,
		struct mtk_cipher_reqctx *rctx, const bool copy)
{
	void *pages;
	int totallen;

	*dst = kmalloc(sizeof(**dst), GFP_KERNEL);
	if (!*dst) {
		printk("NO MEM\n");
		return -ENOMEM;
	}
	/* allocate enough memory for full scatterlist */
	totallen = rctx->assoclen + rctx->textsize + rctx->authsize;

	pages = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA,
					get_order(totallen));

	if (!pages) {
		kfree(*dst);
		*dst = NULL;
		printk("no free pages\n");
		return -ENOMEM;
	}

	sg_init_table(*dst, 1);
	sg_set_buf(*dst, pages, totallen);

	/* copy only as requested */
	if (copy)
		sg_copy_to_buffer(src, sg_nents(src), pages, len);

	return 0;
}

static inline bool mtk_is_sg_aligned(struct scatterlist *sg, u32 len, const int blksz)
{
	int nents;

	for (nents = 0; sg; sg = sg_next(sg), ++nents) {
		/* When destination buffers are not aligned to the cache line
		 * size we need bounce buffers. The DMA-API requires that the
		 * entire line is owned by the DMA buffer.
		 */
		if (!IS_ALIGNED(sg->offset, 4))
			return false;

		/* segments need to be blocksize aligned */
		if (len <= sg->length) {
			if (!IS_ALIGNED(len, blksz))
				return false;

			return true;
		}

		if (!IS_ALIGNED(sg->length, blksz))
			return false;

		len -= sg->length;
	}
	return false;
}

void mtk_ctx_saRecord(struct mtk_cipher_ctx *ctx, const u8 *key,
				const u32 nonce, const unsigned int keylen,
				const unsigned long flags)
{
	struct saRecord_s *saRecord;

	saRecord = ctx->sa;

	saRecord->saCmd0.bits.ivSource = 2;
	saRecord->saCmd0.bits.saveIv = 1;
	saRecord->saCmd0.bits.opGroup = 0;
	saRecord->saCmd0.bits.opCode = 0;

	switch ((flags & MTK_ALG_MASK)) {
	case MTK_ALG_AES:
		saRecord->saCmd0.bits.cipher = 3;
		saRecord->saCmd1.bits.aesKeyLen = (keylen / 8);
		break;
	case MTK_ALG_3DES:
		saRecord->saCmd0.bits.cipher = 1;
		break;
	case MTK_ALG_DES:
		saRecord->saCmd0.bits.cipher = 0;
		break;
	default:
		saRecord->saCmd0.bits.cipher = 15;
	}

	switch ((flags & MTK_HASH_MASK)) {
	case MTK_HASH_SHA256:
		saRecord->saCmd0.bits.hash = 3;
		break;
	case MTK_HASH_SHA224:
		saRecord->saCmd0.bits.hash = 2;
		break;
	case MTK_HASH_SHA1:
		saRecord->saCmd0.bits.hash = 1;
		break;
	case MTK_HASH_MD5:
		saRecord->saCmd0.bits.hash = 0;
		break;
	default:
		saRecord->saCmd0.bits.hash = 15;
	}

	saRecord->saCmd0.bits.hdrProc = 0;
	saRecord->saCmd0.bits.padType = 3;
	saRecord->saCmd0.bits.extPad = 0;
	saRecord->saCmd0.bits.scPad = 0;

	switch ((flags & MTK_MODE_MASK)) {
	case MTK_MODE_CBC:
		saRecord->saCmd1.bits.cipherMode = 1;
		break;
	case MTK_MODE_CTR:
		saRecord->saCmd1.bits.cipherMode = 2;
		break;
	case MTK_MODE_ECB:
		saRecord->saCmd1.bits.cipherMode = 0;
		break;
	}

	saRecord->saCmd1.bits.byteOffset = 0;
	saRecord->saCmd1.bits.hashCryptOffset = 0;
	saRecord->saCmd0.bits.digestLength = 0;
	saRecord->saCmd1.bits.copyPayload = 0;

	if (IS_HMAC(flags)) {
		saRecord->saCmd1.bits.hmac = 1;
		saRecord->saCmd1.bits.copyDigest = 1;
		saRecord->saCmd1.bits.copyHeader = 1;
	} else {
		saRecord->saCmd1.bits.hmac = 0;
		saRecord->saCmd1.bits.copyDigest = 0;
		saRecord->saCmd1.bits.copyHeader = 0;
	}

	memcpy(saRecord->saKey, key, keylen);

	if (IS_RFC3686(flags))
		saRecord->saNonce = nonce;

	/* Default for now, might be used for ESP offload */
	saRecord->saCmd1.bits.seqNumCheck = 0;
	saRecord->saSpi = 0x0;
	saRecord->saSeqNumMask[0] = 0x0;
	saRecord->saSeqNumMask[1] = 0x0;
}

/*
 * Poor mans Scatter/gather function:
 * Create a Descriptor for every segment to avoid copying buffers.
 * For performance better to wait for hardware to perform multiple DMA
 *
 */
inline int mtk_scatter_combine(struct mtk_device *mtk,
 			struct mtk_cipher_reqctx *rctx,
			struct scatterlist *sgsrc, struct scatterlist *sgdst,
			u32 datalen,  bool complete, unsigned int *areq,
			int offsetin)
{
	dma_addr_t saRecord_base = rctx->saRecord_base;
	dma_addr_t saState_base;
	unsigned int remainin, remainout;
	int offsetout = 0;
	u32 n, len;
	dma_addr_t saddr, daddr;
	u32 srcAddr, dstAddr;
	bool nextin = false;
	bool nextout = false;
	struct eip93_descriptor_s cdesc;
	int ndesc_cdr = 0, err;

	if (complete)
		saState_base = rctx->saState_base;
	else
		saState_base = rctx->saState_base_ctr;

	cdesc.peCrtlStat.word = 0;
	cdesc.peCrtlStat.bits.hostReady = 1;
	cdesc.peCrtlStat.bits.prngMode = 0;
	cdesc.peCrtlStat.bits.hashFinal = 1;
	cdesc.peCrtlStat.bits.padCrtlStat = 0;
	cdesc.peCrtlStat.bits.peReady = 0;
	cdesc.saAddr = saRecord_base;
	cdesc.stateAddr = saState_base;
	cdesc.arc4Addr = (u32)areq;
	if (IS_HMAC(rctx->flags))
		cdesc.userId = MTK_DESC_AEAD;
	else
		cdesc.userId = MTK_DESC_SKCIPHER;
	cdesc.peLength.word = 0;
	cdesc.peLength.bits.byPass = 0;
	cdesc.peLength.bits.hostReady = 1;

	n = datalen;
	remainin = min(sg_dma_len(sgsrc), n);
	remainout = min(sg_dma_len(sgdst), n);
	saddr = sg_dma_address(sgsrc);
	daddr = sg_dma_address(sgdst);

	do {
		if (nextin) {
			sgsrc = sg_next(sgsrc);
			remainin = min(sg_dma_len(sgsrc), n);
			if (remainin == 0)
				continue;

			saddr = sg_dma_address(sgsrc);
			offsetin = 0;
			nextin = false;
		}

		if (nextout) {
			sgdst = sg_next(sgdst);
			remainout = min(sg_dma_len(sgdst), n);
			if (remainout == 0)
				continue;

			daddr = sg_dma_address(sgdst);
			offsetout = 0;
			nextout = false;
		}
		srcAddr = saddr + offsetin;
		dstAddr = daddr + offsetout;

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

		cdesc.srcAddr = srcAddr;
		cdesc.dstAddr = dstAddr;
		cdesc.peLength.bits.length = len;

		if (n == 0)
			if (complete == true) {
				cdesc.userId |= MTK_DESC_LAST;
				cdesc.userId |= MTK_DESC_FINISH;
				}

		err = mtk_put_descriptor(mtk, cdesc);
		if (err)
			dev_err(mtk->dev, "No empty Descriptor space");

		ndesc_cdr++;
	} while (n);

	return ndesc_cdr;
}

int mtk_send_req(struct crypto_async_request *base,
			const struct mtk_cipher_ctx *ctx,
			struct scatterlist *reqsrc, struct scatterlist *reqdst,
			const u8 *reqiv, struct mtk_cipher_reqctx *rctx)
{
	struct mtk_device *mtk = ctx->mtk;
	int ndesc_cdr = 0, ctr_cdr = 0;
	int offset = 0, err;
	int src_nents, dst_nents;
	u32 aad = rctx->assoclen;
	u32 textsize = rctx->textsize;
	u32 authsize = rctx->authsize;
	u32 datalen = aad + textsize;
	u32 totlen_src = datalen;
	u32 totlen_dst = datalen;
	struct scatterlist *src, *src_ctr;
	struct scatterlist *dst, *dst_ctr;
	struct saRecord_s *saRecord;
	struct saState_s *saState;
	u32 start, end, ctr, blocks;
	unsigned long flags = rctx->flags;
	bool overflow;
	bool complete = true;
	bool src_align = true, dst_align = true;
	u32 iv[AES_BLOCK_SIZE / sizeof(u32)], *esph;
	int blksize = 1, offsetin = 0;

	switch ((flags & MTK_ALG_MASK))	{
	case MTK_ALG_AES:
		blksize = AES_BLOCK_SIZE;
		break;
	case MTK_ALG_DES:
		blksize = DES_BLOCK_SIZE;
		break;
	case MTK_ALG_3DES:
		blksize = DES3_EDE_BLOCK_SIZE;
		break;
	}

	if (!IS_CTR(rctx->flags)) {
		if (IS_GENIV(rctx->flags))
			textsize -= rctx->ivsize;
		if (!IS_ALIGNED(textsize, blksize))
			return -EINVAL;
	}

	rctx->sg_src = reqsrc;
	src = reqsrc;
	rctx->sg_dst = reqdst;
	dst = reqdst;

	if (ctx->aead) {
		if (IS_ENCRYPT(flags))
			totlen_dst += authsize;
		else
			totlen_src += authsize;
	}

	src_nents = sg_nents_for_len(src, totlen_src);
	dst_nents = sg_nents_for_len(dst, totlen_dst);

	if (src == dst) {
		src_nents = max(src_nents, dst_nents);
		dst_nents = src_nents;
		if (unlikely((totlen_src || totlen_dst) &&
		    (src_nents <= 0))) {
			dev_err(mtk->dev, "In-place buffer not large enough (need %d bytes)!",
				max(totlen_src, totlen_dst));
			return -EINVAL;
		}
	} else {
		if (unlikely(totlen_src && (src_nents <= 0))) {
			dev_err(mtk->dev, "Source buffer not large enough (need %d bytes)!",
				totlen_src);
			return -EINVAL;
		}

		if (unlikely(totlen_dst && (dst_nents <= 0))) {
			dev_err(mtk->dev, "Dest buffer not large enough (need %d bytes)!",
				totlen_dst);
			return -EINVAL;
		}
	}

	if (ctx->aead) {
		if (dst_nents == 1 && src_nents == 1) {
			src_align = mtk_is_sg_aligned(src, totlen_src, blksize);
			if (src ==  dst)
				dst_align = src_align;
			else
				dst_align = mtk_is_sg_aligned(reqdst,
							totlen_dst, blksize);
		} else {
			src_align = false;
			dst_align = false;
		}
	} else {
		src_align = mtk_is_sg_aligned(src, totlen_src, blksize);
		if (src == dst)
			dst_align = src_align;
		else
			dst_align = mtk_is_sg_aligned(reqdst, totlen_dst,
								blksize);
	}

	if (!src_align) {
		err = mtk_make_sg_cpy(mtk, rctx->sg_src, &rctx->sg_src,
					totlen_src, rctx, true);
		if (err)
			return err;
		src = rctx->sg_src;
	}

	if (!dst_align) {
		err = mtk_make_sg_cpy(mtk, rctx->sg_dst, &rctx->sg_dst,
					totlen_dst, rctx, false);
		if (err)
			return err;

		dst = rctx->sg_dst;
	}

	rctx->saState_ctr = NULL;
	rctx->saState = NULL;

	if ((IS_ECB(flags)) || (IS_GENIV(flags))) {
		rctx->iv_dma = false;
		rctx->saState_base = NULL;
		goto skip_iv;
	}

	/* make sure IV is DMA-able */
	if (!IS_ALIGNED((u32)reqiv, 16))
			rctx->iv_dma = false;
	memcpy(iv, reqiv, rctx->ivsize);

	overflow = (IS_CTR(rctx->flags) && (!IS_RFC3686(rctx->flags)));

	if (overflow) {
		/* Compute data length. */
		blocks = DIV_ROUND_UP(totlen_src, AES_BLOCK_SIZE);
		ctr = be32_to_cpu(iv[3]);
		/* Check 32bit counter overflow. */
		start = ctr;
		end = start + blocks - 1;
		if (end < start) {
			offset = AES_BLOCK_SIZE * -start;
			/*
			 * Increment the counter manually to cope with
			 * the hardware counter overflow.
			 */
			iv[3] = 0xffffffff;
			crypto_inc((u8 *)iv, AES_BLOCK_SIZE);
			complete = false;
			rctx->saState_ctr = dma_pool_zalloc(mtk->saState_pool,
				GFP_KERNEL, &rctx->saState_base_ctr);
			if (!rctx->saState_ctr)
				dev_err(mtk->dev, "No State_ctr DMA memory\n");

			memcpy(rctx->saState_ctr->stateIv, reqiv, rctx->ivsize);
		}
	}

	if (rctx->iv_dma) {
		rctx->saState = (void *)reqiv;
	} else {
		rctx->saState = dma_pool_zalloc(mtk->saState_pool,
					GFP_KERNEL, &rctx->saState_base);
		if (!rctx->saState)
			dev_err(mtk->dev, "No saState DMA memory\n");
	}

	saState = rctx->saState;

	if (rctx->saState_ctr)
		memcpy(saState->stateIv, iv, rctx->ivsize);

	if (IS_RFC3686(flags)) {
		saState->stateIv[0] = ctx->sa->saNonce;
		saState->stateIv[1] = iv[0];
		saState->stateIv[2] = iv[1];
		saState->stateIv[3] = cpu_to_be32(1);
	}

	if (rctx->iv_dma)
		rctx->saState_base = dma_map_single(mtk->dev, (void *)reqiv,
						rctx->ivsize,	DMA_TO_DEVICE);
	else if (IS_CBC(flags) || overflow)
			memcpy(saState->stateIv, iv, rctx->ivsize);

skip_iv:
	rctx->saRecord = dma_pool_zalloc(mtk->saRecord_pool, GFP_KERNEL,
					&rctx->saRecord_base);
	if (!rctx->saRecord)
		dev_err(mtk->dev, "No saRecord DMA memory\n");

	saRecord = rctx->saRecord;

	memcpy(saRecord, ctx->sa, sizeof(struct saRecord_s));

	if (IS_DECRYPT(flags))
		saRecord->saCmd0.bits.direction = 1;

	if ((IS_ECB(flags)) || (IS_GENIV(flags)))
		saRecord->saCmd0.bits.saveIv = 0;

	if (IS_HMAC(flags)) {
		saRecord->saCmd1.bits.byteOffset = 0;
		saRecord->saCmd1.bits.hashCryptOffset = (aad / 4);
		saRecord->saCmd0.bits.digestLength = (authsize / 4);
	}

	if (ctx->aead) {
		saRecord->saCmd0.bits.opCode = 1;
		if (IS_DECRYPT(flags))
			saRecord->saCmd1.bits.copyDigest = 0;
	}

	if (IS_GENIV(flags)) {
		saRecord->saCmd0.bits.opGroup = 1;
		saRecord->saCmd0.bits.opCode = 0;
		saRecord->saCmd1.bits.seqNumCheck = 1;

		if (IS_ENCRYPT(flags)) {
			datalen = rctx->textsize - rctx->ivsize;
			/* seems EIP93 needs to process the header itself
			 * So get the spi and sequence number from orginal
			 * header for now
			 */
			esph = sg_virt(rctx->sg_src);
			saRecord->saSpi = ntohl(esph[0]);
			saRecord->saSeqNum[0] = ntohl(esph[1]) - 1;
			offsetin = rctx->assoclen + rctx->ivsize;
			saRecord->saCmd1.bits.copyHeader = 0;
			saRecord->saCmd1.bits.copyDigest = 0;
			saRecord->saCmd0.bits.hdrProc = 1;
			saRecord->saCmd0.bits.ivSource = 3;
		} else {
			esph = sg_virt(rctx->sg_src);
			saRecord->saSpi = ntohl(esph[0]);
			saRecord->saSeqNum[0] = ntohl(esph[1]);
			saRecord->saCmd1.bits.copyHeader = 1;
			saRecord->saCmd1.bits.copyDigest = 0;
			saRecord->saCmd0.bits.hdrProc = 1;
			saRecord->saCmd0.bits.ivSource = 1;
			datalen += rctx->authsize;
		}
	}

	/* map DMA_BIDIRECTIONAL to invalidate cache on destination
	 * implies __dma_cache_wback_inv
	 */
	dma_map_sg(mtk->dev, dst, sg_nents(dst), DMA_BIDIRECTIONAL);
	if (src != dst)
		dma_map_sg(mtk->dev, src, sg_nents(src), DMA_TO_DEVICE);


	if (unlikely(complete == false)) {
		src_ctr = src;
		dst_ctr = dst;
		/* process until offset of the counter overflow */
		ctr_cdr = mtk_scatter_combine(mtk, rctx, src, dst, offset,
						complete, (void *)base, 0);
		/* Jump to offset. */
		src = scatterwalk_ffwd(rctx->ctr_src, src_ctr, offset);
		dst = ((src_ctr == dst_ctr) ? src :
			scatterwalk_ffwd(rctx->ctr_dst, dst_ctr, offset));

		datalen -= offset;
		complete = true;
		/* map DMA_BIDIRECTIONAL to invalidate cache on destination */
		dma_map_sg(mtk->dev, dst, sg_nents(dst), DMA_BIDIRECTIONAL);
		if (src != dst)
			dma_map_sg(mtk->dev, src, sg_nents(src), DMA_TO_DEVICE);
	}

	ndesc_cdr = mtk_scatter_combine(mtk, rctx, src, dst, datalen, complete,
			(void *)base, offsetin);

	return ndesc_cdr + ctr_cdr;
}

static void mtk_unmap_dma(struct mtk_device *mtk, struct mtk_cipher_reqctx *rctx,
			struct scatterlist *reqsrc, struct scatterlist *reqdst)
{
	u32 len = rctx->assoclen + rctx->textsize;
	u32 authsize = rctx->authsize;
	u32 flags = rctx->flags;
	u32 *otag;
	int i;

	if (rctx->sg_src == rctx->sg_dst) {
		dma_unmap_sg(mtk->dev, rctx->sg_dst, sg_nents(rctx->sg_dst),
							DMA_FROM_DEVICE);
		goto process_tag;
	}

	dma_unmap_sg(mtk->dev, rctx->sg_src, sg_nents(rctx->sg_src),
							DMA_TO_DEVICE);

	if (rctx->sg_src != reqsrc)
		mtk_free_sg_cpy(len +  rctx->authsize, &rctx->sg_src);

	dma_unmap_sg(mtk->dev, rctx->sg_dst, sg_nents(rctx->sg_dst),
							DMA_FROM_DEVICE);

	/* SHA tags need conversion from net-to-host */
process_tag:
	if (IS_DECRYPT(flags))
		authsize = 0;

	if (authsize && (!IS_GENIV(flags))) {
		if (!IS_HASH_MD5(flags)) {
			otag = sg_virt(rctx->sg_dst) + len;
			for (i = 0; i < (authsize / 4); i++)
			otag[i] = ntohl(otag[i]);
		}
	}

	if (rctx->sg_dst != reqdst) {
		sg_copy_from_buffer(reqdst, sg_nents(reqdst),
				sg_virt(rctx->sg_dst), len + authsize);
		mtk_free_sg_cpy(len + rctx->authsize, &rctx->sg_dst);
	}
}

void mtk_handle_result(struct mtk_device *mtk,
	struct crypto_async_request *async, struct mtk_cipher_reqctx *rctx,
	struct scatterlist *reqsrc, struct scatterlist *reqdst,	u8 *reqiv,
	bool complete, int err)
{
	mtk_unmap_dma(mtk, rctx, reqsrc, reqdst);

	if (IS_BUSY(rctx->flags)) {
		local_bh_disable();
		async->complete(async, -EINPROGRESS);
		local_bh_enable();
	}

	if (!complete)
		return;

	if (rctx->iv_dma) {
		dma_unmap_single(mtk->dev, rctx->saState_base, rctx->ivsize,
						DMA_BIDIRECTIONAL);
	} else {
		if ((!IS_ECB(rctx->flags)) || (!IS_GENIV(rctx->flags)))  {
			memcpy(reqiv, rctx->saState->stateIv, rctx->ivsize);
			if (rctx->saState)
				dma_pool_free(mtk->saState_pool, rctx->saState,
							rctx->saState_base);
		}
	}

	if (rctx->saState_ctr)
		dma_pool_free(mtk->saState_pool, rctx->saState_ctr,
						rctx->saState_base_ctr);

	dma_pool_free(mtk->saRecord_pool, rctx->saRecord, rctx->saRecord_base);

	local_bh_disable();
	async->complete(async, err);
	local_bh_enable();
}
#ifdef CONFIG_EIP93_SKCIPHER
void mtk_skcipher_handle_result(struct mtk_device *mtk,
				struct crypto_async_request *async,
				bool complete, int err)
{
	struct skcipher_request *req = skcipher_request_cast(async);
	struct mtk_cipher_reqctx *rctx = skcipher_request_ctx(req);

	mtk_handle_result(mtk, async, rctx, req->src, req->dst, req->iv,
				complete, err);
}
#endif
