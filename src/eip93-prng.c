/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include "eip93-common.h"
#include "eip93-regs.h"
#include "eip93-prng.h"
#include "eip93-ring.h"


/*----------------------------------------------------------------------------
 * mtk_prng_activate
 *
 * This function initializes the PE PRNG for the ARM mode.
 *
 * Return Value
 *      true: PRNG is initialized
 *     false: PRNG initialization failed
 */
bool mtk_prng_activate(struct mtk_device *mtk, bool fLongSA)
{
	int i;
	struct eip93_descriptor_s *cdesc;
	struct eip93_descriptor_s *rdesc;
	unsigned int GetCount = 0;
	int LoopLimiter = 2500;
	saRecord_t *saRecord;
	dma_addr_t saPhyAddr;
	void *SrcBuffer;
	void *DstBuffer;
	dma_addr_t SrcPhyAddr, DstPhyAddr;
	const uint32_t PRNGKey[]  = {0xe0fc631d, 0xcbb9fb9a,
					0x869285cb, 0xcbb9fb9a,
					0, 0, 0, 0};
	const uint32_t PRNGSeed[]  = {0x758bac03, 0xf20ab39e,
					0xa569f104, 0x95dfaea6,
					0, 0, 0, 0};
	const uint32_t PRNGDateTime[] = {0, 0, 0, 0, 0, 0, 0, 0};

	if (!mtk)
		return -ENODEV;

	SrcBuffer = kzalloc(4080, GFP_KERNEL);
	DstBuffer = kzalloc(4080, GFP_KERNEL);
	SrcPhyAddr = (u32)dma_map_single(mtk->dev, (void *)SrcBuffer,
				4080, DMA_BIDIRECTIONAL);

	DstPhyAddr = (u32)dma_map_single(mtk->dev, (void *)DstBuffer,
				4080, DMA_BIDIRECTIONAL);

	saRecord = (saRecord_t *) dma_zalloc_coherent(mtk->dev,
				sizeof(saRecord_t), &saPhyAddr, GFP_KERNEL);
	if (unlikely(saRecord == NULL)) {
		dev_err(mtk->dev, "dma_alloc for saRecord_prepare failed\n");
		return -ENOMEM;
	}

	saRecord->saCmd0.word = 0x00001307;
	saRecord->saCmd1.word = 0x02000000;

	for (i = 0; i < 8; i++) {
		saRecord->saKey[i] = PRNGKey[i];
		saRecord->saIDigest[i] = PRNGSeed[i];
		saRecord->saODigest[i] = PRNGDateTime[i];
	}

	cdesc = mtk_ring_next_wptr(mtk, &mtk->ring[0].cdr);
	memset(cdesc, 0, sizeof(struct eip93_descriptor_s));
	rdesc = mtk_ring_next_wptr(mtk, &mtk->ring[0].rdr);
	cdesc->peCrtlStat.bits.prngMode = 1;
	cdesc->srcAddr = (u32)SrcPhyAddr;
	cdesc->dstAddr = (u32)DstPhyAddr;
	cdesc->saAddr = (u32)saPhyAddr;
	cdesc->peCrtlStat.bits.hostReady = 1;
	cdesc->peCrtlStat.bits.peReady = 0;
	cdesc->peLength.bits.hostReady = 1;
	cdesc->peLength.bits.peReady = 0;

	writel(1, mtk->base + EIP93_REG_PE_CD_COUNT);

	while (LoopLimiter > 0) {
		GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT)
				& GENMASK(10, 0);
		if (GetCount > 0)
			break;

		LoopLimiter--;
		cpu_relax();
	}

	if (LoopLimiter <= 0) {
		dev_err(mtk->dev, "PRNG no result descriptor\n");
		goto fail;
	}

	writel(1, mtk->base + EIP93_REG_PE_RD_COUNT);
	cdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].cdr);
	rdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].rdr);

	dma_free_coherent(mtk->dev, sizeof(saRecord_t), saRecord, saPhyAddr);
	dma_unmap_single(mtk->dev, SrcPhyAddr, 4080, DMA_TO_DEVICE);
	dma_unmap_single(mtk->dev, DstPhyAddr, 4080, DMA_FROM_DEVICE);
	kfree(SrcBuffer);
	kfree(DstBuffer);

	if (rdesc->peCrtlStat.bits.errStatus == 0) {
		dev_info(mtk->dev, "PRNG Initialized.\n");
		return true;
	}

fail:
	return false;
}
int mtk_prng_seed(struct crypto_rng *tfm, const u8 *seed,
		       unsigned int slen)
{
	struct rng_alg *alg = crypto_rng_alg(tfm);
	struct mtk_alg_template *tmpl = container_of(alg,
				struct mtk_alg_template, alg.rng);
	struct mtk_device *mtk = tmpl->mtk;

	/* TODO actually reseed PRNG, store seed for now */
	if (slen <= 32)
		memcpy(mtk->seed, seed, slen);

	return 0;
}

/*
 * PRNG Generate
 *
 * TODO: rewrite this to create CDR / IRQ return
 *       to use proper Queue Handling.
 */

int mtk_prng_generate(struct crypto_rng *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int dlen)
{
	struct rng_alg *alg = crypto_rng_alg(tfm);
	struct mtk_alg_template *tmpl = container_of(alg,
				struct mtk_alg_template, alg.rng);
	struct mtk_device *mtk = tmpl->mtk;
	eip93_descriptor_t *cdesc;
	eip93_descriptor_t *rdesc;
	int LoopLimiter = 2500;
	saRecord_t *saRecord;
	dma_addr_t saPhyAddr;
	u32 *SrcBuffer = (u32 *)src;
	u32 *DstBuffer = (u32 *)dst;
	dma_addr_t SrcPhyAddr, DstPhyAddr;
	int GetCount;

	if (!mtk)
		return -ENODEV;

	SrcPhyAddr = (u32)dma_map_single(mtk->dev, (void *)SrcBuffer, slen,
			DMA_BIDIRECTIONAL);

	DstPhyAddr = (u32)dma_map_single(mtk->dev, (void *)DstBuffer, dlen,
			DMA_BIDIRECTIONAL);

	saRecord = (saRecord_t *) dma_zalloc_coherent(NULL, sizeof(saRecord_t),
			&saPhyAddr, GFP_KERNEL);
	if (unlikely(saRecord == NULL)) {
		dev_err(mtk->dev, "PRNG: Alloc for saRecord_prepare failed!\n");
		return -ENOMEM;
	}

	saRecord->saCmd0.word = 0x00001307;
	saRecord->saCmd1.word = 0x02000000;

	cdesc = mtk_ring_next_wptr(mtk, &mtk->ring[0].cdr);

	cdesc->peCrtlStat.bits.prngMode = 2;
	cdesc->srcAddr = (u32)SrcPhyAddr;
	cdesc->dstAddr = (u32)DstPhyAddr;
	cdesc->saAddr = (u32)saPhyAddr;
	cdesc->peCrtlStat.bits.hostReady = 1;
	cdesc->peCrtlStat.bits.peReady = 0;
	cdesc->peLength.bits.length = dlen;
	cdesc->peLength.bits.hostReady = 1;
	cdesc->peLength.bits.peReady = 0;

	writel(1, mtk->base + EIP93_REG_PE_CD_COUNT);

	while (LoopLimiter > 0)	{
		GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT)
					& GENMASK(10 , 0);

		if (GetCount > 0)
			break;

		LoopLimiter--;
		cpu_relax();
	}

	if (LoopLimiter <= 0) {
		dev_err(mtk->dev, "PRNG: no result descriptor\n");
	goto fail;
	}

	rdesc = mtk_ring_next_rptr(mtk, &mtk->ring[0].rdr);

	if (rdesc->peCrtlStat.bits.errStatus > 0)
		goto fail;

	dma_free_coherent(mtk->dev, dlen, saRecord, saPhyAddr);
	dma_unmap_single(mtk->dev, SrcPhyAddr, dlen, DMA_TO_DEVICE);
	dma_unmap_single(mtk->dev, DstPhyAddr, dlen, DMA_FROM_DEVICE);

	return 0;

fail:
	return false;
}

struct mtk_alg_template mtk_alg_prng = {
	.type = MTK_ALG_TYPE_PRNG,
	.flags = 0,
	.alg.rng = {
		.generate = mtk_prng_generate,
		.seed = mtk_prng_seed,
		.seedsize = 0,
		.base = {
			.cra_name = "stdrng",
			.cra_driver_name = "eip93-prng",
			.cra_priority = 300,
			.cra_ctxsize = 0,
			.cra_module = THIS_MODULE,
		},
	},
};



