#include "common-eip93.h"
#include "regs-eip93.h"




/*
{
	.type = CRYPTO_ALG_TYPE_RNG,
	.alg.rng = {
		.base = {
			.cra_name		= "stdrng",
			.cra_driver_name	= "mtk-eip93_prng",
			.cra_priority		= 300,
			.cra_ctxsize		= 0,
			.cra_module		= THIS_MODULE,
		},
		.generate               = mtk_prng_generate,
		.seed                   = mtk_prng_seed,
		.seedsize               = 0, //MTK_SEED_LEN / BITS_PER_BYTE,
	}
},
*/



int mtk_prng_seed(struct crypto_rng *tfm, const u8 *seed,
		       unsigned int slen)
{
	struct mtk_alg_template *algt;
	struct rng_alg *alg = crypto_rng_alg(tfm);
	struct mtk_device *mtk;

	algt = container_of(alg, struct mtk_alg_template, alg.rng);
	mtk = algt->mtk;

	if (slen <= 32)
		memcpy(mtk->seed, seed, slen);

	return 0;
}

int mtk_prng_generate(struct crypto_rng *tfm, const u8 *src,
			   unsigned int slen, u8 *dst, unsigned int dlen)
{
	struct mtk_alg_template *algt;
	struct rng_alg *alg = crypto_rng_alg(tfm);
	int GetCount, ctr;
	struct mtk_device *mtk;
	eip93DescpHandler_t *EIP93_CmdDscr;
	eip93DescpHandler_t *EIP93_ResDscr;
	int LoopLimiter = 2500;
	saRecord_t *saRecord;
	dma_addr_t saPhyAddr;
	u32 *SrcBuffer = (u32 *)src;
	u32 *DstBuffer = (u32 *)dst;
	dma_addr_t SrcPhyAddr, DstPhyAddr;

	algt = container_of(alg, struct mtk_alg_template, alg.rng);
	mtk = algt->mtk;

	if (!mtk) {
		printk("No MTK?\n");
		return -ENODEV;
	}
	printk("MTK-EIP93: Generate PRNG\n");

	ctr = (mtk->rec_rear_idx + 1) % MTK_RING_SIZE;

	SrcPhyAddr = (u32)dma_map_single(mtk->dev, (void *)SrcBuffer, dlen,
			DMA_BIDIRECTIONAL);

	DstPhyAddr = (u32)dma_map_single(mtk->dev, (void *)DstBuffer, dlen,
			DMA_BIDIRECTIONAL);

	// Create SA and State records
	saRecord = (saRecord_t *) dma_zalloc_coherent(NULL, sizeof(saRecord_t), &saPhyAddr, GFP_KERNEL);
	if (unlikely(saRecord == NULL))
	{
		printk("\n\n !!dma_alloc for saRecord_prepare failed!! \n\n");
		//errVal = -ENOMEM;
//		goto free_cmdHandler;
	}

	// Fill in SA for PRNG Init
	saRecord->saCmd0.word = 0x00001307;   // SA word 0
	saRecord->saCmd1.word = 0x02000000;   // SA word 1

	// Fill in command descriptor
	EIP93_CmdDscr = &mtk->cd[ctr];

	EIP93_CmdDscr->peCrtlStat.bits.prngMode = 2;
	EIP93_CmdDscr->srcAddr = (u32)SrcPhyAddr;
	EIP93_CmdDscr->dstAddr = (u32)DstPhyAddr;
	EIP93_CmdDscr->saAddr = (u32)saPhyAddr;
	EIP93_CmdDscr->peCrtlStat.bits.hostReady= 1;
	EIP93_CmdDscr->peCrtlStat.bits.peReady= 0;
	EIP93_CmdDscr->peLength.bits.length = dlen;
	EIP93_CmdDscr->peLength.bits.hostReady= 1;
	EIP93_CmdDscr->peLength.bits.peReady= 0;

	// now wait for the result descriptor
	writel(1, mtk->base + EIP93_REG_PE_CD_COUNT);
	// normally this will we get the result descriptors in no-time
	while(LoopLimiter > 0)
	{
	GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & (BIT_10 - 1);

        if (GetCount > 0)
            break;

        LoopLimiter--;
	cpu_relax();
	}

	mtk->rec_rear_idx = (mtk->rec_rear_idx + 1) % MTK_RING_SIZE;
	mtk->rec_front_idx = (mtk->rec_front_idx + 1) % MTK_RING_SIZE;

	if (LoopLimiter <= 0) {
		printk("EIP93_ARM_PacketGet could not retrieve a result descriptor\n");
	goto fail;
	}

	EIP93_ResDscr = &mtk->rd[ctr];

	if (EIP93_ResDscr->peCrtlStat.bits.errStatus > 0)
		goto fail;

	dma_free_coherent(mtk->dev, dlen, saRecord, saPhyAddr);
	dma_unmap_single(mtk->dev, SrcPhyAddr, dlen,
			DMA_TO_DEVICE);
	dma_unmap_single(mtk->dev, DstPhyAddr, dlen,
			DMA_FROM_DEVICE);

	return 0;

fail:
	return false;
}

