// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include "eip93-common.h"
#include "eip93-regs.h"
#include "eip93-prng.h"
#include "eip93-ring.h"

static LIST_HEAD(rng_algs);

/*----------------------------------------------------------------------------
 * mtk_prng_activate
 *
 * This function initializes the PE PRNG for the ARM mode.
 *
 * Return Value
 *      true: PRNG is initialized
 *     false: PRNG initialization failed
 */
bool mtk_prng_activate (struct mtk_device *mtk, bool fLongSA)
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
    const uint32_t PRNGKey[]      = {0xe0fc631d, 0xcbb9fb9a,
        0x869285cb, 0xcbb9fb9a,
        0, 0, 0, 0};
    const uint32_t PRNGSeed[]     = {0x758bac03, 0xf20ab39e,
        0xa569f104, 0x95dfaea6,
        0, 0, 0, 0};
    const uint32_t PRNGDateTime[] = {0, 0, 0, 0, 0, 0, 0, 0};
    
    if (!mtk)
        return -ENODEV;
    
    SrcBuffer = kzalloc(4080, GFP_KERNEL);
    DstBuffer = kzalloc(4080, GFP_KERNEL);
    
    SrcPhyAddr = (u32)dma_map_single(mtk->dev, (void *)SrcBuffer, 4080,
                                     DMA_BIDIRECTIONAL);
    
    DstPhyAddr = (u32)dma_map_single(mtk->dev, (void *)DstBuffer, 4080,
                                     DMA_BIDIRECTIONAL);
    
    // Create SA and State records
    saRecord = (saRecord_t *) dma_zalloc_coherent(mtk->dev,
						sizeof(saRecord_t), &saPhyAddr, GFP_KERNEL);
    if (unlikely(saRecord == NULL))
    {
        dev_err(mtk->dev, "!!dma_alloc for saRecord_prepare failed!! \n\n");
        return -ENOMEM;
    }
    
    // Fill in SA for PRNG Init
    saRecord->saCmd0.word = 0x00001307;   // SA word 0
    saRecord->saCmd1.word = 0x02000000;   // SA word 1
    
    for(i = 0; i < 8; i++) {
        saRecord->saKey[i]= PRNGKey[i];
        saRecord->saIDigest[i] = PRNGSeed[i];
        saRecord->saODigest[i] = PRNGDateTime[i];
    }
    
    // Fill in command descriptor
	cdesc = mtk_ring_next_wptr(mtk, &mtk->ring[0].cdr);
	memset(cdesc, 0, sizeof(struct eip93_descriptor_s));
	rdesc = mtk_ring_next_wptr(mtk, &mtk->ring[0].rdr);	
	cdesc->peCrtlStat.bits.prngMode = 1; // PRNG Init function
	cdesc->srcAddr = (u32)SrcPhyAddr;
	cdesc->dstAddr = (u32)DstPhyAddr;
	cdesc->saAddr = (u32)saPhyAddr;
	cdesc->peCrtlStat.bits.hostReady= 1;
	cdesc->peCrtlStat.bits.peReady= 0;
	cdesc->peLength.bits.hostReady= 1;
	cdesc->peLength.bits.peReady= 0;
    
    // now wait for the result descriptor
    writel(1, mtk->base + EIP93_REG_PE_CD_COUNT);

    // normally this will we get the result descriptors in no-time
    while(LoopLimiter > 0)
    {
        GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10, 0);
        
        if (GetCount > 0)
            break;
        
        LoopLimiter--;
        cpu_relax();
    }
    
    if (LoopLimiter <= 0) {
        printk("EIP93 PRNG could not retrieve a result descriptor\n");
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
		return true; // success
    }
    
fail:
    return false;
}
int mtk_prng_seed(struct crypto_rng *tfm, const u8 *seed,
		       unsigned int slen)
{
	struct mtk_alg_template *algt;
	struct rng_alg *alg = crypto_rng_alg(tfm);
	struct mtk_device *mtk;

	algt = container_of(alg, struct mtk_alg_template, alg.rng);
	mtk = algt->mtk;

	// TODO actually reseed PRNG, store seed for now
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
	struct mtk_alg_template *tmpl = to_prng_tmpl(tfm);
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

	if (!mtk) {
		return -ENODEV;
	}

	SrcPhyAddr = (u32)dma_map_single(mtk->dev, (void *)SrcBuffer, slen,
			DMA_BIDIRECTIONAL);

	DstPhyAddr = (u32)dma_map_single(mtk->dev, (void *)DstBuffer, dlen,
			DMA_BIDIRECTIONAL);

	// Create SA and State records
	saRecord = (saRecord_t *) dma_zalloc_coherent(NULL, sizeof(saRecord_t),
			&saPhyAddr, GFP_KERNEL);
	if (unlikely(saRecord == NULL))
	{
		dev_err(mtk->dev, "PRNG: Alloc for saRecord_prepare failed!\n");
		return -ENOMEM;
	}

	// Fill in SA for PRNG Init
	saRecord->saCmd0.word = 0x00001307;   // SA word 0
	saRecord->saCmd1.word = 0x02000000;   // SA word 1

	// Fill in command descriptor
	cdesc = mtk_ring_next_wptr(mtk, &mtk->ring[0].cdr);

	cdesc->peCrtlStat.bits.prngMode = 2; // for now disregard src
	cdesc->srcAddr = (u32)SrcPhyAddr;
	cdesc->dstAddr = (u32)DstPhyAddr;
	cdesc->saAddr = (u32)saPhyAddr;
	cdesc->peCrtlStat.bits.hostReady= 1;
	cdesc->peCrtlStat.bits.peReady= 0;
	cdesc->peLength.bits.length = dlen; //requested bytes
	cdesc->peLength.bits.hostReady= 1;
	cdesc->peLength.bits.peReady= 0;

	// now wait for the result descriptor
	writel(1, mtk->base + EIP93_REG_PE_CD_COUNT);
	// normally this will we get the result descriptors in no-time
	while(LoopLimiter > 0)
	{
	GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10 , 0);

        if (GetCount > 0)
            break;

        LoopLimiter--;
	cpu_relax();
	}

	if (LoopLimiter <= 0) {
		printk("PRNG: couldn't retrieve result descriptor\n");
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

static void mtk_prng_unregister(struct mtk_device *mtk)
{
	struct mtk_alg_template *tmpl, *n;

	list_for_each_entry_safe(tmpl, n, &rng_algs, entry) {
		crypto_unregister_rng(&tmpl->alg.rng);
		list_del(&tmpl->entry);
		kfree(tmpl);
	}
}

static int mtk_prng_register(struct mtk_device *mtk)
{
	struct mtk_alg_template *tmpl;
	struct rng_alg *alg;
	int ret;

	// Initilaize the PRNG in AUTO Mode
	ret = mtk_prng_activate(mtk, true);

	if (!ret) {
		printk("PRNG not activated\n");
		return 0;
	}

	tmpl = kzalloc(sizeof(*tmpl), GFP_KERNEL);
	if (!tmpl)
		return -ENOMEM;

	alg = &tmpl->alg.rng;

	alg->generate			= mtk_prng_generate;
	alg->seed				= mtk_prng_seed;
	alg->seedsize			= 0;

	snprintf(alg->base.cra_name, CRYPTO_MAX_ALG_NAME, "%s", "stdrng");
	snprintf(alg->base.cra_driver_name, CRYPTO_MAX_ALG_NAME, "%s",
		 "eip93-prng");

	alg->base.cra_priority		= 300;
	alg->base.cra_ctxsize		= 0; //sizeof(struct mtk_prng_ctx);
	alg->base.cra_module		= THIS_MODULE;
//	alg->base.cra_init		= mtk_prng_kcapi_init;


	INIT_LIST_HEAD(&tmpl->entry);
	tmpl->crypto_alg_type = CRYPTO_ALG_TYPE_RNG;
	tmpl->alg_flags = 0; // TODO
	tmpl->mtk = mtk;

	ret = crypto_register_rng(alg);

	if (ret) {
		kfree(tmpl);
		dev_err(mtk->dev, "%s registration failed\n", alg->base.cra_name);
		return ret;
	}

	list_add_tail(&tmpl->entry, &rng_algs);
	dev_dbg(mtk->dev, "%s is registered\n", alg->base.cra_name);
	return 0;
}

const struct mtk_algo_ops prng_ops = {
	.type = CRYPTO_ALG_TYPE_RNG,
	.register_algs = mtk_prng_register,
	.unregister_algs = mtk_prng_unregister,
};


