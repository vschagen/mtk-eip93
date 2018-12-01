/*
 * Copyright (c) 2018, Richard van Schagen. All rights reserved.
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

#include <crypto/algapi.h>
#include <crypto/internal/hash.h>
#include <crypto/sha.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "common-eip93.h"
#include "core-eip93.h"
#include "regs-eip93.h"
#include "eip93-prng.h"
#include "eip93-cipher.h"

#include "eip93-hash.h"

static const struct mtk_algo_ops *mtk_ops[] = {
	&ablkcipher_ops,
//	&ahash_ops,
};

static void mtk_unregister_algs(struct mtk_device *mtk)
{
	const struct mtk_algo_ops *ops;
	u32 i;

	for (i = 0; i < ARRAY_SIZE(mtk_ops); i++) {
		ops = mtk_ops[i];
		ops->unregister_algs(mtk);
	}
}

static int mtk_register_algs(struct mtk_device *mtk)
{
	const struct mtk_algo_ops *ops;
	uint32_t i, ret = -ENODEV;

	for (i = 0; i < ARRAY_SIZE(mtk_ops); i++) {
		ops = mtk_ops[i];
		ret = ops->register_algs(mtk);
		if (ret)
			break;
	}

	return ret;
}

// get one request from finished queue

static inline int mtk_get_finished_req(struct mtk_device *mtk)
{
	struct eip93DescpHandler_s *rd;
	struct mtk_dma_rec *rec;
	unsigned long flags;	
	int ctr;
	unsigned int saddr = 0;
	unsigned int daddr = 0;
	unsigned int ret;
	uint32_t interrupts = 0;
	int GetCount, count = 0;

	GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & (BIT_10 - 1);
	ret = -1;

	while (GetCount) {
		count = count + 1;
		GetCount = GetCount - 1;
//		spin_lock_irqsave(&mtk->lock, flags);
		ctr = mtk->rec_front_idx;
		rd = &mtk->rd[ctr];
		rec = &mtk->rec[ctr];
		mtk->rec_front_idx = (mtk->rec_front_idx + 1) % MTK_RING_SIZE;
//		spin_unlock_irqrestore(&mtk->lock, flags);

		if (rd->peCrtlStat.bits.errStatus > 0) {
			dev_err(mtk->dev, "Err: %02x \n",
				rd->peCrtlStat.bits.errStatus);
		}
/*
		if (rec->saddr != saddr) {
			saddr = rec->saddr;
			dma_unmap_page(mtk->dev, saddr, rec->ssize,
				DMA_TO_DEVICE);
		}
		if (rec->daddr != daddr) {
			daddr = rec->daddr;
				dma_unmap_page(mtk->dev, daddr, rec->dsize,
					DMA_FROM_DEVICE);
		}
*/
		if (rec->flags & BIT_0) {
			ret = ctr;
			break;
		}
	}
	if (count > 0) {
		writel(count, mtk->base + EIP93_REG_PE_RD_COUNT);
		mtk->getcount = mtk->getcount - count;
	}
	return ret;
}

static irqreturn_t mtk_irq_handler(int irq, void *dev_id)
{
	struct mtk_device *mtk = (struct mtk_device *)dev_id;
	u32 irq_status;
	u32 GetCount;

	//irq_status = readl(mtk->base + EIP93_REG_INT_MASK_STAT);

	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);
	writel(0xffffffff, mtk->base + EIP93_REG_MASK_DISABLE);

	tasklet_schedule(&mtk->done_tasklet);

	return IRQ_HANDLED;
}
/*
	if (irq_status & BIT_0) {
		writel(BIT_0, mtk->base + EIP93_REG_INT_CLR);
		writel(BIT_0, mtk->base + EIP93_REG_MASK_DISABLE);
		if (mtk->count > 0) {
			tasklet_hi_schedule(&mtk->done_tasklet);
		}
		return IRQ_HANDLED;
	}

	if (irq_status & BIT_1) {
		writel(BIT_1, mtk->base + EIP93_REG_INT_CLR);
		writel(BIT_1, mtk->base + EIP93_REG_MASK_DISABLE);
		if (mtk->count > 0) {
			tasklet_hi_schedule(&mtk->done_tasklet);
		}
		return IRQ_HANDLED;
	}


// TODO: error handler; for now just clear ALL //
	printk("IRQ: %08x\n", irq_status);
	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);

	return IRQ_HANDLED;
}
*/

static void mtk_tasklet_req_done(unsigned long data)
{
	struct mtk_device *mtk = (struct mtk_device *)data;
	int GetCount, trycount;
	u32 pe_status;
	int ctr;
	struct mtk_dma_rec *rec;
	unsigned long flags;	

	if (mtk->count == 0) {
		writel(BIT_1, mtk->base + EIP93_REG_INT_CLR);
		writel(BIT_1, mtk->base + EIP93_REG_MASK_ENABLE);
		return;
	}

get_more:
	// get one finished request...
	ctr = mtk_get_finished_req(mtk);

	if (ctr < 0) {
		cpu_relax();
		goto get_more;
	}
 	rec = &mtk->rec[ctr];
	if (rec->flags & BIT_1) {
		mtk_cipher_req_done(mtk, ctr);
		cpu_relax();
	}

	if (mtk->count > 1) {
		goto get_more;
	}
	// Clear and Enable
	writel(BIT_1, mtk->base + EIP93_REG_INT_CLR);
	writel(BIT_1, mtk->base + EIP93_REG_MASK_ENABLE);
	return;
}

/*----------------------------------------------------------------------------
 * mtk_prng_activate
 *
 * This function initializes the PE PRNG for the ARM mode.
 *
 * Return Value
 *      true: PRNG is initialized
 *     false: PRNG initialization failed
 */
static bool mtk_prng_activate (struct mtk_device *mtk, bool fLongSA)
{
	int i, ctr;
	eip93DescpHandler_t *EIP93_CmdDscr;
	eip93DescpHandler_t *EIP93_ResDscr;
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

	//printk("SaState: %d, SaRecord: %d\n",sizeof(saState_t), sizeof(saRecord_t));
	//           56            128
	// Fill in SA for PRNG Init
	saRecord->saCmd0.word = 0x00001307;   // SA word 0
	saRecord->saCmd1.word = 0x02000000;   // SA word 1

	for(i = 0; i < 8; i++) {
		saRecord->saKey[i]= PRNGKey[i];
		saRecord->saIDigest[i] = PRNGSeed[i];
		saRecord->saODigest[i] = PRNGDateTime[i];
	}

	// Fill in command descriptor
	ctr = mtk->rec_rear_idx;

	EIP93_CmdDscr = &mtk->cd[ctr];
	EIP93_CmdDscr->peCrtlStat.bits.prngMode = 1; // PRNG Init function
	EIP93_CmdDscr->srcAddr = (u32)SrcPhyAddr;
	EIP93_CmdDscr->dstAddr = (u32)DstPhyAddr;
	EIP93_CmdDscr->saAddr = (u32)saPhyAddr;
	EIP93_CmdDscr->peCrtlStat.bits.hostReady= 1;
	EIP93_CmdDscr->peCrtlStat.bits.peReady= 0;
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

	if (LoopLimiter <= 0) {
		printk("EIP93 PRNG could not retrieve a result descriptor\n");
	goto fail;
	}
	ctr = mtk->rec_front_idx;

	EIP93_ResDscr = &mtk->rd[ctr];
	writel(1, mtk->base + EIP93_REG_PE_RD_COUNT);

	if (EIP93_ResDscr->peCrtlStat.bits.errStatus == 0) {
		dma_free_coherent(mtk->dev, sizeof(saRecord_t), saRecord, saPhyAddr);
		dma_unmap_single(mtk->dev, SrcPhyAddr, 4080,
			DMA_TO_DEVICE);
		dma_unmap_single(mtk->dev, DstPhyAddr, 4080,
			DMA_FROM_DEVICE);
		kfree(SrcBuffer);
		kfree(DstBuffer);
		dev_info(mtk->dev, "PRNG Initialized.\n");

		mtk->rec_rear_idx++;
		mtk->rec_front_idx++;

		return true; // success
	}

fail:
	return false;
}

void mtk_initialize(struct mtk_device *mtk)
{
	uint8_t fRstPacketEngine = 1;
	uint8_t fResetRing = 1;
	uint8_t PE_Mode = 3; // ARM mode!!
	uint8_t fBO_PD_en = 0;
	uint8_t fBO_SA_en = 0 ;
	uint8_t fBO_Data_en = 0;
	uint8_t fBO_TD_en = 0;
	uint8_t fEnablePDRUpdate = 1;
	uint32_t interrupts = 0;
	int InputThreshold = 64;
	int OutputThreshold = 64;
	int DescriptorCountDone = 1;
	int DescriptorPendingCount = 1;
	int DescriptorDoneTimeout = 0;

	writel((fRstPacketEngine & 1) |
		((fResetRing & 1) << 1) |
		((PE_Mode &(BIT_2-1)) << 8) |
		((fBO_PD_en & 1) << 16) |
		((fBO_SA_en & 1) << 17) |
		((fBO_Data_en  & 1) << 18) |
		((fBO_TD_en & 1) << 20) |
		((fEnablePDRUpdate & 1) << 10),
		mtk->base + EIP93_REG_PE_CONFIG);

	udelay(10);

	fRstPacketEngine = 0;
	fResetRing = 0;

	writel((fRstPacketEngine & 1) |
		((fResetRing & 1) << 1) |
		((PE_Mode &(BIT_2-1)) << 8) |
		((fBO_PD_en & 1) << 16) |
		((fBO_SA_en & 1) << 17) |
		((fBO_Data_en  & 1) << 18) |
		((fBO_TD_en & 1) << 20) |
		((fEnablePDRUpdate & 1) << 10),
		mtk->base + EIP93_REG_PE_CONFIG);

	// Initialize the BYTE_ORDER_CFG register
	writel((EIP93_BYTE_ORDER_PD & (BIT_4-1)) |
		((EIP93_BYTE_ORDER_SA & (BIT_4-1)) << 4) |
		((EIP93_BYTE_ORDER_DATA & (BIT_4-1)) << 8) |
		((EIP93_BYTE_ORDER_TD & (BIT_2-1)) << 16),
		mtk->base + EIP93_REG_PE_ENDIAN_CONFIG);
	// Initialize the INT_CFG register
	writel((EIP93_INT_HOST_OUTPUT_TYPE & 1 ) |
		((EIP93_INT_PULSE_CLEAR << 1) & 1),
		mtk->base + EIP93_REG_INT_CFG);
	// Clock Control, must for DHM, optional for ARM
//	writel(0x1, mtk->base + EIP93_REG_PE_CLOCK_CTRL);

	writel((InputThreshold& (BIT_10-1)) |
		((OutputThreshold & (BIT_10-1)) << 16),
		mtk->base + EIP93_REG_PE_BUF_THRESH);

         writel((DescriptorCountDone & (BIT_10-1)) |
		((DescriptorPendingCount & (BIT_10-1)) << 16) |
		((DescriptorDoneTimeout  & (BIT_6-1)) << 26) |
		BIT_31,	mtk->base + EIP93_REG_PE_RING_THRESH);

	// Clear/ack all interrupts before disable all
	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);
	writel(0xffffffff, mtk->base + EIP93_REG_MASK_DISABLE);

	// Initilaize the PRNG in AUTO Mode
	mtk_prng_activate(mtk, true);
	// Activate Interrupts:
	writel(BIT_1, mtk->base + EIP93_REG_MASK_ENABLE);
}

/* Allocate Descriptor rings */
static int mtk_desc_init(struct mtk_device *mtk)
{
	int RingOffset, RingSize;
	size_t size;
	size = (MTK_RING_SIZE * sizeof(struct eip93DescpHandler_s));

	mtk->cd = dma_zalloc_coherent(mtk->dev, size,
					&mtk->phy_cd, GFP_KERNEL);
	if (!mtk->cd)
		goto err_cleanup;

	dev_info(mtk->dev, "CD Ring : %08X\n", mtk->phy_cd);

	size = (MTK_RING_SIZE * sizeof(struct eip93DescpHandler_s));

	mtk->rd = dma_zalloc_coherent(mtk->dev, size,
					&mtk->phy_rd, GFP_KERNEL);
	if (!mtk->rd)
		goto err_cleanup;

	dev_info(mtk->dev, "RD Ring : %08X\n", mtk->phy_rd);

	size = (MTK_RING_SIZE * sizeof(struct mtk_dma_rec));

	mtk->rec = dma_zalloc_coherent(mtk->dev, size,
					&mtk->phy_rec,  GFP_KERNEL);

	if (!mtk->rec)
		goto err_cleanup;

	dev_info(mtk->dev, "Rec Ring : %08X\n", mtk->phy_rec);

	writel((u32)mtk->phy_cd, mtk->base + EIP93_REG_PE_CDR_BASE);
	writel((u32)mtk->phy_rd, mtk->base + EIP93_REG_PE_RDR_BASE);

	RingOffset = 8; // 8 words per descriptor
	RingSize = MTK_RING_SIZE - 1;
	writel(((RingOffset & (BIT_8-1)) << 16) | ( RingSize & (BIT_10-1)),
		mtk->base + EIP93_REG_PE_RING_CONFIG);

	// Create SA and State records
	size = (MTK_RING_SIZE * sizeof(struct saRecord_s));

	mtk->saRecord = dma_zalloc_coherent(mtk->dev, size, &mtk->phy_record, GFP_KERNEL);

	size = (MTK_RING_SIZE * sizeof(struct saState_s));

	mtk->saState = dma_zalloc_coherent(mtk->dev, size, &mtk->phy_state, GFP_KERNEL);
/*
	if (unlikely(saState == NULL))
	{
		dev_err(mtk->dev, "\n\n !!dma_alloc for saState_prepare failed!! \n\n");
		errVal = -ENOMEM;
		goto free_saRecord;
	}	
*/
	mtk->rec_rear_idx = 0;
	mtk->rec_front_idx = 0;
	mtk->result = 0;
	mtk->count = 0;

	return 0;
err_cleanup:
	return -ENOMEM;
}

/* Free Descriptor Rings */
static void mtk_desc_free(struct mtk_device *mtk)
{
	size_t	size;

	writel(0, mtk->base + EIP93_REG_PE_CDR_BASE);
	writel(0, mtk->base + EIP93_REG_PE_RDR_BASE);

	size = MTK_RING_SIZE * sizeof(struct eip93DescpHandler_s);

	if (mtk->cd) {
		dma_free_coherent(mtk->dev, size, mtk->cd, mtk->phy_cd);
		mtk->cd = NULL;
		mtk->phy_cd = 0;
	}

	size = MTK_RING_SIZE * sizeof(struct eip93DescpHandler_s);

	if (mtk->rd) {
		dma_free_coherent(mtk->dev, size, mtk->rd, mtk->phy_rd);
		mtk->rd = NULL;
		mtk->phy_rd = 0;
	}

	size = MTK_RING_SIZE * sizeof(struct mtk_dma_rec);

	if (mtk->rec) {
		dma_free_coherent(mtk->dev, size, mtk->rec, mtk->phy_rec);
		mtk->rec = NULL;
		mtk->phy_rec = 0;
	}

	size = MTK_RING_SIZE * sizeof(struct saRecord_s);

	if (mtk->saRecord) {
		dma_free_coherent(mtk->dev, size, mtk->saRecord, mtk->phy_record);
		mtk->saRecord = NULL;
		mtk->phy_record = 0;
	}

	size = MTK_RING_SIZE * sizeof(struct saState_s);

	if (mtk->saState) {
		dma_free_coherent(mtk->dev, size, mtk->saState, mtk->phy_state);
		mtk->saState = NULL;
		mtk->phy_state = 0;
	}
}

static int mtk_crypto_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct mtk_device *mtk;
	struct resource *res;
	int ret;

	mtk = devm_kzalloc(dev, sizeof(*mtk), GFP_KERNEL);
	if (!mtk)
		return -ENOMEM;

	mtk->dev = dev;
	platform_set_drvdata(pdev, mtk);

	res = platform_get_resource(pdev, IORESOURCE_MEM, 0);
	mtk->base = devm_ioremap_resource(&pdev->dev, res);

	if (IS_ERR(mtk->base))
		return PTR_ERR(mtk->base);

	mtk->irq = platform_get_irq(pdev, 0);

	if (mtk->irq <0) {
		dev_err(mtk->dev, "Cannot get IRQ resource\n");
		return mtk->irq;
	}
	dev_info(mtk->dev, "Assigning IRQ: %d", mtk->irq);

	ret = devm_request_threaded_irq(mtk->dev, mtk->irq, mtk_irq_handler,
					NULL, IRQF_ONESHOT,
					dev_name(mtk->dev), mtk);

	ret = mtk_desc_init(mtk);
	ret = mtk_register_algs(mtk);
	mtk_initialize(mtk);

	tasklet_init(&mtk->done_tasklet, mtk_tasklet_req_done,
		     (unsigned long)mtk);


	return 0;
}

static int mtk_crypto_remove(struct platform_device *pdev)
{
	struct mtk_device *mtk = platform_get_drvdata(pdev);

	tasklet_kill(&mtk->done_tasklet);
	mtk_unregister_algs(mtk);
	mtk_desc_free(mtk);

	printk("mtk-eip93 removed.\n");

	return 0;
}

static const struct of_device_id mtk_crypto_of_match[] = {
	{ .compatible = "mediatek,mtk-eip93", },
	{}
};
MODULE_DEVICE_TABLE(of, mtk_crypto_of_match);

static struct platform_driver mtk_crypto_driver = {
	.probe = mtk_crypto_probe,
	.remove = mtk_crypto_remove,
	.driver = {
		.name = "mtk-eip93",
		.of_match_table = mtk_crypto_of_match,
	},
};
module_platform_driver(mtk_crypto_driver);

MODULE_LICENSE("GPL");
MODULE_DESCRIPTION("Mediatek EIP-93 crypto engine driver");
MODULE_ALIAS("platform:" KBUILD_MODNAME);
MODULE_AUTHOR("Richard van Schagen (vschagen@cs.com)");
