// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2018
 *
 * Richard van Schagen <vschagen@cs.com>
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

#include "eip93-common.h"
#include "eip93-core.h"
#include "eip93-regs.h"
#include "eip93-prng.h"
#include "eip93-cipher.h"
#include "eip93-hash.h"

static const struct mtk_algo_ops *mtk_ops[] = {
	&prng_ops,
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
	int ctr;
	unsigned long flags = 0;
	unsigned int ret;
	int GetCount, count = 0;

	spin_lock_bh(&mtk->lock);

	ret = -1;
	ctr = mtk->rec_front_idx;

	GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10, 0);

	while (GetCount > 0) {	
		count = count + 1;
		rd = &mtk->rd[mtk->rec_front_idx];
		rec = &mtk->rec[mtk->rec_front_idx];
		mtk->rec_front_idx = (mtk->rec_front_idx + 1) % MTK_RING_SIZE;

		if (rd->peCrtlStat.bits.errStatus > 0) {
			dev_err(mtk->dev, "Err: %02x \n",
				rd->peCrtlStat.bits.errStatus);
		}
		dma_unmap_page(mtk->dev, rec->saddr, rec->ssize,
				DMA_TO_DEVICE);
		dma_unmap_page(mtk->dev, rec->daddr, rec->dsize,
				DMA_FROM_DEVICE);
		mtk->count = mtk->count - 1;
		if (rec->flags & BIT(0)) {
			ret = ctr;
			break;
		}

		GetCount = GetCount - 1;
	}

	if (count > 0) {
		writel(count, mtk->base + EIP93_REG_PE_RD_COUNT);
	}

	spin_unlock_bh(&mtk->lock);

	return ret;
}

static irqreturn_t mtk_irq_thread(int irq, void *dev_id)
{
	struct mtk_device *mtk = (struct mtk_device *)dev_id;
	struct ablkcipher_request *req = NULL;
	int ctr, more;
	struct mtk_dma_rec *rec;
	unsigned long flags;
	int GetCount = 0;
	int Batch = 0;

	GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10, 0);

	if (GetCount == 0)
		goto clear_en;

get_more:
	// get one finished request...
	ctr = mtk_get_finished_req(mtk);

	if (ctr < 0) {
		goto clear_en;
	}

 	rec = &mtk->rec[ctr];
	if (rec->flags & BIT(1)) {
		mtk_cipher_req_done(mtk, ctr);
	}

	GetCount = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10, 0);

	if (GetCount > 0) {
//		if (Batch < 4) {
//			Batch++;
			goto get_more;
//		}
	}
clear_en:
	// Clear and Enable
	writel(BIT(1), mtk->base + EIP93_REG_INT_CLR);
	writel(BIT(1), mtk->base + EIP93_REG_MASK_ENABLE);
	return IRQ_HANDLED;
}

static irqreturn_t mtk_irq_handler(int irq, void *dev_id)
{
	struct mtk_device *mtk = (struct mtk_device *)dev_id;
	u32 irq_status;

	irq_status = readl(mtk->base + EIP93_REG_INT_MASK_STAT);

	if (irq_status & BIT(0)) {
		writel(BIT(0), mtk->base + EIP93_REG_INT_CLR);
		writel(BIT(0), mtk->base + EIP93_REG_MASK_DISABLE);
		if (mtk->count > 0) {
			return IRQ_WAKE_THREAD;
		}
		return IRQ_HANDLED;
	}

	if (irq_status & BIT(1)) {
		writel(BIT(1), mtk->base + EIP93_REG_INT_CLR);
		writel(BIT(1), mtk->base + EIP93_REG_MASK_DISABLE);
		if (mtk->count > 0) {
			return IRQ_WAKE_THREAD;
		}
		return IRQ_WAKE_THREAD;
	}


// TODO: error handler; for now just clear ALL //
//	printk("IRQ: %08x\n", irq_status);
//	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);

	return IRQ_NONE;
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
	int InputThreshold = 32;
	int OutputThreshold = 32;
	int DescriptorCountDone = 0;
	int DescriptorPendingCount = 0;
	int DescriptorDoneTimeout = 10;

	writel((fRstPacketEngine & 1) |
		((fResetRing & 1) << 1) |
		((PE_Mode & GENMASK(2, 0)) << 8) |
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
		((PE_Mode & GENMASK(2, 0)) << 8) |
		((fBO_PD_en & 1) << 16) |
		((fBO_SA_en & 1) << 17) |
		((fBO_Data_en  & 1) << 18) |
		((fBO_TD_en & 1) << 20) |
		((fEnablePDRUpdate & 1) << 10),
		mtk->base + EIP93_REG_PE_CONFIG);

	// Initialize the BYTE_ORDER_CFG register
	writel((EIP93_BYTE_ORDER_PD & GENMASK(4, 0)) |
		((EIP93_BYTE_ORDER_SA & GENMASK(4, 0)) << 4) |
		((EIP93_BYTE_ORDER_DATA & GENMASK(4, 0)) << 8) |
		((EIP93_BYTE_ORDER_TD & GENMASK(2, 0)) << 16),
		mtk->base + EIP93_REG_PE_ENDIAN_CONFIG);
	// Initialize the INT_CFG register
	writel((EIP93_INT_HOST_OUTPUT_TYPE & 1 ) |
		((EIP93_INT_PULSE_CLEAR << 1) & 1),
		mtk->base + EIP93_REG_INT_CFG);
	// Clock Control, must for DHM, optional for ARM
//	writel(0x1, mtk->base + EIP93_REG_PE_CLOCK_CTRL);

	writel((InputThreshold & GENMASK(10, 0)) |
		((OutputThreshold & GENMASK(10, 0)) << 16),
		mtk->base + EIP93_REG_PE_BUF_THRESH);

         writel((DescriptorCountDone & GENMASK(10, 0)) |
		((DescriptorPendingCount & GENMASK(10, 0)) << 16) |
		((DescriptorDoneTimeout  & GENMASK(6, 0)) << 26) |
		BIT(31), mtk->base + EIP93_REG_PE_RING_THRESH);

	// Clear/ack all interrupts before disable all
	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);
	writel(0xffffffff, mtk->base + EIP93_REG_MASK_DISABLE);

	// Activate Interrupts:
	writel(BIT(1), mtk->base + EIP93_REG_MASK_ENABLE);
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
	writel(((RingOffset & GENMASK(8, 0)) << 16) | ( RingSize & GENMASK(10, 0)),
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
					mtk_irq_thread, IRQF_ONESHOT,
					dev_name(mtk->dev), mtk);

	ret = mtk_desc_init(mtk);
	mtk_initialize(mtk);

	ret = mtk_register_algs(mtk);

	return 0;
}

static int mtk_crypto_remove(struct platform_device *pdev)
{
	struct mtk_device *mtk = platform_get_drvdata(pdev);

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

MODULE_AUTHOR("Richard van Schagen <vschagen@cs.com>");
MODULE_ALIAS("platform:" KBUILD_MODNAME);
MODULE_DESCRIPTION("Mediatek EIP-93 crypto engine driver");
MODULE_LICENSE("GPL v2");
