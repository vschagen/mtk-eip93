// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include <linux/atomic.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>

#include "eip93-main.h"
#include "eip93-regs.h"
#include "eip93-common.h"

#ifdef CONFIG_CRYPTO_DEV_EIP93_AES
#include "eip93-aes.h"
#endif
#ifdef CONFIG_CRYPTO_DEV_EIP93_DES
#include "eip93-des.h"
#endif
#ifdef CONFIG_CRYPTO_DEV_EIP93_AEAD
#include "eip93-aead.h"
#endif

static struct mtk_alg_template *mtk_algs[] = {
#ifdef CONFIG_CRYPTO_DEV_EIP93_DES
	&mtk_alg_ecb_des,
	&mtk_alg_cbc_des,
	&mtk_alg_ecb_des3_ede,
	&mtk_alg_cbc_des3_ede,
#endif
#ifdef CONFIG_CRYPTO_DEV_EIP93_AES
	&mtk_alg_ecb_aes,
	&mtk_alg_cbc_aes,
	&mtk_alg_ctr_aes,
	&mtk_alg_rfc3686_aes,
#endif
#ifdef CONFIG_CRYPTO_DEV_EIP93_AEAD
#ifdef CONFIG_CRYPTO_DEV_EIP93_DES
	&mtk_alg_authenc_hmac_md5_cbc_des,
	&mtk_alg_authenc_hmac_sha1_cbc_des,
	&mtk_alg_authenc_hmac_sha224_cbc_des,
	&mtk_alg_authenc_hmac_sha256_cbc_des,
	&mtk_alg_authenc_hmac_md5_cbc_des3_ede,
	&mtk_alg_authenc_hmac_sha1_cbc_des3_ede,
	&mtk_alg_authenc_hmac_sha224_cbc_des3_ede,
	&mtk_alg_authenc_hmac_sha256_cbc_des3_ede,
#endif
	&mtk_alg_authenc_hmac_md5_cbc_aes,
	&mtk_alg_authenc_hmac_sha1_cbc_aes,
	&mtk_alg_authenc_hmac_sha224_cbc_aes,
	&mtk_alg_authenc_hmac_sha256_cbc_aes,
	&mtk_alg_authenc_hmac_md5_rfc3686_aes,
	&mtk_alg_authenc_hmac_sha1_rfc3686_aes,
	&mtk_alg_authenc_hmac_sha224_rfc3686_aes,
	&mtk_alg_authenc_hmac_sha256_rfc3686_aes,
#endif
};

inline void mtk_irq_disable(struct mtk_device *mtk, u32 mask)
{
	__raw_writel(mask, mtk->base + EIP93_REG_MASK_DISABLE);
}

inline void mtk_irq_enable(struct mtk_device *mtk, u32 mask)
{
	__raw_writel(mask, mtk->base + EIP93_REG_MASK_ENABLE);
}

inline void mtk_irq_clear(struct mtk_device *mtk, u32 mask)
{
	__raw_writel(mask, mtk->base + EIP93_REG_INT_CLR);
}

static void mtk_unregister_algs(struct mtk_device *mtk, int i)
{
	int j;

	for (j = 0; j < i; j++) {
		switch (mtk_algs[j]->type) {
		case MTK_ALG_TYPE_SKCIPHER:
			crypto_unregister_skcipher(&mtk_algs[j]->alg.skcipher);
			break;
		case MTK_ALG_TYPE_AEAD:
			crypto_unregister_aead(&mtk_algs[j]->alg.aead);
			break;
		}
	}
}

static int mtk_register_algs(struct mtk_device *mtk)
{
	int i, ret = 0;

	for (i = 0; i < ARRAY_SIZE(mtk_algs); i++) {
		mtk_algs[i]->mtk = mtk;

		switch (mtk_algs[i]->type) {
		case MTK_ALG_TYPE_SKCIPHER:
			ret = crypto_register_skcipher(&mtk_algs[i]->alg.skcipher);
			break;
		case MTK_ALG_TYPE_AEAD:
			ret = crypto_register_aead(&mtk_algs[i]->alg.aead);
			break;
		}
		if (ret)
			goto fail;
	}

	return 0;

fail:
	mtk_unregister_algs(mtk, i);

	return ret;
}

void mtk_handle_result_descriptor(struct mtk_device *mtk)
{
	struct crypto_async_request *async = NULL;
	struct eip93_descriptor_s *rdesc;
	bool last_entry, complete;
	u32 flags;
	int handled, ready;
	int err = 0;
	union peCrtlStat_w	done1;
	union peLength_w	done2;

get_more:
	handled = 0;

	ready = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10, 0);

	if (!ready) {
		mtk_irq_clear(mtk, EIP93_INT_PE_RDRTHRESH_REQ);
		mtk_irq_enable(mtk, EIP93_INT_PE_RDRTHRESH_REQ);
		return;
	}

	last_entry = false;
	complete = false;

	while (ready) {
		rdesc = mtk_get_descriptor(mtk);
		if (IS_ERR(rdesc)) {
			dev_err(mtk->dev, "Ndesc: %d nreq: %d\n",
				handled, ready);
			err = -EIO;
			break;
		}
		/* make sure DMA is finished writing */
		do {
			done1.word = READ_ONCE(rdesc->peCrtlStat.word);
			done2.word = READ_ONCE(rdesc->peLength.word);
		} while ((!done1.bits.peReady) || (!done2.bits.peReady));

		err = rdesc->peCrtlStat.bits.errStatus;

		flags = rdesc->userId;
		async = (struct crypto_async_request *)rdesc->arc4Addr;

		writel(1, mtk->base + EIP93_REG_PE_RD_COUNT);
		mtk_irq_clear(mtk, EIP93_INT_PE_RDRTHRESH_REQ);

		handled++;
		ready--;

		if (flags & MTK_DESC_LAST) {
			last_entry = true;
			break;
		}
	}

	if (!last_entry)
		goto get_more;
#ifdef CONFIG_CRYPTO_DEV_EIP93_SKCIPHER
	if (flags & MTK_DESC_SKCIPHER)
		mtk_skcipher_handle_result(mtk, async, err);
#endif
#ifdef CONFIG_CRYPTO_DEV_EIP93_AEAD
	if (flags & MTK_DESC_AEAD)
		mtk_aead_handle_result(mtk, async, err);
#endif
	goto get_more;
}

static void mtk_done_task(unsigned long data)
{
	struct mtk_device *mtk = (struct mtk_device *)data;

	mtk_handle_result_descriptor(mtk);
}

static irqreturn_t mtk_irq_handler(int irq, void *dev_id)
{
	struct mtk_device *mtk = (struct mtk_device *)dev_id;
	u32 irq_status;

	irq_status = readl(mtk->base + EIP93_REG_INT_MASK_STAT);

	if (irq_status & EIP93_INT_PE_RDRTHRESH_REQ) {
		mtk_irq_disable(mtk, EIP93_INT_PE_RDRTHRESH_REQ);
		tasklet_schedule(&mtk->ring->done_task);
		return IRQ_HANDLED;
	}

/* TODO: error handler; for now just clear ALL */
	mtk_irq_clear(mtk, irq_status);
	if (irq_status)
		mtk_irq_disable(mtk, irq_status);

	return IRQ_NONE;
}

void mtk_initialize(struct mtk_device *mtk)
{
	uint8_t fRstPacketEngine = 1;
	uint8_t fResetRing = 1;
	uint8_t PE_Mode = 3;
	uint8_t fBO_PD_en = 0;
	uint8_t fBO_SA_en = 0;
	uint8_t fBO_Data_en = 0;
	uint8_t fBO_TD_en = 0;
	uint8_t fEnablePDRUpdate = 1;
	int InputThreshold = 256;
	int OutputThreshold = 256;
	int DescriptorCountDone = MTK_RING_SIZE - MTK_RING_BUSY;
	int DescriptorPendingCount = 1;
	int DescriptorDoneTimeout = 5;
	u32 regVal;

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

	/* Initialize the BYTE_ORDER_CFG register */
	writel((EIP93_BYTE_ORDER_PD & GENMASK(4, 0)) |
		((EIP93_BYTE_ORDER_SA & GENMASK(4, 0)) << 4) |
		((EIP93_BYTE_ORDER_DATA & GENMASK(4, 0)) << 8) |
		((EIP93_BYTE_ORDER_TD & GENMASK(2, 0)) << 16),
		mtk->base + EIP93_REG_PE_ENDIAN_CONFIG);
	/* Initialize the INT_CFG register */
	writel((EIP93_INT_HOST_OUTPUT_TYPE & 1) |
		((EIP93_INT_PULSE_CLEAR << 1) & 1),
		mtk->base + EIP93_REG_INT_CFG);
	/* Clock Control, must for DHM, optional for ARM
	 * 0x1 Only enable Packet Engine Clock
	 *     AES, DES and HASH clocks on demand
	 * Activating all clocks per performance
	 */
	regVal = BIT(0) | BIT(1) | BIT(2) | BIT(4);
	writel(regVal, mtk->base + EIP93_REG_PE_CLOCK_CTRL);

	writel((InputThreshold & GENMASK(10, 0)) |
		((OutputThreshold & GENMASK(10, 0)) << 16),
		mtk->base + EIP93_REG_PE_BUF_THRESH);

	/* Clear/ack all interrupts before disable all */
	mtk_irq_clear(mtk, 0xFFFFFFFF);
	mtk_irq_disable(mtk, 0xFFFFFFFF);

	writel(BIT(31) | (DescriptorCountDone & GENMASK(10, 0)) |
		(((DescriptorPendingCount - 1) & GENMASK(10, 0)) << 16) |
		((DescriptorDoneTimeout  & GENMASK(4, 0)) << 26),
		mtk->base + EIP93_REG_PE_RING_THRESH);
}

static void mtk_desc_free(struct mtk_device *mtk,
				struct mtk_desc_ring *cdr,
				struct mtk_desc_ring *rdr)
{
	writel(0, mtk->base + EIP93_REG_PE_RING_CONFIG);
	writel(0, mtk->base + EIP93_REG_PE_CDR_BASE);
	writel(0, mtk->base + EIP93_REG_PE_RDR_BASE);
}

static int mtk_desc_init(struct mtk_device *mtk,
			struct mtk_desc_ring *cdr,
			struct mtk_desc_ring *rdr)
{
	struct mtk_state_pool *saState_pool;
	int RingOffset, RingSize, i;

	cdr->offset = sizeof(struct eip93_descriptor_s);
	cdr->base = dmam_alloc_coherent(mtk->dev, cdr->offset * MTK_RING_SIZE,
					&cdr->base_dma, GFP_KERNEL);
	if (!cdr->base)
		return -ENOMEM;

	cdr->write = cdr->base;
	cdr->base_end = cdr->base + cdr->offset * (MTK_RING_SIZE - 1);
	cdr->read  = cdr->base;

	rdr->offset = sizeof(struct eip93_descriptor_s);
	rdr->base = dmam_alloc_coherent(mtk->dev, rdr->offset * MTK_RING_SIZE,
					&rdr->base_dma, GFP_KERNEL);
	if (!rdr->base)
		return -ENOMEM;

	rdr->write = rdr->base;
	rdr->base_end = rdr->base + rdr->offset * (MTK_RING_SIZE - 1);
	rdr->read  = rdr->base;

	writel((u32)cdr->base_dma, mtk->base + EIP93_REG_PE_CDR_BASE);
	writel((u32)rdr->base_dma, mtk->base + EIP93_REG_PE_RDR_BASE);

	RingOffset = 8; /* 8 words per descriptor */
	RingSize = MTK_RING_SIZE - 1;

	writel(((RingOffset & GENMASK(8, 0)) << 16) |
		(RingSize & GENMASK(10, 0)),
		mtk->base + EIP93_REG_PE_RING_CONFIG);

	atomic_set(&mtk->ring->free, MTK_RING_SIZE - 1);
	/* Create State record DMA pool */
	RingOffset = sizeof(struct saState_s);
	RingSize =  RingOffset * MTK_RING_SIZE;
	mtk->ring->saState = dmam_alloc_coherent(mtk->dev, RingSize,
					&mtk->ring->saState_dma, GFP_KERNEL);
	if (!mtk->ring->saState)
		return -ENOMEM;

	mtk->ring->saState_pool = devm_kcalloc(mtk->dev, 1,
				sizeof(struct mtk_state_pool) * MTK_RING_SIZE,
				GFP_KERNEL);

	for (i = 0; i < MTK_RING_SIZE; i++) {
		saState_pool = &mtk->ring->saState_pool[i];
		saState_pool->base = mtk->ring->saState + (i * RingOffset);
		saState_pool->base_dma = mtk->ring->saState_dma + (i * RingOffset);
		saState_pool->in_use = false;
	}

	return 0;
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

	if (mtk->irq < 0)
		return mtk->irq;

	ret = devm_request_threaded_irq(mtk->dev, mtk->irq, mtk_irq_handler,
					NULL, IRQF_ONESHOT,
					dev_name(mtk->dev), mtk);

	mtk->ring = devm_kcalloc(mtk->dev, 1, sizeof(*mtk->ring), GFP_KERNEL);

	if (!mtk->ring)
		return -ENOMEM;

	ret = mtk_desc_init(mtk, &mtk->ring->cdr, &mtk->ring->rdr);

	if (ret)
		return ret;

	tasklet_init(&mtk->ring->done_task, mtk_done_task, (unsigned long)mtk);

	spin_lock_init(&mtk->ring->read_lock);
	spin_lock_init(&mtk->ring->write_lock);

	mtk_initialize(mtk);

	/* Init. finished, enable RDR interupt */
	mtk_irq_enable(mtk, EIP93_INT_PE_RDRTHRESH_REQ);

	ret = mtk_register_algs(mtk);

	dev_info(mtk->dev, "EIP93 Crypto Engine Initialized.");

	return 0;
}

static int mtk_crypto_remove(struct platform_device *pdev)
{
	struct mtk_device *mtk = platform_get_drvdata(pdev);

	mtk_unregister_algs(mtk, ARRAY_SIZE(mtk_algs));

	tasklet_kill(&mtk->ring->done_task);

	/* Clear/ack all interrupts before disable all */
	mtk_irq_clear(mtk, 0xFFFFFFFF);
	mtk_irq_disable(mtk, 0xFFFFFFFF);

	writel(0, mtk->base + EIP93_REG_PE_CLOCK_CTRL);

	mtk_desc_free(mtk, &mtk->ring->cdr, &mtk->ring->rdr);
	dev_info(mtk->dev, "EIP93 removed.\n");

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
