// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include <crypto/algapi.h>
#include <crypto/internal/hash.h>
#include <crypto/sha.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/dmapool.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <linux/types.h>

#include "eip93-common.h"
#include "eip93-core.h"
#include "eip93-regs.h"
#include "eip93-ring.h"
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

static void mtk_push_request(struct mtk_device *mtk)
{
	int DescriptorCountDone = 0;
	int DescriptorPendingCount = 0;
	int DescriptorDoneTimeout = 1;

	DescriptorPendingCount = min_t(int, mtk->ring[0].requests, 10);

	if (!DescriptorPendingCount)
		return;

	writel((DescriptorCountDone & GENMASK(10, 0)) |
		(((DescriptorPendingCount - 1) & GENMASK(10, 0)) << 16) |
		((DescriptorDoneTimeout  & GENMASK(6, 0)) << 26) |
		BIT(31), mtk->base + EIP93_REG_PE_RING_THRESH);
}

static void mtk_dequeue(struct mtk_device *mtk)
{
	struct crypto_async_request *req, *backlog;
	struct mtk_context *ctx;
	int ret = 0, commands, results;
	int nreq = 0, cdesc = 0, rdesc = 0;

	req = mtk->ring[0].req;
	backlog = mtk->ring[0].backlog;
	if (req)
		goto handle_req;
	
	while (true) {
		spin_lock_bh(&mtk->ring[0].queue_lock);
		backlog = crypto_get_backlog(&mtk->ring[0].queue);
		req = crypto_dequeue_request(&mtk->ring[0].queue);
		spin_unlock_bh(&mtk->ring[0].queue_lock);

		if (!req) {
			mtk->ring[0].req = NULL;
			mtk->ring[0].backlog = NULL;
			goto finalize;
		}

handle_req:
		ctx = crypto_tfm_ctx(req->tfm);
		ret = ctx->send(req, &commands, &results);

		if (ret)
			goto request_failed;

		if (backlog)
			backlog->complete(backlog, -EINPROGRESS);

		if (!commands && !results)
			continue;

		cdesc += commands;
		rdesc += results;
		nreq++;
	}
request_failed:
	mtk->ring[0].req = req;
	mtk->ring[0].backlog = backlog;

finalize:
	if (!nreq)
		return;

	spin_lock_bh(&mtk->ring[0].lock);
	mtk->ring[0].requests += cdesc;

	if (!mtk->ring[0].busy) {
		mtk_push_request(mtk);
		mtk->ring[0].busy = true;
	}

	spin_unlock_bh(&mtk->ring[0].lock);

	/* Writing new descriptor count starts DMA action */
	writel(cdesc, mtk->base + EIP93_REG_PE_CD_COUNT);
//	writel(BIT(1), mtk->base + EIP93_REG_MASK_ENABLE);
}

static void mtk_dequeue_work(struct work_struct *work)
{
	struct mtk_work_data *data =
		container_of(work, struct mtk_work_data, work);

	mtk_dequeue(data->mtk);
}

inline struct crypto_async_request * mtk_rdr_req_get(struct mtk_device *mtk)
{
	int i = mtk_ring_curr_rptr_index(mtk);
	struct mtk_dma_rec *rec = &mtk->ring[0].cdr_dma[i];

	return (struct crypto_async_request *)rec->req;
}

static inline void mtk_handle_result_descriptor(struct mtk_device *mtk)
{ 
	struct crypto_async_request *req = NULL;
	struct mtk_dma_rec *rec;
	struct mtk_context *ctx;
	int ret, i, ndesc, rptr;
	int nreq = 0, tot_descs = 0;
	bool should_complete;

	nreq = readl(mtk->base + EIP93_REG_PE_RD_COUNT) & GENMASK(10, 0);

	if (!nreq)
		goto requests_left;

	for (i = 0; i < nreq; i++) {

		rptr = mtk_ring_curr_rptr_index(mtk);
		rec = &mtk->ring[0].cdr_dma[rptr];

		if (rec->flags & BIT(1)) {
			req = mtk_rdr_req_get(mtk);
		} else { 
			break;
		}

		if (!req)
				goto acknowledge;

		ctx = crypto_tfm_ctx(req->tfm);
		ndesc = ctx->handle_result(mtk, req, &should_complete, &ret);

		if (ndesc < 0) {
			dev_err(mtk->dev, "failed get result\n");
			goto acknowledge;
		}

		if (should_complete) {
			local_bh_disable();
			req->complete(req, ret);
			local_bh_enable();
		}

		tot_descs += ndesc;
	}

acknowledge:
	if (tot_descs) {
		writel(tot_descs, mtk->base + EIP93_REG_PE_RD_COUNT);
	}

requests_left:
	spin_lock_bh(&mtk->ring[0].lock);
	mtk->ring[0].requests -= tot_descs;
	mtk_push_request(mtk);

	if (!mtk->ring[0].requests)
		mtk->ring[0].busy = false;

	spin_unlock_bh(&mtk->ring[0].lock);
}

static irqreturn_t mtk_irq_thread(int irq, void *dev_id)
{
	struct mtk_device *mtk = (struct mtk_device *)dev_id;

	mtk_handle_result_descriptor(mtk);

	queue_work(mtk->ring[0].workqueue, &mtk->ring[0].work_data.work);

	// Clear and Enable
	//writel(BIT(1), mtk->base + EIP93_REG_INT_CLR);
	//writel(BIT(1), mtk->base + EIP93_REG_MASK_ENABLE);

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
		if (mtk->ring[0].requests > 0) {
			return IRQ_WAKE_THREAD;
		}
	}

	if (irq_status & BIT(1)) {
		writel(BIT(1), mtk->base + EIP93_REG_INT_CLR);
		if (mtk->ring[0].requests > 0) {
			//writel(BIT(1), mtk->base + EIP93_REG_MASK_DISABLE);
			return IRQ_WAKE_THREAD;
		} else {
			return IRQ_HANDLED;
		}
	}


// TODO: error handler; for now just clear ALL //
	printk("IRQ: %08x\n", irq_status);
	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);
	writel(0xffffffff, mtk->base + EIP93_REG_MASK_DISABLE);

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
	int InputThreshold = 16;
	int OutputThreshold = 16;
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
		((DescriptorDoneTimeout  & GENMASK(6, 0)) << 26),
		mtk->base + EIP93_REG_PE_RING_THRESH);

	// Clear/ack all interrupts before disable all
	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);
	writel(0xffffffff, mtk->base + EIP93_REG_MASK_DISABLE);
}

/* Allocate Descriptor rings */
static int mtk_desc_init(struct mtk_device *mtk,
			struct mtk_desc_ring *cdr,
			struct mtk_desc_ring *rdr)
{
	int RingOffset, RingSize;
	size_t	size;

	cdr->offset = sizeof(struct eip93_descriptor_s);
	cdr->base = dmam_alloc_coherent(mtk->dev, cdr->offset * MTK_RING_SIZE,
					&cdr->base_dma, GFP_KERNEL);
	if (!cdr->base)
		goto err_cleanup;
	cdr->write = cdr->base;
	cdr->base_end = cdr->base + cdr->offset * (MTK_RING_SIZE - 1);
	cdr->read  = cdr->base;

	dev_dbg(mtk->dev, "CD Ring : %pad\n", &cdr->base_dma);

	rdr->offset = sizeof(struct eip93_descriptor_s);
	rdr->base = dmam_alloc_coherent(mtk->dev, rdr->offset * MTK_RING_SIZE,
					&rdr->base_dma, GFP_KERNEL);
	if (!rdr->base)
		goto err_cleanup;

	rdr->write = rdr->base;
	rdr->base_end = rdr->base + rdr->offset * (MTK_RING_SIZE - 1);
	rdr->read  = rdr->base;

	dev_dbg(mtk->dev, "RD Ring : %pad\n", &rdr->base_dma);

	writel((u32)cdr->base_dma, mtk->base + EIP93_REG_PE_CDR_BASE);
	writel((u32)rdr->base_dma, mtk->base + EIP93_REG_PE_RDR_BASE);

	RingOffset = 8; // 8 words per descriptor
	RingSize = MTK_RING_SIZE - 1;

	writel(((RingOffset & GENMASK(8, 0)) << 16) | ( RingSize & GENMASK(10, 0)),
		mtk->base + EIP93_REG_PE_RING_CONFIG);

	size = MTK_RING_SIZE * sizeof(struct saRecord_s);

	// Create SA and State records
	size = (MTK_RING_SIZE * sizeof(struct saRecord_s));

	mtk->saRecord = dma_zalloc_coherent(mtk->dev, size,
								&mtk->saRecord_base, GFP_KERNEL);

	size = (MTK_RING_SIZE * sizeof(struct saState_s));

	mtk->saState = dma_zalloc_coherent(mtk->dev, size,
								&mtk->saState_base, GFP_KERNEL);
/*
	if (unlikely(saState == NULL))
	{
		dev_err(mtk->dev, "\n\n !!dma_alloc for saState_prepare failed!! \n\n");
		errVal = -ENOMEM;
		goto free_saRecord;
	}	
*/


	return 0;
err_cleanup:
	return -ENOMEM;
}

/* Free Descriptor Rings */
static void mtk_desc_free(struct mtk_device *mtk,
				struct mtk_desc_ring *cdr,
				struct mtk_desc_ring *rdr)
{
	size_t size;

	writel(0, mtk->base + EIP93_REG_PE_CDR_BASE);
	writel(0, mtk->base + EIP93_REG_PE_RDR_BASE);

/*
	if (cdr) {
		dma_free_coherent(mtk->dev, cdr->offset * MTK_RING_SIZE,
			cdr->base, cdr->base_dma);
		cdr->base = NULL;
		cdr->base_dma = 0;
	}

	if (rdr) {
		dma_free_coherent(mtk->dev, rdr->offset * MTK_RING_SIZE,
			rdr->base, rdr->base_dma);
		rdr->base = NULL;
		rdr->base_dma = 0;
	}
*/
	size = MTK_RING_SIZE * sizeof(struct saRecord_s);

	if (mtk->saRecord) {
		dma_free_coherent(mtk->dev, size, mtk->saRecord, mtk->saRecord_base);
		mtk->saRecord = NULL;
		mtk->saRecord_base = 0;
	}

	size = MTK_RING_SIZE * sizeof(struct saState_s);

	if (mtk->saState) {
		dma_free_coherent(mtk->dev, size, mtk->saState, mtk->saState_base);
		mtk->saState = NULL;
		mtk->saState_base = 0;
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
					mtk_irq_thread, IRQF_ONESHOT, dev_name(mtk->dev), mtk);
/*
	mtk->context_pool = dmam_pool_create("mtk-context", mtk->dev,
						sizeof(struct mtk_context_record), 1, 0);

	if (!mtk->context_pool) {
		dev_err(mtk->dev, "No context mem\n");
		return -ENOMEM;
	}
*/
	mtk->ring = devm_kcalloc(mtk->dev, 1, sizeof(*mtk->ring), GFP_KERNEL);

	if (!mtk->ring) {
		dev_err(mtk->dev, "Can't allocate Ring memory\n");
	}

	mtk->ring[0].cdr_dma = devm_kzalloc(mtk->dev, MTK_RING_SIZE *
							sizeof(struct mtk_dma_rec), GFP_KERNEL);

	if (!mtk->ring[0].cdr_dma) {
		dev_err(mtk->dev, "cant allocate CDR_DMA memory\n");
	}

	ret = mtk_desc_init(mtk, &mtk->ring[0].cdr, &mtk->ring[0].rdr);

	mtk->ring[0].requests = 0;
	mtk->ring[0].busy = false;

	crypto_init_queue(&mtk->ring[0].queue, MTK_QUEUE_LENGTH);

	spin_lock_init(&mtk->ring[0].lock);
	spin_lock_init(&mtk->ring[0].queue_lock);

	mtk->ring[0].work_data.mtk = mtk;
	INIT_WORK(&mtk->ring[0].work_data.work, mtk_dequeue_work);
	mtk->ring[0].workqueue = create_singlethread_workqueue("wq_eip93");

	mtk_initialize(mtk);

	/* Init. finished, enable RDR interupt */
	writel(BIT(1), mtk->base + EIP93_REG_MASK_ENABLE);

	ret = mtk_register_algs(mtk);

	dev_info(mtk->dev, "Init succesfull\n");

	return 0;
}

static int mtk_crypto_remove(struct platform_device *pdev)
{
	struct mtk_device *mtk = platform_get_drvdata(pdev);

	// Clear/ack all interrupts before disable all
	writel(0xffffffff, mtk->base + EIP93_REG_INT_CLR);
	writel(0xffffffff, mtk->base + EIP93_REG_MASK_DISABLE);

	destroy_workqueue(mtk->ring[0].workqueue);

	mtk_unregister_algs(mtk);

	mtk_desc_free(mtk, &mtk->ring[0].cdr, &mtk->ring[0].rdr);

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
