// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@icloud.com>
 * Christian Marangi <ansuelsmth@gmail.com
 */

#include <linux/atomic.h>
#include <linux/clk.h>
#include <linux/delay.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/of.h>
#include <linux/platform_device.h>
#include <linux/spinlock.h>
#include <crypto/aes.h>
#include <crypto/ctr.h>

#include "eip93-main.h"
#include "eip93-regs.h"
#include "eip93-common.h"
#include "eip93-cipher.h"
#include "eip93-aes.h"
#include "eip93-des.h"
#include "eip93-aead.h"
#include "eip93-hash.h"
#include "eip93-ipsec.h"

static struct eip93_alg_template *eip93_algs[] = {
	&eip93_alg_md5,
	&eip93_alg_sha1,
	&eip93_alg_sha224,
	&eip93_alg_sha256,
	&eip93_alg_hmac_md5,
	&eip93_alg_hmac_sha1,
	&eip93_alg_hmac_sha224,
	&eip93_alg_hmac_sha256,
	&eip93_alg_ecb_des,
	&eip93_alg_cbc_des,
	&eip93_alg_ecb_des3_ede,
	&eip93_alg_cbc_des3_ede,
	&eip93_alg_ecb_aes,
	&eip93_alg_cbc_aes,
	&eip93_alg_ctr_aes,
	&eip93_alg_rfc3686_aes,
	&eip93_alg_authenc_hmac_md5_cbc_des,
	&eip93_alg_authenc_hmac_sha1_cbc_des,
	&eip93_alg_authenc_hmac_sha224_cbc_des,
	&eip93_alg_authenc_hmac_sha256_cbc_des,
	&eip93_alg_authenc_hmac_md5_cbc_des3_ede,
	&eip93_alg_authenc_hmac_sha1_cbc_des3_ede,
	&eip93_alg_authenc_hmac_sha224_cbc_des3_ede,
	&eip93_alg_authenc_hmac_sha256_cbc_des3_ede,
	&eip93_alg_authenc_hmac_md5_cbc_aes,
	&eip93_alg_authenc_hmac_sha1_cbc_aes,
	&eip93_alg_authenc_hmac_sha224_cbc_aes,
	&eip93_alg_authenc_hmac_sha256_cbc_aes,
	&eip93_alg_authenc_hmac_sha1_ecb_null,
	&eip93_alg_authenc_hmac_md5_rfc3686_aes,
	&eip93_alg_authenc_hmac_sha1_rfc3686_aes,
	&eip93_alg_authenc_hmac_sha224_rfc3686_aes,
	&eip93_alg_authenc_hmac_sha256_rfc3686_aes,
};

inline void eip93_irq_disable(struct eip93_device *eip93, u32 mask)
{
	__raw_writel(mask, eip93->base + EIP93_REG_MASK_DISABLE);
}

inline void eip93_irq_enable(struct eip93_device *eip93, u32 mask)
{
	__raw_writel(mask, eip93->base + EIP93_REG_MASK_ENABLE);
}

inline void eip93_irq_clear(struct eip93_device *eip93, u32 mask)
{
	__raw_writel(mask, eip93->base + EIP93_REG_INT_CLR);
}

static void eip93_unregister_algs(unsigned int i)
{
	unsigned int j;

	for (j = 0; j < i; j++) {
		switch (eip93_algs[j]->type) {
		case EIP93_ALG_TYPE_SKCIPHER:
			crypto_unregister_skcipher(&eip93_algs[j]->alg.skcipher);
			break;
		case EIP93_ALG_TYPE_AEAD:
			crypto_unregister_aead(&eip93_algs[j]->alg.aead);
			break;
		case EIP93_ALG_TYPE_HASH:
			crypto_unregister_ahash(&eip93_algs[i]->alg.ahash);
			break;
		}
	}
}

static int eip93_register_algs(struct eip93_device *eip93, u32 supported_algo_flags)
{
	unsigned int i;
	int ret = 0;

	for (i = 0; i < ARRAY_SIZE(eip93_algs); i++) {
		u32 alg_flags = eip93_algs[i]->flags;

		eip93_algs[i]->eip93 = eip93;

		if ((IS_DES(alg_flags) || IS_3DES(alg_flags)) &&
		    !(supported_algo_flags & EIP93_PE_OPTION_TDES))
			continue;

		if (IS_AES(alg_flags)) {
			if (!(supported_algo_flags & EIP93_PE_OPTION_AES))
				continue;

			if (!IS_HMAC(alg_flags)) {
				if (supported_algo_flags & EIP93_PE_OPTION_AES_KEY128)
					eip93_algs[i]->alg.skcipher.max_keysize =
						AES_KEYSIZE_128;

				if (supported_algo_flags & EIP93_PE_OPTION_AES_KEY192)
					eip93_algs[i]->alg.skcipher.max_keysize =
						AES_KEYSIZE_192;

				if (supported_algo_flags & EIP93_PE_OPTION_AES_KEY256)
					eip93_algs[i]->alg.skcipher.max_keysize =
						AES_KEYSIZE_256;

				if (IS_RFC3686(alg_flags))
					eip93_algs[i]->alg.skcipher.max_keysize +=
						CTR_RFC3686_NONCE_SIZE;
			}
		}

		if (IS_HASH_MD5(alg_flags) &&
		    !(supported_algo_flags & EIP93_PE_OPTION_MD5))
			continue;

		if (IS_HASH_SHA1(alg_flags) &&
		    !(supported_algo_flags & EIP93_PE_OPTION_SHA_1))
			continue;

		if (IS_HASH_SHA224(alg_flags) &&
		    !(supported_algo_flags & EIP93_PE_OPTION_SHA_224))
			continue;

		if (IS_HASH_SHA256(alg_flags) &&
		    !(supported_algo_flags & EIP93_PE_OPTION_SHA_256))
			continue;

		switch (eip93_algs[i]->type) {
		case EIP93_ALG_TYPE_SKCIPHER:
			ret = crypto_register_skcipher(&eip93_algs[i]->alg.skcipher);
			break;
		case EIP93_ALG_TYPE_AEAD:
			ret = crypto_register_aead(&eip93_algs[i]->alg.aead);
			break;
		case EIP93_ALG_TYPE_HASH:
			ret = crypto_register_ahash(&eip93_algs[i]->alg.ahash);
			break;
		}
		if (ret)
			goto fail;
	}

	return 0;

fail:
	eip93_unregister_algs(i);

	return ret;
}

static void eip93_handle_result_descriptor(struct eip93_device *eip93)
{
	struct eip93_descriptor *rdesc;
	struct eip93_desc_ring *rdr_ring = &eip93->ring->rdr;
	struct eip93_callback_ring *callback = &eip93->ring->callback;
        struct eip93_callback_ops *ops;
	u16 desc_flags, idx;
	int left;
	u32 pe_ctrl_stat, pe_length, user_id;
	int handled = 0;
	int done = 0;
	int budget = EIP93_BUDGET;
	int n = 0;
	struct eip93_list todo[EIP93_BUDGET];
	bool busy = false;

get_more:
	rdr_ring->write = FIELD_GET(GENMASK(25, 16), readl_relaxed(eip93->base + EIP93_REG_PE_RING_RW_PNTR));
	left = readl_relaxed(eip93->base + EIP93_REG_PE_RD_COUNT) & EIP93_PE_RD_COUNT;
	rmb();

	if (!left) {
		if (handled) {
			dma_wmb();
			writel(handled, eip93->base + EIP93_REG_PE_RD_COUNT);
		}
		eip93_irq_clear(eip93, EIP93_INT_RDR_THRESH);
		eip93_irq_enable(eip93, EIP93_INT_RDR_THRESH);
		return;
	}

	while (left) {
		rdesc = &rdr_ring->desc[rdr_ring->read];
		dma_rmb();
		/* make sure DMA is finished writing */
		pe_ctrl_stat = READ_ONCE(rdesc->pe_ctrl_stat_word);
		pe_length = READ_ONCE(rdesc->pe_length_word);
		if (FIELD_GET(EIP93_PE_CTRL_PE_READY_DES_TRING_OWN, pe_ctrl_stat) !=
			 EIP93_PE_CTRL_PE_READY ||
			 FIELD_GET(EIP93_PE_LENGTH_HOST_PE_READY, pe_length) !=
			 EIP93_PE_LENGTH_PE_READY)
			 break;

		dma_rmb();

		user_id = READ_ONCE(rdesc->user_id);
		desc_flags = FIELD_GET(EIP93_PE_USER_ID_DESC_FLAGS, user_id);
                idx = FIELD_GET(EIP93_PE_USER_ID_CRYPTO_IDR, user_id);
                ops = &callback->ops[idx];
		ops->pe_ctrl_stat = pe_ctrl_stat;
		ops->pe_length = pe_length;

		if (desc_flags & EIP93_DESC_LAST) {
			todo[done].idx = idx;
			done++;
		}
		/* clear ready bits but write a word is faster*/
		rdesc->pe_ctrl_stat_word = 0;
		rdesc->pe_length_word = 0;

		rdr_ring->read = (rdr_ring->read + 1) &EIP93_RING_MASK;

		budget--;
		handled++;
		left--;

		if (!budget)
			break;
	}

	if (handled) {
		wmb();
		writel(handled, eip93->base + EIP93_REG_PE_RD_COUNT);
	}

	/* push engine for more RDR */
	busy = eip93_kick_engine(eip93, 0, handled);
	handled = 0;

	if (!done)
		goto get_more;

	for (n = 0; n < done; n++) {
		idx = todo[n].idx;
		ops = &callback->ops[idx];
		if (ops->callback)
                    ops->callback(ops->context, ops->pe_ctrl_stat, ops->pe_length);
                ops->callback = NULL;
		eip93_callback_free(eip93, idx);
	}

	done = 0;
	n = 0;

	if (budget)
		goto get_more;

	eip93_irq_clear(eip93, EIP93_INT_RDR_THRESH);
	eip93_irq_enable(eip93, EIP93_INT_RDR_THRESH);
}

static void eip93_done_task(unsigned long data)
{
	struct eip93_device *eip93 = (struct eip93_device *)data;

	eip93_handle_result_descriptor(eip93);
}

static irqreturn_t eip93_irq_handler(int irq, void *data)
{
	struct eip93_device *eip93 = data;
	u32 irq_status;

	irq_status = readl(eip93->base + EIP93_REG_INT_MASK_STAT);
	if (FIELD_GET(EIP93_INT_RDR_THRESH, irq_status)) {
		eip93_irq_disable(eip93, EIP93_INT_RDR_THRESH);
		tasklet_schedule(&eip93->ring->done_task);
		return IRQ_HANDLED;
	}

	/* Ignore errors in AUTO mode, handled by the RDR */
	eip93_irq_clear(eip93, irq_status);
	if (irq_status)
		eip93_irq_disable(eip93, irq_status);

	return IRQ_NONE;
}

static void eip93_initialize(struct eip93_device *eip93, u32 supported_algo_flags)
{
	u32 val;

	/* Reset PE and rings */
	val = EIP93_PE_CONFIG_RST_PE | EIP93_PE_CONFIG_RST_RING;
	val |= EIP93_PE_TARGET_AUTO_RING_MODE;
	/* For Auto mode, update the CDR ring owner after processing */
	val |= EIP93_PE_CONFIG_EN_CDR_UPDATE;
	writel(val, eip93->base + EIP93_REG_PE_CONFIG);

	/* Wait for PE and ring to reset */
	usleep_range(10, 20);

	/* Release PE and ring reset */
	val = readl(eip93->base + EIP93_REG_PE_CONFIG);
	val &= ~(EIP93_PE_CONFIG_RST_PE | EIP93_PE_CONFIG_RST_RING);
	writel(val, eip93->base + EIP93_REG_PE_CONFIG);

	/* Config Clocks */
	val = EIP93_PE_CLOCK_EN_PE_CLK;
	if (supported_algo_flags & EIP93_PE_OPTION_TDES)
		val |= EIP93_PE_CLOCK_EN_DES_CLK;
	if (supported_algo_flags & EIP93_PE_OPTION_AES)
		val |= EIP93_PE_CLOCK_EN_AES_CLK;
	if (supported_algo_flags &
	    (EIP93_PE_OPTION_MD5 | EIP93_PE_OPTION_SHA_1 | EIP93_PE_OPTION_SHA_224 |
	     EIP93_PE_OPTION_SHA_256))
		val |= EIP93_PE_CLOCK_EN_HASH_CLK;
	writel(val, eip93->base + EIP93_REG_PE_CLOCK_CTRL);

	/* Config DMA thresholds */
	val = FIELD_PREP(EIP93_PE_OUTBUF_THRESH, 128) |
	      FIELD_PREP(EIP93_PE_INBUF_THRESH, 128);
	writel(val, eip93->base + EIP93_REG_PE_BUF_THRESH);

	/* Clear/ack all interrupts before disable all */
	eip93_irq_clear(eip93, EIP93_INT_ALL);
	eip93_irq_disable(eip93, EIP93_INT_ALL);

	/* Setup CRD threshold to trigger interrupt */
	val = FIELD_PREP(EIPR93_PE_CDR_THRESH, EIP93_RING_SIZE - EIP93_RING_BUSY);
	/*
	 * Configure RDR interrupt to be triggered if RD counter is not 0
	 * for more than 2^(N+10) system clocks.
	 */
	val |= FIELD_PREP(EIPR93_PE_RDR_THRESH, 0);
	val |= FIELD_PREP(EIPR93_PE_RD_TIMEOUT, 10) | EIPR93_PE_TIMEROUT_EN;
	writel(val, eip93->base + EIP93_REG_PE_RING_THRESH);
}

static void eip93_desc_free(struct eip93_device *eip93)
{
	writel(0, eip93->base + EIP93_REG_PE_RING_CONFIG);
	writel(0, eip93->base + EIP93_REG_PE_CDR_BASE);
	writel(0, eip93->base + EIP93_REG_PE_RDR_BASE);
}

static int eip93_set_ring(struct eip93_device *eip93, struct eip93_desc_ring *ring)
{
	ring->desc = dmam_alloc_coherent(eip93->dev,
					 sizeof(struct eip93_descriptor) * EIP93_RING_SIZE,
					 &ring->base_dma, GFP_KERNEL);
	if (!ring->desc)
		return -ENOMEM;

	ring->write = 0;
	ring->read  = 0;

	return 0;
}

static int eip93_desc_init(struct eip93_device *eip93)
{
	struct eip93_desc_ring *cdr = &eip93->ring->cdr;
	struct eip93_desc_ring *rdr = &eip93->ring->rdr;
	struct eip93_sa_ring *sa_pool = &eip93->ring->sa_pool;
	struct eip93_state_ring *state_pool = &eip93->ring->state_pool;
	struct eip93_callback_ring *callback = &eip93->ring->callback;
	int ret;
	u32 val;

	eip93->ring->queued = 0;
	eip93->ring->pending = 0;
	eip93->ring->threshold = 0;

	ret = eip93_set_ring(eip93, cdr);
	if (ret)
		return ret;

	ret = eip93_set_ring(eip93, rdr);
	if (ret)
		return ret;

	writel((u32 __force)cdr->base_dma, eip93->base + EIP93_REG_PE_CDR_BASE);
	writel((u32 __force)rdr->base_dma, eip93->base + EIP93_REG_PE_RDR_BASE);

	val = FIELD_PREP(EIP93_PE_RING_SIZE, EIP93_RING_SIZE - 1);
	writel(val, eip93->base + EIP93_REG_PE_RING_CONFIG);

	sa_pool->sa_record = dmam_alloc_coherent(eip93->dev,
					 sizeof(struct sa_record) * EIP93_SA_POOL,
					 &sa_pool->base_dma, GFP_KERNEL);
	if (!sa_pool->sa_record)
		return -ENOMEM;

	state_pool->state = dmam_alloc_coherent(eip93->dev,
					 sizeof(struct sa_state) * EIP93_STATE_POOL,
					 &state_pool->base_dma, GFP_KERNEL);
	if (!state_pool->state)
		return -ENOMEM;
		
	callback->ops = devm_kzalloc(eip93->dev,
	                            sizeof(struct eip93_callback_ops) * EIP93_STATE_POOL,
	                            GFP_KERNEL);
    
        if (!callback->ops)
                return -ENOMEM;

	return 0;
}

static void eip93_cleanup(struct eip93_device *eip93)
{
	tasklet_kill(&eip93->ring->done_task);

	/* Clear/ack all interrupts before disable all */
	eip93_irq_clear(eip93, EIP93_INT_ALL);
	eip93_irq_disable(eip93, EIP93_INT_ALL);

	writel(0, eip93->base + EIP93_REG_PE_CLOCK_CTRL);

	eip93_desc_free(eip93);

	idr_destroy(&eip93->ring->crypto_async_idr);
}

static int eip93_crypto_probe(struct platform_device *pdev)
{
	struct device *dev = &pdev->dev;
	struct eip93_device *eip93;
	u32 ver, algo_flags;
	int ret;

	eip93 = devm_kzalloc(dev, sizeof(*eip93), GFP_KERNEL);
	if (!eip93)
		return -ENOMEM;

	eip93->dev = dev;
	platform_set_drvdata(pdev, eip93);

	eip93->base = devm_platform_ioremap_resource(pdev, 0);
	if (IS_ERR(eip93->base))
		return PTR_ERR(eip93->base);

	eip93->irq = platform_get_irq(pdev, 0);
	if (eip93->irq < 0)
		return eip93->irq;

	ret = devm_request_threaded_irq(eip93->dev, eip93->irq, eip93_irq_handler,
					NULL, IRQF_ONESHOT,
					dev_name(eip93->dev), eip93);

	eip93->ring = devm_kcalloc(eip93->dev, 1, sizeof(*eip93->ring), GFP_KERNEL);
	if (!eip93->ring)
		return -ENOMEM;

	ret = eip93_desc_init(eip93);

	if (ret)
		return ret;

	tasklet_init(&eip93->ring->done_task, eip93_done_task, (unsigned long)eip93);

	spin_lock_init(&eip93->ring->read_lock);
	spin_lock_init(&eip93->ring->write_lock);

	spin_lock_init(&eip93->ring->idr_lock);
	idr_init(&eip93->ring->crypto_async_idr);

	algo_flags = readl(eip93->base + EIP93_REG_PE_OPTION_1);

	eip93_initialize(eip93, algo_flags);

	/* Init finished, enable RDR interrupt */
	eip93_irq_enable(eip93, EIP93_INT_RDR_THRESH);

	ret = eip93_register_algs(eip93, algo_flags);
	if (ret) {
		eip93_cleanup(eip93);
		return ret;
	}

	ver = readl(eip93->base + EIP93_REG_PE_REVISION);
	/* EIP_EIP_NO:MAJOR_HW_REV:MINOR_HW_REV:HW_PATCH,PE(ALGO_FLAGS) */
	dev_info(eip93->dev, "EIP%lu:%lx:%lx:%lx,PE(0x%x:0x%x)\n",
		 FIELD_GET(EIP93_PE_REVISION_EIP_NO, ver),
		 FIELD_GET(EIP93_PE_REVISION_MAJ_HW_REV, ver),
		 FIELD_GET(EIP93_PE_REVISION_MIN_HW_REV, ver),
		 FIELD_GET(EIP93_PE_REVISION_HW_PATCH, ver),
		 algo_flags,
		 readl(eip93->base + EIP93_REG_PE_OPTION_0));

	return 0;
}

static void eip93_crypto_remove(struct platform_device *pdev)
{
	struct eip93_device *eip93 = platform_get_drvdata(pdev);

	eip93_unregister_algs(ARRAY_SIZE(eip93_algs));
	eip93_cleanup(eip93);
}

static const struct of_device_id eip93_crypto_of_match[] = {
	{ .compatible = "inside-secure,safexcel-eip93i", },
	{ .compatible = "inside-secure,safexcel-eip93ie", },
	{ .compatible = "inside-secure,safexcel-eip93is", },
	{ .compatible = "inside-secure,safexcel-eip93ies", },
	/* IW not supported currently, missing AES-XCB-MAC/AES-CCM */
	/* { .compatible = "inside-secure,safexcel-eip93iw", }, */
	{}
};
MODULE_DEVICE_TABLE(of, eip93_crypto_of_match);

static struct platform_driver eip93_crypto_driver = {
	.probe = eip93_crypto_probe,
	.remove = eip93_crypto_remove,
	.driver = {
		.name = "inside-secure-eip93",
		.of_match_table = eip93_crypto_of_match,
	},
};
module_platform_driver(eip93_crypto_driver);

MODULE_AUTHOR("Richard van Schagen <vschagen@cs.com>");
MODULE_AUTHOR("Christian Marangi <ansuelsmth@gmail.com>");
MODULE_DESCRIPTION("Mediatek EIP-93 crypto engine driver");
MODULE_LICENSE("GPL");
