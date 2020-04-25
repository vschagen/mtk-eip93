/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#ifndef _CORE_H_
#define _CORE_H_

#include <linux/atomic.h>
#include <linux/completion.h>
#include <crypto/aead.h>
#include <crypto/internal/hash.h>
#include <crypto/internal/rng.h>
#include <crypto/internal/skcipher.h>

struct mtk_work_data {
	struct work_struct	work;
	struct mtk_device	*mtk;
};

/**
 * struct mtk_device - crypto engine device structure
 */
struct mtk_device {
	void __iomem		*base;
	struct device		*dev;
	struct clk		*clk;
	int			irq;

	struct tasklet_struct	tasklet;

	struct mtk_ring		*ring;

	struct saRecord_s	*saRecord;
	struct saState_s	*saState;
	dma_addr_t		saState_base;
	dma_addr_t		saRecord_base;

	struct mtk_prng_device	*prng;
};


struct mtk_prng_device {
	struct saRecord_s	*PRNGSaRecord;
	dma_addr_t		PRNGSaRecord_dma;
	void 			*PRNGBuffer[2];
	dma_addr_t		PRNGBuffer_dma[2];
	struct completion 	Filled;
	uint32_t		cur_buf;
	atomic_t		State;
};

/**
 * struct mtk_desc_buf - holds the records associated with the ringbuffer
 * @flags: Flags to indicate e.g. last block.
 * @req: crypto_async_request
 * @saPointer: reference to saState to retreive IV
 */
struct mtk_desc_buf {
	u32		flags;
	u32		*req;
	u32		saPointer;
};

struct mtk_desc_ring {
	void			*base;
	void			*base_end;
	dma_addr_t		base_dma;
	/* write and read pointers */
	void			*read;
	void			*write;
	/* descriptor element offset */
	u32			offset;
};

struct mtk_ring {
	spinlock_t			lock;

	struct workqueue_struct		*workdone;
	struct mtk_work_data		work_done;

	/* command/result rings */
	struct mtk_desc_ring		cdr;
	struct mtk_desc_ring		rdr;
	/* descriptor scatter/gather record */
	struct mtk_desc_buf		*dma_buf;
	spinlock_t			desc_lock;
	spinlock_t			rdesc_lock;

	/* Number of request in the engine. */
	int				requests;

	/* The rings is handling at least one request */
	bool				busy;

	/* Store for current request when not
	 * enough resources avialable.
	 */
	struct crypto_async_request	*req;
	struct crypto_async_request	*backlog;
};

struct mtk_context {
	int (*handle_result)(struct mtk_device *mtk,
				struct crypto_async_request *req,
				bool *complete,  int *ret);
};

enum mtk_alg_type {
	MTK_ALG_TYPE_SKCIPHER,
	MTK_ALG_TYPE_AEAD,
	MTK_ALG_TYPE_AHASH,
	MTK_ALG_TYPE_PRNG,
};

struct mtk_alg_template {
	struct mtk_device	*mtk;
	enum mtk_alg_type	type;
	unsigned long		flags;
	union {
		struct skcipher_alg	skcipher;
		struct aead_alg		aead;
		struct ahash_alg	ahash;
		struct rng_alg		rng;
	} alg;
};

#endif /* _CORE_H_ */
