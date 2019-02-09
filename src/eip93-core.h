// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#ifndef _CORE_H_
#define _CORE_H_

#include <linux/dma-mapping.h>
#include <crypto/aead.h>
#include <crypto/algapi.h>
#include <crypto/internal/hash.h>
#include <crypto/sha.h>
#include <crypto/skcipher.h>


struct mtk_work_data {
	struct work_struct	work;
	struct mtk_device	*mtk;
};

/**
 * struct mtk_device - crypto engine device structure
 * @queue: crypto request queue
 * @lock: the lock protects queue and req
 * @done_tasklet: done tasklet object
 * @front_idx: dma-idx pointer (to be replaced)
 * @read_idx: dma-idx pointer (to be replaced)
 * @rec: DMA-record structure
 * @result: result of current transform
 * @base: virtual IO base
 * @dev: pointer to device structure number
 * @irq: allocated interrupt
 * @async_req_enqueue: invoked by every algorithm to enqueue a request
 * @async_req_done: invoked by every algorithm to finish its request
 */
struct mtk_device {
	void __iomem			*base;
	struct device			*dev;
	struct clk				*clk;
	int						irq;

	struct mtk_ring			*ring;
	struct saRecord_s		*saRecord;
	struct saState_s		*saState;
	dma_addr_t				saState_base;
	dma_addr_t				saRecord_base;
	unsigned int			seed[8];
};

/**
 * struct mtk_dma_rec - holds the records associated with the ringbuffer
 * @src: Dma address of the source packet
 * @Dst: Dma address of the destination
 * @size: Size of the packet
 * @req: holds the async_request
 */
struct mtk_dma_rec {
	unsigned int			srcDma; // no need
	unsigned int			dstDma; // no need
	unsigned int			dmaLen; // no need
	unsigned int			flags; // indicate last via hashFinal bit?
	unsigned int			*req; // can be stored in UserID field
	unsigned int			result; // no need
};

struct mtk_desc_buf {
	DEFINE_DMA_UNMAP_ADDR(src_addr);
	DEFINE_DMA_UNMAP_ADDR(dst_addr);
	u16 src_len;
	u16 dst_len;
};

struct mtk_desc_ring {
	void		*base;
	void		*base_end;
	dma_addr_t	base_dma;

	/* write and read pointers */
	void		*read;
	void		*write;

	/* descriptor element offset */
	unsigned	offset;
};

struct mtk_ring {
	spinlock_t					lock;

	struct workqueue_struct		*workqueue;
	struct mtk_work_data		work_data;

	/* command/result rings */
	struct mtk_desc_ring		cdr;
	struct mtk_desc_ring		rdr;

	/* descriptor scatter/gather record */
	struct mtk_dma_rec			*cdr_dma;
	struct mtk_desc_buf			*dma_buf;

	/* queue */
	struct crypto_queue			queue;
	spinlock_t					queue_lock;

	/* Number of request in the engine. */
	int							requests;

	/* The rings is handling at least one request */
	bool						busy;

	/* Store for current request wehn not
	 * enough resources avialable.
	 */
	struct crypto_async_request	*req;
	struct crypto_async_request	*backlog;
};

struct mtk_context {
	int (*send)(struct crypto_async_request *req, int *commands,
				int *results);
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
	unsigned long 		flags;
	union {
		struct skcipher_alg	skcipher;
		struct aead_alg		aead;
		struct ahash_alg	ahash;
		struct rng_alg		rng;
	} alg;
};

void mtk_push_request(struct mtk_device *mtk);

#endif /* _CORE_H_ */
