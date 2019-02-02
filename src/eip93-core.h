// SPDX-License-Identifier: GPL-2.0
/*
 * Copyright (C) 2019
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#ifndef _CORE_H_
#define _CORE_H_

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
	unsigned int			srcDma;
	unsigned int			dstDma;
	unsigned int			dmaLen;
	unsigned int			flags;
	unsigned int			*req;
	unsigned int			result;
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

struct mtk_cipher_drv {
	struct list_head		dev_list;
	spinlock_t			lock;
};

static struct mtk_cipher_drv mtk_cipher = {
	.dev_list = LIST_HEAD_INIT(mtk_cipher.dev_list),
	.lock = __SPIN_LOCK_UNLOCKED(mtk_cipher.lock),
};

/**
 * struct mtk_algo_ops - algorithm operations per crypto type
 * @type: should be CRYPTO_ALG_TYPE_XXX
 * @register_algs: invoked by core to register the algorithms
 * @unregister_algs: invoked by core to unregister the algorithms
 * @async_req_handle: invoked by core to handle enqueued request
 */
struct mtk_algo_ops {
	u32 type;
	int (*register_algs)(struct mtk_device *mtk);
	void (*unregister_algs)(struct mtk_device *mtk);
	int (*async_req_handle)(struct crypto_async_request *async_req);
};

#endif /* _CORE_H_ */
