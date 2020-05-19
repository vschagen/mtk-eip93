/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include "eip93-common.h"
#include "eip93-core.h"

/*
 * TODO: rethink logic:
 * cdesc and rdesc always go together in sync are two hardware rings
 * so still needs structure for those two.
 */

inline void *mtk_ring_next_wptr(struct mtk_device *mtk,
						struct mtk_desc_ring *ring)
{
	void *ptr = ring->write;

	if ((ring->write == ring->read - ring->offset) ||
		(ring->read == ring->base && ring->write == ring->base_end))
		return ERR_PTR(-ENOMEM);

	if (ring->write == ring->base_end)
		ring->write = ring->base;
	else
		ring->write += ring->offset;

	return ptr;
}

inline void *mtk_ring_next_rptr(struct mtk_device *mtk,
						struct mtk_desc_ring *ring)
{
	void *ptr = ring->read;

	if (ring->write == ring->read)
		return ERR_PTR(-ENOENT);

	if (ring->read == ring->base_end)
		ring->read = ring->base;
	else
		ring->read += ring->offset;

	return ptr;
}

inline void mtk_ring_rollback_wptr(struct mtk_device *mtk,
						struct mtk_desc_ring *ring)
{
	if (ring->write == ring->read)
		return;

	if (ring->write == ring->base)
		ring->write = ring->base_end - ring->offset;
	else
		ring->write -= ring->offset;
}

inline struct eip93_descriptor_s *mtk_add_cdesc(struct mtk_device *mtk)
{
	struct eip93_descriptor_s *cdesc;

	cdesc = mtk_ring_next_wptr(mtk, &mtk->ring->cdr);

	if (IS_ERR(cdesc))
		return cdesc;

	memset(cdesc, 0, sizeof(struct eip93_descriptor_s));

	return cdesc;
}

inline struct eip93_descriptor_s *mtk_add_rdesc(struct mtk_device *mtk)
{
	struct eip93_descriptor_s *rdesc;

	rdesc = mtk_ring_next_wptr(mtk, &mtk->ring->rdr);

	if (IS_ERR(rdesc))
		return rdesc;

	memset(rdesc, 0, sizeof(struct eip93_descriptor_s));

	return rdesc;
}
