/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include "eip93-common.h"
#include "eip93-core.h"


inline int mtk_ring_first_cdr_index(struct mtk_device *mtk)
{
	struct mtk_desc_ring *cdr  = &mtk->ring[0].cdr;

	return (cdr->read - cdr->base) / cdr->offset;
}

inline int mtk_ring_curr_wptr_index(struct mtk_device *mtk)
{
	struct mtk_desc_ring *cdr  = &mtk->ring[0].cdr;

	return (cdr->write - cdr->base) / cdr->offset;
}

inline int mtk_ring_curr_rptr_index(struct mtk_device *mtk)
{
	struct mtk_desc_ring *rdr  = &mtk->ring[0].rdr;

	return (rdr->read - rdr->base) / rdr->offset;
}

inline int mtk_ring_cdr_index(struct mtk_device *mtk,
				struct eip93_descriptor_s *cdesc)
{
	struct mtk_desc_ring *cdr = &mtk->ring[0].cdr;

	return ((void *)cdesc - cdr->base) / cdr->offset;
}

inline int mtk_ring_rdr_index(struct mtk_device *mtk,
				struct eip93_descriptor_s *rdesc)
{
	struct mtk_desc_ring *rdr = &mtk->ring[0].rdr;

	return ((void *)rdesc - rdr->base) / rdr->offset;
}

inline void *mtk_ring_next_wptr(struct mtk_device *mtk,
					struct mtk_desc_ring *ring, u32 *idx)
{
	void *ptr = ring->write;

	*idx = (ring->write - ring->base) / ring->offset;

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
					struct mtk_desc_ring *ring, u32 *idx)
{
	void *ptr = ring->read;

	if (ring->write == ring->read)
		return ERR_PTR(-ENOENT);

	*idx = (ring->read - ring->base) / ring->offset;

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

inline void *mtk_ring_curr_wptr(struct mtk_device *mtk)
{
	struct mtk_desc_ring *cdr  = &mtk->ring[0].cdr;

	return cdr->write;
}

inline void *mtk_ring_curr_rptr(struct mtk_device *mtk)
{
	struct mtk_desc_ring *rdr  = &mtk->ring[0].rdr;

	return rdr->read;
}

inline struct eip93_descriptor_s *mtk_add_cdesc(struct mtk_device *mtk,
								u32 *idx)
{
	struct eip93_descriptor_s *cdesc;

	cdesc = mtk_ring_next_wptr(mtk, &mtk->ring[0].cdr, idx);

	if (IS_ERR(cdesc))
		return cdesc;

	memset(cdesc, 0, sizeof(struct eip93_descriptor_s));

	return cdesc;
}

inline struct eip93_descriptor_s *mtk_add_rdesc(struct mtk_device *mtk,
								u32 *idx)
{
	struct eip93_descriptor_s *rdesc;

	rdesc = mtk_ring_next_wptr(mtk, &mtk->ring[0].rdr, idx);

	if (IS_ERR(rdesc))
		return rdesc;

	memset(rdesc, 0, sizeof(struct eip93_descriptor_s));

	return rdesc;
}
