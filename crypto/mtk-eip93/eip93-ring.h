/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2019 - 2021
 *
 * Richard van Schagen <vschagen@cs.com>
 */

inline int mtk_put_descriptor(struct mtk_device *mtk,
					struct eip93_descriptor_s *desc);

inline void *mtk_get_descriptor(struct mtk_device *mtk);

inline int mtk_get_free_saState(struct mtk_device *mtk);
