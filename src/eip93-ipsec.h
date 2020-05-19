/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */

#include <net/xfrm.h>

#include "eip93-common.h"

#define IPSEC_MAX_ADAPTER_COUNT			16
#define IPSEC_MAX_SA_COUNT			32

int mtk_protocol_register(struct mtk_device *mtk);

void mtk_protocol_deregister(struct mtk_device *mtk);

void mtk_ipsec_handle_result(struct mtk_device *mtk, struct sk_buff *skb,
			dma_addr_t srcAddr, u8 nexthdr, int len, int err);

struct ipsec_sa_entry {
	struct hlist_node		hlist;
	struct mtk_device		*mtk;
	struct xfrm_state		*xs;
	struct saRecord_s		*sa;
	dma_addr_t			sa_base;
	struct sdesc			*sdesc;
	struct eip93_descriptor_s	cdesc;
	xfrm_address_t			daddr;
	__be32				spi;
};

struct ipsec_adapter {
	struct net_device		*netdev;
	struct mtk_device		*mtk;
};

struct ipsec_table {
	struct ipsec_sa_entry		*rx_tbl;
	struct ipsec_sa_entry		*tx_tbl;
};
