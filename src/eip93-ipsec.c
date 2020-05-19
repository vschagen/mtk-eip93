/* SPDX-License-Identifier: GPL-2.0
 *
 * Copyright (C) 2020
 *
 * Richard van Schagen <vschagen@cs.com>
 */
#define DEBUG 1

#include <crypto/authenc.h>
#include <crypto/hmac.h>
#include <crypto/internal/des.h>
#include <crypto/md5.h>
#include <crypto/sha.h>
#include <linux/netdevice.h>
#include <net/xfrm.h>

#include "eip93-common.h"
#include "eip93-core.h"
#include "eip93-cipher.h"
#include "eip93-ipsec.h"
#include "eip93-regs.h"
#include "eip93-ring.h"

/*
 * declare adapter static for now
 */

static struct ipsec_adapter	*adapter;
static struct ipsec_sa_entry    *sa_list;

static int mtk_xfrm_add_state(struct xfrm_state *x);
static void mtk_xfrm_del_state(struct xfrm_state *x);
static void mtk_xfrm_free_state(struct xfrm_state *x);
static bool mtk_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *x);
static void mtk_advance_esn_state(struct xfrm_state *x);

static const struct xfrmdev_ops mtk_xfrmdev_ops = {
	.xdo_dev_state_add      = mtk_xfrm_add_state,
	.xdo_dev_state_delete   = mtk_xfrm_del_state,
	.xdo_dev_state_free     = mtk_xfrm_free_state,
	.xdo_dev_offload_ok     = mtk_ipsec_offload_ok,
	.xdo_dev_state_advance_esn = mtk_advance_esn_state,
};

/*
 * Add offload xfrms to Net Device Interface
 * Should be called from the NIC driver itself
 * for now call it upon the first ESP packet.
 */

bool mtk_add_xfrmops(struct net_device *netdev)
{
	int i;

	if (!netdev) {
		printk("add xfrm ops without netdev??\n");
		return false;
	}

	for (i = 0; i < IPSEC_MAX_ADAPTER_COUNT; i++) {
		if (adapter[i].netdev == NULL)
			break;
		// maybe update vs just return //
		if (adapter[i].netdev == netdev) {
			netdev_info(netdev, "Exists\n");
			return true;
		}
	};

	if (i ==  IPSEC_MAX_ADAPTER_COUNT) {
		netdev_info(netdev, "Adapter list is full, cannot offload\n");
		return false;
	}
	adapter[i].netdev = netdev;

	netdev->xfrmdev_ops = &mtk_xfrmdev_ops;
 	netdev->hw_enc_features |= NETIF_F_HW_ESP;
 	netdev->features |= NETIF_F_HW_ESP;
 	rtnl_lock();
 	netdev_change_features(netdev);
 	rtnl_unlock();
	netdev_info(netdev, "ESP Hardware offload features added\n");
	return true;
 }

/*
 * mtk_validate_state
 * return 0 in case doesn't validate or "flags" which
 * can never be "0"
 */
unsigned long int mtk_validate_state(struct xfrm_state *x)
{
 	struct net_device *netdev = x->xso.dev;
 	unsigned long int flags = 0;

	if (x->id.proto != IPPROTO_ESP) {
 		netdev_info(netdev, "Only ESP xfrm state may be offloaded\n");
 		return 0;
 	}
	/* TODO: add ipv6 support */
	if (x->props.family != AF_INET) {
//		&& x->props.family != AF_INET6) {
		netdev_info(netdev, "Only IPv4 xfrm states may be offloaded\n");
		return 0;
	}
	if (x->aead) {
		netdev_info(netdev, "Cannot offload xfrm states with aead\n");
		return 0;
	}
 	if (x->props.aalgo == SADB_AALG_NONE) {
 		netdev_info(netdev, "Can only offload without encryption xfrm states\n");
 		return 0;
 	}
 	if (x->props.calgo != SADB_X_CALG_NONE) {
 		netdev_info(netdev, "Cannot offload compressed xfrm states\n");
 		return 0;
 	}
 	/* TODO: support ESN */
 	if (x->props.flags & XFRM_STATE_ESN) {
 		netdev_info(netdev, "Cannot offload ESN xfrm states\n");
 		return 0;
 	}
 	/* TODO: add transport mode */
 	if (x->props.mode != XFRM_MODE_TUNNEL) {
 //		&& x->props.mode != XFRM_MODE_TRANSPORT) {
 		dev_info(&netdev->dev, "Only tunnel xfrm states may be offloaded\n");
 		return 0;
 	}
 	if (x->encap) {
 		netdev_info(netdev, "Encapsulated xfrm state may not be offloaded\n");
 		return 0;
 	}
 	if (x->tfcpad) {
 		netdev_info(netdev, "Cannot offload xfrm states with tfc padding\n");
 		return 0;
 	}

	netdev_info(netdev, "Got: %s with %s\n",
				x->ealg->alg_name, x->aalg->alg_name);

     	switch (x->props.ealgo) {
 	case SADB_EALG_DESCBC:
 		flags |= MTK_ALG_DES | MTK_MODE_CBC;
 		break;
 	case SADB_EALG_3DESCBC:
 		flags |= MTK_ALG_3DES | MTK_MODE_CBC;
 		break;
 	case SADB_X_EALG_AESCBC:
 		flags |= MTK_ALG_AES | MTK_MODE_CBC;
 		break;
 	case SADB_X_EALG_AESCTR:
 		flags |= MTK_ALG_AES | MTK_MODE_CTR;
 	case SADB_EALG_NULL:
 		break;
 	default:
 		netdev_info(netdev, "Cannot offload encryption: %s\n", x->ealg->alg_name);
 		return 0;
 	}

 	switch (x->props.aalgo) {
 	case SADB_AALG_SHA1HMAC:
 		flags |= MTK_HASH_SHA1;
 		break;
 	case SADB_X_AALG_SHA2_256HMAC:
 		flags |= MTK_HASH_SHA256;
 		break;
 	case SADB_AALG_MD5HMAC:
 		flags |= MTK_HASH_MD5;
 		break;
 	default:
 		netdev_info(netdev, "Cannot offload authentication: %s\n", x->aalg->alg_name);
 		return 0;
	}
 /*
 	if (x->aead->alg_icv_len != 128) {
 		netdev_info(netdev, "Cannot offload xfrm states with AEAD ICV length other than 128bit\n");
 		return -EINVAL;
 	}
 */

 /*
 	TODO check key_len
 	// split for RFC3686 with nonce vs others !!
 	if ((x->aead->alg_key_len != 128 + 32) &&
 	    (x->aead->alg_key_len != 256 + 32)) {
 		netdev_info(netdev, "Cannot offload xfrm states with AEAD key length other than 128/256 bit\n");
 		return -EINVAL;
 	}
 */
	return flags;
}

static int mtk_create_sa(struct mtk_device *mtk, struct ipsec_sa_entry *ipsec,
			struct xfrm_state *x, unsigned long int flags)
{
	struct saRecord_s *saRecord;
	struct crypto_shash *hash;
	char *alg_base;
	const u8 *enckey = x->ealg->alg_key;
	unsigned int enckeylen = (x->ealg->alg_key_len >>3);
	const u8 *authkey = x->aalg->alg_key;
	unsigned int authkeylen = (x->aalg->alg_key_len >>3);
	unsigned int trunc_len = (x->aalg->alg_trunc_len >>3);
	u32 nonce = 0;
	unsigned int size;
	int err;

	if (IS_HASH_MD5(flags))
		alg_base = "md5";
	if (IS_HASH_SHA1(flags))
		alg_base = "sha1";
	if (IS_HASH_SHA256(flags))
		alg_base = "sha256";

	hash = crypto_alloc_shash(alg_base, 0, CRYPTO_ALG_NEED_FALLBACK);
	if (IS_ERR(hash)) {
	 	dev_err(mtk->dev, "base driver %s could not be loaded.\n",
			 alg_base);
	return PTR_ERR(hash);
	}

	size = sizeof(struct shash_desc) + crypto_shash_descsize(hash);
	ipsec->sdesc = kmalloc(size, GFP_KERNEL);
	if (!ipsec->sdesc) {
		dev_err(mtk->dev, "Couldnt allocate memory for shash\n");
		return PTR_ERR(ipsec->sdesc);
	}
	ipsec->sdesc->shash.tfm = hash;

	ipsec->sa = dma_pool_zalloc(mtk->saRecord_pool, GFP_KERNEL,
					 &ipsec->sa_base);
	if (!ipsec->sa)
		dev_err(mtk->dev, "No saRecord DMA memory\n");

	saRecord = ipsec->sa;

	/* Encryption key */
	mtk_ctx_saRecord(ipsec->sa, enckey, nonce, enckeylen, flags);
	/* authentication key */
	err = mtk_authenc_setkey(ipsec->sa,  ipsec->sdesc, authkey, authkeylen);
	if (err)
		dev_err(mtk->dev, "Set Key failed: %d\n", err);

	/* TODO check inbound or outbound */
	saRecord->saCmd0.bits.direction = 1;
	saRecord->saCmd1.bits.byteOffset = 0;
	saRecord->saCmd1.bits.hashCryptOffset = 0; //(8 >> 2)(rctx->assoclen >> 2);
	saRecord->saCmd0.bits.digestLength = (trunc_len >> 2);
	saRecord->saCmd1.bits.hmac = 1;
	saRecord->saCmd0.bits.padType = 0;
	saRecord->saCmd1.bits.copyPad = 0;
	saRecord->saCmd1.bits.copyDigest = 1;
	saRecord->saCmd0.bits.opCode = 0;
	saRecord->saCmd0.bits.opGroup = 1;
	saRecord->saCmd1.bits.copyHeader = 1;
	saRecord->saCmd0.bits.hdrProc = 0; // dont veryify header
	saRecord->saCmd0.bits.ivSource = 1;
	saRecord->saCmd1.bits.seqNumCheck = 0; // dont check sequencing
	printk("spi: %08x\n", x->id.spi);
	saRecord->saSpi = x->id.spi;
	saRecord->saSeqNum[0] = 1;
	saRecord->saSeqNum[1] = 0;

	ipsec->cdesc.peCrtlStat.bits.hostReady = 1;
	ipsec->cdesc.peCrtlStat.bits.prngMode = 0;
	ipsec->cdesc.peCrtlStat.bits.hashFinal = 1;
	ipsec->cdesc.peCrtlStat.bits.padCrtlStat = 1;
	ipsec->cdesc.peCrtlStat.bits.peReady = 0;
	ipsec->cdesc.saAddr = ipsec->sa_base;
	ipsec->cdesc.stateAddr = 0;
	ipsec->cdesc.arc4Addr = 0; // skb pointer
	ipsec->cdesc.userId = flags | MTK_DESC_IPSEC | MTK_DESC_LAST | MTK_DESC_FINISH;
	ipsec->xs = x;
	ipsec->daddr = x->id.daddr;
	ipsec->spi = x->id.spi;

	return 0;
}

 /*
 * mtk_xfrm_add_state
 */
static int mtk_xfrm_add_state(struct xfrm_state *x)
{
	struct net_device *netdev = x->xso.dev;
	struct ipsec_sa_entry *ipsec;
	struct mtk_device *mtk;
	unsigned long int flags = 0;
	int i, err;

	printk("add state\n");

	flags = mtk_validate_state(x);

	if (!flags) {
		printk("flags: %08lx \n", flags);
		return -EOPNOTSUPP;
	}

	for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
		if (sa_list[i].xs == NULL)
				break;
	};

	if (i == IPSEC_MAX_SA_COUNT) {
		return -ENOSPC;
	}

	ipsec = &sa_list[i];
	mtk = ipsec->mtk;

	if (!mtk) {
		printk("cant find mtk from sa_list?\n");
		return -EINVAL;
	} else {
		dev_info(mtk->dev, "adding state\n");
	}

	/* TODO: changed to ipsec pointer
	 * TODO: add key checks
	 */

	err = mtk_create_sa(mtk, ipsec, x, flags);
	if (err) {
		dev_err(mtk->dev, "error creating sa\n");
		return err;
	}

	x->xso.offload_handle = (unsigned long)ipsec;
	try_module_get(THIS_MODULE);
	dev_info(mtk->dev, "inbound spi: %08x saddr: %08x\n",
					ipsec->spi, ipsec->daddr.a4);
	netdev_info(netdev, "State added\n");

	return 0;
}

static void mtk_xfrm_del_state(struct xfrm_state *x)
{
	struct ipsec_sa_entry *ipsec;
	struct mtk_device *mtk;
	int i;

	printk("Delete State\n");

	for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
		if (sa_list[i].xs == x)
			break;
	};

	if (i == IPSEC_MAX_SA_COUNT) {
		return;
	}
	ipsec = &sa_list[i];
	ipsec->xs = NULL;
	mtk = ipsec->mtk;
	if (!mtk) {
		printk("cant find mtk from sa_list? unable to free DMA\n");
	} else {
		dma_pool_free(mtk->saRecord_pool, ipsec->sa, ipsec->sa_base);
	}

	module_put(THIS_MODULE);

	dev_info(mtk->dev, "Deleted State\n");

	return;
}

static void mtk_xfrm_free_state(struct xfrm_state *x)
{
	printk("Free State\n");

	return;
}

static void mtk_advance_esn_state(struct xfrm_state *x)
{
	printk("ESN State\n");

	return;
}

/**
 * mtk_ipsec_offload_ok - can this packet use the xfrm hw offload
 * @skb: current data packet
 * @xs: pointer to transformer state struct
 **/
static bool mtk_ipsec_offload_ok(struct sk_buff *skb, struct xfrm_state *xs)
{
	printk("mtk offload\n");

	if (xs->props.family == AF_INET) {
		/* Offload with IPv4 options is not supported yet */
		if (ip_hdr(skb)->ihl != 5)
			return false;
	} else {
		/* Offload with IPv6 extension headers is not support yet */
		if (ipv6_ext_hdr(ipv6_hdr(skb)->nexthdr))
			return false;
	}

	return false;
//	return true;
}

void mtk_ipsec_handle_result(struct mtk_device *mtk, struct sk_buff *skb,
			dma_addr_t srcAddr, u8 nexthdr, int len, int err)
{
	struct ipsec_sa_entry *ipsec;
	struct net_device *netdev = skb->dev;
	const struct iphdr *iph = ip_hdr(skb);
	struct ip_esp_hdr *esph;
	int i;
	__be32 spi;
	__be32 daddr;

	esph = (struct ip_esp_hdr *)skb->data;
	spi = esph->spi;
	daddr = iph->daddr;

	printk("len: %d, skb->len: %d", len, skb->len);

	printk("IRQ: spi:%08x saddr:  %08x\n", spi, daddr);

	if (netdev) {
		netdev_info(netdev, "xfrm decrypted\n");
	} else
		printk("No netdev ??\n");

	/*
	 * unmap skb-len
	 * returned len = without padding
	 */
	dma_unmap_single(mtk->dev, srcAddr, skb->len, DMA_FROM_DEVICE);

	print_hex_dump_bytes("", DUMP_PREFIX_NONE, skb->data, skb->len);

	for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
		if (sa_list[i].spi == spi && sa_list[i].daddr.a4 == daddr)
				break;
	};
	if (i == IPSEC_MAX_SA_COUNT) {
		dev_info(mtk->dev, "unable to find xfrm?\n");
		return;
	}
	printk("ipsec xfrm found\n");
	if (err ==  1) {
		printk("-EBADMSG\n");
	}
	ipsec = &sa_list[i];
}

static int mtk_ipsec_offload(struct mtk_device *mtk,
			struct eip93_descriptor_s desc, struct sk_buff *skb)
{
	struct eip93_descriptor_s *cdesc, *rdesc;
	dma_addr_t saddr;

	print_hex_dump_bytes("", DUMP_PREFIX_NONE, skb->data, skb->len);

	saddr = dma_map_single(mtk->dev, (void *)skb->data, skb->len,
						DMA_BIDIRECTIONAL);

	spin_lock(&mtk->ring[0].write_lock);
	rdesc = mtk_add_rdesc(mtk);
	if (IS_ERR(rdesc))
		dev_err(mtk->dev, "No RDR mem");

	cdesc = mtk_add_cdesc(mtk);
	if (IS_ERR(cdesc))
		dev_err(mtk->dev, "No CDR mem");

	cdesc->peCrtlStat.word = desc.peCrtlStat.word;
	cdesc->srcAddr = saddr;
	cdesc->dstAddr = saddr;
	cdesc->saAddr = desc.saAddr;
	cdesc->stateAddr = desc.stateAddr;
	cdesc->arc4Addr = (unsigned int *)skb;
	cdesc->userId = desc.userId;
	cdesc->peLength.bits.byPass = 0;
	cdesc->peLength.bits.length = skb->len;
	cdesc->peLength.bits.hostReady = 1;
	spin_unlock(&mtk->ring[0].write_lock);
	/*   */
	spin_lock(&mtk->ring[0].lock);
	mtk->ring[0].requests += 1;
	mtk->ring[0].busy = true;
	spin_unlock(&mtk->ring[0].lock);

	writel(1, mtk->base + EIP93_REG_PE_CD_COUNT);
	dev_info(mtk->dev, "Skb queued to hardware\n");

	return 0;
}

/*
 * XFRM Protocol callback functions
 *
 */

static int mtk_input(struct sk_buff *skb, int nexthdr, __be32 spi,
		     int encap_type, bool update_skb_dev)
{
	printk("mtk_input\n");

/*
	struct ip_tunnel *tunnel;
	const struct iphdr *iph = ip_hdr(skb);
	struct net *net = dev_net(skb->dev);
	struct ip_tunnel_net *itn = net_generic(net, vti_net_id);

	tunnel = ip_tunnel_lookup(itn, skb->dev->ifindex, TUNNEL_NO_KEY,
				  iph->saddr, iph->daddr, 0);
	if (tunnel) {
		if (!xfrm4_policy_check(NULL, XFRM_POLICY_IN, skb))
			goto drop;

		XFRM_TUNNEL_SKB_CB(skb)->tunnel.ip4 = tunnel;

		if (update_skb_dev)
			skb->dev = tunnel->dev;

		return xfrm_input(skb, nexthdr, spi, encap_type);
	}

	return -EINVAL;
drop:
	kfree_skb(skb);
	return 0;
*/
	return -EINVAL;
}

static int mtk_rcv(struct sk_buff *skb, __be32 spi, bool update_skb_dev)
{
	struct xfrm_state *x;
	struct ip_esp_hdr *esph;
	struct net_device *netdev = skb->dev;
	const struct iphdr *iph = ip_hdr(skb);

	int protocol = iph->protocol;

	printk("mtk-rcv\n");

//	XFRM_SPI_SKB_CB(skb)->family = AF_INET;
//	XFRM_SPI_SKB_CB(skb)->daddroff = offsetof(struct iphdr, daddr);

	switch (protocol) {
	case IPPROTO_ESP:
		esph = (struct ip_esp_hdr *)(skb->data+(iph->ihl<<2));
		//spi = esph->spi;
		printk("inbound spi:%08x\n", esph->spi);
		break;
	case IPPROTO_AH:
//		ah = (struct ip_auth_hdr *)(skb->data+(iph->ihl<<2));
//		spi = ah->spi;
		break;
	case IPPROTO_COMP:
//		ipch = (struct ip_comp_hdr *)(skb->data+(iph->ihl<<2));
//		spi = htonl(ntohs(ipch->cpi));
		break;
//	default:
//		return 0;
	}

	return mtk_input(skb, ip_hdr(skb)->protocol, spi, 0, update_skb_dev);
}

static int mtk_rcv_proto(struct sk_buff *skb)
{
	struct ipsec_sa_entry *ipsec;
	const struct iphdr *iph = ip_hdr(skb);
	struct net *net = dev_net(skb->dev);
	struct net_device *netdev = skb->dev;
	int protocol = iph->protocol;
	struct ip_esp_hdr *esph;
	__be32 spi;
	__be32 daddr;
	int ret, i;
	unsigned int elen = skb->len - sizeof(struct ip_esp_hdr);

	esph = (struct ip_esp_hdr *)(skb->data);
	spi = esph->spi;
	daddr = iph->daddr;

	if (netdev) {
		ret = mtk_add_xfrmops(netdev);
	} else
		printk("No netdev ??\n");

	for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
		if ((sa_list[i].spi == spi)) // && (sa_list[i].daddr.a4 == daddr))
			break;
	};
	if (i == IPSEC_MAX_SA_COUNT) {
		printk("not found\n");
		return -EINVAL;
	}
	ipsec = &sa_list[i];
	printk("found: %08x, daddr.a4: %08x\n", ipsec->spi, ipsec->daddr.a4);

	ret = mtk_ipsec_offload(ipsec->mtk, ipsec->cdesc, skb);

	return -EINPROGRESS;
}

static int mtk_input_proto(struct sk_buff *skb, int nexthdr, __be32 spi,
			   int encap_type)
{
	printk("input proto\n");

	return -EINVAL;
}

static int mtk_rcv_cb(struct sk_buff *skb, int err)
{
	printk("mtk-rcv-cb\n");

	return 1;
/*
	unsigned short family;
	struct net_device *dev;
	struct pcpu_sw_netstats *tstats;
	struct xfrm_state *x;
	const struct xfrm_mode *inner_mode;
	struct ip_tunnel *tunnel = XFRM_TUNNEL_SKB_CB(skb)->tunnel.ip4;
	u32 orig_mark = skb->mark;
	int ret;

	if (!tunnel)
		return 1;

	dev = tunnel->dev;

	if (err) {
		dev->stats.rx_errors++;
		dev->stats.rx_dropped++;

		return 0;
	}

	x = xfrm_input_state(skb);

	inner_mode = &x->inner_mode;

	if (x->sel.family == AF_UNSPEC) {
		inner_mode = xfrm_ip2inner_mode(x, XFRM_MODE_SKB_CB(skb)->protocol);
		if (inner_mode == NULL) {
			XFRM_INC_STATS(dev_net(skb->dev),
				       LINUX_MIB_XFRMINSTATEMODEERROR);
			return -EINVAL;
		}
	}

	family = inner_mode->family;

	skb->mark = be32_to_cpu(tunnel->parms.i_key);
	ret = xfrm_policy_check(NULL, XFRM_POLICY_IN, skb, family);
	skb->mark = orig_mark;

	if (!ret)
		return -EPERM;

	skb_scrub_packet(skb, !net_eq(tunnel->net, dev_net(skb->dev)));
	skb->dev = dev;

	tstats = this_cpu_ptr(dev->tstats);

	u64_stats_update_begin(&tstats->syncp);
	tstats->rx_packets++;
	tstats->rx_bytes += skb->len;
	u64_stats_update_end(&tstats->syncp);
*/
}

static int mtk_err(struct sk_buff *skb, u32 info)
{
	printk("mtk_err\n");
/*
	__be32 spi;
	__u32 mark;
	struct xfrm_state *x;
	struct ip_tunnel *tunnel;
	struct ip_esp_hdr *esph;
	struct ip_auth_hdr *ah ;
	struct ip_comp_hdr *ipch;
	struct net *net = dev_net(skb->dev);
	const struct iphdr *iph = (const struct iphdr *)skb->data;
	int protocol = iph->protocol;
	struct ip_tunnel_net *itn = net_generic(net, vti_net_id);

	tunnel = ip_tunnel_lookup(itn, skb->dev->ifindex, TUNNEL_NO_KEY,
				  iph->daddr, iph->saddr, 0);
	if (!tunnel)
		return -1;

	mark = be32_to_cpu(tunnel->parms.o_key);

	switch (protocol) {
	case IPPROTO_ESP:
		esph = (struct ip_esp_hdr *)(skb->data+(iph->ihl<<2));
		spi = esph->spi;
		break;
	case IPPROTO_AH:
		ah = (struct ip_auth_hdr *)(skb->data+(iph->ihl<<2));
		spi = ah->spi;
		break;
	case IPPROTO_COMP:
		ipch = (struct ip_comp_hdr *)(skb->data+(iph->ihl<<2));
		spi = htonl(ntohs(ipch->cpi));
		break;
	default:
		return 0;
	}

	switch (icmp_hdr(skb)->type) {
	case ICMP_DEST_UNREACH:
		if (icmp_hdr(skb)->code != ICMP_FRAG_NEEDED)
			return 0;
	case ICMP_REDIRECT:
		break;
	default:
		return 0;
	}

	x = xfrm_state_lookup(net, mark, (const xfrm_address_t *)&iph->daddr,
			      spi, protocol, AF_INET);
	if (!x)
		return 0;

	if (icmp_hdr(skb)->type == ICMP_DEST_UNREACH)
		ipv4_update_pmtu(skb, net, info, 0, protocol);
	else
		ipv4_redirect(skb, net, 0, protocol);
	xfrm_state_put(x);
*/
	return 0;
}

static struct xfrm4_protocol mtk_esp4_protocol __read_mostly = {
	.handler	=	mtk_rcv_proto,
	.input_handler	=	mtk_input_proto,
	.cb_handler	=	mtk_rcv_cb,
	.err_handler	=	mtk_err,
	.priority	=	300,
};
/* Register xfrm protocol */
int mtk_protocol_register(struct mtk_device *mtk)
{
	int i, err;
	int size;

	size = sizeof(struct ipsec_adapter) * IPSEC_MAX_ADAPTER_COUNT;
	adapter = kmalloc(size, GFP_KERNEL);

	size = sizeof(struct ipsec_sa_entry) * IPSEC_MAX_SA_COUNT;
	sa_list = kmalloc(size, GFP_KERNEL);

	for (i = 0; i < IPSEC_MAX_SA_COUNT; i++) {
		sa_list[i].xs = NULL;
		sa_list[i].mtk = mtk;
	};

	for (i = 0; i < IPSEC_MAX_ADAPTER_COUNT; i++) {
		adapter[i].netdev = NULL;
		adapter[i].mtk = mtk;
	};

	err = xfrm4_protocol_register(&mtk_esp4_protocol, IPPROTO_ESP);
	if (err < 0)
		dev_err(mtk->dev, "xfrm4 protocol register failed\n");

	dev_info(mtk->dev,"xfrm4 protocols registed\n");
	return err;
}

void mtk_protocol_deregister(struct mtk_device *mtk)
{
	xfrm4_protocol_deregister(&mtk_esp4_protocol, IPPROTO_ESP);
	dev_info(mtk->dev,"xfrm4 protocols deregisted\n");

	/* TODO: unregister extra XFRM OFFLOAD */
	kfree(sa_list);
	kfree(adapter);
}
