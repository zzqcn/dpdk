#ifndef _TSRN10_FLOW_H_
#define _TSRN10_FLOW_H_

#include "base/tsrn10_hw.h"
#include "tsrn10_compat.h"

/* ******************Flow Ctrl***********************************/
#define TSRN10_SRC_IP_MASK		(1 << 0)
#define TSRN10_DST_IP_MASK		(1 << 1)
#define TSRN10_SRC_PORT_MASK		(1 << 2)
#define TSRN10_DST_PORT_MASK		(1 << 3)
#define TSRN10_L4_PROTO_MASK		(1 << 4)

#define TSRN10_MAX_LAYER2_FILTERS	(16)
#define TSRN10_MAX_TUPLE5_FILTERS	(128)
#define TSRN10_MAX_TCP_SYNC_FILTERS	(1)
#define TSRN10_MAX_TCAM_FILTERS		(4096)
/* ETYPE POLICY */
#define TSRN10_L2_ETQF_ADDR(n)		_ETH_(0x9200 + 0x04 * (n))
#define TSRN10_L2_ETQF_EN		BIT(31)
#define TSRN10_L2_ETQF_VF_EN		BIT(26)
#define TSRN10_L2_PROTO_NUM_MASK	GENMASK(15, 0)
#define TSRN10_L2_ETQS_ADDR(n)		_ETH_(0x9240 + 0x04 * (n))
#define TSRN10_L2_ETQS_ACTION_SHIFT	(31)
#define TSRN10_L2_ETQS_MARK_ATTR_EN	BIT(28)
#define TSRN10_L2_ETQS_RING_EN		BIT(30)
#define	TSRN10_L2_ETQS_RING_SHIFT	(20)
#define TSRN10_L2_ETQS_MARK_MASK	GENMASK(15, 0)
#define TSRN10_L2_UNKONW_ETQS		_ETH_(0x9280)
#define TSRN10_L2_UNKONW_ETQF		_ETH_(0x9284)

/*=======================================================================
 * Normal N-TUPLE5 POLICY
 *=======================================================================
 */
#define TSRN10_SAQF_BASE_ADDR(n)	_ETH_(0xC000 + 0x04 * (n))
#define TSRN10_DAQF_BASE_ADDR(n)	_ETH_(0xC400 + 0x04 * (n))
#define TSRN10_SDPQF_BASE_ADDR(n)	_ETH_(0xC800 + 0x04 * (n))
#define TSRN10_FTQF_BASE_ADDR(n)	_ETH_(0xCC00 + 0x04 * (n))
#define TSRN10_L34TIMIR_BASE_ADDR(n)	_ETH_(0xD000 + 0x04 * (n))

#define TSRN10_QF_SRCPORT		(0x0000FFFF)
#define TSRN10_QF_DSTPORT_SHIFT	        (16)
#define TSRN10_QF_MASK_SHIFT	        (25)
#define TSRN10_QF_PROTO_SHIFT		(16)
#define TSRN10_QF_FILTER_EN		(1 << 31)

#define TSRN10_QF_POLICY_DROP		(1 << 31)
#define TSRN10_QF_POLICY_RING_EN	(1 << 30)
#define TSRN10_QF_POLICY_MARK_EN	(1 << 28)
#define TSRN10_QF_POLICY_PORT_EN	(1 << 29)
#define TSRN10_QF_POLICY_PASS		(0 << 31)
#define TSRN10_QF_POLICY_QREDIRCT_SHIFT (20)
#define TSRN10_MARK_ID_MASK		GENMASK(15, 0)

/* TCP SYNC QF POLICY */
#define TSRN10_SYNQF_ADDR		_ETH_(0x9290)
#define TSRN10_SYNQF_PRIO_ADDR		_ETH_(0x9294)

/* SYNC QF */
#define TSRN10_SYNC_POLICY_DROP		(1 << 31)
#define TSRN10_SYNC_POLICY_RING_EN	(1 << 30)
#define TSRN10_SYNC_POLICY_MARK_EN	(1 << 28)
#define TSRN10_SYNC_POLICY_PORT_EN	(1 << 29)
#define TSRN10_SYNC_POLICY_RING_SHIFT	(20)
#define TSRN10_SYNC_POLICY_RING_MASK	(0xff)
#define TSRN10_SYNC_PRIO_EN		(1 << 31)
#define TSRN10_SYNC_PRIO_HIGH		(1)

enum TSRN10_MATCH_PROTO {
	TSRN10_PROTO_MAT_TCP = 0,
	TSRN10_PROTO_MAT_UDP,
	TSRN10_PROTO_MAT_SCTP,
	TSRN10_PROTO_MAT_L4,
};

enum tsrn10_5tuple_protocol {
	TSRN10_FILTER_PROTO_TCP = 1,
	TSRN10_FILTER_PROTO_UDP,
	TSRN10_FILTER_PROTO_SCTP,
	TSRN10_FILTER_PROTO_MATCH,
};
enum tsrn10_filter_mode {
	TSRN10_TUPLE_NORMAL_MODE = 0,
	TSRN10_TUPLE_TCAM_MODE,
};

enum tsrn10_filter_action {
	TSRN10_FILTER_PASS,
	TSRN10_FILTER_DROP,
};

struct tsrn10_patter_flow_type {
	enum rte_filter_type flow_type;
	uint64_t pattern_mask;
};

#define TSRN10_ETHERTYPE_ATTR		BIT64(RTE_FLOW_ITEM_TYPE_ETH)
#define TSRN10_ETHERTYPE_ATTR_VF	(TSRN10_ETHERTYPE_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_VF))
#define TSRN10_ETHERTYPE_VLAN_ATTR	(TSRN10_ETHERTYPE_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_VLAN))
#define TSRN10_NTUPLE_V4_ATTR		(BIT64(RTE_FLOW_ITEM_TYPE_ETH) | BIT64(RTE_FLOW_ITEM_TYPE_IPV4))
#define TSRN10_NTUPLE_V6_ATTR		(BIT64(RTE_FLOW_ITEM_TYPE_ETH) | BIT64(RTE_FLOW_ITEM_TYPE_IPV6))
#define TSRN10_NTUPLE_V4_ATTR_VF	(TSRN10_NTUPLE_V4_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_VF))
#define TSRN10_NTUPLE_V4_ATTR_UDP	(TSRN10_NTUPLE_V4_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_UDP))
#define TSRN10_NTUPLE_V4_ATTR_UDP_VF	(TSRN10_NTUPLE_V4_ATTR_UDP | BIT64(RTE_FLOW_ITEM_TYPE_VF))
#define TSRN10_NTUPLE_V4_ATTR_TCP	(TSRN10_NTUPLE_V4_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_TCP))
#define TSRN10_NTUPLE_V4_ATTR_TCP_VF	(TSRN10_NTUPLE_V4_ATTR_TCP | BIT64(RTE_FLOW_ITEM_TYPE_VF))
#define TSRN10_NTUPLE_V4_ATTR_SCTP	(TSRN10_NTUPLE_V4_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_SCTP))
#define TSRN10_NTUPLE_V4_ATTR_SCTP_VF	(TSRN10_NTUPLE_V4_ATTR_SCTP | BIT64(RTE_FLOW_ITEM_TYPE_VF))

#define TSRN10_NTUPLE_VLAN_V4_ATTR	(TSRN10_NTUPLE_V4_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_VLAN))
#define TSRN10_NTUPLE_VLAN_V4_TCP_ATTR	(TSRN10_NTUPLE_V4_ATTR_TCP | BIT64(RTE_FLOW_ITEM_TYPE_VLAN))
#define TSRN10_NTUPLE_VLAN_V4_UDP_ATTR	(TSRN10_NTUPLE_V4_ATTR_UDP | BIT64(RTE_FLOW_ITEM_TYPE_VLAN))
#define TSRN10_NTUPLE_VLAN_V4_SCTP_ATTR	(TSRN10_NTUPLE_V4_ATTR_SCTP |  BIT64(RTE_FLOW_ITEM_TYPE_VLAN))

#define TSRN10_NTUPLE_V6_ATTR_TCP	(TSRN10_NTUPLE_V6_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_TCP))
#define TSRN10_NTUPLE_V6_ATTR_TCP_VF	(TSRN10_NTUPLE_V6_ATTR_TCP | BIT64(RTE_FLOW_ITEM_TYPE_VF))
#define TSRN10_NTUPLE_V6_ATTR_UDP	(TSRN10_NTUPLE_V6_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_UDP))
#define TSRN10_NTUPLE_V6_ATTR_UDP_VF	(TSRN10_NTUPLE_V6_ATTR_UDP | BIT64(RTE_FLOW_ITEM_TYPE_VF))
#define TSRN10_NTUPLE_V6_ATTR_SCTP	(TSRN10_NTUPLE_V6_ATTR | BIT64(RTE_FLOW_ITEM_TYPE_SCTP))
#define TSRN10_NTUPLE_V6_ATTR_SCTP_VF	(TSRN10_NTUPLE_V6_ATTR_SCTP | BIT64(RTE_FLOW_ITEM_TYPE_VF))

#define TSRN10_VLAN_ATTR		(BIT64(RTE_FLOW_ITEM_TYPE_ETH) | \
					BIT64(RTE_FLOW_ITEM_TYPE_VLAN) | \
					BIT64(RTE_FLOW_ITEM_TYPE_VF))

#define TSRN10_VXLAN_V4_ATTR		(BIT64(RTE_FLOW_ITEM_TYPE_ETH) | \
					BIT64(RTE_FLOW_ITEM_TYPE_IPV4) | \
					BIT64(RTE_FLOW_ITEM_TYPE_UDP)  | \
					BIT64(RTE_FLOW_ITEM_TYPE_VXLAN) | \
					BIT64(RTE_FLOW_ITEM_TYPE_ETH)  | \
					BIT64(RTE_FLOW_ITEM_TYPE_VF))

/* =========== RSS policy =============== */
#define TSRN10_RSS_MAX_SIZE		(10)
#define TSRN10_RSS_MAX_KEY_SIZE		(40)
#define TSRN10_RSS_HASH_CFG_MASK	(0x3F30000)
#define TSRN10_RSS_HASH_IPV4_TCP	(1 << 16)
#define TSRN10_RSS_HASH_IPV4		(1 << 17)
#define TSRN10_RSS_HASH_IPV6		(1 << 20)
#define TSRN10_RSS_HASH_IPV6_TCP	(1 << 21)
#define TSRN10_RSS_HASH_IPV4_UDP	(1 << 22)
#define TSRN10_RSS_HASH_IPV6_UDP	(1 << 23)
#define TSRN10_RSS_HASH_IPV4_SCTP	(1 << 24)
#define TSRN10_RSS_HASH_IPV6_SCTP	(1 << 25)

struct tsrn10_rss_hash_cfg {
	uint32_t func_id;
	uint32_t reg_val;
	uint64_t rss_flag;
};

enum tsrn10_rss_hash_type {
	TSRN10_RSS_IPV4,
	TSRN10_RSS_IPV6,
	TSRN10_RSS_IPV4_TCP,
	TSRN10_RSS_IPV4_UDP,
	TSRN10_RSS_IPV4_SCTP,
	TSRN10_RSS_IPV6_TCP,
	TSRN10_RSS_IPV6_UDP,
	TSRN10_RSS_IPV6_SCTP,
};

struct tsrn10_rss_cfg_match_pattern {
	uint64_t rss_cfg;
	uint64_t match_pattern;
};

struct tsrn10_5tuple_rule {
	enum tsrn10_5tuple_protocol proto;
	uint8_t proto_id;		/* l4 protocol. */

	uint16_t dst_port;              /* dst port in little endian */
	uint16_t src_port;              /* src port in little endian */
	uint32_t dst_ip;
	uint32_t src_ip;
	uint32_t mark_id;
	/* When Nic Is Flow engine Work on TCAM mode it can support
	 * dst/src/ ip/port proto mask And when it work on Ntuple Mode
	 * It just use to judge the pattern if or not to use for match rule
	 * 1 is means don't use for match 0 is means use for match
	 */
	uint32_t dst_ip_mask;		/* if mask is 1b, do not compare dst ip. */
	uint32_t src_ip_mask;		/* if mask is 1b, do not compare src ip. */
	uint16_t dst_port_mask;		/* if mask is 1b, do not compare dst port. */
	uint16_t src_port_mask;		/* if mask is 1b, do not compare src port. */
	uint8_t proto_mask;		/* if mask is 1b, do not compare protocol. */
	uint8_t mark_dis;		/* if mask is 1b, do not mark the filter rule */

	uint8_t vf_used;
	uint16_t dst_vf;

	uint8_t redir_vaild;	/* rule action of queue */
	uint16_t queue;		/* rx queue assigned to */
	enum tsrn10_filter_action action;
	/* rule priority attr */
	uint8_t group;
	uint8_t priority;
};

#define TSRN10_RSS_INSET_QUEUE	BIT(0)
#define TSRN10_RSS_INSET_KEY	BIT(1)
#define TSRN10_RSS_INSET_TYPE	BIT(2)
struct tsrn10_rss_rule {
	struct rte_flow_action_rss rss_cfg;

	uint8_t phy_id;
	uint8_t vf_used;
	uint16_t dst_vf;
	uint32_t inset;
};

struct tsrn10_rss_filter_pattern {
	TAILQ_ENTRY(tsrn10_rss_filter_pattern) node;
	struct rte_flow_action_rss rss_cfg;
	uint32_t inset;
	uint8_t key[TSRN10_RSS_MAX_KEY_SIZE * sizeof(uint32_t)]; /* Hash key. */
	uint8_t phy_id;
	uint8_t vf_used;
	uint16_t dst_vf;
};

struct tsrn10_5tuple_filter {
	TAILQ_ENTRY(tsrn10_5tuple_filter) node;
	uint16_t index;		/* the index of 5tuple filter sw */
	uint16_t hw_idx;	/* the Real Hw Location For Acl Engine */
	struct tsrn10_5tuple_rule filter_rule;
};

struct tsrn10_l2type_match_param {
	uint16_t ethertype;
	uint32_t etqf;
	uint32_t etqs;
	uint16_t flags;
	uint8_t mark_dis;
	uint32_t mark_id;

	uint8_t vf_used;
	uint16_t dst_vf;

	enum tsrn10_filter_action action;
};
struct tsrn10_ethertype_rule {
	struct tsrn10_l2type_match_param param;
	uint8_t redir_vaild;
	uint16_t queue; /* Rediect Qudue Index */
};

struct tsrn10_ethertype_filter {
	TAILQ_ENTRY(tsrn10_ethertype_filter) node;
	uint16_t index;
	uint16_t hw_idx;
	struct tsrn10_ethertype_rule filter_rule;
};

struct tsrn10_patterns_parse {
	const enum rte_flow_item_type pattern_type;
	int (*parse)(struct rte_eth_dev *dev,
		     const struct rte_flow_item *pattern,
		     struct rte_flow *flow,
		     struct rte_flow_error *error);
};

TAILQ_HEAD(tsrn10_5tuple_filter_list, tsrn10_5tuple_filter);
TAILQ_HEAD(tsrn10_ethertype_filter_list, tsrn10_ethertype_filter);
TAILQ_HEAD(tsrn10_rss_filter_list, tsrn10_rss_filter_pattern);

TAILQ_HEAD(tsrn10_flow_list, rte_flow);

struct tsrn10_filter_info {
	enum tsrn10_filter_mode mode;
	/* Bit mask for every ethertype filter*/
	uint8_t ethertype_mask[TSRN10_MAX_LAYER2_FILTERS];
	uint32_t ethertype_rule_count;
	uint32_t max_ethertype_rule_num;
	uint32_t ethertype_rule_base;
	struct tsrn10_ethertype_filter_list ethertype_list;
	/* Bit mask for every used 5tuple filter */
	uint8_t fivetuple_mask[TSRN10_MAX_TCAM_FILTERS];
	uint32_t ntuple_rule_count;
	uint32_t max_ntuple_num;
	uint32_t ntuple_rule_base;
	struct tsrn10_5tuple_filter_list fivetuple_list;

	/* Tcp sync filter */
	uint32_t synfq;
	uint32_t syn_prio;
	/* Back Store Last Rss Cfg */
	struct tsrn10_rss_filter_list rss_cfg_list;
	struct tsrn10_rss_filter_pattern rss_rule;

	struct tsrn10_flow_list flow_list;
	uint32_t flow_count;
	uint16_t mark_flow_cnt;
};

struct tsrn10_action_patterns {
	uint8_t mark_en;
	struct rte_flow_action_mark mark;
	uint8_t redirect_en;
	struct rte_flow_action_queue redir;
	enum tsrn10_filter_action rule_action;

	uint8_t rss_en;
	struct rte_flow_action_rss rss;

	uint8_t vf_attr_en;
	struct rte_flow_action_vf act_vf;
};

struct tsrn10_tcp_sync_filter_rule {
	uint16_t queue;
	uint8_t redir_vaild;
	uint8_t high_pri;
	uint8_t mark_en;
	uint16_t mark_id;
	enum tsrn10_filter_action action;
};

struct tsrn10_vlan_rule {
	uint16_t vlan_tag;
	uint16_t vf_pool;
};

struct tsrn10_vxlan_rule {
	uint16_t vxlan_vni;
	uint16_t vf_pool;
};

struct rte_flow {
	TAILQ_ENTRY(rte_flow) node;
	enum rte_filter_type filter_type;
	uint64_t pattern_type; /* Filter Proto Layer Struct */
	uint64_t match_target; /* Match Proto Layer Target */
	union {
		struct tsrn10_ethertype_rule ethertype_rule;
		struct tsrn10_5tuple_rule ntuple_rule;
		struct tsrn10_rss_rule rss_rule;
		struct tsrn10_tcp_sync_filter_rule sync_rule;
		struct tsrn10_vlan_rule vlan_rule;
		struct tsrn10_vxlan_rule vxlan_rule;
	};
	uint8_t vf_used;
	uint16_t dst_vf;
};

static const struct tsrn10_rss_hash_cfg rss_cfg[] = {
	{TSRN10_RSS_IPV4, TSRN10_RSS_HASH_IPV4, ETH_RSS_IPV4},
	{TSRN10_RSS_IPV4, TSRN10_RSS_HASH_IPV4, ETH_RSS_FRAG_IPV4},
	{TSRN10_RSS_IPV4, TSRN10_RSS_HASH_IPV4, ETH_RSS_NONFRAG_IPV4_OTHER},
	{TSRN10_RSS_IPV6, TSRN10_RSS_HASH_IPV6, ETH_RSS_IPV6},
	{TSRN10_RSS_IPV6, TSRN10_RSS_HASH_IPV6, ETH_RSS_FRAG_IPV6},
	{TSRN10_RSS_IPV6, TSRN10_RSS_HASH_IPV6, ETH_RSS_NONFRAG_IPV6_OTHER},
	{TSRN10_RSS_IPV4_TCP, TSRN10_RSS_HASH_IPV4_TCP, ETH_RSS_NONFRAG_IPV4_TCP},
	{TSRN10_RSS_IPV4_UDP, TSRN10_RSS_HASH_IPV4_UDP, ETH_RSS_NONFRAG_IPV4_UDP},
	{TSRN10_RSS_IPV4_SCTP, TSRN10_RSS_HASH_IPV4_SCTP, ETH_RSS_NONFRAG_IPV4_SCTP},
	{TSRN10_RSS_IPV6_TCP, TSRN10_RSS_HASH_IPV6_TCP, ETH_RSS_NONFRAG_IPV6_TCP},
	{TSRN10_RSS_IPV6_UDP, TSRN10_RSS_HASH_IPV6_UDP, ETH_RSS_NONFRAG_IPV6_UDP},
	{TSRN10_RSS_IPV6_SCTP, TSRN10_RSS_HASH_IPV6_SCTP, ETH_RSS_NONFRAG_IPV6_SCTP}
};

static const struct
tsrn10_rss_cfg_match_pattern rss_match_pattern[] = {
	{ETH_RSS_IPV4,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV4)},
	{ETH_RSS_FRAG_IPV4,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV4)},
	{ETH_RSS_IPV6,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV6)},
	{ETH_RSS_FRAG_IPV6,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV6)},
	{ETH_RSS_NONFRAG_IPV4_TCP,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV4) |
		BIT64(RTE_FLOW_ITEM_TYPE_TCP)},
	{ETH_RSS_NONFRAG_IPV4_UDP,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV4) |
		BIT64(RTE_FLOW_ITEM_TYPE_UDP)},
	{ETH_RSS_NONFRAG_IPV4_SCTP,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV4) |
		BIT64(RTE_FLOW_ITEM_TYPE_SCTP)},
	{ETH_RSS_NONFRAG_IPV6_TCP,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV6) |
		BIT64(RTE_FLOW_ITEM_TYPE_TCP)},
	{ETH_RSS_NONFRAG_IPV6_UDP,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV6) |
		BIT64(RTE_FLOW_ITEM_TYPE_UDP)},
	{ETH_RSS_NONFRAG_IPV6_SCTP,
		BIT64(RTE_FLOW_ITEM_TYPE_ETH) |
		BIT64(RTE_FLOW_ITEM_TYPE_IPV6) |
		BIT64(RTE_FLOW_ITEM_TYPE_SCTP)},
};

#define TSRN10_RSS_HASH_MAX_CFG (sizeof(rss_cfg) / \
				 sizeof(struct tsrn10_rss_hash_cfg))

void tsrn10_disable_rss(struct rte_eth_dev *dev);
void
tsrn10_rss_hash_set(struct rte_eth_dev *dev, struct rte_eth_rss_conf *rss_conf);
void
tsrn10_set_unknow_packet_rule(struct rte_eth_dev *dev,
			      struct tsrn10_ethertype_rule *rule);
#endif /* _TSRN10_FLOW_H_ */
