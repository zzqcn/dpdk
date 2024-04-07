#include <sys/queue.h>
#include <stdio.h>
#include <errno.h>
#include <stdint.h>
#include <stdarg.h>

#include <rte_common.h>
#include <rte_interrupts.h>
#include <rte_byteorder.h>
#include <rte_log.h>
#include <rte_debug.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(17, 5, 0, 0) > RTE_VERSION
#include <rte_pci.h>
#else
#if RTE_VERSION_NUM(21, 2, 0, 0) > RTE_VERSION
#include <rte_ethdev_pci.h>
#else
#include <ethdev_pci.h>
#endif
#endif
#include <rte_ether.h>
#include <rte_memory.h>
#include <rte_eal.h>
#include <rte_atomic.h>
#include <rte_malloc.h>
#include <rte_dev.h>
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#include <rte_flow.h>
#include <rte_flow_driver.h>
#endif
#include <rte_tailq.h>

#include "tsrn10.h"
#include "tsrn10_flow.h"
#include "base/tsrn10_tcam.h"

uint8_t rss_default_key[40] = {
	0x6D, 0x5A, 0x56, 0xDA, 0x25, 0x5B, 0x0E, 0xC2,
	0x41, 0x67, 0x25, 0x3D, 0x43, 0xA3, 0x8F, 0xB0,
	0xD0, 0xCA, 0x2B, 0xCB, 0xAE, 0x7B, 0x30, 0xB4,
	0x77, 0xCB, 0x2D, 0xA3, 0x80, 0x30, 0xF2, 0x0C,
	0x6A, 0x42, 0xB7, 0x3B, 0xBE, 0xAC, 0x01, 0xFA,
};

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
static int
tsrn10_flow_parse(struct rte_eth_dev *dev,
		  struct rte_flow *flow,
		  const struct rte_flow_attr *attr,
		  const struct rte_flow_item pattern[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error);
#endif

static int
tsrn10_add_del_ethertype_filter(struct rte_eth_dev *dev,
				struct tsrn10_ethertype_rule *rule,
				bool add,
				struct rte_flow_error *error);
static int
tsrn10_add_del_ntuple_filter(struct rte_eth_dev *dev,
			     struct tsrn10_5tuple_rule *rule,
			     bool add,
			     struct rte_flow_error *error);
static void
tsrn10_mark_flow_rx_offload_en(struct rte_eth_dev *dev, bool en);


static inline uint16_t
tsrn10_get_real_vf_queue(struct rte_eth_dev *dev __rte_unused,
			 uint8_t vf_num __rte_unused,
			 uint16_t qid __rte_unused)
{
	/* TODO */
	return 0;
}


#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
static inline enum tsrn10_5tuple_protocol
convert_protocol_type(uint8_t protocol_value)
{
	if (protocol_value == IPPROTO_TCP)
		return TSRN10_FILTER_PROTO_TCP;
	else if (protocol_value == IPPROTO_UDP)
		return TSRN10_FILTER_PROTO_UDP;
	else if (protocol_value == IPPROTO_SCTP)
		return TSRN10_FILTER_PROTO_SCTP;
	else
		return TSRN10_FILTER_PROTO_MATCH;
}

static inline int
tsrn10_parse_ntuple_filter(struct rte_eth_ntuple_filter *filter,
			   struct tsrn10_5tuple_rule *rule)
{
	if (filter->queue >= TSRN10_MAX_RX_QUEUE_NUM)
		return -EINVAL;

	switch (filter->dst_ip_mask) {
	case UINT32_MAX:
		rule->dst_ip_mask = 0;
		rule->dst_ip = filter->dst_ip;
		break;
	case 0:
		rule->dst_ip_mask = 1;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid dst_ip mask.");
		return -EINVAL;
	}

	switch (filter->src_ip_mask) {
	case UINT32_MAX:
		rule->src_ip_mask = 0;
		rule->src_ip = filter->src_ip;
		break;
	case 0:
		rule->src_ip_mask = 1;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid src_ip mask.");
		return -EINVAL;
	}

	switch (filter->dst_port_mask) {
	case UINT16_MAX:
		rule->dst_port_mask = 0;
		rule->dst_port = filter->dst_port;
		break;
	case 0:
		rule->dst_port_mask = 1;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid dst_port mask.");
		return -EINVAL;
	}

	switch (filter->src_port_mask) {
	case UINT16_MAX:
		rule->src_port_mask = 0;
		rule->src_port = filter->src_port;
		break;
	case 0:
		rule->src_port_mask = 1;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid src_port mask.");
		return -EINVAL;
	}

	switch (filter->proto_mask) {
	case UINT8_MAX:
		rule->proto_mask = 0;
		rule->proto =
		    convert_protocol_type(filter->proto);
		break;
	case 0:
		rule->proto_mask = 1;
		break;
	default:
		PMD_DRV_LOG(ERR, "invalid protocol mask.");
		return -EINVAL;
	}
	rule->queue = filter->queue;

	return 0;
}
#endif

static inline struct tsrn10_5tuple_filter *
tsrn10_5tuple_filter_lookup(struct tsrn10_5tuple_filter_list *filter_list,
			    struct tsrn10_5tuple_rule *rule)
{
	struct tsrn10_5tuple_filter *it;

	TAILQ_FOREACH(it, filter_list, node) {
		if (memcmp(rule, &it->filter_rule,
			   sizeof(struct tsrn10_5tuple_rule)) == 0) {
			return it;
		}
	}
	return NULL;
}

static uint16_t
tsrn10_get_ntuple_rule_loc(struct rte_eth_dev *dev,
			   uint16_t index)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	uint16_t i = 0;

	i = (filter_info->ntuple_rule_base +
		filter_info->max_ntuple_num - 1) - index;

	return i;
}

static void
tsrn10_setup_ntuple_filter(struct rte_eth_dev *dev,
			   struct tsrn10_5tuple_filter *filter)
{
	struct tsrn10_5tuple_rule *rule = &filter->filter_rule;
	struct tsrn10_eth_port *port_phy = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t src_port = 0, dst_port = 0;
	uint32_t src_ip = 0, dst_ip = 0;
	uint16_t queue = rule->queue;
	uint8_t l4_proto_match = 0;
	uint8_t l4_proto_type = 0;
	uint32_t filter_act = 0;
	uint32_t action = 0;
	uint32_t port = 0;
	uint8_t mask = 0;
	int i;

	if (rule->vf_used)
		queue = tsrn10_get_real_vf_queue(dev, rule->dst_vf, queue);

	queue = tsrn10_get_dma_ring_index(port_phy, queue);
	queue -= port_phy->attr.port_offset;
	/* ntuple rule store in big end */
	/* rule store is follow first set first match in
	 * positive sequence so store rule inverted sequence
	 * to achive first set last match
	 */
	i = tsrn10_get_ntuple_rule_loc(dev, filter->index);
	filter->hw_idx = i;
	src_ip = rte_be_to_cpu_32(rule->src_ip);
	dst_ip = rte_be_to_cpu_32(rule->dst_ip);
	src_port = rte_be_to_cpu_16(rule->src_port);
	dst_port = rte_be_to_cpu_16(rule->dst_port);
	tsrn10_eth_wr(hw, TSRN10_SAQF_BASE_ADDR(i), src_ip);
	tsrn10_eth_wr(hw, TSRN10_DAQF_BASE_ADDR(i), dst_ip);

	/* the hardware tuple engine need a little end port number */
	port = (dst_port << TSRN10_QF_DSTPORT_SHIFT) |
		(src_port & TSRN10_QF_SRCPORT);

	tsrn10_eth_wr(hw, TSRN10_SDPQF_BASE_ADDR(i), port);

	switch (rule->proto) {
	case TSRN10_FILTER_PROTO_TCP:
		l4_proto_type = IPPROTO_TCP;
		l4_proto_match = TSRN10_PROTO_MAT_TCP;
		break;
	case TSRN10_FILTER_PROTO_UDP:
		l4_proto_type = IPPROTO_UDP;
		l4_proto_match = TSRN10_PROTO_MAT_UDP;
		break;
	case TSRN10_FILTER_PROTO_SCTP:
		l4_proto_type = IPPROTO_SCTP;
		l4_proto_match = TSRN10_PROTO_MAT_SCTP;
		break;
	default:
		l4_proto_type = rule->proto_id;
		l4_proto_match = TSRN10_PROTO_MAT_L4;
	}

	if (rule->src_ip_mask == 1 || !src_ip)
		mask |= TSRN10_SRC_IP_MASK;
	if (rule->dst_ip_mask == 1 || !dst_ip)
		mask |= TSRN10_DST_IP_MASK;
	if (rule->src_port_mask == 1 || !src_port)
		mask |= TSRN10_SRC_PORT_MASK;
	if (rule->dst_port_mask == 1 || !dst_port)
		mask |= TSRN10_DST_PORT_MASK;
	if (rule->proto_mask == 1 && !l4_proto_type)
		mask |= TSRN10_L4_PROTO_MASK;

	/* add filter rule */
	filter_act = TSRN10_QF_FILTER_EN | mask << TSRN10_QF_MASK_SHIFT;
	filter_act |= l4_proto_type << TSRN10_QF_PROTO_SHIFT | l4_proto_match;
	tsrn10_eth_wr(hw, TSRN10_FTQF_BASE_ADDR(i), filter_act);
	/* setup action */
	if (rule->action == TSRN10_FILTER_DROP) {
		action = rule->mark_id ? TSRN10_QF_POLICY_MARK_EN : 0;
		action |= rule->mark_id | TSRN10_QF_POLICY_DROP;
		tsrn10_eth_wr(hw, TSRN10_L34TIMIR_BASE_ADDR(i), action);
	} else {
		action = rule->mark_id ? TSRN10_QF_POLICY_MARK_EN : 0;
		action |= rule->mark_id | TSRN10_QF_POLICY_PASS;
		if (rule->redir_vaild) {
			action |= TSRN10_QF_POLICY_RING_EN;
			action |= queue << TSRN10_QF_POLICY_QREDIRCT_SHIFT;
		}
		tsrn10_eth_wr(hw, TSRN10_L34TIMIR_BASE_ADDR(i), action);
	}
}

static uint16_t
tsrn10_tcam_ntuple_get_free_loc(struct rte_eth_dev *dev __rte_unused,
				struct tsrn10_5tuple_filter *filter)
{
	uint16_t idx = 0;
#define TSRN10_TCAM_MAX_GROUP_PRIO	(32)
#define TSRN10_TCAM_MAX_GROUP_NUM	(128)

	idx = 4095 - (TSRN10_TCAM_MAX_GROUP_PRIO *
		(filter->index % TSRN10_TCAM_MAX_GROUP_NUM) +
		filter->index / TSRN10_TCAM_MAX_GROUP_NUM);

	return idx;
}

static int
tsrn10_setup_tcam_ntuple_filter(struct rte_eth_dev *dev,
				struct tsrn10_5tuple_filter *filter)
{
	/* 1. find a avail location for the rule add to tcam table
	 * 2. write rule to the idx of tcam table
	 */
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_5tuple_rule *rule = &filter->filter_rule;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t src_port_mask = 0, dst_port_mask = 0;
	uint32_t src_ip_mask = 0, dst_ip_mask = 0;
	uint16_t src_port = 0, dst_port = 0;
	uint32_t src_ip = 0, dst_ip = 0;
	uint16_t queue = rule->queue;
	uint8_t l4_proto_type = 0;
	uint8_t l4_proto_mask = 0;
	uint32_t ip_mask = 0;
	uint32_t l4_port = 0;
	uint32_t l4_mask = 0;
	uint32_t mark_id = 0;
	uint32_t action = 0;
	uint16_t idx = 0;

	if (rule->vf_used)
		queue = tsrn10_get_real_vf_queue(dev, rule->dst_vf, queue);

	queue = tsrn10_get_dma_ring_index(port, queue);
	queue -= port->attr.port_offset;
	src_ip = rte_cpu_to_be_32(rule->src_ip);
	dst_ip = rte_cpu_to_be_32(rule->dst_ip);
	src_ip_mask = rte_cpu_to_be_32(rule->src_ip_mask);
	dst_ip_mask = rte_cpu_to_be_32(rule->dst_ip_mask);
	src_port = rte_cpu_to_be_16(rule->src_port);
	dst_port = rte_cpu_to_be_16(rule->dst_port);
	src_port_mask = rte_cpu_to_be_16(rule->src_port_mask);
	dst_port_mask = rte_cpu_to_be_16(rule->dst_port_mask);

	idx = tsrn10_tcam_ntuple_get_free_loc(dev, filter);
	filter->hw_idx = idx;
	/* tcam rule commit must insure rule has complete write
	 * to the hw, so we must change engine mode for protect the
	 * engine rule critical area
	 */
	tsrn10_nicx_wr(hw, TSRN10_TCAM_MODE_CTRL, TSRN10_ACL_RAM_MODE);
	tsrn10_nicx_wr(hw, TSRN10_TCAM_CACHE_EN, false);

	if (src_ip) {
		tsrn10_nicx_wr(hw, TSRN10_TCAM_SIPQF(idx), src_ip);
		ip_mask = src_ip_mask ? src_ip_mask : UINT32_MAX;
		tsrn10_nicx_wr(hw, TSRN10_TCAM_SIPQF_MASK(idx), ip_mask);
	} else {
		tsrn10_nicx_wr(hw, TSRN10_TCAM_SIPQF(idx), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_SIPQF_MASK(idx), 0);
	}
	if (dst_ip) {
		tsrn10_nicx_wr(hw, TSRN10_TCAM_DIPQF(idx), dst_ip);
		ip_mask = dst_ip_mask ? dst_ip_mask : UINT32_MAX;
		tsrn10_nicx_wr(hw, TSRN10_TCAM_DIPQF_MASK(idx), ip_mask);
	} else {
		tsrn10_nicx_wr(hw, TSRN10_TCAM_DIPQF(idx), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_DIPQF_MASK(idx), 0);
	}
	if (src_port) {
		l4_port = src_port << TSRN10_TCAM_SRC_L4P_OFFSET;
		l4_mask = (src_port_mask ? src_port_mask : UINT16_MAX)
			<< TSRN10_TCAM_SRC_L4P_OFFSET;
	}
	if (dst_port) {
		l4_port |= dst_port;
		l4_mask |= dst_port_mask ? dst_port_mask : UINT16_MAX;
	}

	if (src_port || dst_port) {
		tsrn10_nicx_wr(hw, TSRN10_TCAM_L4PQF(idx), l4_port);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_L4PQF_MASK(idx), l4_mask);
	} else {
		tsrn10_nicx_wr(hw, TSRN10_TCAM_L4PQF(idx), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_L4PQF_MASK(idx), 0);
	}
	switch (rule->proto) {
	case TSRN10_FILTER_PROTO_TCP:
		l4_proto_type = IPPROTO_TCP;
		break;
	case TSRN10_FILTER_PROTO_UDP:
		l4_proto_type = IPPROTO_UDP;
		break;
	case TSRN10_FILTER_PROTO_SCTP:
		l4_proto_type = IPPROTO_SCTP;
		break;
	default:
		l4_proto_type = rule->proto_id;
	}

	if (l4_proto_type) {
		action |= l4_proto_type;
		l4_proto_mask = rule->proto_mask ? rule->proto_mask : UINT8_MAX;
	}
	if (rule->action == TSRN10_FILTER_DROP) {
		action |= TSRN10_TCAM_ACT_DROP;
		action |= rule->mark_id ? TSRN10_TCAM_ACT_MARK_EN : 0;
		tsrn10_nicx_wr(hw, TSRN10_TCAM_ACTQF(idx), action);

		mark_id = rule->mark_id << TSRN10_TCAM_ACT_MARK_OFFSET;
		mark_id |= l4_proto_mask;
		tsrn10_nicx_wr(hw, TSRN10_TCAM_ACT_MARK(idx), mark_id);
	} else {
		action |= TSRN10_TCAM_ACT_PASS | TSRN10_TCAM_ACT_RING_EN;
		if (rule->redir_vaild) {
			action |= TSRN10_TCAM_ACT_RING_EN;
			action |= queue << TSRN10_TCAM_ACT_QID_OFFSET;
		}
		action |= rule->mark_id ? TSRN10_TCAM_ACT_MARK_EN : 0;
		tsrn10_nicx_wr(hw, TSRN10_TCAM_ACTQF(idx), action);

		mark_id = rule->mark_id << TSRN10_TCAM_ACT_MARK_OFFSET;
		mark_id	|= l4_proto_mask;
		tsrn10_nicx_wr(hw, TSRN10_TCAM_ACT_MARK(idx), mark_id);
	}

	tsrn10_nicx_wr(hw, TSRN10_TCAM_MODE_CTRL, TSRN10_ACL_TCAM_MODE);

	return 0;
}

static int
tsrn10_add_ntuple_filter(struct rte_eth_dev *dev,
			 struct tsrn10_5tuple_filter *filter)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	uint16_t i;

	/* 1.check weather rule reach the max filter rule TODO */
	if (filter_info->ntuple_rule_count >= filter_info->max_ntuple_num)
		return -ENOMEM;

	/* Find a valid Location Of Ethertype Rule Sequence */
	for (i = 0; i < filter_info->max_ntuple_num; i++) {
		if (!(filter_info->fivetuple_mask[i])) {
			filter_info->fivetuple_mask[i] |= 1;
			filter->index = i;
			TAILQ_INSERT_TAIL(&filter_info->fivetuple_list,
					  filter,
					  node);
			break;
		}
	}

	filter_info->ntuple_rule_count++;

	if (filter_info->mode == TSRN10_TUPLE_NORMAL_MODE)
		tsrn10_setup_ntuple_filter(dev, filter);
	else
		tsrn10_setup_tcam_ntuple_filter(dev, filter);

	return 0;
}

static void
tsrn10_del_5tuple_filter(struct rte_eth_dev *dev,
			 struct tsrn10_5tuple_filter *filter)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t index = filter->hw_idx;
	uint16_t sw_idx = filter->index;

	TAILQ_REMOVE(&filter_info->fivetuple_list, filter, node);
	filter_info->fivetuple_mask[sw_idx] = 0;
	rte_free(filter);
	if (filter_info->mode == TSRN10_TUPLE_NORMAL_MODE) {
		tsrn10_eth_wr(hw, TSRN10_SDPQF_BASE_ADDR(index), 0);
		tsrn10_eth_wr(hw, TSRN10_FTQF_BASE_ADDR(index), 0);
		tsrn10_eth_wr(hw, TSRN10_L34TIMIR_BASE_ADDR(index), 0);
	} else {
		/* tcam rule commit must insure rule has complete write
		 * to the hw, so we must change engine mode for protect the
		 * engine rule critical area
		 */
		tsrn10_nicx_wr(hw, TSRN10_TCAM_MODE_CTRL, TSRN10_ACL_RAM_MODE);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_CACHE_EN, false);

		tsrn10_nicx_wr(hw, TSRN10_TCAM_DIPQF(index), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_DIPQF_MASK(index), 0);

		tsrn10_nicx_wr(hw, TSRN10_TCAM_SIPQF(index), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_SIPQF_MASK(index), 0);

		tsrn10_nicx_wr(hw, TSRN10_TCAM_L4PQF(index), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_L4PQF_MASK(index), 0);

		tsrn10_nicx_wr(hw, TSRN10_TCAM_ACTQF(index), 0);
		tsrn10_nicx_wr(hw, TSRN10_TCAM_ACT_MARK(index), 0);

		tsrn10_nicx_wr(hw, TSRN10_TCAM_MODE_CTRL, TSRN10_ACL_TCAM_MODE);
	}

	filter_info->ntuple_rule_count--;
}

static void
tsrn10_tcam_module_en(struct rte_eth_dev *dev,
		      struct tsrn10_filter_info *filter_info)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint32_t en = 0;

	en = filter_info->ntuple_rule_count ? true : false;
	tsrn10_nicx_wr(hw, TSRN10_TCAM_ENABLE, en);
}

#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
static int
tsrn10_get_ntuple_filter(struct rte_eth_dev *dev,
			 struct rte_eth_ntuple_filter *rule_filter)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_5tuple_rule rule_5tuple;
	struct tsrn10_5tuple_filter *filter;
	int ret;

	if (rule_filter->flags != RTE_5TUPLE_FLAGS) {
		PMD_DRV_LOG(ERR, "only 5tuple is supported.");
		return -EINVAL;
	}

	memset(&rule_5tuple, 0, sizeof(struct tsrn10_5tuple_rule));
	ret = tsrn10_parse_ntuple_filter(rule_filter, &rule_5tuple);
	if (ret < 0)
		return ret;

	filter = tsrn10_5tuple_filter_lookup(&filter_info->fivetuple_list,
			&rule_5tuple);
	if (filter == NULL) {
		PMD_DRV_LOG(ERR, "filter doesn't exist.");
		return -ENOENT;
	}
	rule_filter->queue = filter->filter_rule.queue;

	return 0;
}

/*
 * tsrn10_ntuple_filter_handle - Handle operations for ntuple filter.
 * @dev: pointer to rte_eth_dev structure
 * @filter_op:operation will be taken.
 * @arg: a pointer to specific structure corresponding to the filter_op
 */
int tsrn10_ntuple_filter_handle(struct rte_eth_dev *dev,
				enum rte_filter_op filter_op,
				void *arg)
{
	struct rte_eth_ntuple_filter *rule =
		(struct rte_eth_ntuple_filter *)arg;
	struct tsrn10_5tuple_rule rule_5tuple;
	struct rte_flow_error error;
	int ret;

	memset(&error, 0, sizeof(error));
	if (filter_op == RTE_ETH_FILTER_NOP)
		return 0;

	if (arg == NULL) {
		PMD_DRV_LOG(ERR, "arg shouldn't be NULL for operation %u.",
				filter_op);
		return -EINVAL;
	}

	if (filter_op != RTE_ETH_FILTER_GET) {
		if (rule->flags != RTE_5TUPLE_FLAGS)
			PMD_DRV_LOG(ERR, "only tuple 5 is supported.");

		if (rule->queue >= dev->data->nb_rx_queues) {
			PMD_DRV_LOG(ERR, "Rx queue is override %d\n",
					dev->data->nb_rx_queues);
			return -EINVAL;
		}
		memset(&rule_5tuple, 0, sizeof(struct tsrn10_5tuple_rule));
		ret = tsrn10_parse_ntuple_filter(rule,
				&rule_5tuple);
		if (ret)
			return ret;

		if (rule->flags == RTE_ETHTYPE_FLAGS_DROP)
			rule_5tuple.action = TSRN10_FILTER_DROP;
		else
			rule_5tuple.action = TSRN10_FILTER_PASS;
	}

	switch (filter_op) {
	case RTE_ETH_FILTER_ADD:
		ret = tsrn10_add_del_ntuple_filter(dev,
						   &rule_5tuple,
						   true,
						   &error);
		break;
	case RTE_ETH_FILTER_DELETE:
		ret = tsrn10_add_del_ntuple_filter(dev,
						   &rule_5tuple,
						   false,
						   &error);
		break;
	case RTE_ETH_FILTER_GET:
		ret = tsrn10_get_ntuple_filter(dev,
				(struct rte_eth_ntuple_filter *)arg);
		break;
	default:
		PMD_DRV_LOG(ERR, "unsupported operation %u.", filter_op);
		ret = -EINVAL;
		break;
	}
	if (error.message)
		PMD_DRV_LOG(ERR, "%s", error.message);

	return ret;
}
#endif

static inline struct tsrn10_ethertype_filter *
tsrn10_ethertype_filter_lookup(struct tsrn10_ethertype_filter_list *filter_list,
			       struct tsrn10_ethertype_rule *rule)
{
	struct tsrn10_ethertype_filter *it;

	TAILQ_FOREACH(it, filter_list, node) {
		if (!memcmp(&it->filter_rule.param, &rule->param,
					sizeof(rule->param)))
			return it;
	}
	return NULL;
}

static inline int
tsrn10_ethertype_filter_remove(struct rte_eth_dev *dev,
			       struct tsrn10_ethertype_filter *filter)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint16_t hw_idx = filter->hw_idx;
	uint16_t sw_idx = filter->index;
	uint32_t etqf = 0;
	uint32_t etqs = 0;

	filter_info->ethertype_mask[sw_idx] = 0;

	filter->filter_rule.param.ethertype = 0;

	tsrn10_eth_wr(hw, TSRN10_L2_ETQF_ADDR(hw_idx), etqf);
	tsrn10_eth_wr(hw, TSRN10_L2_ETQS_ADDR(hw_idx), etqs);

	TAILQ_REMOVE(&filter_info->ethertype_list, filter, node);
	rte_free(filter);
	filter_info->ethertype_rule_count--;

	return 0;
}

void
tsrn10_set_unknow_packet_rule(struct rte_eth_dev *dev,
			      struct tsrn10_ethertype_rule *rule)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t queue = rule->queue;
	uint32_t etqf = 0, etqs = 0;

	queue = tsrn10_get_dma_ring_index(port, queue);
	queue -= port->attr.port_offset;
	etqs = TSRN10_L2_ETQS_RING_EN |
		(queue << TSRN10_L2_ETQS_RING_SHIFT) |
		(rule->param.action << TSRN10_L2_ETQS_ACTION_SHIFT);
	etqf = TSRN10_L2_ETQF_EN;

	tsrn10_eth_wr(hw, TSRN10_L2_UNKONW_ETQF, etqf);
	tsrn10_eth_wr(hw, TSRN10_L2_UNKONW_ETQS, etqs);
}


static uint16_t
tsrn10_get_ethertype_rule_loc(struct rte_eth_dev *dev,
			      uint16_t index)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	uint16_t i = 0;

	i = (filter_info->ethertype_rule_base +
		filter_info->max_ethertype_rule_num - 1) - index;

	return i;
}

static int
tsrn10_add_ethertype_filter(struct rte_eth_dev *dev,
			    struct tsrn10_ethertype_filter *filter)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_ethertype_rule *rule = &filter->filter_rule;
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint8_t queue = rule->queue;
	uint32_t etqf = 0, etqs = 0;
	int i;
	/* Find a valid Location Of Ethertype Rule Sequence */
	for (i = 0; i < TSRN10_MAX_LAYER2_FILTERS; i++) {
		if (!(filter_info->ethertype_mask[i])) {
			filter_info->ethertype_mask[i] |= 1;
			filter->index = i;
			TAILQ_INSERT_TAIL(&filter_info->ethertype_list,
					filter,
					node);
			break;
		}
	}
	queue = tsrn10_get_dma_ring_index(port, queue);
	queue -= port->attr.port_offset;
	filter->hw_idx = tsrn10_get_ethertype_rule_loc(dev, filter->index);

	filter_info->ethertype_rule_count++;
	etqs = TSRN10_L2_ETQS_RING_EN |
		(queue << TSRN10_L2_ETQS_RING_SHIFT) |
		(rule->param.action << TSRN10_L2_ETQS_ACTION_SHIFT);
	if (!rule->param.mark_dis)
		etqs |= (rule->param.mark_id & TSRN10_L2_ETQS_MARK_MASK) |
			TSRN10_L2_ETQS_MARK_ATTR_EN;

	etqf = TSRN10_L2_ETQF_EN | rule->param.ethertype;

	tsrn10_eth_wr(hw, TSRN10_L2_ETQF_ADDR(filter->hw_idx), etqf);
	tsrn10_eth_wr(hw, TSRN10_L2_ETQS_ADDR(filter->hw_idx), etqs);

	return 0;
}

#ifdef USE
static inline void
tsrn10_ethertype_filter_enable(struct tsrn10_hw *hw, bool en)
{
	uint32_t reg = tsrn10_eth_rd(hw, TSRN10_L2TYPE_FILTER_CTRL);

	if (en)
		reg |= TSRN10_L2TYPE_FILTER_EN;
	else
		reg ^= TSRN10_L2TYPE_FILTER_EN;

	tsrn10_eth_wr(hw, TSRN10_L2TYPE_FILTER_CTRL, reg);
}
#endif

#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
static int
tsrn10_parse_ethertype_filter(struct rte_eth_dev *dev,
			      struct rte_eth_ethertype_filter *filter,
			      struct tsrn10_ethertype_rule *rule)
{
	if (filter->flags & RTE_ETHTYPE_FLAGS_MAC) {
		PMD_DRV_LOG(ERR, "mac compare is unsupported.");
		return -EINVAL;
	}
	if (filter->queue > dev->data->nb_rx_queues) {
		PMD_DRV_LOG(ERR, "Rx queue is override %d\n",
				dev->data->nb_rx_queues);
		return -EINVAL;
	}

	rule->queue = filter->queue;

	rule->param.ethertype = filter->ether_type;

	if (filter->flags & RTE_ETHTYPE_FLAGS_DROP)
		rule->param.action = TSRN10_FILTER_DROP;
	else
		rule->param.action = TSRN10_FILTER_PASS;

	return 0;
}

static int
tsrn10_get_ethertype_filter(struct rte_eth_dev *dev,
			    struct rte_eth_ethertype_filter *filter)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_ethertype_filter *etype_filter;
	struct tsrn10_ethertype_rule rule;

	memset(&rule, 0, sizeof(rule));
	if (tsrn10_parse_ethertype_filter(dev, filter, &rule))
		return -EINVAL;

	etype_filter = tsrn10_ethertype_filter_lookup(&filter_info->ethertype_list, &rule);
	if (!etype_filter) {
		PMD_DRV_LOG(ERR, "ethertype (0x%04x) filter doesn't exist.",
				filter->ether_type);
		return -ENOENT;
	}

	filter->ether_type = etype_filter->filter_rule.param.ethertype;
	filter->flags = (etype_filter->filter_rule.param.action ==
			TSRN10_FILTER_DROP) ?
			RTE_ETHTYPE_FLAGS_DROP : 0;
	filter->queue = etype_filter->filter_rule.queue;

	return 0;
}

/*
 * tsrn10_ethertype_filter_handle - Handle operations for ethertype filter.
 * @dev: pointer to rte_eth_dev structure
 * @filter_op:operation will be taken.
 * @arg: a pointer to specific structure corresponding to the filter_op
 */
int tsrn10_ethertype_filter_handle(struct rte_eth_dev *dev,
				   enum rte_filter_op filter_op,
				   void *arg)
{
	struct tsrn10_ethertype_rule ethertype_rule;
	struct rte_eth_ethertype_filter *filter = arg;
	struct rte_flow_error error;
	int ret = 0;

	memset(&error, 0, sizeof(error));
	memset(&ethertype_rule, 0, sizeof(ethertype_rule));

	if (filter_op == RTE_ETH_FILTER_NOP)
		return 0;

	if (arg == NULL) {
		PMD_DRV_LOG(ERR, "arg shouldn't be NULL for operation %u.",
				filter_op);
		return -EINVAL;
	}
	if (filter_op != RTE_ETH_FILTER_GET)
		tsrn10_parse_ethertype_filter(dev, filter, &ethertype_rule);

	switch (filter_op) {
	case RTE_ETH_FILTER_ADD:
		ret = tsrn10_add_del_ethertype_filter(dev, &ethertype_rule,
						      true, &error);
		break;
	case RTE_ETH_FILTER_DELETE:
		ret = tsrn10_add_del_ethertype_filter(dev, &ethertype_rule,
						      false, &error);
		break;
	case RTE_ETH_FILTER_GET:
		ret = tsrn10_get_ethertype_filter(dev,
				  (struct rte_eth_ethertype_filter *)arg);
		break;
	default:
		PMD_DRV_LOG(ERR, "unsupported operation %u.", filter_op);
		ret = -EINVAL;
		break;
	}
	if (error.message)
		PMD_DRV_LOG(ERR, "%s", error.message);

	return ret;
}
#endif

static int
tsrn10_add_del_syn_filter(struct rte_eth_dev *dev,
			  struct tsrn10_tcp_sync_filter_rule *filter,
			  bool add,
			  struct rte_flow_error *error __rte_unused)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint32_t syn_prio = 0;
	uint32_t synfq = 0;
	uint16_t queue = 0;

	queue = tsrn10_get_dma_ring_index(port, filter->queue);
	queue -= port->attr.port_offset;

	if (add) {
		syn_prio = TSRN10_SYNC_PRIO_EN;
		if (filter->high_pri)
			syn_prio |= TSRN10_SYNC_PRIO_HIGH;
		else
			syn_prio &= ~TSRN10_SYNC_PRIO_HIGH;
		if (filter->action == TSRN10_FILTER_DROP) {
			synfq = TSRN10_SYNC_POLICY_DROP;
		} else {
			if (filter->redir_vaild) {
				synfq = TSRN10_SYNC_POLICY_RING_EN;
				synfq |= queue << TSRN10_SYNC_POLICY_RING_SHIFT;
			}
			if (filter->mark_en) {
				synfq |= TSRN10_SYNC_POLICY_MARK_EN;
				synfq |= filter->mark_id;
			}
		}
		if (filter->mark_en)
			tsrn10_mark_flow_rx_offload_en(dev, 1);
	} else {
		syn_prio = tsrn10_eth_rd(hw, TSRN10_SYNQF_PRIO_ADDR);
		if (!(syn_prio & TSRN10_SYNC_PRIO_EN))
			return -ENOENT;

		syn_prio &= ~(TSRN10_SYNC_PRIO_EN | TSRN10_SYNC_PRIO_HIGH);
		synfq = 0;
		if (filter->mark_en)
			tsrn10_mark_flow_rx_offload_en(dev, 0);
	}

	tsrn10_eth_wr(hw, TSRN10_SYNQF_ADDR, synfq);
	tsrn10_eth_wr(hw, TSRN10_SYNQF_PRIO_ADDR, syn_prio);

	filter_info->syn_prio = syn_prio;
	filter_info->synfq = synfq;

	return 0;
}

#if RTE_VERSION_NUM(20, 11, 0, 0) > RTE_VERSION
static int
tsrn10_syn_filter_get(struct rte_eth_dev *dev,
		      struct rte_eth_syn_filter *filter)
{
	struct tsrn10_filter_info *filter_info =
		TSRN10_DEV_TO_FILTER_INFO(dev);

	uint32_t syn_prio = filter_info->syn_prio;
	uint32_t synfq = filter_info->synfq;

	if (syn_prio & TSRN10_SYNC_PRIO_EN) {
		filter->hig_pri = (syn_prio & TSRN10_SYNC_PRIO_HIGH) ? 1 : 0;
		filter->queue = (uint16_t)
			(((synfq >> TSRN10_SYNC_POLICY_RING_SHIFT) &
			  TSRN10_SYNC_POLICY_RING_MASK));
		return 0;
	}

	return -ENOENT;
}

int tsrn10_syn_filter_handle(struct rte_eth_dev *dev,
			     enum rte_filter_op filter_op,
			     void *arg)
{
	struct rte_eth_syn_filter *rule = (struct rte_eth_syn_filter *)arg;
	struct tsrn10_tcp_sync_filter_rule filter;
	struct rte_flow_error error;
	int ret = 0;

	memset(&error, 0, sizeof(error));
	if (filter_op == RTE_ETH_FILTER_NOP)
		return 0;

	if (arg == NULL) {
		PMD_DRV_LOG(ERR, "arg shouldn't be NULL for operation %u",
				filter_op);
		return -EINVAL;
	}
	if (filter_op != RTE_ETH_FILTER_GET) {
		memset(&filter, 0, sizeof(filter));
		filter.queue = rule->queue;
		filter.high_pri = rule->hig_pri;
	}
	switch (filter_op) {
	case RTE_ETH_FILTER_ADD:
		ret = tsrn10_add_del_syn_filter(dev,
						&filter,
						true, &error);
		break;
	case RTE_ETH_FILTER_DELETE:
		ret = tsrn10_add_del_syn_filter(dev,
						&filter,
						false, &error);
		break;
	case RTE_ETH_FILTER_GET:
		ret = tsrn10_syn_filter_get(dev,
					    (struct rte_eth_syn_filter *)arg);
		break;
	default:
		PMD_DRV_LOG(ERR, "unsupported operation %u", filter_op);
		ret = -EINVAL;
		break;
	}
	if (error.message)
		PMD_DRV_LOG(ERR, "%s", error.message);

	return ret;
}
#endif

void tsrn10_disable_rss(struct rte_eth_dev *dev)
{
	/* 1.Clear Redirection Table */
	/* 2.Clear Rss Hash Cfg */
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct rte_eth_rss_conf *cur_act = &port->rss_cfg;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_rx_queue *rxq = NULL;
	uint8_t rss_disable = 0;
	uint32_t mrqc_reg = 0;
	uint16_t p_id, index;
	uint16_t idx;

	memset(cur_act, 0, sizeof(*cur_act));
	p_id = port->attr.nr_lane;

	for (idx = 0; idx < adapter->num_ports; idx++)
		if (!adapter->port[idx]->rss_cfg.rss_hf)
			rss_disable++;

	for (idx = 0; idx < dev->data->nb_rx_queues; idx++) {
		rxq = dev->data->rx_queues[idx];
		if (!rxq)
			continue;
		rxq->rx_offload_capa &= ~DEV_RX_OFFLOAD_RSS_HASH;
	}
	/* Get Default Queue Ring Num */
	rxq = dev->data->rx_queues[0];
	index = rxq->attr.index - port->attr.port_offset;
	for (idx = 0; idx < TSRN10_RSS_INDIR_SIZE; idx++)
		tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, idx),
				index);

	if (rss_disable == adapter->num_ports) {
		mrqc_reg = tsrn10_eth_rd(hw, TSRN10_RSS_MRQC_ADDR);
		mrqc_reg &= ~TSRN10_RSS_HASH_CFG_MASK;
		tsrn10_eth_wr(hw, TSRN10_RSS_MRQC_ADDR, mrqc_reg);
	}
}

void
tsrn10_rss_hash_set(struct rte_eth_dev *dev, struct rte_eth_rss_conf *rss_conf)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_rx_queue *rxq = NULL;
	uint8_t *hash_key;
	uint32_t mrqc_reg = 0;
	uint32_t rss_key;
	uint64_t rss_hf;
	uint16_t i;

	rss_hf = rss_conf->rss_hf;
	hash_key = rss_conf->rss_key;
	if (hash_key != NULL) {
		for (i = 0; i < 10; i++) {
			rss_key  = hash_key[(i * 4)];
			rss_key |= hash_key[(i * 4) + 1] << 8;
			rss_key |= hash_key[(i * 4) + 2] << 16;
			rss_key |= hash_key[(i * 4) + 3] << 24;
			rss_key = rte_cpu_to_be_32(rss_key);
			tsrn10_eth_wr(hw, TSRN10_RSS_KEY_TABLE(9 - i), rss_key);
		}
	}
	if (rss_hf) {
		for (i = 0; i < RTE_DIM(rss_cfg); i++)
			if (rss_cfg[i].rss_flag & rss_hf)
				mrqc_reg |= rss_cfg[i].reg_val;

#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		uint64_t rss_hash_level = ETH_RSS_LEVEL(rss_conf->rss_hf);
		/* Enable Inner RSS mode
		 * If Enable, Outer(VXLAN/NVGRE) RSS Won't Calc
		 */
		if (rss_hash_level == ETH_RSS_LEVEL_INNERMOST)
			tsrn10_eth_wr(hw, TSRN10_RSS_INNER_CTRL,
					TSRN10_INNER_RSS_EN);
#endif
		tsrn10_eth_wr(hw, TSRN10_RSS_MRQC_ADDR, mrqc_reg);
		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			rxq = dev->data->rx_queues[i];
			if (!rxq)
				continue;
			rxq->rx_offload_capa |= DEV_RX_OFFLOAD_RSS_HASH;
		}
	}
}

static void
tsrn10_enable_rxq_mark(struct rte_eth_dev *dev, bool en)
{
	int i;

	for (i = 0; i < dev->data->nb_rx_queues; i++) {
		struct tsrn10_rx_queue *rxq = dev->data->rx_queues[i];

		if (!rxq)
			continue;
		rxq->mark_enabled = en;
	}
	PMD_DRV_LOG(DEBUG, "MARK Flow Action on RX set to %d", en);
}

static void
tsrn10_mark_flow_rx_offload_en(struct rte_eth_dev *dev, bool en)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);

	if (en)
		filter_info->mark_flow_cnt++;
	else
		if (filter_info->mark_flow_cnt)
			filter_info->mark_flow_cnt--;
	if (filter_info->mark_flow_cnt)
		tsrn10_enable_rxq_mark(dev, 1);
	else
		tsrn10_enable_rxq_mark(dev, 0);
}

static int
tsrn10_add_del_ethertype_filter(struct rte_eth_dev *dev,
				struct tsrn10_ethertype_rule *rule,
				bool add,
				struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_ethertype_filter *filter;
	int ret = 0;

	filter = tsrn10_ethertype_filter_lookup(&filter_info->ethertype_list,
						rule);
	if (filter && add)
		return rte_flow_error_set(error, EEXIST,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Add Cur Ethertype Rule Has Been Exists");
	if (!filter && !add)
		return rte_flow_error_set(error, ENOENT,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Delete Cur Ethertype Rule Isn't Exists");
	if (add) {
		if (filter_info->ethertype_rule_count >=
			filter_info->max_ethertype_rule_num)
			return rte_flow_error_set(error, ENOMEM,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Ethertype Rule Is Out Of Range Support");
		filter = rte_zmalloc("tsrn10_ethertype_filter",
			       sizeof(struct tsrn10_ethertype_filter), 0);
		if (filter == NULL)
			return rte_flow_error_set(error, ENOMEM,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Alloc Ethertype Rule Isn't Failed");

		rte_memcpy(&filter->filter_rule,
				rule,
				sizeof(struct tsrn10_ethertype_rule));
		ret = tsrn10_add_ethertype_filter(dev, filter);
		if (ret < 0) {
			rte_free(filter);
			return ret;
		}
		if (!filter->filter_rule.param.mark_dis)
			tsrn10_mark_flow_rx_offload_en(dev, 1);
	} else {
		tsrn10_ethertype_filter_remove(dev, filter);
		if (!filter->filter_rule.param.mark_dis)
			tsrn10_mark_flow_rx_offload_en(dev, 0);
	}

	return 0;
}

static int
tsrn10_add_del_ntuple_filter(struct rte_eth_dev *dev,
			     struct tsrn10_5tuple_rule *rule,
			     bool add,
			     struct rte_flow_error *error)
{
	/*1. check weather tuple 5 rule */
	/*2. parse 5 tuple filter to rule match rule */
	/*3. lookup filter by match rule */
	/*4. if not add drop it */
	/*5. add the new rule to filter list */
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_5tuple_filter *filter;

	filter = tsrn10_5tuple_filter_lookup(&filter_info->fivetuple_list,
			rule);
	if (filter != NULL && add)
		return rte_flow_error_set(error, EEXIST,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Add Cur Ntuple Rule Has Been Exists");

	if (filter == NULL && !add)
		return rte_flow_error_set(error, ENOENT,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Delete Cur Ntuple Rule Isn't Exists");

	if (add) {
		filter = rte_zmalloc("tsrn10_5tuple_filter",
				sizeof(struct tsrn10_5tuple_filter), 0);
		if (filter == NULL)
			return rte_flow_error_set(error, ENOMEM,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Alloc Ntuple Rule Mem Failed");
		rte_memcpy(&filter->filter_rule,
				rule,
				sizeof(struct tsrn10_5tuple_rule));
		if (tsrn10_add_ntuple_filter(dev, filter)) {
			rte_free(filter);
			return rte_flow_error_set(error, ENOMEM,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Out Of Range Support For Ntuple Rule");
		}
		if (!filter->filter_rule.mark_dis)
			tsrn10_mark_flow_rx_offload_en(dev, 1);
	} else {
		tsrn10_del_5tuple_filter(dev, filter);
		if (!filter->filter_rule.mark_dis)
			tsrn10_mark_flow_rx_offload_en(dev, 0);
	}
	if (filter_info->mode == TSRN10_TUPLE_TCAM_MODE)
		tsrn10_tcam_module_en(dev, filter_info);

	return 0;
}

#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
#ifdef USE
static int
tsrn10_rss_cfg_is_same(const struct rte_flow_action_rss *comp,
		       const struct rte_flow_action_rss *with)
{
	return (comp->func == with->func &&
			comp->level == with->level &&
			comp->types == with->types &&
			comp->key_len == with->key_len &&
			comp->queue_num == with->queue_num &&
			!memcmp(comp->key, with->key, with->key_len) &&
			!memcmp(comp->queue, with->queue,
				sizeof(*with->queue) * with->queue_num));
}
#endif

static void
tsrn10_rss_redirect_update(struct rte_eth_dev *dev,
			   struct tsrn10_rss_filter_pattern *filter)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint32_t *indirtbl = port->indirtbl;
	uint8_t p_id = port->attr.nr_port;
	struct tsrn10_rx_queue *rxq;
	uint8_t redir_rid = 0;
	uint8_t dma_index = 0;
	uint16_t i, j = 0;

	memset(indirtbl, 0, sizeof(uint32_t) * TSRN10_RSS_INDIR_SIZE);
	if (filter->rss_cfg.queue_num) {
		for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++) {
			redir_rid = (uint8_t)filter->rss_cfg.queue[j];
			redir_rid %= dev->data->nb_rx_queues;
			rxq = dev->data->rx_queues[redir_rid];
			dma_index = rxq->attr.index - port->attr.port_offset;
			indirtbl[i] = dma_index;
			j = (j == filter->rss_cfg.queue_num - 1) ? 0 : (j + 1);
		}
		/* TODO We Must Turn Indirtbl To Hardware Real Ring
		 * Value When We Are In Two/Four Port mode
		 */
		for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++)
			tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, i),
					indirtbl[i]);
	}
}

static void tsrn10_rss_conf_update(struct rte_eth_dev *dev,
				   struct tsrn10_rss_rule *rule,
				   struct rte_eth_rss_conf *rss_conf,
				   bool action)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct rte_eth_rss_conf *cur_act = &port->rss_cfg;

	if (action) {
		rss_conf->rss_key = rule->rss_cfg.key_len ?
				(void *)(uintptr_t)rule->rss_cfg.key : NULL;
		rss_conf->rss_key_len = rule->rss_cfg.key_len;
		rss_conf->rss_hf = cur_act->rss_hf | rule->rss_cfg.types;
	} else {
		rss_conf->rss_key = rule->rss_cfg.key_len ?
				(void *)(uintptr_t)rule->rss_cfg.key : NULL;
		rss_conf->rss_key_len = rule->rss_cfg.key_len;
		rss_conf->rss_hf = cur_act->rss_hf & ~rule->rss_cfg.types;
	}
}

static void
tsrn10_rss_reset_reta_tb(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	struct tsrn10_rx_queue *rxq = NULL;
	uint16_t i = 0, j = 0, p_id = 0;
	uint32_t dma_index = 0;

	p_id = port->attr.nr_lane;

	if (port->hw_rss_en) {
		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			rxq = dev->data->rx_queues[i];
			if (!rxq)
				continue;
			rxq->rx_offload_capa |= DEV_RX_OFFLOAD_RSS_HASH;
		}
		for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++) {
			j = i % dev->data->nb_rx_queues;
			rxq = dev->data->rx_queues[j];
			if (!rxq)
				continue;
			dma_index = rxq->attr.index - port->attr.port_offset;
			tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, i), dma_index);
		}
	} else {
		for (i = 0; i < dev->data->nb_rx_queues; i++) {
			rxq = dev->data->rx_queues[i];
			if (!rxq)
				continue;
			rxq->rx_offload_capa &= ~DEV_RX_OFFLOAD_RSS_HASH;
		}
		rxq = dev->data->rx_queues[0];
		if (!rxq)
			TSRN10_PMD_LOG(ERR, "default RXQ is NULL");
		dma_index = rxq->attr.index - port->attr.port_offset;
		for (i = 0; i < TSRN10_RSS_INDIR_SIZE; i++) {
			tsrn10_eth_wr(hw, TSRN10_RSS_REDIR_TB(p_id, i),
					dma_index);
		}
	}
}

static void
tsrn10_rss_reset_key(struct rte_eth_dev *dev)
{
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint32_t rss_key = 0;
	uint8_t *hash_key;
	uint8_t i = 0;

	hash_key = rss_default_key;
	for (i = 0; i < 10; i++) {
		rss_key  = hash_key[(i * 4)];
		rss_key |= hash_key[(i * 4) + 1] << 8;
		rss_key |= hash_key[(i * 4) + 2] << 16;
		rss_key |= hash_key[(i * 4) + 3] << 24;
		rss_key = rte_cpu_to_be_32(rss_key);
		tsrn10_eth_wr(hw, TSRN10_RSS_KEY_TABLE(9 - i), rss_key);
	}
}

static void
tsrn10_rss_reset_type(struct rte_eth_dev *dev)
{
	struct tsrn10_eth_port *port = TSRN10_DEV_TO_PORT(dev);
	struct rte_eth_rss_conf *cur_act = &port->rss_cfg;
	struct tsrn10_hw *hw = TSRN10_DEV_TO_HW(dev);
	uint32_t mrqc_reg = 0;
	uint64_t rss_hf;
	uint16_t i = 0;

	rss_hf = cur_act->rss_hf;
	if (rss_hf) {
		for (i = 0; i < RTE_DIM(rss_cfg); i++)
			if (rss_cfg[i].rss_flag & rss_hf)
				mrqc_reg |= rss_cfg[i].reg_val;
#if RTE_VERSION_NUM(20, 11, 0, 0) <= RTE_VERSION
		uint64_t rss_hash_level = ETH_RSS_LEVEL(rss_hf);
		/* Enable Inner RSS mode
		 * If Enable, Outer(VXLAN/NVGRE) RSS Won't Calc
		 */
		if (rss_hash_level == ETH_RSS_LEVEL_INNERMOST)
			tsrn10_eth_wr(hw, TSRN10_RSS_INNER_CTRL,
					TSRN10_INNER_RSS_EN);
		else
			tsrn10_eth_wr(hw, TSRN10_RSS_INNER_CTRL,
					0);
#endif
		tsrn10_eth_wr(hw, TSRN10_RSS_MRQC_ADDR, mrqc_reg);
	} else
		tsrn10_disable_rss(dev);
}

static int
tsrn10_del_rss_filter(struct rte_eth_dev *dev,
		      struct tsrn10_rss_rule *rule,
		      struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_rss_filter_pattern *ptr;
	void *temp;

	TAILQ_FOREACH_SAFE(ptr, &filter_info->rss_cfg_list, node, temp) {
		if (!memcmp(&ptr->rss_cfg, &rule->rss_cfg,
				sizeof(struct rte_flow_action_rss)) &&
				ptr->inset == rule->inset) {
			/* reset queue set to default reta */
			if (rule->inset & TSRN10_RSS_INSET_QUEUE)
				tsrn10_rss_reset_reta_tb(dev);
			/* reset the rss key to default */
			if (rule->inset & TSRN10_RSS_INSET_KEY)
				tsrn10_rss_reset_key(dev);
			/* reset the rss type to default */
			if (rule->inset & TSRN10_RSS_INSET_TYPE)
				tsrn10_rss_reset_type(dev);

			TAILQ_REMOVE(&filter_info->rss_cfg_list, ptr, node);
			rte_free(ptr);

			return 0;
		}
	}

	return rte_flow_error_set(error, EINVAL,
			RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
			"cur destry rss rule cfg not exists");
}

static int
tsrn10_check_rss_rule_exist(struct tsrn10_filter_info *filter_info,
			    struct tsrn10_rss_rule *rule)
{
	struct tsrn10_rss_filter_pattern *ptr;
	void *temp;

	TAILQ_FOREACH_SAFE(ptr, &filter_info->rss_cfg_list, node, temp) {
		if (!memcmp(&ptr->rss_cfg, &rule->rss_cfg,
		     sizeof(struct rte_flow_action_rss)))
			return true;
	}

	return false;
}

#if 0
static int
tsrn10_check_rss_key_rule(struct tsrn10_filter_info *filter_info,
			  struct tsrn10_rss_rule *rule)
{
	struct tsrn10_rss_filter_pattern *ptr;
	void *temp;

	TAILQ_FOREACH_SAFE(ptr, &filter_info->rss_cfg_list, node, temp) {
		if (!memcmp(rule->rss_cfg.key, ptr->rss_cfg.key,
			rule->rss_cfg.key_len * sizeof(*ptr->rss_cfg.key)))
			return true;
	}

	return false;
}

static int
tsrn10_check_rss_queue_rule(struct tsrn10_filter_info *filter_info,
			    struct tsrn10_rss_rule *rule)
{
	struct tsrn10_rss_filter_pattern *ptr;
	void *temp;

	TAILQ_FOREACH_SAFE(ptr, &filter_info->rss_cfg_list, node, temp) {
		if (!memcmp(rule->rss_cfg.queue, ptr->rss_cfg.queue,
			rule->rss_cfg.queue_num * sizeof(*rule->rss_cfg.queue)))
			return true;
	}

	return false;
}
#endif

static int
tsrn10_add_rss_filter(struct rte_eth_dev *dev,
		      struct tsrn10_rss_rule *rule,
		      struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_rss_filter_pattern *filter = NULL;
	struct rte_eth_rss_conf update_conf;

#if 0
	/* There can't be more than one RSS queue rule existing */
	if (rule->rss_cfg.queue_num &&
		tsrn10_check_rss_queue_rule(filter_info, rule))
		return rte_flow_error_set(error, EEXIST,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Rss Queue Rule Just Support One");

	/* There can't be more than one RSS Key rule existing */
	if (rule->rss_cfg.key_len &&
		tsrn10_check_rss_key_rule(filter_info, rule))
		return rte_flow_error_set(error, EEXIST,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Rss Key Rule Just Support One");
#endif
	if (tsrn10_check_rss_rule_exist(filter_info, rule))
		return rte_flow_error_set(error, EEXIST,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"current rss rule has been exists");

	filter = rte_zmalloc("tsrn10_rss_filter_pattern",
			sizeof(struct tsrn10_rss_filter_pattern), 0);
	if (filter == NULL)
		return -ENOMEM;

	filter->rss_cfg = rule->rss_cfg;
	filter->inset = rule->inset;

	if (filter->rss_cfg.queue_num)
		tsrn10_rss_redirect_update(dev, filter);
	memset(&update_conf, 0, sizeof(update_conf));
	tsrn10_rss_conf_update(dev, rule, &update_conf, true);
	if (!update_conf.rss_hf)
		tsrn10_disable_rss(dev);
	else
		tsrn10_rss_hash_set(dev, &update_conf);

	TAILQ_INSERT_TAIL(&filter_info->rss_cfg_list, filter, node);

	return 0;
}

static int
tsrn10_add_del_rss_filter(struct rte_eth_dev *dev,
			  struct tsrn10_rss_rule *rule,
			  bool add,
			  struct rte_flow_error *error)
{
	if (add)
		return tsrn10_add_rss_filter(dev, rule, error);
	else
		return tsrn10_del_rss_filter(dev, rule, error);
}

#endif /* RTE_VERSION > 19.11  */

#if RTE_VERSION_NUM(17, 2, 0, 16) <= RTE_VERSION

static int
tsrn10_add_del_vxlan_filter(struct rte_eth_dev *dev __rte_unused,
			    struct tsrn10_vxlan_rule *rule __rte_unused,
			    bool add __rte_unused)
{
	return 0;
}

static int
tsrn10_add_del_vlan_filter(struct rte_eth_dev *dev __rte_unused,
			   struct tsrn10_vlan_rule *rule __rte_unused,
			   bool add __rte_unused)
{
	return 0;
}

/* Destroy a flow rule on tsrn10. */
static int
tsrn10_flow_destroy(struct rte_eth_dev *dev,
		    struct rte_flow *flow,
		    struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter = TSRN10_DEV_TO_FILTER_INFO(dev);
	int ret = 0;

	switch (flow->filter_type) {
	case RTE_ETH_FILTER_NTUPLE:
		ret = tsrn10_add_del_ntuple_filter(dev,
				&flow->ntuple_rule, false, error);
		break;
	case RTE_ETH_FILTER_ETHERTYPE:
		ret = tsrn10_add_del_ethertype_filter(dev,
				&flow->ethertype_rule, false, error);
		break;
	case RTE_ETH_FILTER_SYN:
		ret = tsrn10_add_del_syn_filter(dev, &flow->sync_rule, false, error);
		break;
#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
	case RTE_ETH_FILTER_HASH:
		ret = tsrn10_add_del_rss_filter(dev, &flow->rss_rule, false, error);
		break;
#endif /* RTE_VERSION > 19.11 */
	default:
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ACTION, flow,
				"Destroy Flow type not supported");
	}
	if (ret)
		goto err;
	/* Remove This flow entry info form manage handle*/
	TAILQ_REMOVE(&filter->flow_list, flow, node);
	rte_free(flow);

	return 0;
err:

	return ret;
}

/**
 * Create a flow rule.
 * Theoretically one rule can match more than one filters.
 * We will let it use the filter which it hit first.
 * So, the sequence matters.
 */
static struct rte_flow *
tsrn10_flow_create(struct rte_eth_dev *dev,
		   const struct rte_flow_attr *attr,
		   const struct rte_flow_item pattern[],
		   const struct rte_flow_action actions[],
		   struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct rte_flow *flow = NULL;
	int32_t ret = -EINVAL;

	flow = rte_zmalloc("tsrn10_rte_flow", sizeof(struct rte_flow), 0);

	if (!flow) {
		rte_flow_error_set(error, ENOMEM,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Alloc Rte_Flow Rule Failed");
		return NULL;
	}

	ret = tsrn10_flow_parse(dev, flow, attr, pattern, actions, error);
	if (ret)
		goto err;

	switch (flow->filter_type) {
	case RTE_ETH_FILTER_NTUPLE:
		ret = tsrn10_add_del_ntuple_filter(dev,
				&flow->ntuple_rule, true, error);
		break;
	case RTE_ETH_FILTER_ETHERTYPE:
		ret = tsrn10_add_del_ethertype_filter(dev,
				&flow->ethertype_rule, true, error);
		break;
	case RTE_ETH_FILTER_SYN:
		ret = tsrn10_add_del_syn_filter(dev, &flow->sync_rule,
						true, error);
		break;
#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
	case RTE_ETH_FILTER_HASH:
		ret = tsrn10_add_del_rss_filter(dev, &flow->rss_rule,
						true, error);
		break;
#endif /* RTE_VERSION > 19.11 */
	case RTE_ETH_FILTER_TUNNEL:
		ret = tsrn10_add_del_vxlan_filter(dev, &flow->vxlan_rule, true);
		break;
	case RTE_ETH_FILTER_L2_TUNNEL:
		ret = tsrn10_add_del_vlan_filter(dev, &flow->vlan_rule, true);
		break;
	default:
		goto err;
	}
	if (ret)
		goto err;

	TAILQ_INSERT_TAIL(&filter->flow_list, flow, node);

	return flow;
err:
	rte_free(flow);

	if (!error->message)
		rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
				"Create Rte_Flow Failed");
	return NULL;
}

static inline int
tsrn10_check_vf_action_pattern(struct rte_eth_dev *dev,
			       struct rte_flow *flow,
			       struct rte_flow_error *error)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	struct tsrn10_vfinfo *vfinfo = &adapter->vfinfo[flow->dst_vf];
	struct tsrn10_5tuple_rule *rule = &flow->ntuple_rule;

	if (flow->dst_vf > adapter->max_vfs || !vfinfo)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL, "VF Index Is Outof Range Of Max VFS");
	else
		if (rule->queue > vfinfo->rx_queue_num)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					NULL, "VF Queue Index is Outof "
					"Range Of Rx Queues");
	return 0;
}

static int
tsrn10_check_ntuple_item_pattern(struct rte_flow *flow,
				 struct rte_flow_error *error)
{
	if (flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_ETH))
		return  rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, NULL,
				"Ntuple Rule Dno't Support Match Eth Pattern");

	if (!(flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_IPV4)) &&
	    !(flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_TCP)) &&
	    !(flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_UDP)) &&
	    !(flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_SCTP))) {
		return  rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, NULL,
				"Ntuple Rule Just Support Match "
				"IPV4/TCP/UDP/SCTP Pattern");
	}
	return 0;
}

static int
tsrn10_parse_ntuple_action(struct rte_eth_dev *dev,
			   struct rte_flow *flow,
			   struct tsrn10_action_patterns *pattern,
			   struct rte_flow_error *error)
{
	struct tsrn10_5tuple_rule *rule = &flow->ntuple_rule;
	uint8_t l4_proto_type = 0;

	if (tsrn10_check_ntuple_item_pattern(flow, error))
		return -rte_errno;

	if (pattern->redirect_en) {
		rule->action = pattern->rule_action;
		rule->queue = pattern->redir.index;
		rule->redir_vaild = true;
		if (rule->queue >= dev->data->nb_rx_queues)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ACTION_CONF, NULL,
				"Queue Index Is Outof Range Of Rx Queues");
	}
	if (flow->vf_used) {
		if (tsrn10_check_vf_action_pattern(dev, flow, error))
			return -rte_errno;
		rule->vf_used = flow->vf_used;
		rule->dst_vf = flow->dst_vf;
	}

	if (!pattern->mark_en)
		rule->mark_dis = 1;
	else
		rule->mark_id = pattern->mark.id;
	if (rule->mark_id > UINT16_MAX)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL, "ntuple action Mark Range from 0 to 65535");
	switch (rule->proto) {
	case TSRN10_FILTER_PROTO_TCP:
		l4_proto_type = IPPROTO_TCP;
		break;
	case TSRN10_FILTER_PROTO_UDP:
		l4_proto_type = IPPROTO_UDP;
		break;
	case TSRN10_FILTER_PROTO_SCTP:
		l4_proto_type = IPPROTO_SCTP;
		break;
	default:
		l4_proto_type = 0;
	}
	if ((l4_proto_type && rule->proto_id) &&
			rule->proto_id != l4_proto_type)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				NULL, "L3 Proto_id Conflict With L4 type");

	return 0;
}

static int
tsrn10_check_ethertype_item_pattern(struct rte_flow *flow,
				    struct rte_flow_error *error)
{
	if (!(flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_ETH)))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL, "Ethertype Rule Just "
				"Support Match Eth Proto");

	if (flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_IPV4) ||
	    flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_IPV6) ||
	    flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_TCP) ||
	    flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_UDP) ||
	    flow->match_target & BIT64(RTE_FLOW_ITEM_TYPE_TCP))
		return  rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, NULL,
				"Ethertype Rule Dont't Support Set "
				"IPV4/TCP/UDP/SCTP Pattern");

	return 0;
}

static int
tsrn10_parse_ethertype_action(struct rte_eth_dev *dev,
			      struct rte_flow *flow,
			      struct tsrn10_action_patterns *pattern,
			      struct rte_flow_error *error)
{
	struct tsrn10_ethertype_rule *rule = &flow->ethertype_rule;

	if (tsrn10_check_ethertype_item_pattern(flow, error))
		return -rte_errno;

	if (pattern->redirect_en) {
		rule->param.action = pattern->rule_action;
		rule->queue = pattern->redir.index;
		rule->redir_vaild = true;
		if (rule->queue >= dev->data->nb_rx_queues)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ACTION_CONF, NULL,
				"Queue Index Is Outof Range Of Rx Queues");
	}

	if (flow->vf_used) {
		if (tsrn10_check_vf_action_pattern(dev, flow, error))
			return -rte_errno;

		rule->param.vf_used = flow->vf_used;
		rule->param.dst_vf = flow->dst_vf;
	}

	if (pattern->mark_en) {
		rule->param.mark_dis = 0;
		rule->param.mark_id = pattern->mark.id;
	} else {
		rule->param.mark_dis = 1;
	}
	if (rule->param.mark_id > UINT16_MAX)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL, "ethertype action Mark "
				"Range from 0 to 65535");

	return 0;
}

static int
tsrn10_check_sync_item_pattern(struct rte_flow *flow,
			       struct rte_flow_error *error)
{
	if (flow->match_target != BIT64(RTE_FLOW_ITEM_TYPE_TCP))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL, "TCP Sync Rule Just "
				"Support Match TCP Sync_Flags");
	return 0;
}


static int
tsrn10_parse_tcpsync_action(struct rte_eth_dev *dev __rte_unused,
			    struct rte_flow *flow,
			    struct tsrn10_action_patterns *pattern,
			    struct rte_flow_error *error)
{
	struct tsrn10_tcp_sync_filter_rule *rule = &flow->sync_rule;

	if (tsrn10_check_sync_item_pattern(flow, error))
		return -rte_errno;

	if (flow->vf_used)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL, "Don't Support VF Pattern Attr");

	if (pattern->redirect_en) {
		rule->queue = pattern->redir.index;
		rule->action = pattern->rule_action;
		rule->redir_vaild = true;
		if (rule->queue >= dev->data->nb_rx_queues)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					NULL, "Queue Index Is Outof"
					" Range Of Rx Queues");
	}

	if (pattern->mark_en) {
		rule->mark_en = true;
		rule->mark_id = pattern->mark.id;
		if (pattern->mark.id > UINT16_MAX)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ACTION_CONF,
					NULL, "sync action Mark "
					"Range from 0 to 65535");
	}

	return 0;
}

#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
static int
tsrn10_check_rss_pattern(struct rte_flow *flow,
			 const struct rte_flow_action_rss *rss,
			 struct rte_flow_error *error)
{
	struct tsrn10_rss_rule *rule = &flow->rss_rule;
	uint16_t i = 0;

	for (i = 0; i < RTE_DIM(rss_match_pattern); i++) {
		if (rss->types & rss_match_pattern[i].rss_cfg &&
		    (flow->pattern_type &&
		     flow->pattern_type !=
		     rss_match_pattern[i].match_pattern)) {
			return rte_flow_error_set
				(error, EINVAL, RTE_FLOW_ERROR_TYPE_ITEM, rss,
				 "RSS Pattern Is Not Correct For rss types");
		}
	}
	rule->inset |= TSRN10_RSS_INSET_TYPE;

	return 0;
}

static int
tsrn10_parse_rss_action(struct rte_eth_dev *dev,
			struct rte_flow *flow,
			struct tsrn10_action_patterns *pattern,
			struct rte_flow_error *error)
{
	struct rte_flow_action_rss *rss = &pattern->rss;
	struct tsrn10_rss_rule *rule = &flow->rss_rule;
	uint16_t idx;

	if (flow->vf_used)
		return rte_flow_error_set
			(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, rss,
			 "Rss Don't Support Set For VF");
	if (rss->func && rss->func != RTE_ETH_HASH_FUNCTION_TOEPLITZ)
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL, "Don't Support Change Hash Func "
			       "Just Support Hash Func Toeplitz");
#if RTE_VERSION_NUM(20, 11, 0, 0) < RTE_VERSION
	if (rss->level && (rss->types != ETH_RSS_LEVEL_INNERMOST ||
			   rss->types != ETH_RSS_LEVEL_OUTERMOST))
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ACTION_CONF,
				NULL, "tunnel rss mode just inner or outer support ");
#else
	if (rss->level)
		return rte_flow_error_set
			(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, rss,
			 "a nonzero RSS encapsulation level is not supported");
#endif
#if RTE_VERSION_NUM(20, 8, 0, 0) >= RTE_VERSION
	/* Workaround Testpmd BUG */
	const char *testpmd_key = "testpmd's default RSS hash key, "
				  "override it for better balancing";
	if (rss->key_len == TSRN10_RSS_MAX_KEY_SIZE &&
		!memcmp(rss->key, testpmd_key, TSRN10_RSS_MAX_KEY_SIZE))
		rss->key_len = 0;
#endif
	if (rss->key_len && rss->key_len != TSRN10_RSS_MAX_KEY_SIZE)
		return rte_flow_error_set
			(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, rss,
			 "RSS hash key must be exactly 40 bytes");
	if (rss->queue_num && rss->queue_num > dev->data->nb_rx_queues)
		return rte_flow_error_set
			(error, ENOTSUP, RTE_FLOW_ERROR_TYPE_ACTION, rss,
			 "Redirect Queues Is Out Of Max Queue Num");
	if (rss->queue_num) {
		for (idx = 0; idx < rss->queue_num; idx++) {
			if (rss->queue[idx] &&
			    rss->queue[idx] > dev->data->nb_rx_queues) {
				return rte_flow_error_set(error, ENOTSUP,
						RTE_FLOW_ERROR_TYPE_ACTION, rss,
						"Queue Index Is Out Of Range "
						"Of Set Max Queues Num");
			}
		}
		rule->inset |= TSRN10_RSS_INSET_QUEUE;
	}

	rule->rss_cfg = *rss;

	if (rss->types && (!(rss->types & TSRN10_SUPPORT_RSS_OFFLOAD_ALL) ||
			   (rss->types & TSRN10_NOT_SUPPORT_RSS_ALL)))
		return rte_flow_error_set
			(error, EINVAL, RTE_FLOW_ERROR_TYPE_ACTION_CONF, rss,
			 "RSS type Is Not Support");
	if (rss->key && rss->key_len)
		rule->inset |= TSRN10_RSS_INSET_KEY;
	if (rss->types)
		return tsrn10_check_rss_pattern(flow, rss, error);

	return 0;
}
#endif

static int
tsrn10_parse_vxlan_action(struct rte_eth_dev *dev __rte_unused,
			  struct rte_flow *flow __rte_unused,
			  struct tsrn10_action_patterns *pattern __rte_unused,
			  struct rte_flow_error *error __rte_unused)
{
	return 0;
}

static int
tsrn10_parse_vlan_action(struct rte_eth_dev *dev __rte_unused,
			  struct rte_flow *flow __rte_unused,
			  struct tsrn10_action_patterns *pattern __rte_unused,
			  struct rte_flow_error *error __rte_unused)
{
	return 0;
}

static int
tsrn10_action_parse(struct rte_eth_dev *dev,
		    const struct rte_flow_action actions[],
		    struct rte_flow *flow,
		    struct rte_flow_error *error)
{
	static const enum rte_flow_action_type tsrn10_support_action[] = {
		RTE_FLOW_ACTION_TYPE_END,
		RTE_FLOW_ACTION_TYPE_QUEUE,
		RTE_FLOW_ACTION_TYPE_DROP,
		RTE_FLOW_ACTION_TYPE_MARK,
#if RTE_VERSION_NUM(17, 11, 0, 0) <= RTE_VERSION
		RTE_FLOW_ACTION_TYPE_SECURITY,
#endif
		RTE_FLOW_ACTION_TYPE_RSS,
		RTE_FLOW_ACTION_TYPE_PF,
		RTE_FLOW_ACTION_TYPE_VF
	};
	const struct rte_flow_action *act = actions;
	struct tsrn10_action_patterns conf;
	uint8_t act_mark_cnt = 0;
	uint8_t act_rss_cnt = 0;
	uint8_t act_q_cnt = 0;
	int8_t ret = -EINVAL;
	bool find;
	uint64_t i;

	memset(&conf, 0, sizeof(conf));

	for (; act->type != RTE_FLOW_ACTION_TYPE_END; act++) {
		for (i = 0; i < RTE_DIM(tsrn10_support_action); i++) {
			find = false;
			switch (act->type) {
			case RTE_FLOW_ACTION_TYPE_QUEUE:
				rte_memcpy(&conf.redir, act->conf,
					sizeof(struct rte_flow_action_queue));
				conf.rule_action = TSRN10_FILTER_PASS;
				conf.redirect_en = 1;
				find = true;
				act_q_cnt++;
				break;
			case RTE_FLOW_ACTION_TYPE_DROP:
				conf.rule_action = TSRN10_FILTER_DROP;
				conf.redirect_en = 1;
				find = true;
				act_q_cnt++;
				break;
			case RTE_FLOW_ACTION_TYPE_RSS:
				rte_memcpy(&conf.rss, act->conf,
					sizeof(struct rte_flow_action_rss));
				conf.rss_en = 1;
				flow->filter_type = RTE_ETH_FILTER_HASH;
				find = true;
				act_rss_cnt++;
				break;
			case RTE_FLOW_ACTION_TYPE_MARK:
				rte_memcpy(&conf.mark, act->conf,
					sizeof(struct rte_flow_action_mark));
				conf.mark_en = 1;
				find = true;
				act_mark_cnt++;
				break;
			case RTE_FLOW_ACTION_TYPE_VF:
				rte_memcpy(&conf.act_vf, act->conf,
					sizeof(struct rte_flow_action_vf));
				conf.vf_attr_en = 1;
				find = true;
				break;
			case RTE_FLOW_ACTION_TYPE_PF:
				find = true;
				break;
			default:
				return rte_flow_error_set(error, ENOTSUP,
						RTE_FLOW_ERROR_TYPE_ACTION, act,
						"Flow Act type not supported");
			}
			if (find)
				break;
		}
	}
	if (act_q_cnt >= 2)
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ACTION, act,
				"Flow Act type Queue 1 Rule Just Support One");
	if (act_mark_cnt >= 2)
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ACTION, act,
				"Flow Act type Mark 1 Rule Just Support One");
	if (act_rss_cnt >= 2)
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ACTION, act,
				"Flow Act type RSS 1 Rule Just Support One");

	switch (flow->filter_type) {
	case RTE_ETH_FILTER_NTUPLE:
		ret = tsrn10_parse_ntuple_action(dev, flow, &conf, error);
		break;
	case RTE_ETH_FILTER_ETHERTYPE:
		ret = tsrn10_parse_ethertype_action(dev, flow, &conf, error);
		break;
	case RTE_ETH_FILTER_SYN:
		ret = tsrn10_parse_tcpsync_action(dev, flow, &conf, error);
		break;
#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
	case RTE_ETH_FILTER_HASH:
		ret = tsrn10_parse_rss_action(dev, flow, &conf, error);
		break;
#endif
	case RTE_ETH_FILTER_TUNNEL:
		ret = tsrn10_parse_vxlan_action(dev, flow, &conf, error);
		break;
	case RTE_ETH_FILTER_L2_TUNNEL:
		ret = tsrn10_parse_vlan_action(dev, flow, &conf, error);
		break;
	default:
		rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_HANDLE, act,
				"Flow Pattern Isn't Support");
		break;
	}

	return ret;
}

static int
tsrn10_parse_eth(struct rte_eth_dev *dev __rte_unused,
		 const struct rte_flow_item *item,
		 struct rte_flow *flow,
		 struct rte_flow_error *error)
{
	struct tsrn10_ethertype_rule *rule = &flow->ethertype_rule;
	const struct rte_flow_item_eth *eth_spec;
	const struct rte_flow_item_eth *eth_mask;


	eth_spec = item->spec;
	eth_mask = item->mask;

	if ((!eth_spec || !eth_mask) &&
	     flow->filter_type == RTE_ETH_FILTER_ETHERTYPE)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"NULL ETH spec/mask");
	if (!eth_spec)
		return 0;
	if ((!rte_is_zero_ether_addr(&eth_spec->src) ||
			(!rte_is_zero_ether_addr(&eth_spec->dst))))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"Ether dont support MAC_addr match");

	if ((eth_mask->type & UINT16_MAX) != UINT16_MAX)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"Invalid ethertype mask Just Support "
				"Full Mask For Ethertype");

	rule->param.ethertype = rte_be_to_cpu_16(eth_spec->type);
	/* Avoid For Ntuple Rule Match NA */
	if (rule->param.ethertype == RTE_ETHER_TYPE_IPV4 ||
	    rule->param.ethertype == RTE_ETHER_TYPE_IPV6 ||
	    rule->param.ethertype == RTE_ETHER_TYPE_VLAN)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"IPV4/IPV6 CVLAN ID Isn't"
				" Support Match For Ethertype");
	flow->filter_type = RTE_ETH_FILTER_ETHERTYPE;
	flow->match_target |= BIT64(RTE_FLOW_ITEM_TYPE_ETH);

	return 0;
}

static int
tsrn10_parse_vlan(struct rte_eth_dev *dev __rte_unused,
		  const struct rte_flow_item *item,
		  struct rte_flow *flow __rte_unused,
		  struct rte_flow_error *error)
{
	const struct rte_flow_item_vlan *vlan_spec = item->spec;
	const struct rte_flow_item_vlan *vlan_mask = item->mask;

	if (!vlan_spec && !vlan_mask)
		return 0;
#if RTE_VERSION_NUM(18, 5, 0, 0) < RTE_VERSION
	if (!(vlan_spec && vlan_mask) ||
	    vlan_mask->inner_type)
#else
	if (!(vlan_spec && vlan_mask))
#endif
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  item,
					  "Invalid vlan item Don't Support "
					  "Vlan Inner Type");

	if (!vlan_mask->tci)
		return rte_flow_error_set(error, EINVAL,
					  RTE_FLOW_ERROR_TYPE_ITEM,
					  item,
					  "TCI VID must be specified");
	if (vlan_mask->tci != UINT16_MAX)
		rte_flow_error_set(error, EINVAL,
				   RTE_FLOW_ERROR_TYPE_ITEM,
				   item,
				   "Don't Support Partial TCI VID Match");
	return 0;
}

static int
tsrn10_parse_ip4(struct rte_eth_dev *dev,
		 const struct rte_flow_item *item,
		 struct rte_flow *flow,
		 struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	const struct rte_flow_item_ipv4 *ipv4_spec, *ipv4_last, *ipv4_mask;
	struct tsrn10_5tuple_rule *rule = &flow->ntuple_rule;

	ipv4_spec = item->spec;
	ipv4_mask = item->mask;
	ipv4_last = item->last;

	if (ipv4_last && filter_info->mode == TSRN10_TUPLE_TCAM_MODE) {
		if (!ipv4_spec || !ipv4_mask) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"Not support range");
		}
		/* Only src/dst ip_offset supports range on TCAM mode */
		if (ipv4_last->hdr.version_ihl ||
				ipv4_last->hdr.type_of_service ||
				ipv4_last->hdr.total_length ||
				ipv4_last->hdr.packet_id ||
				ipv4_last->hdr.time_to_live ||
				ipv4_last->hdr.hdr_checksum ||
				ipv4_last->hdr.fragment_offset ||
				filter_info->mode == TSRN10_TUPLE_NORMAL_MODE)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"Not support range Just "
					"support Src/Dst IP Range");
		rule->dst_ip_mask = ipv4_last->hdr.dst_addr;
		rule->src_ip_mask = ipv4_last->hdr.src_addr;
		rule->proto_mask = ipv4_last->hdr.next_proto_id;

		flow->match_target |= BIT64(RTE_FLOW_ITEM_TYPE_IPV4);
	}
	if (ipv4_spec && ipv4_mask) {
		/* Check IPv4 mask and update input set */
		if (ipv4_mask->hdr.version_ihl ||
				ipv4_mask->hdr.total_length ||
				ipv4_mask->hdr.type_of_service ||
				ipv4_mask->hdr.packet_id ||
				ipv4_mask->hdr.hdr_checksum ||
				ipv4_mask->hdr.fragment_offset)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"Invalid IPv4 mask Just Support "
					"Src/Dst Ip Address For Match");

		if (filter_info->mode == TSRN10_TUPLE_NORMAL_MODE) {
			if (ipv4_mask->hdr.src_addr != UINT32_MAX)
				rule->src_ip_mask = 1;
			if (ipv4_mask->hdr.dst_addr != UINT32_MAX)
				rule->dst_ip_mask = 1;
			if (ipv4_mask->hdr.next_proto_id != UINT8_MAX)
				rule->proto_mask = 1;
		} else {
			rule->src_ip_mask = ipv4_mask->hdr.src_addr;
			rule->dst_ip_mask = ipv4_mask->hdr.dst_addr;
			rule->proto_mask = ipv4_mask->hdr.next_proto_id;
		}
		rule->src_ip = ipv4_spec->hdr.src_addr;
		rule->dst_ip = ipv4_spec->hdr.dst_addr;
		rule->proto_id = ipv4_spec->hdr.next_proto_id;

		flow->match_target |= BIT64(RTE_FLOW_ITEM_TYPE_IPV4);
	} else {
		/* Outer IP_HEADER Is not For Match
		 * So This May Be a Inner IP_HEADER Match Rule
		 */
	}


	return 0;
}

static int
tsrn10_parse_ip6(struct rte_eth_dev *dev __rte_unused,
		 const struct rte_flow_item *item,
		 struct rte_flow *flow __rte_unused,
		 struct rte_flow_error *error)
{
	const struct rte_flow_item_ipv6 *ipv6_spec, *ipv6_last, *ipv6_mask;

	ipv6_spec = item->spec;
	ipv6_mask = item->mask;
	ipv6_last = item->last;

	if (ipv6_spec || ipv6_mask || ipv6_last)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"Ipv6 Don't Support As Pattern");


	return 0;
}

/* Parse pattern type of TCP */
static int
tsrn10_parse_tcp(struct rte_eth_dev *dev,
		 const struct rte_flow_item *item,
		 struct rte_flow *flow,
		 struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_5tuple_rule *rule = &flow->ntuple_rule;
	const struct rte_flow_item_tcp *tcp_spec = item->spec;
	const struct rte_flow_item_tcp *tcp_mask = item->mask;
	const struct rte_flow_item_tcp *tcp_last = item->last;
	uint8_t tcp_attr_en = 0;
	uint8_t tcp_sync_en = 0;

	rule->proto = TSRN10_FILTER_PROTO_TCP;

	if (!(tcp_mask && tcp_spec))
		return 0;

	if (tcp_last && filter_info->mode == TSRN10_TUPLE_TCAM_MODE) {
		if (!tcp_spec || !tcp_mask) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"TCP Not support range");
		}
		/* On Tcam Mode Support Src/Dst Port Mask */
		if (tcp_last->hdr.sent_seq ||
				tcp_last->hdr.recv_ack ||
				tcp_last->hdr.data_off ||
				tcp_last->hdr.tcp_flags ||
				tcp_last->hdr.rx_win ||
				tcp_last->hdr.cksum ||
				tcp_last->hdr.tcp_urp ||
				filter_info->mode == TSRN10_TUPLE_NORMAL_MODE)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"TCP Not support range just "
					"support Src/Dst Port Rnage");

		rule->src_port_mask = tcp_last->hdr.src_port;
		rule->dst_port_mask = tcp_last->hdr.dst_port;
	}

	if (tcp_mask->hdr.sent_seq ||
			tcp_mask->hdr.recv_ack ||
			tcp_mask->hdr.data_off ||
			tcp_mask->hdr.rx_win ||
			tcp_mask->hdr.cksum ||
			tcp_mask->hdr.tcp_urp ||
			(tcp_mask->hdr.tcp_flags &&
			tcp_spec->hdr.tcp_flags != RTE_TCP_SYN_FLAG))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"TCP only dst/src port FLAG-SYNC Support");
	if (tcp_spec->hdr.tcp_flags == RTE_TCP_SYN_FLAG)
		tcp_sync_en = 1;
	if (filter_info->mode == TSRN10_TUPLE_NORMAL_MODE) {
		if (tcp_mask->hdr.src_port != UINT16_MAX)
			rule->src_port_mask = 1;
		if (tcp_mask->hdr.dst_port != UINT16_MAX)
			rule->dst_port_mask = 1;
	}
	if (tcp_mask->hdr.src_port) {
		rule->src_port = tcp_spec->hdr.src_port;
		tcp_attr_en = 1;
	}
	if (tcp_mask->hdr.dst_port) {
		rule->dst_port = tcp_spec->hdr.dst_port;
		tcp_attr_en = 1;
	}
	if (!tcp_attr_en && !tcp_sync_en)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"TCP SrC/DsT port Is not exist");
	if (tcp_attr_en && tcp_sync_en)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"TCP Sync Flags Rule Don't Support"
				" Match With TCP Port");
	if (!tcp_attr_en && tcp_sync_en)
		flow->filter_type = RTE_ETH_FILTER_SYN;

	flow->match_target |= BIT64(RTE_FLOW_ITEM_TYPE_TCP);

	return 0;
}

static int
tsrn10_parse_udp(struct rte_eth_dev *dev __rte_unused,
		 const struct rte_flow_item *item,
		 struct rte_flow *flow,
		 struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_5tuple_rule *rule = &flow->ntuple_rule;
	const struct rte_flow_item_udp *udp_spec = item->spec;
	const struct rte_flow_item_udp *udp_mask = item->mask;
	const struct rte_flow_item_udp *udp_last = item->last;
	uint8_t udp_attr_en = 0;

	rule->proto = TSRN10_FILTER_PROTO_UDP;

	if (!(udp_mask && udp_spec))
		return 0;

	if (udp_last && filter_info->mode == TSRN10_TUPLE_TCAM_MODE) {
		if (!udp_spec || !udp_mask) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"UDP Not support range");
		}
		/* On Tcam Mode Support Src/Dst Port Mask */
		if (udp_last->hdr.dgram_cksum ||
				udp_last->hdr.dgram_len ||
				filter_info->mode == TSRN10_TUPLE_NORMAL_MODE)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"UDP Not support range Just "
					"support Src/Dst Port Rnage");
		rule->src_port_mask = udp_last->hdr.src_port;
		rule->dst_port_mask = udp_last->hdr.dst_port;
	}
	if (filter_info->mode == TSRN10_TUPLE_NORMAL_MODE) {
		if (udp_mask->hdr.src_port != UINT16_MAX)
			rule->src_port_mask = 1;
		if (udp_mask->hdr.dst_port != UINT16_MAX)
			rule->dst_port_mask = 1;
	} else {
		rule->src_port_mask = udp_mask->hdr.src_port;
		rule->dst_port_mask = udp_mask->hdr.dst_port;
	}
	/* Only dest/src port is used */
	if (udp_mask->hdr.dgram_len || udp_mask->hdr.dgram_cksum)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"UDP only support Dest/Src port");

	if (udp_mask->hdr.dst_port) {
		rule->dst_port = udp_spec->hdr.dst_port;
		udp_attr_en = 1;
	}
	if (udp_mask->hdr.src_port) {
		rule->src_port = udp_spec->hdr.src_port;
		udp_attr_en = 1;
	}

	if (!udp_attr_en)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"UDP SrC/DsT port Is not exist");

	flow->match_target |= BIT64(RTE_FLOW_ITEM_TYPE_UDP);

	return 0;
}

static int
tsrn10_parse_sctp(struct rte_eth_dev *dev __rte_unused,
		  const struct rte_flow_item *item,
		  struct rte_flow *flow,
		  struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_5tuple_rule *rule = &flow->ntuple_rule;
	const struct rte_flow_item_sctp *sctp_spec = item->spec;
	const struct rte_flow_item_sctp *sctp_mask = item->mask;
	const struct rte_flow_item_sctp *sctp_last = item->last;
	uint8_t sctp_attr_en = 0;

	rule->proto = TSRN10_FILTER_PROTO_SCTP;

	if (!sctp_mask || !sctp_spec)
		return 0;

	if (sctp_last && filter_info->mode == TSRN10_TUPLE_TCAM_MODE) {
		if (!sctp_spec || !sctp_mask) {
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"STCP Not support range");
		}
		/* On Tcam Mode Support Src/Dst Port Mask */
		if (sctp_last->hdr.tag ||
				sctp_last->hdr.cksum ||
				filter_info->mode == TSRN10_TUPLE_NORMAL_MODE)
			return rte_flow_error_set(error, EINVAL,
					RTE_FLOW_ERROR_TYPE_ITEM,
					item,
					"SCTP Not support range");
		rule->src_port_mask = sctp_last->hdr.src_port;
		rule->dst_port_mask = sctp_last->hdr.dst_port;
	}
	if (filter_info->mode == TSRN10_TUPLE_NORMAL_MODE) {
		if (sctp_mask->hdr.src_port != UINT16_MAX)
			rule->src_port_mask = 1;
		if (sctp_mask->hdr.dst_port != UINT16_MAX)
			rule->dst_port_mask = 1;
	}

	/* Only dest/src port is used */
	if (sctp_mask->hdr.tag || sctp_mask->hdr.cksum)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM_MASK, item,
				"SCTP only support Dest/Src port");

	if (sctp_mask->hdr.dst_port) {
		rule->dst_port = sctp_spec->hdr.dst_port;
		sctp_attr_en = 1;
	}
	if (sctp_mask->hdr.src_port) {
		rule->src_port = sctp_spec->hdr.src_port;
		sctp_attr_en = 1;
	}
	if (!sctp_attr_en)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"SCTP SrC/DsT port Is not exist");

	flow->match_target |= BIT64(RTE_FLOW_ITEM_TYPE_SCTP);

	return 0;
}

static int
tsrn10_parse_vxlan(struct rte_eth_dev *dev __rte_unused,
		   const struct rte_flow_item *item __rte_unused,
		   struct rte_flow *flow __rte_unused,
		   struct rte_flow_error *error __rte_unused)
{
	return 0;
}

static int
tsrn10_flow_is_vf(struct rte_eth_dev *dev,
		  const struct rte_flow_item *item,
		  struct rte_flow *flow,
		  struct rte_flow_error *error)
{
	struct tsrn10_eth_adapter *adapter = TSRN10_DEV_TO_ADAPTER(dev);
	const struct rte_flow_item_vf *vf_spec;

	vf_spec = item->spec;
	if (vf_spec->id >= adapter->max_vfs)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM,
				item,
				"Invalid VF ID for FLOW.");
	flow->vf_used = 1;
	flow->dst_vf = vf_spec->id;

	return 0;
}

static int
tsrn10_attribute_parse(const struct rte_flow_attr *attr,
		       struct rte_flow_error *error)

{
	if (unlikely(attr->egress))
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, attr,
				"Flow config is not support on egress");
	if (unlikely(!attr->ingress))
		return rte_flow_error_set(error, ENOTSUP,
				RTE_FLOW_ERROR_TYPE_ATTR_INGRESS, attr,
				"Ingress Flag need to set");

	return 0;
}

static const struct tsrn10_patterns_parse patter_parse[] = {
	{RTE_FLOW_ITEM_TYPE_ETH, tsrn10_parse_eth},
	{RTE_FLOW_ITEM_TYPE_VLAN, tsrn10_parse_vlan},
	{RTE_FLOW_ITEM_TYPE_IPV4, tsrn10_parse_ip4},
	{RTE_FLOW_ITEM_TYPE_IPV6, tsrn10_parse_ip6},
	{RTE_FLOW_ITEM_TYPE_TCP, tsrn10_parse_tcp},
	{RTE_FLOW_ITEM_TYPE_UDP, tsrn10_parse_udp},
	{RTE_FLOW_ITEM_TYPE_SCTP, tsrn10_parse_sctp},
	{RTE_FLOW_ITEM_TYPE_VXLAN, tsrn10_parse_vxlan},
	{RTE_FLOW_ITEM_TYPE_VF, tsrn10_flow_is_vf},
	{RTE_FLOW_ITEM_TYPE_END, NULL}
};

struct tsrn10_patter_flow_type pattern_attrs[] = {
	{RTE_ETH_FILTER_ETHERTYPE, TSRN10_ETHERTYPE_ATTR},
	{RTE_ETH_FILTER_ETHERTYPE, TSRN10_ETHERTYPE_ATTR_VF},
	{RTE_ETH_FILTER_ETHERTYPE, TSRN10_ETHERTYPE_VLAN_ATTR},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_V4_ATTR},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_VLAN_V4_ATTR},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_V4_ATTR_VF},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_V4_ATTR_UDP},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_V4_ATTR_UDP_VF},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_VLAN_V4_UDP_ATTR},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_V4_ATTR_TCP},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_V4_ATTR_TCP_VF},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_VLAN_V4_TCP_ATTR},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_V4_ATTR_SCTP},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_V4_ATTR_SCTP_VF},
	{RTE_ETH_FILTER_NTUPLE, TSRN10_NTUPLE_VLAN_V4_SCTP_ATTR},
	{RTE_ETH_FILTER_NTUPLE,	TSRN10_NTUPLE_V6_ATTR_TCP},
	{RTE_ETH_FILTER_NTUPLE,	TSRN10_NTUPLE_V6_ATTR_TCP_VF},
	{RTE_ETH_FILTER_NTUPLE,	TSRN10_NTUPLE_V6_ATTR_UDP},
	{RTE_ETH_FILTER_NTUPLE,	TSRN10_NTUPLE_V6_ATTR_UDP_VF},
	{RTE_ETH_FILTER_NTUPLE,	TSRN10_NTUPLE_V6_ATTR_SCTP},
	{RTE_ETH_FILTER_NTUPLE,	TSRN10_NTUPLE_V6_ATTR_SCTP_VF},
	{RTE_ETH_FILTER_TUNNEL, TSRN10_VXLAN_V4_ATTR},
	{RTE_ETH_FILTER_L2_TUNNEL, TSRN10_VLAN_ATTR}
};

static struct tsrn10_patter_flow_type *
tsrn10_get_flow_type(struct rte_flow *filter,
		     const struct rte_flow_item patterns[])
{
	const struct rte_flow_item *item = patterns;
	uint16_t i = 0;
	uint64_t pattern_mask = 0;

	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		if (item->type == RTE_FLOW_ITEM_TYPE_VOID)
			continue;
		pattern_mask |= BIT64(item->type);
	}

	filter->pattern_type = pattern_mask;

	for (i = 0; i < RTE_DIM(pattern_attrs); i++)
		if (pattern_attrs[i].pattern_mask == pattern_mask)
			return &pattern_attrs[i];

	return NULL;
}

static int
tsrn10_pattern_parse(struct rte_eth_dev *dev,
		     const struct rte_flow_item patterns[],
		     struct rte_flow *filter,
		     struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	const struct rte_flow_item *item = patterns;
	struct tsrn10_patter_flow_type *flow_attr;
	uint16_t i;
	int ret = 0;

	if (item == NULL)
		return 0;

	flow_attr = tsrn10_get_flow_type(filter, patterns);
	if (!flow_attr)
		return 0;
	if (filter_info->mode == TSRN10_TUPLE_TCAM_MODE &&
			flow_attr->pattern_mask & BIT(RTE_FLOW_ITEM_TYPE_IPV6))
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"TCAM mode Flow pattern Not Support IPV6");

	filter->filter_type = flow_attr->flow_type;

	for (; item->type != RTE_FLOW_ITEM_TYPE_END; item++) {
		for (i = 0; i < RTE_DIM(patter_parse); i++) {
			if (item->type == patter_parse[i].pattern_type &&
				BIT64(item->type) & flow_attr->pattern_mask) {
				ret = patter_parse[i].parse(dev, item,
						filter, error);
				if (ret)
					goto err;
				break;
			}
		}
	}

	return 0;
err:
	if (!error->message)
		return rte_flow_error_set(error, EINVAL,
				RTE_FLOW_ERROR_TYPE_ITEM, item,
				"Flow pattern Not Support");
	return ret;
}

static int
tsrn10_flow_parse(struct rte_eth_dev *dev,
		  struct rte_flow *flow,
		  const struct rte_flow_attr *attr,
		  const struct rte_flow_item pattern[],
		  const struct rte_flow_action actions[],
		  struct rte_flow_error *error)
{
	if (tsrn10_attribute_parse(attr, error))
		return -rte_errno;
	if (tsrn10_pattern_parse(dev, pattern, flow, error))
		return -rte_errno;
	if (tsrn10_action_parse(dev, actions, flow, error))
		return -rte_errno;
	if (flow->filter_type == RTE_ETH_FILTER_SYN)
		flow->sync_rule.high_pri = attr->priority ? 1 : 0;

	return 0;
}

static int
tsrn10_flow_validate(struct rte_eth_dev *dev,
		     const struct rte_flow_attr *attr,
		     const struct rte_flow_item pattern[],
		     const struct rte_flow_action actions[],
		     struct rte_flow_error *error)
{
	/* 1.verity attr, pattern, actions if we can't support
	 * 2.decide which type rule will match to be use
	 * action is support or not
	 * pattern if is not support
	 */
	struct rte_flow filter;

	memset(&filter, 0, sizeof(struct rte_flow));

	return tsrn10_flow_parse(dev, &filter, attr, pattern, actions, error);
}

static int
tsrn10_flow_flush_ethertype_filter(struct rte_eth_dev *dev,
				   struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_ethertype_filter_list
		*ethertype_list = &filter_info->ethertype_list;
	struct tsrn10_ethertype_filter *filter;
	struct rte_flow *flow;
	void *temp;
	int ret = 0;

	while ((filter = TAILQ_FIRST(ethertype_list))) {
		ret = tsrn10_add_del_ethertype_filter(dev,
				&filter->filter_rule, false, error);
		if (ret)
			return ret;
	}

	/* Delete ethertype flows in flow list. */
	TAILQ_FOREACH_SAFE(flow, &filter_info->flow_list, node, temp) {
		if (flow->filter_type == RTE_ETH_FILTER_ETHERTYPE) {
			TAILQ_REMOVE(&filter_info->flow_list, flow, node);
			rte_free(flow);
		}
	}

	return ret;
}

static int
tsrn10_flow_flush_ntuple_filter(struct rte_eth_dev *dev,
				struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct tsrn10_5tuple_filter_list
		*fivetuple_list = &filter_info->fivetuple_list;
	struct tsrn10_5tuple_filter *filter;
	struct rte_flow *flow;
	void *temp;
	int ret = 0;

	while ((filter = TAILQ_FIRST(fivetuple_list))) {
		ret = tsrn10_add_del_ntuple_filter(dev,
				&filter->filter_rule, false, error);
		if (ret)
			return ret;
	}

	/* Delete ethertype flows in flow list. */
	TAILQ_FOREACH_SAFE(flow, &filter_info->flow_list, node, temp) {
		if (flow->filter_type == RTE_ETH_FILTER_NTUPLE) {
			TAILQ_REMOVE(&filter_info->flow_list, flow, node);
			rte_free(flow);
		}
	}

	return ret;
}

static int
tsrn10_flow_flush_sync_filter(struct rte_eth_dev *dev,
			      struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct rte_flow *flow;
	int ret = -EINVAL;
	void *temp;

	/* Delete ethertype flows in flow list. */
	TAILQ_FOREACH_SAFE(flow, &filter_info->flow_list, node, temp) {
		if (flow->filter_type == RTE_ETH_FILTER_SYN) {
			ret = tsrn10_add_del_syn_filter(dev,
					&flow->sync_rule, false, error);
			if (ret)
				return ret;

			TAILQ_REMOVE(&filter_info->flow_list, flow, node);
			rte_free(flow);
		}
	}

	return 0;
}

#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
static int
tsrn10_flow_flush_rss_filter(struct rte_eth_dev *dev,
			     struct rte_flow_error *error)
{
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct rte_flow *flow;
	int ret = -EINVAL;
	void *temp;

	/* Delete ethertype flows in flow list. */
	TAILQ_FOREACH_SAFE(flow, &filter_info->flow_list, node, temp) {
		if (flow->filter_type == RTE_ETH_FILTER_HASH) {
			ret = tsrn10_add_del_rss_filter(dev, &flow->rss_rule,
							false, error);
			if (ret)
				return ret;

			TAILQ_REMOVE(&filter_info->flow_list, flow, node);
			rte_free(flow);
		}
	}

	return 0;
}
#endif /* RTE_VERSION > 19.11 */

/*  Destroy all flow rules associated with a port on tsrn10. */
static int
tsrn10_flow_flush(struct rte_eth_dev *dev,
		  struct rte_flow_error *error)
{
	/* TAILLIST REMOVE ANY EXIST Rule filter according
	 * The manage handle
	 */
	struct tsrn10_filter_info *filter_info = TSRN10_DEV_TO_FILTER_INFO(dev);
	struct rte_flow *flow, *next;
	int ret = -EINVAL;

	ret = tsrn10_flow_flush_ethertype_filter(dev, error);
	if (ret)
		return error->message ?
			ret : rte_flow_error_set(error, -ret,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Failed to ethertype flush flows.");
	ret = tsrn10_flow_flush_ntuple_filter(dev, error);
	if (ret)
		return error->message ?
			ret : rte_flow_error_set(error, -ret,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Failed to ntuple flush flows.");
#if RTE_VERSION_NUM(19, 11, 0, 0) < RTE_VERSION
	ret = tsrn10_flow_flush_rss_filter(dev, error);
	if (ret)
		return error->message ?
			ret : rte_flow_error_set(error, -ret,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Failed to rss rule flush flows.");
#endif /* RTE_VERSION > 19.11 */
	tsrn10_flow_flush_sync_filter(dev, error);
	if (ret)
		return error->message ?
			ret : rte_flow_error_set(error, -ret,
					RTE_FLOW_ERROR_TYPE_HANDLE, NULL,
					"Failed to Flush TCP-Sync Anti Rule");

	TAILQ_FOREACH_SAFE(flow, &filter_info->flow_list, node, next)
		TAILQ_REMOVE(&filter_info->flow_list, flow, node);

	return 0;
}

struct rte_flow_ops tsrn10_flow_ops = {
	.validate = tsrn10_flow_validate,
	.create = tsrn10_flow_create,
	.destroy = tsrn10_flow_destroy,
	.flush = tsrn10_flow_flush,
};
#endif
