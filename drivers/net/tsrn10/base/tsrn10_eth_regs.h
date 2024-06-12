#ifndef _TSRN10_ETH_REGS_H_
#define _TSRN10_ETH_REGS_H_

#include "tsrn10_common.h"

/* PTP 1588 TM Offload */
#define TSRN10_ETH_PTP_TX_STATUS(n)	_ETH_(0x0400 + ((n) * 0x14))
#define TSRN10_ETH_PTP_TX_HTIMES(n)	_ETH_(0x0404 + ((n) * 0x14))
#define TSRN10_ETH_PTP_TX_LTIMES(n)	_ETH_(0x0408 + ((n) * 0x14))
#define TSRN10_ETH_PTP_TX_TS_ST(n)	_ETH_(0x040c + ((n) * 0x14))
#define TSRN10_ETH_PTP_TX_CLEAR(n)	_ETH_(0x0410 + ((n) * 0x14))

#define TSRN10_ETH_ENGINE_BYPASS	_ETH_(0x8000)
#define TSRN10_EN_TUNNEL_VXLAN_PARSE	_ETH_(0x8004)
#define TSRN10_ETH_MAC_LOOPBACK		_ETH_(0x8008)
#define TSRN10_ETH_FIFO_CTRL		_ETH_(0x800c)
#define TSRN10_ETH_FOUR_FIFO		BIT(0)
#define TSRN10_ETH_TWO_FIFO		BIT(1)
#define TSRN10_ETH_ONE_FIFO		BIT(2)
#define TSRN10_FIFO_CFG_EN		(0x1221)
#define TSRN10_ETH_VXLAN_PORT_CTRL	_ETH_(0x8010)
#define TSRN10_ETH_VXLAN_DEF_PORT	(4789)
#define TSRN10_HOST_FILTER_EN		_ETH_(0x801c)
#define TSRN10_HW_SCTP_CKSUM_CTRL	_ETH_(0x8038)
#define TSRN10_HW_CHECK_ERR_CTRL	_ETH_(0x8060)
#define TSRN10_HW_ERR_HDR_LEN		BIT(0)
#define TSRN10_HW_ERR_PKTLEN		BIT(1)
#define TSRN10_HW_L3_CKSUM_ERR		BIT(2)
#define TSRN10_HW_L4_CKSUM_ERR		BIT(3)
#define TSRN10_HW_SCTP_CKSUM_ERR	BIT(4)
#define TSRN10_HW_INNER_L3_CKSUM_ERR	BIT(5)
#define TSRN10_HW_INNER_L4_CKSUM_ERR	BIT(6)
#define TSRN10_HW_CKSUM_ERR_MASK	GENMASK(6, 2)
#define TSRN10_HW_CHECK_ERR_MASK	GENMASK(6, 0)
#define TSRN10_HW_ERR_RX_ALL_MASK	GENMASK(1, 0)

#define TSRN10_REDIR_CTRL		_ETH_(0x8030)
#define TSRN10_VLAN_Q_STRIP_CTRL(n)	_ETH_(0x8040 + 0x4 * ((n) / 32))
/* This Just VLAN Master Switch */
#define TSRN10_VLAN_TUNNEL_STRIP_EN	_ETH_(0x8050)
#define TSRN10_VLAN_TUNNEL_STRIP_MODE	_ETH_(0x8054)
#define TSRN10_VLAN_TUNNEL_STRIP_OUTER	(0)
#define TSRN10_VLAN_TUNNEL_STRIP_INNER	(1)
#define TSRN10_RSS_INNER_CTRL		_ETH_(0x805c)
#define TSRN10_INNER_RSS_EN		(1)

#define TSRN10_ETH_DEFAULT_RX_RING	_ETH_(0x806c)
#define TSRN10_RX_FC_HI_WATER(n)	_ETH_(0x80c0 + ((n) * 0x8))
#define TSRN10_RX_FC_LO_WATER(n)	_ETH_(0x80c4 + ((n) * 0x8))

#define TSRN10_RX_FIFO_FULL_THRETH(n)	_ETH_(0x8070 + ((n) * 0x8))
#define TSRN10_RX_WORKAROUND_VAL	_ETH_(0x7ff)
#define TSRN10_RX_DEFAULT_VAL		_ETH_(0x270)

#define TSRN10_MIN_FRAME_CTRL		_ETH_(0x80f0)
#define TSRN10_MAX_FRAME_CTRL		_ETH_(0x80f4)

#define TSRN10_RX_FC_ENABLE		_ETH_(0x8520)
#define TSRN10_RING_FC_EN(n)		_ETH_(0x8524 + 0x4 * ((n) / 32))
#define TSRN10_RING_FC_THRESH(n)	_ETH_(0x8a00 + 0x4 * (n))

/* Mac Host Filter  */
#define TSRN10_MAC_FCTRL		_ETH_(0x9110)
#define TSRN10_MAC_FCTRL_MPE		BIT(8)	/* Multicast Promiscuous En */
#define TSRN10_MAC_FCTRL_UPE		BIT(9)	/* Unicast Promiscuous En */
#define TSRN10_MAC_FCTRL_BAM		BIT(10) /* Broadcast Accept Mode */
#define TSRN10_MAC_FCTRL_BYPASS		(TSRN10_MAC_FCTRL_MPE | \
					TSRN10_MAC_FCTRL_UPE | \
					TSRN10_MAC_FCTRL_BAM)
/* MC UC Mac Hash Filter Ctrl */
#define TSRN10_MAC_MCSTCTRL		_ETH_(0x9114)
#define TSRN10_MAC_HASH_MASK		GENMASK(11, 0)
#define TSRN10_MAC_MULTICASE_TBL_EN	BIT(2)
#define TSRN10_MAC_UNICASE_TBL_EN	BIT(3)
#define TSRN10_UC_HASH_TB(n)		_ETH_(0xA800 + ((n) * 0x4))
#define TSRN10_MC_HASH_TB(n)		_ETH_(0xAC00 + ((n) * 0x4))

#define TSRN10_VLAN_FILTER_CTRL		_ETH_(0x9118)
#define TSRN10_L2TYPE_FILTER_CTRL	(TSRN10_VLAN_FILTER_CTRL)
#define TSRN10_L2TYPE_FILTER_EN		BIT(31)
#define TSRN10_VLAN_FILTER_EN		BIT(30)

#define TSRN10_FC_PAUSE_FWD_ACT		_ETH_(0x9280)
#define TSRN10_FC_PAUSE_DROP		BIT(31)
#define TSRN10_FC_PAUSE_PASS		(0)
#define TSRN10_FC_PAUSE_TYPE		_ETH_(0x9284)
#define TSRN10_FC_PAUSE_POLICY_EN	BIT(31)
#define TSRN10_PAUSE_TYPE		_ETH_(0x8808)

#define TSRN10_INPUT_USE_CTRL		_ETH_(0x91d0)
#define TSRN10_INPUT_VALID_MASK		(0xf)
#define TSRN10_INPUT_POLICY(n)		_ETH_(0x91e0 + ((n) * 0x4))

/* RSS */
#define TSRN10_RSS_MRQC_ADDR		_ETH_(0x92a0)
#define TSRN10_SRIOV_CTRL		TSRN10_RSS_MRQC_ADDR
#define TSRN10_SRIOV_ENABLE		BIT(3)

#define TSRN10_RSS_REDIR_TB(mac, idx)	_ETH_(0xe000 + \
		((mac) * 0x200) + ((idx) * 0x4))
#define TSRN10_RSS_KEY_TABLE(idx)	_ETH_(0x92d0 + ((idx) * 0x4))
/*=======================================================================
 *HOST_MAC_ADDRESS_FILTER
 *=======================================================================
 */
#define TSRN10_RAL_BASE_ADDR(vf_id)	_ETH_(0xA000 + 0x04 * (vf_id))
#define TSRN10_RAH_BASE_ADDR(vf_id)	_ETH_(0xA400 + 0x04 * (vf_id))
#define TSRN10_MAC_FILTER_EN		BIT(31)

/* ETH Statistic */
#define TSRN10_ETH_RXTRANS_DROP(p_id)	 _ETH_((0x8904) + ((p_id) * (0x40)))
#define TSRN10_ETH_RXTRANS_CAT_ERR(p_id) _ETH_((0x8928) + ((p_id) * (0x40)))
#define TSRN10_ETH_TXTM_DROP		 _ETH_(0X0470)

#define TSRN10_VFTA_BASE_ADDR		_ETH_(0xB000)
#define TSRN10_VFTA_HASH_TABLE(id)	(TSRN10_VFTA_BASE_ADDR + 0x4 * (id))
#define TSRN10_ETYPE_BASE_ADDR		_ETH_(0xB300)
#define TSRN10_MPSAR_BASE_ADDR(vf_id)	_ETH_(0xB400 + 0x04 * (vf_id))
#define TSRN10_PFVLVF_BASE_ADDR		_ETH_(0xB600)
#define TSRN10_PFVLVFB_BASE_ADDR	_ETH_(0xB700)
#define TSRN10_TUNNEL_PFVLVF_BASE_ADDR	_ETH_(0xB800)
#define TSRN10_TUNNEL_PFVLVFB_BASE_ADDR	_ETH_(0xB900)

#define TSRN10_TC_PORT_MAP_TB(port)	_ETH_(0xe840 + 0x04 * (port))
#endif /* TSRN10_ETH_REGS_H_ */