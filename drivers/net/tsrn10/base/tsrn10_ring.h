#ifndef _TSRN10_RING_H_
#define _TSRN10_RING_H_

#include <stdint.h>
#include "tsrn10_common.h"
#pragma pack(push)
#pragma pack(1)



/*= === cmd=== */
#define TSRN10_EOP		BIT(0) /* End Of Packet */
#define TSRN10_DD		BIT(1)
#define TSRN10_RS		BIT(2)


#define TSRN10_DESC_TYPE_SHIFT	(3)
#define TSRN10_CTRL_DESC	(1 << 3)
#define TSRN10_DATA_DESC	(0 << 3)

#define TSRN10_RX_PTP_OFFLOAD	BIT(4)

#define TSRN10_TX_TSO_OFFLOAD	BIT(4)
#define TSRN10_TX_PTP_OFFLOAD	BIT(10)

#define TSRN10_TX_TCP_TSO_EN (TSRN10_TX_TSO_OFFLOAD | \
			      TSRN10_IP_CKSUM_OFFLOAD | \
			      TSRN10_L4_CKSUM_OFFLOAD | \
			      TSRN10_L4TYPE_TCP)

#define TSRN10_L3TYPE_IPV6	(1 << 5)
#define TSRN10_L3TYPE_IPV4	(0 << 5)

#define TSRN10_L4TYPE_TCP	(1 << 6)
#define TSRN10_L4TYPE_SCTP	(2 << 6)
#define TSRN10_L4TYPE_UDP	(3 << 6)
#define TSRN10_L4TYPE_MASK	(3 << 6)

#define TSRN10_RX_ERR_MASK	GENMASK(12, 8)
#define TSRN10_RX_L3_ERR	BIT(8)
#define TSRN10_RX_L4_ERR	BIT(9)
#define TSRN10_RX_SCTP_ERR	BIT(10)
#define TSRN10_RX_IN_L3_ERR	BIT(11)
#define TSRN10_RX_IN_L4_ERR	BIT(12)

/* TX Offload */
#define TSRN10_IP_CKSUM_OFFLOAD	BIT(11)
#define TSRN10_L4_CKSUM_OFFLOAD	BIT(12)
#define TSRN10_VLAN_OFFLOAD_EN	BIT(15)
#define TSRN10_VLAN_TCI_OFFSET	(16)
#define TSRN10_VLAN_TCI_MASK	(0xffff)

#define TSRN10_DESC_STATE_OFFSET (16)
#define TSRN10_PADING_LEN_OFFSET (16)

#define TSRN10_RX_TUNNEL_MASK	GENMASK(14, 13)
#define TSRN10_RX_TUNNEL_VXLAN	(0b01 << 13)
#define TSRN10_RX_TUNNEL_NVGRE	(0b10 << 13)
#define TSRN10_SUPPORT_PTYPE_MASK (0x60F0)

#define TSRN10_RX_L3_TYPE_MASK    BIT(7)

typedef struct date_rx_desc {
	u64 pkt_addr;
	u8 reserve[6];
	u16 cmd;
} data_rx_desc_t;

typedef struct ctrl_rx_desc {
	u32 rss_hash;
	union {
		uint32_t mark_data;
		struct {
			u16 mark;
			u8 veb;
			u8 ack;
		} marks;
	};
	union {
		uint32_t lens;
		struct {
			u16 len;
			u16 pad_len;
		} hdr;
	};

	union {
		uint32_t vlan_cmd;
#define TSRN10_CMD_DD	(0x20000)
#define TSRN10_CMD_EOP	(0x10000)
		struct {
			u16 vlan_tci;
			u16 cmd;
		} st;
	};
} ctrl_rx_desc_t;

typedef struct data_tx_desc {
	u64 addr;	/* Pkt Dma Address */

	u16 blen;	/* Pkt Data Len */
	u16 ip_len:9;	/* Ip Header Len */
	u16 mac_len:7;	/* Mac Header Len */

	u16 vlan;	/* Vlan Info */

	u16 cmd;	/* Ctrl Command */
} data_tx_desc_t;

#define TSRN10_TX_OFFLOAD_L4_CKSUM	BIT(12)
#define TSRN10_TX_OFFLOAD_L3_CKSUM	BIT(11)
#define TSRN10_TX_OFFLOAD_VLAN_ACT_SHIFT (13)
#define TSRN10_TX_TUNNEL_TYPE_SHIFT	(8)
#define TSRN10_TX_TUNNEL_TYPE_MASK	GENMASK(9, 8)
#define TSRN10_TX_TUNNEL_TYPE_VXLAN	(1 << TSRN10_TX_TUNNEL_TYPE_SHIFT)
#define TSRN10_TX_TUNNEL_TYPE_NVGRE	(2 << TSRN10_TX_TUNNEL_TYPE_SHIFT)

typedef struct ctrl_tx_desc {
	u16 mss;	/* TOS sz */
	u8 vf_num;	/* Vf Num */
#define TSRN10_TX_VF_PKT	BIT(7)
	u8 l4_len;	/* TCP Header Size */
	u8 tunnel_len;	/* Tunnel Header Size */
	u16 vlan_tag;	/* Svlan Id */
	u8 veb_tran;	/* Mark Pkt Is Transmit By Veb */
#define TSRN10_TX_VEB	BIT(1)
	u8 rev[6];
	u16 cmd;	/* Ctrl Command*/
} ctrl_tx_desc_t;

#define TSRN10_TX_CTX_INVLAN_ACT_SHIFT (10)
#define TSRN10_TX_OFFLOAD_VLAN_NONE	(0)
#define TSRN10_TX_OFFLOAD_VLAN_STRIP	(1)
#define TSRN10_TX_OFFLOAD_VLAN_INSERT	(2)

#pragma pack(pop)

#endif /* _TSRN10_RING_H_ */
