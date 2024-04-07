#ifndef _TSRN10_H_
#define _TSRN10_H_

#include <stdbool.h>
#include <stdio.h>
#include <rte_dev.h>
#include <rte_version.h>
#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#include <rte_flow.h>
#include <rte_flow_driver.h>
#endif
#include <rte_cycles.h>
#include <rte_spinlock.h>
#include <rte_mbuf.h>

#include "tsrn10_logs.h"

#include "tsrn10_compat.h"
#define PATCH_RELEASE_VERSION "v0.2.4"

#include "base/tsrn10_hw.h"
#include "tsrn10_flow.h"
#include "tsrn10_ptp.h"
#include "base/tsrn10_ptype.h"

#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
#define RTE_PARSE_ARGS_SUPPORTED 1
#endif

#define TSRN10_ON  (1)
#define TSRN10_OFF (0)
#define VF_ISO_EN

#define USING_MBX

#define PCI_VENDOR_ID_MUCSE		(0x8848)
#define TSRN10_DEV_ID_N10G		(0x1000)
#define TSRN10_DEV_ID_N10G_C		(0x1c00)
#define TSRN10_DEV_ID_N10L		(0x1060)
#define TSRN10_DEV_ID_N10L_C		(0x1c60)
#define TSRN10_DEV_ID_N10G_X4		(0x1020)
#define TSRN10_DEV_ID_N10G_X4_C		(0x1c20)
#define TSRN10_DEV_ID_N400L_X4		(0x1021)
#define TSRN10_DEV_ID_N400L_X4_C	(0x1c21)
#define TSRN10_DEV_ID_N400L_X2		(0X1001)
#define TSRN10_DEV_ID_N400L_X2_C	(0X1c01)
#define TSRN10_DEV_ID_VF		(0x1080)
#define TSRN10_DEV_ID_VF_C		(0x1c80)
#define TSRN10_DEV_ID_N400_VF		(0x1081)

/* Peer Port Own Indepent Resource */
#define TSRN10_PORT_MAX_MACADDR		(32)
#define TSRN10_PORT_MAX_UC_MAC_SIZE	(256)
#define TSRN10_PORT_MAX_VLAN_HASH	(12)
#define TSRN10_PORT_MAX_UC_HASH_TB	(8)

/* Hardware Resource info */
#define TSRN10_MAX_RX_QUEUE_NUM		(128)
#define TSRN10_MAX_TX_QUEUE_NUM		(128)
#define TSRN10_N400_MAX_RX_QUEUE_NUM	(8)
#define TSRN10_N400_MAX_TX_QUEUE_NUM	(8)
#define TSRN10_MAX_HASH_KEY_SIZE	(10)
#define TSRN10_MAX_MAC_ADDRS		(128)
#define MAX_SUPPORT_VF_NUM		(64)
#define TSRN10_MAX_VFTA_SIZE		(128)
#define TSRN10_MAX_TC_SUPPORT		(4)

#define TSRN10_MAX_UC_MAC_SIZE		(4096) /* Max Num of Unicast MAC addr */
#define TSRN10_MAX_UC_HASH_TB		(128)
#define TSRN10_MAX_MC_MAC_SIZE		(4096) /* Max Num of Multicast MAC addr */
#define TSRN10_MAC_MC_HASH_TB		(128)
#define TSRN10_MAX_VLAN_HASH_TB_SIZE	(4096)

#define TSRN10_MAX_UC_HASH_TABLE	(128)
#define TSRN10_MAC_MC_HASH_TABLE	(128)

/* Filter Rule Parameter */
#define TSRN10_MAX_NTUPLE_RULE		(128)
#define TSRN10_MAX_TCAM_NTUPLE_RULE	(4096)
#define TSRN10_MAX_ETYPE_RULE_NUM	(16)

#define TSRN10_VF_MAX_RXQ_NUM		(2)
#define TSRN10_VF_MAX_TXQ_NUM		(2)
#define TSRN10_VF_MAX_MACADDR		(2)

#define TSRN10_SRIOV_VF_POOLS_16	(16)
#define TSRN10_SRIOV_VF_POOLS_32	(32)
#define TSRN10_SRIOV_VF_POOLS_64	(64)
#define TSRN10_SRIOV_VF_POOLS_128	(128)

#define TSRN10_MAX_PORT_OF_PF		(4)

#define TSRN10_RSS_INDIR_SIZE		(128)

/* Ring Info Special */
#define MAX_BD_COUNT			(4096)
#define MIN_BD_COUNT			(128)
#define BD_ALIGN			(2)
#define TSRN10_MIN_DMA_BUF_SIZE		(2048)

#define TSRN10_CFG_BAR			(4)
/* minimum frame size supported */
#define TSRN10_MAC_MINFRM_SIZE		(64)
/* maximum frame size supported */
#define TSRN10_MAC_MAXFRM_SIZE		(9590)
#define TSRN10_MAX_TSO_PKT		(16 * 1024)
#define TSRN10_RX_MAX_MTU_SEG		(64)
#define TSRN10_TX_MAX_MTU_SEG		(32)
#define TSRN10_RX_MAX_SEG		(150)
#define TSRN10_TX_MAX_SEG		(UINT8_MAX)
/* Link Flow Ctrl Attr */
#define TSRN10_FC_DEF_HIGH_WATER	(0x320)
#define TSRN10_FC_DEF_LOW_WATER		(0x270)
#define TSRN10_FC_DEF_PAUSE_TM		(0x100)

#define TSRN10_VLAN_TAG_SIZE               4
#define TSRN10_ETH_OVERHEAD \
	(RTE_ETHER_HDR_LEN + TSRN10_VLAN_TAG_SIZE * 2)

#define TSRN10_RX_CHECKSUM_SUPPORT ( \
	DEV_RX_OFFLOAD_IPV4_CKSUM | \
	DEV_RX_OFFLOAD_UDP_CKSUM | \
	DEV_RX_OFFLOAD_TCP_CKSUM | \
	DEV_RX_OFFLOAD_SCTP_CKSUM | \
	DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM)

#define TSRN10_SUPPORT_RSS_OFFLOAD_ALL ( \
	ETH_RSS_IPV4 | \
	ETH_RSS_FRAG_IPV4 | \
	ETH_RSS_NONFRAG_IPV4_OTHER | \
	ETH_RSS_NONFRAG_IPV4_TCP | \
	ETH_RSS_NONFRAG_IPV4_UDP | \
	ETH_RSS_NONFRAG_IPV4_SCTP |\
	ETH_RSS_IPV6 | \
	ETH_RSS_FRAG_IPV6 | \
	ETH_RSS_NONFRAG_IPV6_OTHER | \
	ETH_RSS_IPV6_EX | \
	ETH_RSS_IPV6_TCP_EX | \
	ETH_RSS_NONFRAG_IPV6_TCP | \
	ETH_RSS_NONFRAG_IPV6_UDP | \
	ETH_RSS_IPV6_UDP_EX | \
	ETH_RSS_NONFRAG_IPV6_SCTP)

#define TSRN10_NOT_SUPPORT_RSS_ALL ( \
	ETH_RSS_L2_PAYLOAD | \
	ETH_RSS_PORT | \
	ETH_RSS_VXLAN | \
	ETH_RSS_GENEVE | \
	ETH_RSS_NVGRE | \
	ETH_RSS_GTPU | \
	ETH_RSS_L3_SRC_ONLY | \
	ETH_RSS_L3_DST_ONLY | \
	ETH_RSS_L4_SRC_ONLY | \
	ETH_RSS_L4_DST_ONLY)

#define TSRN10_TX_CKSUM_OFFLOAD_MASK (		\
		RTE_MBUF_F_TX_IP_CKSUM |	\
		RTE_MBUF_F_TX_L4_MASK |		\
		RTE_MBUF_F_TX_TCP_SEG |		\
		RTE_MBUF_F_TX_OUTER_IP_CKSUM)

#define TSRN10_L4_OFFLOAD_ALL	(RTE_MBUF_F_TX_SCTP_CKSUM | \
				 RTE_MBUF_F_TX_TCP_CKSUM | \
				 RTE_MBUF_F_TX_UDP_CKSUM)

#define TSRN10_MBX_MISC_VECID		RTE_INTR_VEC_ZERO_OFFSET

#define TSRN10_RX_DESC_HIGH_WATER_TH	(96) /* dma fetch desc High water threshold */
#define TSRN10_RX_DEFAULT_BURST		(32)
#define TSRN10_TX_DESC_HIGH_WATER_TH	(64) /* dma fetch desc High water threshold */
#define TSRN10_TX_DEFAULT_BURST		(32)  /* max-num_descs_peer_read */

#define TSRN10_DEFAULT_TX_FREE_THRESH	(32)
#define TSRN10_DEFAULT_TX_RS_THRESH	(32)
#define TSRN10_DEFAULT_RX_FREE_THRESH	(32)

#define TSRN10_RX_MAX_BURST_SIZE	(32)
#define upper_32_bits(n)		((uint32_t)(((n) >> 16) >> 16))
#define lower_32_bits(n)		((uint32_t)(n))

#define TSRN10_MAX_RING_DESC		(4096)
#define TSRN10_RX_MAX_RING_SZ ((TSRN10_MAX_RING_DESC + \
			TSRN10_RX_MAX_BURST_SIZE) * \
		sizeof(struct tsrn10_rx_desc))

#define TSRN10_TX_MAX_RING_SZ ((TSRN10_MAX_RING_DESC + \
			TSRN10_RX_MAX_BURST_SIZE) * \
		sizeof(struct tsrn10_tx_desc))

#define MAX_RING_NAME		(128)

/* EEPROM byte offsets */
#define SFF_MODULE_ID_OFFSET	0x00
#define TSRN10_SFF_8472_COMP	0x5E
#define SFF_DIAG_SUPPORT_OFFSET 0x5c
#define SFF_MODULE_ID_SFP	0x3
#define SFF_MODULE_ID_QSFP	0xc
#define SFF_MODULE_ID_QSFP_PLUS 0xd
#define SFF_MODULE_ID_QSFP28	0x11

struct tsrn10_rxsw_entry {
	struct rte_mbuf *mbuf;  /* Sync With Tx Desc Dma Physical Addr */
};

/* For xmit pkts Some mode a Need Control Desc And a Data Desc
 * So Resource Recycle Need Tag To Find Dma Resource unused
 */
struct tsrn10_txsw_entry {
	struct rte_mbuf *mbuf;  /* Sync With Tx Desc Dma Physical Addr */
	uint16_t next_id;       /* Next Entry Resource Hold Index */
	uint16_t prev_id;       /* Prev Entry Resource Hold Index */
	uint16_t cur_id;        /* Cur Entry Resource Hold Index */
	uint16_t rs_bit_set;
	uint16_t last_id;       /* Last Entry Resource Hold Index */
	uint16_t nb_seg;
};

struct xstats {
	uint64_t obytes;
	uint64_t opackets;

	uint64_t ibytes;
	uint64_t ipackets;

	uint64_t errors;
	/* xmit func can't recycle bd  because of the DD hw Don't set */
	uint64_t tx_ring_full;
	/* Tx sw Drop Pkts because of bd resource */
	uint64_t tx_full_drop;
};

struct tsrn10_queue_attr {
	uint64_t sriov_st;
	uint16_t vf_num;		/* Mark Ring belong to which VF */
	uint16_t queue_id;		/* Sw Queue Index*/
	uint16_t index;			/* Dma Ring Index */
	uint16_t lane_id;		/* Ring Belong To Which Physical Lane */
	uint16_t bd_count;		/* Max BDs */
	uint16_t bd_mask;		/* Mask Of Bds */
	uint16_t rte_pid;		/* Dpdk Mange Port Sequence Id */
};

struct tsrn10_rx_queue {
	struct rte_mempool *mb_pool;	/* mbuf pool to populate RX ring. */
	volatile struct tsrn10_rx_desc *rx_bdr;/* Rx Dma Ring Virtual Addr */
	uint64_t ring_phys_addr;	/* Rx Dma Ring Physical Addr */
	struct tsrn10_rxsw_entry *sw_ring;/* Rx Software Ring Addr */
	volatile uint32_t *rx_tailreg;  /* HW Desc Tail Register */
	volatile uint32_t *rx_headreg;	/* HW Desc Head Register*/
	struct tsrn10_queue_attr attr;
	uint8_t rxq_started;
	bool rx_link;
	bool timestamp_all;		/* user set timestamp all packet */
	bool ptp_en;			/* user enable 1588 feature */
	uint8_t rx_deferred_start;	/*< Do not start queue with dev_start(). */

	uint16_t next_to_clean;		/* Soft-Saved-Tail */
	uint16_t nb_rx_free;		/* Number Available use Desc */

	uint16_t rx_tail;
	uint16_t rxrearm_nb;
	uint16_t rxrearm_start;

	uint16_t rx_hold;		/* Rx Stage Has Avail Mbuf */
	uint16_t rx_next_hold_idx;	/* Next Index Of Fill Mbuf To Stage */
	uint16_t rx_peak_idx;		/* Idx Of Peak Sequence Of Rx Stage */
	uint16_t rx_free_trigger;	/* Rx Free Desc Resource Trigger */
	uint16_t rx_free_thresh;	/* Rx Free Desc Resource Thresh */

	struct rte_mbuf *pkt_first_seg;	/* First Segment Pkt Of Jumbo Frame */
	struct rte_mbuf *pkt_last_seg;	/* Last Segment Pkts Of Jumbo Frame */

	struct rte_mbuf *rx_stage[TSRN10_RX_MAX_BURST_SIZE * 2];
	struct rte_mbuf **free_mbufs;	/* Rx bulk alloc reserve of free mbufs */
	struct xstats stats;
	uint64_t rx_offload_capa;	/* Enable Rxq Offload Feature */
	uint8_t mark_enabled;
	const struct rte_memzone *rz;
	uint16_t rx_buf_len;

	uint64_t mbuf_initializer;	/**< value to init mbufs */
};

enum tsrn10_tx_queue_state {
	TSRN10_TX_QUEUE_STOP = 0,
	TSRN10_TX_QUEUE_START,
};

struct tsrn10_tx_queue {
	volatile struct tsrn10_tx_desc *tx_bdr;/* Tx Dma Ring Virtual Addr */
	uint64_t ring_phys_addr;	/* Tx Dma Ring Physical Addr */
	struct tsrn10_txsw_entry *sw_ring;/* Tx Software Ring Addr */
	uint8_t __iomem *tx_tailreg;	/* HW Desc Tail Register */
	uint8_t __iomem *tx_headreg;	/* HW Desc Head Register*/
	struct tsrn10_queue_attr attr;

	uint8_t txq_started;
	uint8_t tx_link;
	uint8_t tx_deferred_start;	/*< Do not start queue with dev_start(). */

	uint64_t offloads;		/* Tx Offload Feature State*/

	uint16_t next_to_use;		/* Tx Soft-Saved-head */
	uint16_t next_to_clean;
	uint16_t nb_tx_free;		/* Avail Desc To Set PKTS DMA Addr */
	uint16_t nb_tx_used;
	uint16_t last_desc_cleaned;
	uint16_t last_clean;

	uint16_t tx_tail;

	uint16_t tx_next_dd;		/* Next To Scan WriteBack DD Bit */
	uint16_t tx_rs_thresh;		/* Number Of Interval Set RS Bit */
	uint16_t tx_next_rs;		/* Index Of Next Time To Set RS Bit*/
	uint16_t tx_free_thresh;	/* Thresh To Free Tx Desc Resource */
	uint16_t tx_free_trigger;
	uint16_t cur_rs_index;
	uint16_t clean_rs_index;

	struct xstats stats;

	uint16_t head_idx;
	uint16_t tail_idx;
	uint16_t last_use_bd;
	const struct rte_memzone *rz;
};

struct tsrn10_vfinfo {
	uint8_t vf_mac_addr[RTE_ETHER_ADDR_LEN];
	uint16_t rx_dma_quene_base;
	uint16_t tx_dma_quene_base;
	uint16_t rx_queue_num;
	uint16_t tx_queue_num;
	uint16_t tx_maxrate;
	uint16_t vf_vlan_id;
	uint16_t pool_num;

	uint16_t vf_id;
};

struct tsrn10_vlan_filter {
	uint32_t vfta_entries[TSRN10_MAX_VFTA_SIZE]; /* VLAN Filter Table */
};
/*
 * Structure to store private data for each driver instance (for each port).
 */
enum tsrn10_work_mode {
	TSRN10_SINGLE_40G = 0,
	TSRN10_SINGLE_10G = 1,
	TSRN10_DUAL_10G = 2,
	TSRN10_QUAD_10G = 3,
};

struct tsrn10_eth_adapter;

struct tsrn10_hw_stats {
	uint64_t mac_local_fault;
	uint64_t mac_remote_fault;
	uint64_t rx_all_pkts;     /* Include Good And Bad Frame Num */
	uint64_t rx_all_bytes;    /* Include Good And Bad Pkts octes */
	uint64_t rx_good_pkts;
	uint64_t rx_good_bytes;
	uint64_t rx_broadcast;
	uint64_t rx_multicast;
	uint64_t rx_crc_err;
	uint64_t rx_runt_err;     /* Frame Less-than-64-byte with a CRC error*/
	uint64_t rx_jabber_err;   /* Jumbo Frame Crc Error */
	uint64_t rx_undersize_err;/* Frame Less Than 64 bytes Error */
	uint64_t rx_oversize_err; /* Bigger Than Max Support Length Frame */
	uint64_t rx_64octes_pkts;
	uint64_t rx_65to127_octes_pkts;
	uint64_t rx_128to255_octes_pkts;
	uint64_t rx_256to511_octes_pkts;
	uint64_t rx_512to1023_octes_pkts;
	uint64_t rx_1024tomax_octes_pkts;
	uint64_t rx_unicast;
	uint64_t rx_len_err;	 /* Bigger Or Less Than Len Support */
	uint64_t rx_len_invaild; /* Frame Len Isn't equal real Len */
	uint64_t rx_pause; /* Rx Pause Frame Num */
	uint64_t rx_vlan;  /* Rx Vlan Frame Num */
	uint64_t rx_watchdog_err; /* Rx with a watchdog time out error */
	uint64_t rx_bad_pkts;

	uint64_t tx_all_pkts;     /* Include Good And Bad Frame Num */
	uint64_t tx_all_bytes;    /* Include Good And Bad Pkts octes */
	uint64_t tx_broadcast;
	uint64_t tx_multicast;
	uint64_t tx_64octes_pkts;
	uint64_t tx_65to127_octes_pkts;
	uint64_t tx_128to255_octes_pkts;
	uint64_t tx_256to511_octes_pkts;
	uint64_t tx_512to1023_octes_pkts;
	uint64_t tx_1024tomax_octes_pkts;
	uint64_t tx_all_unicast;
	uint64_t tx_all_multicase;
	uint64_t tx_all_broadcast;
	uint64_t tx_underflow_err;
	uint64_t tx_good_pkts;
	uint64_t tx_good_bytes;
	uint64_t tx_pause_pkts;
	uint64_t tx_vlan_pkts;
	uint64_t tx_bad_pkts;
	uint64_t tx_ring_full;
	uint64_t tx_full_drop;
};

struct tsrn10_debug_stats {
	uint64_t rx_alloc_mbuf_fail;
	uint64_t rx_clean_count;
	uint64_t rx_desc_clean_num;
	uint64_t rx_desc_clean_fail;
	uint64_t rx_desc_err;
	uint64_t rx_burst_size;
	uint64_t rx_burst_time;
	uint64_t rx_used_cycle;
	uint64_t rx_cycle_check_count;

	uint64_t rx_burst_count[32];

	uint64_t rx_tail_update[64];
	uint64_t last_tail_size;

	uint64_t tx_mbuf_err;
	uint64_t tx_last_tail;
	uint64_t tx_curl_tail;
	uint64_t tx_next_to_clean;
	uint64_t tx_desc_clean_num;

	uint64_t tx_clean_count;

	uint64_t tx_desc_clean_fail;
	uint64_t tx_free_desc;
	uint64_t tx_desc_err;
	uint64_t tx_burst_size;
	uint64_t tx_burst_time;
	uint64_t tx_used_cycle;
	uint64_t tx_cycle_check_count;

	uint64_t tx_burst_count[32];
};

enum tsrn10_resource_share_m {
	TSRN10_SHARE_CORPORATE = 0,
	TSRN10_SHARE_INDEPEND,
};

/* media type */
enum TSRN10_media_type {
	TSRN10_MEDIA_TYPE_UNKNOWN,
	TSRN10_MEDIA_TYPE_FIBER,
	TSRN10_MEDIA_TYPE_COPPER,
	TSRN10_MEDIA_TYPE_BACKPLANE,
	TSRN10_MEDIA_TYPE_NONE,
};

struct tsrn10_phy_meta {
	uint16_t phy_type;
	uint32_t speed_cap;
	uint32_t supported_link;
	uint16_t link_duplex;
	uint16_t link_autoneg;
	uint8_t media_type;
	bool is_sgmii;
	bool is_backplane;
	bool fec;
	uint32_t phy_identifier;
};

struct tsrn10_port_attr {
	uint16_t max_mac_addrs;	  /* Max Support Mac Address */
	uint16_t uc_hash_tb_size; /* Unicast Hash Table Size */
	uint16_t max_uc_mac_hash; /* Max Num of hash MAC addr for UC */
	uint16_t mc_hash_tb_size; /* Multicast Hash Table Size */
	uint16_t max_mc_mac_hash; /* Max Num Of Hash Mac addr For MC */
	uint16_t max_vlan_hash;   /* Max Num Of Hash For Vlan ID*/
	uint16_t rte_pid;         /* Dpdk Manage Port Sequence Id */
	uint8_t max_rx_queues;    /* Belong To This Port Rxq Resource */
	uint8_t max_tx_queues;	  /* Belong To This Port Rxq Resource */
	uint8_t queue_ring_base;
	uint8_t port_offset;      /* Use For Redir Table Dma Ring Offset Of Port */
	union {
		uint8_t nr_lane; /* phy lane of This PF:0~3 */
		uint8_t nr_port; /* phy lane of This PF:0~3 */
	};
	struct tsrn10_phy_meta phy_meta;
	bool link_ready;
	bool pre_link;
	uint32_t speed;
	uint16_t max_rx_pktlen;   /* Current Port Max Support Packet Len */
	uint16_t max_mtu;
};

enum tsrn10_vlan_type {
	TSRN10_CVLAN_TYPE = 0,
	TSRN10_SVLAN_TYPE = 1,
};

struct tsrn10_port_stats {
	uint64_t rx_miss_inc;
	uint64_t last_rx_miss;
	uint64_t rxcat_err_inc;
	uint64_t last_rxcat_err;
	uint64_t mac_local_fault;
	uint64_t mac_remote_fault;
};

enum tsrn10_port_state {
	TSRN10_PORT_STATE_PAUSE = 0,
	TSRN10_PORT_STATE_FINISH,
	TSRN10_PORT_STATE_SETTING,
};

enum {
	TSRN10_IO_FUNC_USE_NONE = 0,
	TSRN10_IO_FUNC_USE_VEC,
	TSRN10_IO_FUNC_USE_SIMPLE,
	TSRN10_IO_FUNC_USE_COMMON,
};

struct tsrn10_eth_port {
	void *adapt;
	uint8_t mac_addr[RTE_ETHER_ADDR_LEN];
	struct rte_eth_dev *dev; /* Back Resource Record */
	struct tsrn10_port_attr attr;
	bool port_stopped;
	bool port_closed;
	struct tsrn10_hw *hw;

	uint8_t rx_func_sec; /* force set io rx_func */
	uint8_t tx_func_sec; /* force set io tx func*/

	rte_atomic64_t state;
	rte_spinlock_t rx_mac_lock; /* Lock For Mac_cfg resource write */

	bool rss_en;
	bool jumbo_en;
	uint32_t indirtbl[TSRN10_RSS_INDIR_SIZE];
	bool reta_has_cfg;
	bool rxq_num_changed;
	uint32_t last_rx_num;
	uint16_t cur_mtu;
	struct rte_eth_rss_conf rss_cfg;
	bool hw_rss_en;

	struct tsrn10_fc_info fc;
	struct tsrn10_ptp_info ptp;

	rte_atomic64_t ptp_sync_timestamp;

	enum tsrn10_resource_share_m s_mode; /* Port Resource Independ */
	struct tsrn10_debug_stats stats;
	struct tsrn10_hw_stats hw_stats;
	struct tsrn10_port_stats sw_stat;

	struct tsrn10_resource_cmd *cmd_info;
	rte_spinlock_t res_lock;  /* Resource Request Lock */
	/* Recvice Mac Address Record Table */
	uint8_t mac_use_tb[TSRN10_MAX_MAC_ADDRS];
	uint8_t use_num_mac;
	/* Unicast Mac Address Hash Table */
	uint8_t hash_filter_type;
	uint32_t hash_table_shift;
	uint32_t hash_table_count;
	uint32_t uc_hash_mac_addr; /* Record Uc Addr Use Set */
	uint32_t uc_hash_table[TSRN10_MAX_UC_HASH_TABLE];
	uint32_t mc_hash_mac_addr; /* Record Uc Addr Use Set */
	uint32_t mc_hash_table[TSRN10_MAX_UC_HASH_TABLE];
	uint64_t vlans_bitmap[BITS_TO_LONGS(VLAN_N_VID)];
	struct tsrn10_tx_queue *tx_queues[TSRN10_MAX_RX_QUEUE_NUM];

	struct tsrn10_vlan_filter vfta;
	struct tsrn10_filter_info filter;

	enum tsrn10_vlan_type outvlan_type;
	enum tsrn10_vlan_type invlan_type;
};
struct tsrn10_share_ops {
	struct tsrn10_mac_api mac_api;
	struct tsrn10_mbx_api mbx_api;
	struct tsrn10_phy_api phy_api;
};

struct tsrn10_eth_adapter {
	enum tsrn10_work_mode mode;
	enum tsrn10_resource_share_m s_mode; /* Port Resource Share Policy */
	struct tsrn10_share_ops *share_priv;
	struct tsrn10_eth_port *port[TSRN10_MAX_PORT_OF_PF];
	struct tsrn10_vfinfo *vfinfo;
	struct tsrn10_hw hw;

	struct rte_pci_device *pdev;
	struct rte_eth_dev *eth_dev;

	uint8_t rx_func_sec; /* force set io rx_func */
	uint8_t tx_func_sec; /* force set io tx func*/

	uint8_t num_ports;
	uint8_t lane_mask;
	uint8_t lane_link_status;/* 0~3bit 1:link-is-up 0: link-is-down */
	int max_link_speed;

	bool adapter_stopped;
	bool sriov;
	bool unregistered;
	int rss_inited;
	uint8_t pf_id;
	uint8_t mac_hash_mode;
	/* Switch Domain Id */
	uint16_t switch_domain_id;
	uint16_t max_vfs;
	bool debug_mac;

	/*fw-update*/
	bool  do_fw_update;
	char *fw_path;

	bool loopback_en;
	bool fw_sfp_10g_1g_auto_det;

	int fw_force_speed_1g;
#define FOCE_SPEED_1G_NOT_SET  -1
#define FOCE_SPEED_1G_DISABLED 0
#define FOCE_SPEED_1G_ENABLED  1
};

struct tsrn10vf_eth_adapter {
	struct rte_pci_device *pdev;
	struct tsrn10_eth_port *port;
	struct rte_eth_dev *ndev;
	struct tsrn10_hw hw;
	uint8_t rxq_dma_base;
	uint8_t txq_dma_base;
	int num_ports;

	uint64_t max_link_speed;
	bool link_up;

	bool vlan_change_allow;
	uint16_t vlan_id;
	uint16_t add_vlan_num;
};

#define TSRN10_DEV_TO_FILTER_INFO(eth) \
	(&(((struct tsrn10_eth_port *)(eth)->data->dev_private)->filter))

#define TSRN10_DEV_TO_PORT(eth_dev) \
	(((struct tsrn10_eth_port *)((eth_dev)->data->dev_private)))

#define TSRN10_DEV_TO_PORT_ID(dev) \
	(TSRN10_DEV_TO_PORT(dev)->attr.nr_port)

#define TSRN10_DEV_TO_ADAPTER(eth_dev) \
	((struct tsrn10_eth_adapter *)(TSRN10_DEV_TO_PORT(eth_dev)->adapt))

#define TSRN10_PORT_TO_ADAPTER(port) \
	((struct tsrn10_eth_adapter *)((port)->adapt))

#define TSRN10_DEV_TO_HW(eth_dev) \
	(&((struct tsrn10_eth_adapter *)(TSRN10_DEV_TO_PORT((eth_dev))->adapt))->hw)

#define TSRN10_PORT_TO_HW(port) \
	(&(((struct tsrn10_eth_adapter *)(port)->adapt)->hw))

#define TSRN10_DEV_TO_HW_STATS(dev) \
	(&(TSRN10_DEV_TO_PORT((dev))->hw_stats))

#define TSRN10_HW_TO_ADAPTER(hw) \
	((struct tsrn10_eth_adapter *)((hw)->back))

#define TSRN10_DEV_TO_ADAPTER_VF(eth_dev) \
	((struct tsrn10vf_eth_adapter *)((TSRN10_DEV_TO_PORT(eth_dev))->adapt))

#define TSRN10_DEV_TO_HW_VF(eth_dev) \
	((&(((struct tsrn10vf_eth_adapter *)(TSRN10_DEV_TO_PORT((eth_dev)))->adapt))->hw))

#define TSRN10_PORT_TO_HW_VF(port) \
	(&(((struct tsrn10vf_eth_adapter *)(port)->adapt)->hw))

#define TSRN10_DEV_TO_VFTA(dev) \
	(&((struct tsrn10_eth_port *)(dev)->data->dev_private)->vfta)

#define TSRN10_DEV_TO_PTP_INFO(dev) \
	(&((TSRN10_DEV_TO_PORT(dev)->ptp)))

#define TSRN10_DEV_TO_FC_INFO(dev) \
	(&((TSRN10_DEV_TO_PORT(dev)->fc)))

#define TSRN10_DEV_TO_HW_INFO(dev) \
	((TSRN10_DEV_TO_PORT((dev))->hw))

#if RTE_VERSION_NUM(18, 11, 0, 0) <= RTE_VERSION
#define TSRN10_DEV_PP_PRIV_TO_MAC_OPS(dev) \
	(&((struct tsrn10_share_ops *)(dev)->process_private)->mac_api)
#define TSRN10_DEV_PP_PRIV_TO_MBX_OPS(dev) \
	(&((struct tsrn10_share_ops *)(dev)->process_private)->mbx_api)
#define TSRN10_DEV_PP_PRIV_TO_PHY_OPS(dev) \
	(&((struct tsrn10_share_ops *)(dev)->process_private)->phy_api)
#define TSRN10_DEV_TO_MAC_OPS(dev)	TSRN10_DEV_PP_PRIV_TO_MAC_OPS(dev)
#define TSRN10_DEV_TO_MBX_OPS(dev)	TSRN10_DEV_PP_PRIV_TO_MBX_OPS(dev)
#define TSRN10_DEV_TO_PHY_OPS(dev)	TSRN10_DEV_PP_PRIV_TO_PHY_OPS(dev)
#else
#define TSRN10_DEV_TO_HW_MAC_OPS(dev) \
	(&(TSRN10_DEV_TO_HW_INFO(dev)->mac.ops))
#define TSRN10_DEV_TO_HW_MBX_OPS(dev) \
	(&(TSRN10_DEV_TO_HW_INFO(dev)->mbx.ops))
#define TSRN10_DEV_TO_HW_PHY_OPS(dev) \
	(&(TSRN10_DEV_TO_HW_INFO(dev)->phy.ops))
#define TSRN10_DEV_TO_MAC_OPS(dev)	TSRN10_DEV_TO_HW_MAC_OPS(dev)
#define TSRN10_DEV_TO_MBX_OPS(dev)	TSRN10_DEV_TO_HW_MBX_OPS(dev)
#define TSRN10_DEV_TO_PHY_OPS(dev)	TSRN10_DEV_TO_HW_PHY_OPS(dev)
#endif

/* RX/TX TSRN10 function prototypes */
uint16_t tsrn10_xmit_pkts(void *txq, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);
uint16_t tsrn10_recv_pkts(void *rxq, struct rte_mbuf **rx_pkts, uint16_t nb_pkts);
uint16_t tsrn10_scattered_rx(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
uint16_t tsrn10_prep_pkts(void *tx_queue, struct rte_mbuf **tx_pkts, uint16_t nb_pkts);

#if RTE_VERSION_NUM(21, 5, 0, 0) > RTE_VERSION
int tsrn10_ntuple_filter_handle(struct rte_eth_dev *dev,
				enum rte_filter_op filter_op, void *arg);
int tsrn10_ethertype_filter_handle(struct rte_eth_dev *dev,
				   enum rte_filter_op filter_op, void *arg);
int tsrn10_syn_filter_handle(struct rte_eth_dev *dev,
			     enum rte_filter_op filter_op, void *arg);
#endif
void tsrn10_setup_txbdr(struct tsrn10_hw *hw, struct tsrn10_tx_queue *tx_ring);
void tsrn10_setup_rxbdr(struct rte_eth_dev *dev, struct tsrn10_hw *hw,
			struct tsrn10_rx_queue *rx_queue,
			struct rte_mempool *mb_pool);
int tsrn10_mtu_set(struct rte_eth_dev *dev, uint16_t mtu);
int tsrn10_mac_get(struct tsrn10_hw *hw, uint8_t *mac, int nr_port);

static inline void
tsrn10_random_mac_addr(uint8_t *mac_addr)
{
	uint64_t random;
	/* Mac address means */
	/* | 1st | 2nd | 3rd | 4th | 5th | 6th |
	 * |    OUI          | NIC Specific    |
	 * Oui Organizationally Unique Identifier
	 * NIC Network interface Controller
	 * Need To Request For now just use FPGA(xilinx)
	 */
	mac_addr[0] = 0x00;
	mac_addr[1] = 0x4e;
	mac_addr[2] = 0x46;
	/* rand the rest address of mac */
	random = rte_rand();
	memcpy(&mac_addr[3], &random, 3);
}

static inline void tsrn10_reg_offset_init(struct tsrn10_hw *hw)
{
	uint16_t i;

	if ((hw->device_id == TSRN10_DEV_ID_N10G ||
	     hw->device_id == TSRN10_DEV_ID_VF) &&
	     hw->mbx.pf_num) {
#ifdef VF_ISO_EN
		hw->nic_reg += 0x100000;
		hw->msix_base = hw->nic_reg + 0xa0000;
		hw->msix_base += 0x200;
#endif
	} else {
		hw->msix_base = hw->nic_reg + 0xa0000;
	}
	/* === dma status/config====== */
	hw->dev_version  = hw->nic_reg + 0x0000;
	hw->dev_loopback = hw->nic_reg + 0x0004;
	hw->dev_status   = hw->nic_reg + 0x0008;
	hw->dev_dummy    = hw->nic_reg + 0x000c;
	hw->dma_axi_en   = hw->nic_reg + 0x0010;
	hw->dma_axi_st   = hw->nic_reg + 0x0014;


	if (hw->mbx.pf_num)
		hw->msix_base += 0x200;
	/* === queue registers === */
	hw->dma_base     = hw->nic_reg + 0x08000;
	hw->veb_base     = hw->nic_reg + 0x0;
	hw->eth_base     = hw->nic_reg + 0x10000;
	/* mac */
	for (i = 0; i < TSRN10_MAX_HW_PORT_PERR_PF; i++)
		hw->mac_base[i] = hw->nic_reg + 0x60000 + 0x10000 * i;

	/* ===  top reg === */
	hw->comm_reg_base  = hw->nic_reg + 0x30000;
	hw->nic_top_config = hw->comm_reg_base + 0x0004;
}

static inline void tsrn10_enable_sriov(struct tsrn10_hw *hw, uint8_t en)
{
	uint32_t virtual_cfg;

	virtual_cfg = tsrn10_eth_rd(hw, TSRN10_SRIOV_CTRL);

	if (en)
		virtual_cfg |= TSRN10_SRIOV_ENABLE;
	else
		virtual_cfg ^= TSRN10_SRIOV_ENABLE;

	tsrn10_eth_wr(hw, TSRN10_SRIOV_CTRL, virtual_cfg);
}

static __rte_always_inline phys_addr_t
tsrn10_get_dma_addr(struct tsrn10_queue_attr *attr, struct rte_mbuf *mbuf)
{
	phys_addr_t dma_addr;
	phys_addr_t reg;

	dma_addr = rte_cpu_to_le_64(rte_mbuf_data_dma_addr(mbuf));
	if (attr->sriov_st) {
		reg = attr->sriov_st;
		dma_addr |= (reg << 56);
	}

	return dma_addr;
}

uint16_t
tsrn10_xmit_fixed_burst_vec(void *tx_queue, struct rte_mbuf **tx_pkts,
			    uint16_t nb_pkts);
uint16_t
tsrn10_recv_pkts_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
		     uint16_t nb_pkts);

uint16_t tsrn10_legend_xmit(void *_txq, struct rte_mbuf **tx_pkts,
			    uint16_t nb_pkts);
void tsrn10_setup_rx_function(struct rte_eth_dev *dev);
void tsrn10_setup_tx_function(struct rte_eth_dev *dev,
			      struct tsrn10_tx_queue *txq);
int tsrn10_get_dma_ring_index(struct tsrn10_eth_port *port, uint16_t queue_idx);
#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
uint32_t
tsrn10_dev_rx_queue_count(void *rx_queue);
#else
uint32_t
tsrn10_dev_rx_queue_count(struct rte_eth_dev *dev, uint16_t q_id);
#endif
static inline int tsrn10_ring_is_sriov(struct tsrn10_queue_attr *attr)
{
	return (attr->vf_num < UINT16_MAX) ? true : false;
}
/* int rnp_mbx_fw_reset_phy(struct tsrn10_hw *hw); */

int tsrn10_dev_rx_descriptor_done(void *rx_queue, uint16_t offset);
int
tsrn10_dev_rx_descriptor_status(void *rx_queue, uint16_t offset);
int
tsrn10_dev_tx_descriptor_status(void *tx_queue, uint16_t offset);
#if RTE_VERSION_NUM(19, 11, 0, 0) <= RTE_VERSION
int
tsrn10_rx_burst_mode_get(struct rte_eth_dev *dev,
			 __rte_unused uint16_t queue_id,
			 struct rte_eth_burst_mode *mode);
int
tsrn10_tx_burst_mode_get(struct rte_eth_dev *dev,
			 __rte_unused uint16_t queue_id,
			 struct rte_eth_burst_mode *mode);
#endif
int tsrn10_tx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t qidx);
int tsrn10_rx_queue_stop(struct rte_eth_dev *eth_dev, uint16_t qidx);
int tsrn10_tx_queue_start(struct rte_eth_dev *eth_dev, uint16_t qidx);
int tsrn10_rx_queue_start(struct rte_eth_dev *eth_dev, uint16_t qidx);
#if RTE_VERSION_NUM(2, 2, 0, 0) <= RTE_VERSION
void
tsrn10_rx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			 struct rte_eth_rxq_info *qinfo);
void
tsrn10_tx_queue_info_get(struct rte_eth_dev *dev, uint16_t queue_id,
			 struct rte_eth_txq_info *qinfo);
#endif
int tsrn10_alloc_txbdr(struct rte_eth_dev *dev,
		       struct tsrn10_tx_queue *txr,
		       uint16_t nb_desc, int socket_id);
int tsrn10_alloc_rxbdr(struct rte_eth_dev *dev,
		       struct tsrn10_rx_queue *rxq,
		       uint16_t nb_rx_desc, int socket_id);
void tsrn10_rx_queue_release_mbuf(struct tsrn10_rx_queue *rxq);
void
tsrn10_rx_queue_reset(struct rte_eth_dev *dev,
		      struct tsrn10_hw *hw,
		      struct tsrn10_rx_queue *rxq);
void
tsrn10_rx_queue_sw_reset(struct tsrn10_rx_queue *rxq);
uint8_t tsrn10_alloc_rxq_mbuf(struct tsrn10_rx_queue *rxq);

void tsrn10_tx_queue_reset(struct tsrn10_hw *hw,
			   struct tsrn10_tx_queue *txq);

void
tsrn10_tx_queue_sw_reset(struct tsrn10_tx_queue *txq);

void tsrn10_tx_queue_release_mbuf(struct tsrn10_tx_queue *txq);
uint16_t
tsrn10_scattered_burst_vec(void *rx_queue, struct rte_mbuf **rx_pkts,
			   uint16_t nb_pkts);
uint16_t
tsrn10_rx_burst_simple(void *rx_queue, struct rte_mbuf **rx_pkts,
		uint16_t nb_pkts);
int
tsrn10_set_port_link(struct rte_eth_dev *dev, struct tsrn10_phy_cfg *cfg);
static inline int
tsrn10_rxq_vec_setup_default(struct tsrn10_rx_queue *rxq)
{
	struct rte_mbuf mb_def = { .buf_addr = 0 }; /* zeroed mbuf */
	uintptr_t p;

	mb_def.nb_segs = 1;
	mb_def.data_off = RTE_PKTMBUF_HEADROOM;
	mb_def.port = rxq->attr.rte_pid;
	rte_mbuf_refcnt_set(&mb_def, 1);

	/* prevent compiler reordering: rearm_data covers previous fields */
	rte_compiler_barrier();
	p = (uintptr_t)&mb_def.rearm_data;
	rxq->mbuf_initializer = *(uint64_t *)p;

	return 0;
}
#endif /* _TSRN10_H_ */
