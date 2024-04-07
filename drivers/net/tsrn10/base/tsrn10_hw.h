#ifndef _TSRN10_HW_H_
#define _TSRN10_HW_H_

#include <rte_spinlock.h>

#include "tsrn10_dma_regs.h"
#include "tsrn10_eth_regs.h"
#include "tsrn10_mac_regs.h"
#include "tsrn10_pcs.h"
#include "tsrn10_ring.h"
#include "base/tsrn10_cfg.h"
#include "tsrn10_ptp.h"
#include "tsrn10_mbx.h"

#if RTE_VERSION_NUM(17, 2, 0, 0) <= RTE_VERSION
#include <rte_io.h>
#endif

#define TSRN10_MAX_TC_NUM (4)

/* BD RING ALIGNMENT */
#define TSRN10_BD_RING_ALIGN (128)
#ifdef RTE_ARCH_SW_64
#define tsrn10_io_wmb() \
	({                  \
		rte_io_wmb();   \
		rte_io_wmb();   \
		rte_io_wmb();   \
		rte_io_wmb();   \
		rte_io_wmb();   \
		rte_io_wmb();   \
	})
#define tsrn10_io_rmb() \
	({                  \
		rte_io_rmb();   \
		rte_io_rmb();   \
		rte_io_rmb();   \
		rte_io_rmb();   \
		rte_io_rmb();   \
		rte_io_rmb();   \
	})
#endif
#ifdef IO_PRINT
static inline unsigned int tsrn10_rd_reg(void *reg)
{
	unsigned int v = rte_read32((void *)(reg));
#ifdef RTE_ARCH_SW_64
	tsrn10_io_rmb();
#endif
	printf(" rd-reg: %p ==> 0x%08x\n", reg, v);
	return v;
}

static inline void tsrn10_wr_reg(void *reg, int val)
{
	printf(" wd-reg: %p <== 0x%08x\n", reg, val);
#ifdef RTE_ARCH_SW_64
	tsrn10_io_wmb();
#endif
	rte_write32_relaxed((val), (void *)(reg));
}
#else
#if RTE_VERSION_NUM(17, 0, 0, 0) >= RTE_VERSION

#define TSRN10_PCI_REG(reg) (*((volatile uint32_t *)(reg)))
static inline uint32_t tsrn10_rd_reg(volatile void *addr)
{
	uint32_t v = 0;
	v = TSRN10_PCI_REG(addr);
#ifdef RTE_ARCH_SW_64
	tsrn10_io_rmb();
#endif
	return v;
}
static inline void tsrn10_wr_reg(volatile void *reg, int value)
{
#ifdef RTE_ARCH_SW_64
	tsrn10_io_wmb();
#endif
	TSRN10_PCI_REG((reg)) = (value);
}
#else
static inline unsigned int tsrn10_rd_reg(volatile void *addr)
{
	unsigned int v = rte_read32(addr);
#ifdef RTE_ARCH_SW_64
	tsrn10_io_rmb();
#endif
	return v;
}
static inline void tsrn10_wr_reg(volatile void *reg, int val)
{
#ifdef RTE_ARCH_SW_64
	tsrn10_io_wmb();
#endif
	rte_write32_relaxed((val), (reg));
}
#endif
#endif

static inline void p_tsrn10_wr_reg(void *reg, int val)
{
	printf(" wd-reg: %p <== 0x%08x\n", reg, val);

	tsrn10_wr_reg(reg, val);
}

/* ================== reg-rw == */
#define TSRN10_MACADDR_UPDATE_LO(hw, hw_idx, val) \
	tsrn10_eth_wr(hw, TSRN10_RAL_BASE_ADDR(hw_idx), val)
#define TSRN10_MACADDR_UPDATE_HI(hw, hw_idx, val) \
	tsrn10_eth_wr(hw, TSRN10_RAH_BASE_ADDR(hw_idx), val)

#define tsrn10_nicx_rd(hw, off) tsrn10_rd_reg((char *)(hw)->nic_reg + (off))
#define tsrn10_nicx_wr(hw, off, val) \
	tsrn10_wr_reg((char *)(hw)->nic_reg + (off), val)
#define tsrn10_dma_rd(hw, off) tsrn10_rd_reg((char *)(hw)->dma_base + (off))
#define tsrn10_dma_wr(hw, off, val) \
	tsrn10_wr_reg((char *)(hw)->dma_base + (off), val)

#define tsrn10_eth_rd(hw, off) tsrn10_rd_reg((char *)(hw)->eth_base + (off))
#define tsrn10_eth_wr(hw, off, val) \
	tsrn10_wr_reg((char *)(hw)->eth_base + (off), val)

#define tsrn10_mac_rd(hw, id, off) \
	tsrn10_rd_reg((char *)(hw)->mac_base[id] + (off))
#define tsrn10_mac_wr(hw, id, off, val) \
	tsrn10_wr_reg((char *)(hw)->mac_base[id] + (off), val)

#define tsrn10_veb_rd(hw, off) tsrn10_rd_reg((char *)(hw)->veb_base + (off))
#define tsrn10_veb_wr(hw, off, val) \
	tsrn10_wr_reg((char *)(hw)->veb_base + (off), val)

#define mbx_prd32(hw, reg)		p_tsrn10_rd_reg((hw)->nic_reg + (reg))
#define mbx_rd32(hw, reg)		tsrn10_rd_reg((hw)->nic_reg + (reg))
#define mbx_pwr32(hw, reg, val) p_tsrn10_wr_reg((hw)->nic_reg + (reg), (val))
#define mbx_wr32(hw, reg, val)	tsrn10_wr_reg((hw)->nic_reg + (reg), (val))

#define TSRN10_GET_FW_VER(hw) tsrn10_rd_reg((char *)(hw)->nic_reg)

/* TSRN10 Parsed values (Little Endian) */
#define TSRN10_PARSE_ERROR		  (0x8000)
#define TSRN10_PKT_TYPE_ETHER	  (0x0060)
#define TSRN10_PKT_TYPE_IPV4	  (0x0000)
#define TSRN10_PKT_TYPE_IPV6	  (0x0020)
#define TSRN10_PKT_TYPE_IPV4_TCP  (0x0010 | TSRN10_PKT_TYPE_IPV4)
#define TSRN10_PKT_TYPE_IPV6_TCP  (0x0010 | TSRN10_PKT_TYPE_IPV6)
#define TSRN10_PKT_TYPE_IPV4_UDP  (0x0011 | TSRN10_PKT_TYPE_IPV4)
#define TSRN10_PKT_TYPE_IPV6_UDP  (0x0011 | TSRN10_PKT_TYPE_IPV6)
#define TSRN10_PKT_TYPE_IPV4_SCTP (0x0013 | TSRN10_PKT_TYPE_IPV4)
#define TSRN10_PKT_TYPE_IPV6_SCTP (0x0013 | TSRN10_PKT_TYPE_IPV6)
#define TSRN10_PKT_TYPE_IPV4_ICMP (0x0003 | TSRN10_PKT_TYPE_IPV4)
#define TSRN10_PKT_TYPE_IPV6_ICMP (0x0003 | TSRN10_PKT_TYPE_IPV6)

struct tsrn10_hw;

/* Mbx Operate info */
struct tsrn10_mbx_api {
	void (*init_mbx)(struct tsrn10_hw *hw);
	int32_t (*read)(struct tsrn10_hw *hw,
			uint32_t *msg,
			uint16_t size,
			enum MBX_ID);
	int32_t (*write)(struct tsrn10_hw *hw,
			 uint32_t *msg,
			 uint16_t size,
			 enum MBX_ID);
	int32_t (*read_posted)(struct rte_eth_dev *dev,
			       uint32_t *msg,
			       uint16_t size,
			       enum MBX_ID);
	int32_t (*write_posted)(struct rte_eth_dev *dev,
				uint32_t *msg,
				uint16_t size,
				enum MBX_ID);
	int32_t (*check_for_msg)(struct tsrn10_hw *hw, enum MBX_ID);
	int32_t (*check_for_ack)(struct tsrn10_hw *hw, enum MBX_ID);
	int32_t (*check_for_rst)(struct tsrn10_hw *hw, enum MBX_ID);
};

struct tsrn10_mbx_stats {
	u32 msgs_tx;
	u32 msgs_rx;

	u32 acks;
	u32 reqs;
	u32 rsts;
};

struct tsrn10_mbx_info {
	struct tsrn10_mbx_api ops;
	uint32_t usec_delay;	/* retry interval delay time */
	uint32_t timeout;	/* retry ops timeout limit */
	uint16_t size;		/* data buffer size*/
	uint16_t vf_num;	/* Virtual Function num */
	uint16_t pf_num;	/* Physical Function num */
	uint16_t sriov_st;	/* Sriov state */
	bool irq_enabled;
	union {
		struct {
			unsigned short pf_req;
			unsigned short pf_ack;
		};
		struct {
			unsigned short cpu_req;
			unsigned short cpu_ack;
		};
	};
	unsigned short vf_req;
	unsigned short vf_ack;

	struct tsrn10_mbx_stats stats;

	rte_atomic16_t state;
};

enum tsrn10_mpf_modes {
	TSRN10_MPF_MODE_NONE = 0,
	TSRN10_MPF_MODE_MULTI,    /* Multitle Filter */
	TSRN10_MPF_MODE_ALLMULTI, /* Multitle Promisc */
	TSRN10_MPF_MODE_PROMISC,  /* Promisc */
};

struct tsrn10_fc_info;
struct tsrn10_eth_port;
struct tsrn10_mac_api {
	int32_t (*init_hw)(struct tsrn10_hw *hw);
	int32_t (*reset_hw)(struct tsrn10_hw *hw);
	int32_t (*get_fw_ver)(struct tsrn10_hw *hw);
	/* MAC Address */
	int32_t (*get_mac_addr)(struct tsrn10_eth_port *port,
				uint8_t lane,
				uint8_t *macaddr);
	int32_t (*set_default_mac)(struct tsrn10_eth_port *port, uint8_t *mac);
	/* Receive Address Filter Table */
	int32_t (*set_rafb)(struct tsrn10_eth_port *port,
			    uint8_t *mac,
			    uint8_t vm_pool,
			    uint8_t index);
	int32_t (*clear_rafb)(struct tsrn10_eth_port *port,
			      uint8_t vm_pool,
			      uint8_t index);
	/* Update Unicast Address Table */
	int32_t (*update_uta)(struct tsrn10_eth_port *port,
			      uint8_t *addr,
			      uint8_t add);
	int32_t (*enable_uta)(struct tsrn10_eth_port *port, bool add);
	/* Update Multicast Address Table */
	int32_t (*update_mta)(struct tsrn10_eth_port *port,
			      struct rte_ether_addr *mc_list,
			      uint8_t nb_mc);
	int32_t (*enable_mta)(struct tsrn10_eth_port *port, bool add);
	/* Update Mac Packet Filter Mode */
	int32_t (*update_mpfm)(struct tsrn10_eth_port *port,
			       enum tsrn10_mpf_modes mode,
			       bool en);
	/* Mac Flow Ctrl */
	int32_t (*fc_enable)(struct tsrn10_eth_port *port,
			     struct tsrn10_fc_info *fc,
			     uint8_t p_id,
			     bool en);
	int32_t (*en_vlan_f)(struct tsrn10_eth_port *port, bool en);
	int32_t (*add_vlan_f)(struct tsrn10_eth_port *port,
			      uint16_t vlan,
			      bool add);
};

struct tsrn10_mac_info {
	uint8_t assign_addr[RTE_ETHER_ADDR_LEN];
	uint8_t set_addr[RTE_ETHER_ADDR_LEN];
	struct tsrn10_mac_api ops;
};

/* Flow Ctrl Configuration Info */
enum tsrn10_fc_mode {
	TSRN10_FC_NONE = 1,
	TSRN10_FC_RX_PAUSE,
	TSRN10_FC_TX_PAUSE,
	TSRN10_FC_FULL
};

struct tsrn10_fc_info {
	enum tsrn10_fc_mode mode;
	uint32_t hi_water[TSRN10_MAX_TC_NUM];
	uint32_t lo_water[TSRN10_MAX_TC_NUM];
	uint16_t pause_time; /**< Pause quota in the Pause frame */
	bool send_xon;		 /**< Is XON frame need be sent */
	uint8_t ctrl_fwd_en; /**< Forward MAC control frames */
	uint8_t max_tc;		 /**< Max Support TC Of Port */
};

struct tsrn10_ptp_info {
	struct tsrn10_hwtimestamp hwts_ops;
	uint64_t clk_ptp_rate;
	uint64_t sub_second_inc;
	uint32_t default_addend;
};

struct tsrn10_pcs_operations {
	uint32_t (*read)(struct tsrn10_hw *hw, uint8_t p_id, uint32_t addr);
	void (*write)(struct tsrn10_hw *hw,
		      uint8_t p_id,
		      uint32_t addr,
		      uint32_t value);
};

struct tsrn10_pma_operations {
	uint32_t (*read)(struct tsrn10_hw *hw, uint8_t p_id, uint32_t addr);
	void (*write)(struct tsrn10_hw *hw,
		      uint8_t p_id,
		      uint32_t addr,
		      uint32_t value);
};

struct tsrn10_pma_info {
	struct tsrn10_pma_operations ops;
	uint16_t pma_count;
};

struct tsrn10_phy_cfg {
	uint32_t speed;
	uint8_t duplex;
	uint8_t autoneg;
};

struct tsrn10_pcs_info {
	struct tsrn10_pcs_operations ops;
	uint16_t pcs_count;
};

struct tsrn10_phy_api {
	int32_t (*setup_link)(struct rte_eth_dev *dev,
			      struct tsrn10_phy_cfg *cfg);
	void (*get_phy_info)(struct rte_eth_dev *dev);
};

struct tsrn10_phy_info {
	struct tsrn10_phy_api ops;
};

#define TSRN10_MAX_HW_PORT_PERR_PF (4)

#define TSRN10_STATE_MBX_POLLING BIT(0)
/* PCI device info */
struct tsrn10_hw {
	char *vf_num_reg;
	char *nic_reg; /* SI registers, used by all PCI functions */
	char *dma_base;
	char *eth_base;
	char *veb_base;
	char *mac_base[TSRN10_MAX_HW_PORT_PERR_PF];
	char *comm_reg_base;
	char *msix_base;
	/* === dma == */
	char *dev_version;
	char *dev_loopback;
	char *dev_status;
	char *dev_dummy;
	char *dma_axi_en;
	char *dma_axi_st;

	char *nic_top_config;
	/*===mac== */
	char *iobar0;
	uint32_t iobar0_len;
	int fun_id;
	void *back;
	uint8_t pf_vf_num;
	uint16_t device_id;
	uint16_t vendor_id;
	uint8_t function;

	uint8_t revision_id;
	int version;
	int inited;
	int is_sgmii;
	uint8_t force_10g_1g_speed_ablity;
	uint8_t force_speed_stat;
#define FORCE_SPEED_STAT_DISABLED	(0)
#define FORCE_SPEED_STAT_1G		(1)
#define FORCE_SPEED_STAT_10G		(2)

	int sgmii_phy_id;

	int nic_mode;
	unsigned char lane_mask;
	int pfvfnum;
	uint32_t speed;
	unsigned int axi_mhz;
	char phy_port_ids[4]; /*port id: for lane0~3: value: 0 ~ 7*/
	u16 phy_type;
	u16 vf_vlan;
	int fw_version;	 /* Primary FW Version */
	uint32_t fw_uid; /* Subclass Fw Version */
	int lane_of_port[4];
	uint8_t max_port_num;
	uint32_t api_version;

	uint16_t min_dma_size;
	char cookie_p_name[RTE_MEMZONE_NAMESIZE];
	void *cookie_pool;

	struct tsrn10_mac_info mac;
	struct tsrn10_mbx_info mbx;
	struct tsrn10_pcs_info pcs;
	struct tsrn10_pma_info pma;
	struct tsrn10_phy_info phy;
	rte_spinlock_t fw_lock;
	rte_spinlock_t link_sync;
	rte_spinlock_t fc_lock;
};
/* Transmit Descriptor */
#pragma pack(push)
#pragma pack(1)

/* TX Buffer Descriptors (BD) */
struct tsrn10_tx_desc {
	union {
		data_tx_desc_t d; /* tx data descript */
		ctrl_tx_desc_t c; /* tx control descript */
	};
};

/* RX buffer descriptor */
struct tsrn10_rx_desc {
	union {
		data_rx_desc_t d;  /* data descript */
		ctrl_rx_desc_t wb; /* writeback descript */
	};
};
#pragma pack(pop)
#endif
