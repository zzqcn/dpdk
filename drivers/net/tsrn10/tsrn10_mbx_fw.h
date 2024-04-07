#ifndef MBX_FW_CMD_H
#define MBX_FW_CMD_H

#include <linux/types.h>
#include <linux/errno.h>
#include <linux/wait.h>

#ifndef _PACKED_ALIGN4
#define _PACKED_ALIGN4 __attribute__((packed, aligned(4)))
#endif

struct mbx_fw_cmd_reply;
typedef void (*cookie_cb)(struct mbx_fw_cmd_reply *reply, void *priv);

#define TSRN10_MAX_SHARE_MEM (8 * 8)
struct mbx_req_cookie {
	int magic;
#define COOKIE_MAGIC 0xCE
	cookie_cb cb;
	int timeout_ms;
	int errcode;

	/* wait_queue_head_t wait; */
	volatile int done;
	int priv_len;
	char priv[TSRN10_MAX_SHARE_MEM];
};

enum GENERIC_CMD {
	/* generat */
	GET_VERSION = 0x0001,
	READ_REG = 0xFF03,
	WRITE_REG = 0xFF04,
	MODIFY_REG = 0xFF07,

	/* virtualization */
	IFUP_DOWN = 0x0800,
	SEND_TO_PF = 0x0801,
	SEND_TO_VF = 0x0802,

	/* link configuration admin commands */
	GET_PHY_ABALITY = 0x0601,
	GET_MAC_ADDRES = 0x0602,
	RESET_PHY = 0x0603,
	LED_SET = 0x0604,
	GET_LINK_STATUS = 0x0607,
	LINK_STATUS_EVENT = 0x0608,
	SET_LANE_FUN = 0x0609,
	GET_LANE_STATUS = 0x0610,
	SET_EVENT_MASK = 0x0613,
	SET_LOOPBACK_MODE = 0x0618,
	SET_PHY_REG = 0x0628,
	GET_PHY_REG = 0x0629,
	PHY_LINK_SET = 0x0630,

	/*sfp-module*/
	SFP_MODULE_READ = 0x0900,
	SFP_MODULE_WRITE = 0x0901,

	/* fw update */
	FW_UPDATE = 0x0700,
	FW_MAINTAIN = 0x0701,
	WOL_EN = 0x0910,
	GET_DUMP = 0x0a00,
	SET_DUMP = 0x0a10,
	GET_TEMP = 0x0a11,
};

enum link_event_mask {
	EVT_LINK_UP = 1,
	EVT_NO_MEDIA = 2,
	EVT_LINK_FAULT = 3,
	EVT_PHY_TEMP_ALARM = 4,
	EVT_EXCESSIVE_ERRORS = 5,
	EVT_SIGNAL_DETECT = 6,
	EVT_AUTO_NEGOTIATION_DONE = 7,
	EVT_MODULE_QUALIFICATION_FAILD = 8,
	EVT_PORT_TX_SUSPEND = 9,
};

enum pma_type {
	PHY_TYPE_NONE = 0,
	PHY_TYPE_1G_BASE_KX,
	PHY_TYPE_SGMII,
	PHY_TYPE_10G_BASE_KR,
	PHY_TYPE_25G_BASE_KR,
	PHY_TYPE_40G_BASE_KR4,
	PHY_TYPE_10G_BASE_SR,
	PHY_TYPE_40G_BASE_SR4,
	PHY_TYPE_40G_BASE_CR4,
	PHY_TYPE_40G_BASE_LR4,
	PHY_TYPE_10G_BASE_LR,
	PHY_TYPE_10G_BASE_ER,
};

struct phy_abilities {
	unsigned char link_stat;
	unsigned char lane_mask;

	int speed;
	short phy_type;
	short nic_mode;
	short pfnum;
	unsigned int fw_version;
	unsigned int axi_mhz;
	uint8_t port_ids[4];
	uint32_t fw_uid;
	uint32_t phy_id;
} _PACKED_ALIGN4;

enum LOOPBACK_LEVEL {
	LOOPBACK_DISABLE = 0,
	LOOPBACK_MAC = 1,
	LOOPBACK_PCS = 5,
	LOOPBACK_EXTERNAL = 6,
};

enum LOOPBACK_TYPE {
	/* Tx->Rx */
	LOOPBACK_TYPE_LOCAL = 0x0,
};

enum LOOPBACK_FORCE_SPEED {
	LOOPBACK_FORCE_SPEED_NONE = 0x0,
	LOOPBACK_FORCE_SPEED_1GBS = 0x1,
	LOOPBACK_FORCE_SPEED_10GBS = 0x2,
	LOOPBACK_FORCE_SPEED_40_25GBS = 0x3,
};

enum PHY_INTERFACE {
	PHY_INTERNAL_PHY = 0,
	PHY_EXTERNAL_PHY_MDIO = 1,
};

/* Table 3-54.  Get link status response (opcode: 0x0607) */
struct link_stat_data {
	char phy_type;
	unsigned char speed;

	/* 2 */
	char link_stat : 1;
#define LINK_UP	  1
#define LINK_DOWN 0

	char link_fault : 4;
#define LINK_LINK_FAULT	  BIT(0)
#define LINK_TX_FAULT	  BIT(1)
#define LINK_RX_FAULT	  BIT(2)
#define LINK_REMOTE_FAULT BIT(3)

	/* 1:up 0:down */
	char extern_link_stat : 1;
	char media_availble	  : 1;
	/* signal_detect */
	char rev1 : 1;

	/* 3:ignore */
	char an_completed			  : 1;
	char lp_an_ablity			  : 1;
	char parallel_detection_fault : 1;
	char fec_enabled			  : 1;
	char low_power_state		  : 1;
	char link_pause_status		  : 2;
	char qualified_odule		  : 1;

	/* 4 */
	char phy_temp_alarm			   : 1;
	char excessive_link_errors	   : 1;
	char port_tx_suspended		   : 2;
	char force_40G_enabled		   : 1;
	char external_25G_phy_err_code : 3;
#define EXTERNAL_25G_PHY_NOT_PRESENT	   1
#define EXTERNAL_25G_PHY_NVM_CRC_ERR	   2
#define EXTERNAL_25G_PHY_MDIO_ACCESS_FAILD 6
#define EXTERNAL_25G_PHY_INIT_SUCCED	   7

	/* 5 */
	char loopback_enabled_status : 4;
#define LOOPBACK_DISABLE	  0x0
#define LOOPBACK_MAC		  0x1
#define LOOPBACK_SERDES		  0x2
#define LOOPBACK_PHY_INTERNAL 0x3
#define LOOPBACK_PHY_EXTERNAL 0x4
	char loopback_type_status : 1;
#define LOCAL_LOOPBACK	 0 /* tx->rx */
#define FAR_END_LOOPBACK 0 /* rx->Tx */
	char rev3						: 1;
	char external_dev_power_ability : 2;
	/* 6-7 */
	short max_frame_sz;
	/* 8 */
	char _25gb_kr_fec_enabled : 1;
	char _25gb_rs_fec_enabled : 1;
	char crc_enabled		  : 1;
	char rev4				  : 5;
	/* 9 */
	int link_type; /* same as Phy type */
	char link_type_ext;
} _PACKED_ALIGN4;

struct port_stat {
	u8 phy_addr; /* Phy MDIO address */

	u8 duplex	   : 1; /* FIBRE is always 1,Twisted Pair 1 or 0 */
	u8 autoneg	   : 1; /* autoned state */
	u8 fec		   : 1;
	u8 an_rev	   : 1;
	u8 link_traing : 1;
	u8 is_sgmii	   : 1; /* avild fw >= 0.5.0.17 */
	u16 speed;			/* cur port linke speed */

	u16 pause : 4;
	u16 rev	  : 12;
} __attribute__((packed));

#define RNP_SPEED_CAP_UNKNOWN	 (0)
#define RNP_SPEED_CAP_10M_FULL	 BIT(2)
#define RNP_SPEED_CAP_100M_FULL	 BIT(3)
#define RNP_SPEED_CAP_1GB_FULL	 BIT(4)
#define RNP_SPEED_CAP_10GB_FULL	 BIT(5)
#define RNP_SPEED_CAP_40GB_FULL	 BIT(6)
#define RNP_SPEED_CAP_25GB_FULL	 BIT(7)
#define RNP_SPEED_CAP_50GB_FULL	 BIT(8)
#define RNP_SPEED_CAP_100GB_FULL BIT(9)
#define RNP_SPEED_CAP_10M_HALF	 BIT(10)
#define RNP_SPEED_CAP_100M_HALF	 BIT(11)
#define RNP_SPEED_CAP_1GB_HALF	 BIT(12)

struct lane_stat_data {
	u8 nr_lane;		  /* 0-3 cur port correspond with hw lane */
	u8 pci_gen	 : 4; /* nic cur pci speed genX: 1,2,3 */
	u8 pci_lanes : 4; /* nic cur pci x1 x2 x4 x8 x16 */
	u8 pma_type;
	u8 phy_type; /* interface media type */

	u16 linkup		   : 1; /* cur port link state */
	u16 duplex		   : 1; /* duplex state only RJ45 valid */
	u16 autoneg		   : 1; /* autoneg state */
	u16 fec			   : 1; /* fec state */
	u16 rev_an		   : 1;
	u16 link_traing	   : 1; /* link-traing state */
	u16 media_availble : 1;
	u16 is_sgmii	   : 1; /* 1: Twisted Pair 0: FIBRE */
	u16 link_fault	   : 4;
#define LINK_LINK_FAULT	  BIT(0)
#define LINK_TX_FAULT	  BIT(1)
#define LINK_RX_FAULT	  BIT(2)
#define LINK_REMOTE_FAULT BIT(3)
	u16 is_backplane : 1; /* 1: Backplane Mode */
	union {
		u8 phy_addr; /* Phy MDIO address */
		struct {
			u8 mod_abs : 1;
			u8 fault   : 1;
			u8 tx_dis  : 1;
			u8 los	   : 1;
		} sfp;
	};
	u8 sfp_connector;
	u32 speed; /* Current Speed Value */

	u32 si_main;
	u32 si_pre;
	u32 si_post;
	u32 si_tx_boost;
	u32 supported_link; /* Cur nic Support Link cap */
	u32 phy_id;
	u32 advertised_link; /* autoneg mode advertised cap */
} _PACKED_ALIGN4;
/* == flags == */
#define FLAGS_DD  BIT(0) /* driver clear 0, FW must set 1 */
#define FLAGS_CMP BIT(1) /* driver clear 0, FW mucst set */
#define FLAGS_ERR \
	BIT(2) /* driver clear 0, FW must set only if it reporting an error */
#define FLAGS_LB  BIT(9)
#define FLAGS_RD  BIT(10) /* set if additional buffer has command parameters */
#define FLAGS_BUF BIT(12) /* set 1 on indirect command */
#define FLAGS_SI  BIT(13) /* not irq when command complete */
#define FLAGS_EI  BIT(14) /* interrupt on error */
#define FLAGS_FE  BIT(15) /* flush erro */

#ifndef SHM_DATA_MAX_BYTES
#define SHM_DATA_MAX_BYTES (64 - 2 * 4)
#endif

#define MBX_REQ_HDR_LEN		   24
#define MBX_REPLYHDR_LEN	   16
#define MBX_REQ_MAX_DATA_LEN   (SHM_DATA_MAX_BYTES - MBX_REQ_HDR_LEN)
#define MBX_REPLY_MAX_DATA_LEN (SHM_DATA_MAX_BYTES - MBX_REPLYHDR_LEN)

/* driver -> firmware */
struct mbx_fw_cmd_req {
	unsigned short flags;	  /* 0-1 */
	unsigned short opcode;	  /* 2-3 enum LINK_ADM_CMD */
	unsigned short datalen;	  /* 4-5 */
	unsigned short ret_value; /* 6-7 */
	union {
		struct {
			unsigned int cookie_lo; /* 8-11 */
			unsigned int cookie_hi; /* 12-15 */
		};
		void *cookie;
	};
	unsigned int reply_lo; /* 16-19 5dw */
	unsigned int reply_hi; /* 20-23 */
	/* === data === [24-64] 7dw */
	union {
		char data[0];

		struct {
			unsigned int addr;
			unsigned int bytes;
		} r_reg;

		struct {
			unsigned int addr;
			unsigned int data;
			unsigned int bytes;
		} w_reg;

		struct {
			int lane;
			int up;
		} ifup;

		struct {
			int nr_lane;
		} get_lane_st;

		struct {
			int nr_lane;
			int func;
#define LANE_FUN_AN				0
#define LANE_FUN_LINK_TRAING	1
#define LANE_FUN_FEC			2
#define LANE_FUN_SI				3
#define LANE_FUN_SFP_TX_DISABLE 4
#define LANE_FUN_PCI_LANE		5
#define LANE_FUN_PRBS			6

			int value0;
			int value1;
			int value2;
			int value3;
		} set_lane_fun;

		struct {
			int flag;
			int nr_lane;
		} set_dump;

		struct {
			unsigned int bytes;
			unsigned int nr_lane;
			unsigned int bin_phy_lo;
			unsigned int bin_phy_hi;
		} get_dump;

		struct get_temp {
			int temp;
			int volatage;
		} get_temp;

		struct {
			unsigned int nr_lane;
			int value;
#define LED_IDENTIFY_INACTIVE  0
#define LED_IDENTIFY_ACTIVE	   1
#define LED_IDENTIFY_ON		   2 /* led on */
#define LED_IDENTIFY_OFF	   3 /* led off */
#define LED_IDENTIFY_FORCE_ON  4 /* force led on */
#define LED_IDENTIFY_FORCE_OFF 5 /* force led off */
		} led_set;
		struct {
			unsigned int addr;
			unsigned int data;
			unsigned int mask;
		} modify_reg;

		struct {
			uint32_t adv_speed_mask; /* advertised_link cap ctrl */
			uint32_t autoneg;		 /* Autoneg Ctrl */
			uint32_t speed;			 /* Cur Speed Ctrl */
			uint32_t duplex;		 /* duplex mode Ctrl */
			uint32_t nr_lane;		 /* hw lane-id */
		} phy_link_set;

		struct {
			unsigned int nr_lane;
			unsigned int sfp_adr; /* 0xa0 or 0xa2 */
			unsigned int reg;
			unsigned int cnt;
		} sfp_read;

		struct {
			unsigned int nr_lane;
			unsigned int sfp_adr; /* 0xa0 or 0xa2 */
			unsigned int reg;
			unsigned int val;
		} sfp_write;

		struct {
			unsigned int nr_lane; /* 0-3 */
		} get_linkstat;

		struct {
			unsigned short changed_lanes;
			unsigned short lane_status;
			unsigned int port_st_magic;
#define SPEED_VALID_MAGIC 0xa4a6a8a9
			struct port_stat st[4];
		} link_stat; /* FW->RC */
		struct {
			unsigned short enable_stat;
			unsigned short event_mask; /* enum link_event_mask */
		} stat_event_mask;

		struct { /* set loopback */
			unsigned char loopback_level;
			unsigned char loopback_type;
			unsigned char loopback_force_speed;

			char loopback_force_speed_enable : 1;
		} loopback;

		struct {
			int cmd;
#define MT_WRITE_FLASH 1
			int arg0;
			int req_bytes;
			int reply_bytes;
			int ddr_lo;
			int ddr_hi;
		} maintain;

		struct { /* set phy register */
			char phy_interface;
			union {
				char page_num;
				char external_phy_addr;
			};
			int phy_reg_addr;
			int phy_w_data;
			int reg_addr;
			int w_data;
			/* 1 = ignore page_num, use last QSFP */
			char recall_qsfp_page : 1;
			/* page value */
			/* 0 = use page_num for QSFP */
			char nr_lane;
		} set_phy_reg;
		struct {
			int requestor;
#define REQUEST_BY_DPDK	0xa1
#define REQUEST_BY_DRV	0xa2
#define REQUEST_BY_PXE	0xa3
		} get_phy_ablity;

		struct {
			int lane_mask;
			int pfvf_num;
		} get_mac_addr;

		struct {
			char phy_interface;
			union {
				char page_num;
				char external_phy_addr;
			};
			int phy_reg_addr;
			int nr_lane;
		} get_phy_reg;

		struct {
			char paration;
			unsigned int bytes;
			unsigned int bin_phy_lo;
			unsigned int bin_phy_hi;
		} fw_update;
	};
} _PACKED_ALIGN4;

/* firmware -> driver */
struct mbx_fw_cmd_reply {
	/* fw must set: DD, CMP, Error(if error), copy value */
	unsigned short flags;
	/* from command: LB,RD,VFC,BUF,SI,EI,FE */
	unsigned short opcode;	   /* 2-3: copy from req */
	unsigned short error_code; /* 4-5: 0 if no error */
	unsigned short datalen;	   /* 6-7: */
	union {
		struct {
			unsigned int cookie_lo; /* 8-11: */
			unsigned int cookie_hi; /* 12-15: */
		};
		void *cookie;
	};
	/* ===== data ==== [16-64] */
	union {
		char data[0];

		struct version { /* GET_VERSION */
			unsigned int major;
			unsigned int sub;
			unsigned int modify;
		} version;

		struct {
			unsigned int value;
		} r_reg;

		struct {
#define MBX_SFP_READ_MAX_CNT 32
			char value[MBX_SFP_READ_MAX_CNT];
		} sfp_read;

		struct mac_addr {
			int lanes;
			struct _addr {
				/* for macaddr:01:02:03:04:05:06
				 *  mac-hi=0x01020304 mac-lo=0x05060000
				 */
				unsigned char mac[8];
			} addrs[4];
		} mac_addr;

		struct { /* modify_reg */
			unsigned int modified_new_value;
		} modify_reg;

		struct lane_stat_data lanestat;
		struct link_stat_data linkstat;
		struct phy_abilities phy_abilities;
	};
} _PACKED_ALIGN4;

static inline void build_maintain_req(struct mbx_fw_cmd_req *req,
									  void *cookie,
									  int cmd,
									  int arg0,
									  int req_bytes,
									  int reply_bytes,
									  u32 dma_phy_lo,
									  u32 dma_phy_hi)
{
	req->flags = 0;
	req->opcode = FW_MAINTAIN;
	req->datalen = sizeof(req->maintain);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->maintain.cmd = cmd;
	req->maintain.arg0 = arg0;
	req->maintain.req_bytes = req_bytes;
	req->maintain.reply_bytes = reply_bytes;
	req->maintain.ddr_lo = dma_phy_lo;
	req->maintain.ddr_hi = dma_phy_hi;
}

static inline void build_fw_update_req(struct mbx_fw_cmd_req *req,
									   void *cookie,
									   int partition,
									   u32 fw_bin_phy_lo,
									   u32 fw_bin_phy_hi,
									   int fw_bytes)
{
	req->flags = 0;
	req->opcode = FW_UPDATE;
	req->datalen = sizeof(req->fw_update);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->fw_update.paration = partition;
	req->fw_update.bytes = fw_bytes;
	req->fw_update.bin_phy_lo = fw_bin_phy_lo;
	req->fw_update.bin_phy_hi = fw_bin_phy_hi;
}

static inline void build_reset_phy_req(struct mbx_fw_cmd_req *req, void *cookie)
{
	req->flags = 0;
	req->opcode = RESET_PHY;
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->cookie = cookie;
}

static inline void build_phy_abalities_req(struct mbx_fw_cmd_req *req,
					   void *cookie)
{
	req->flags = 0;
	req->opcode = GET_PHY_ABALITY;
	req->datalen = 0;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->cookie = cookie;
	req->get_phy_ablity.requestor = REQUEST_BY_DPDK;
	req->datalen = sizeof(req->get_phy_ablity.requestor);
}

static inline void build_get_macaddress_req(struct mbx_fw_cmd_req *req,
					    int lane_mask,
					    int pfvfnum,
					    void *cookie)
{
	req->flags = 0;
	req->opcode = GET_MAC_ADDRES;
	req->datalen = sizeof(req->get_mac_addr);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->get_mac_addr.lane_mask = lane_mask;
	req->get_mac_addr.pfvf_num = pfvfnum;
}

static inline void build_version_req(struct mbx_fw_cmd_req *req, void *cookie)
{
	req->flags = 0;
	req->opcode = GET_VERSION;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->datalen = 0;
	req->cookie = cookie;
}

/* 7.10.11.8 Read egister admin command */
static inline void
build_readreg_req(struct mbx_fw_cmd_req *req, int reg_addr, void *cookie)
{
	req->flags = 0;
	req->opcode = READ_REG;
	req->datalen = sizeof(req->r_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->r_reg.addr = reg_addr;
	req->r_reg.bytes = 4;
}
/*
 *	@ret:
 *	0:success
 *	!= 0 : error
 */
#ifdef USED
static int cmd_get_readreg_value(struct mbx_fw_cmd_reply *reply, int *value)
{
	if (!(reply->flags & FLAGS_DD))
		return -EINVAL;

	if (reply->flags & FLAGS_ERR)
		return -reply->error_code;
	if (reply->opcode != READ_REG)
		return -EINVAL;

	if (value)
		*value = reply->r_reg.value;
	return 0;
}
#endif

/* 7.10.11.9 Write egister admin command */
static inline void build_writereg_req(struct mbx_fw_cmd_req *req,
				      void *cookie,
				      int reg_addr,
				      int value)
{
	req->flags = 0;
	req->opcode = WRITE_REG;
	req->datalen = sizeof(req->w_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->w_reg.addr = reg_addr;
	req->w_reg.data = value;
	req->w_reg.bytes = 4;
}

static inline void
build_get_lane_status_req(struct mbx_fw_cmd_req *req, int nr_lane, void *cookie)
{
	req->flags = 0;
	req->opcode = GET_LANE_STATUS;
	req->datalen = sizeof(req->get_lane_st);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_lane_st.nr_lane = nr_lane;
}

static inline void
build_get_link_status_req(struct mbx_fw_cmd_req *req, int nr_lane, void *cookie)
{
	req->flags = 0;
	req->opcode = GET_LINK_STATUS;
	req->datalen = sizeof(req->get_linkstat);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->get_linkstat.nr_lane = nr_lane;
}

static inline void build_get_temp(struct mbx_fw_cmd_req *req, void *cookie)
{
	req->flags = 0;
	req->opcode = GET_TEMP;
	req->datalen = 0;
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
}

static inline void build_set_lane_fun(struct mbx_fw_cmd_req *req,
				      int nr_lane,
				      int fun,
				      int value0,
				      int value1,
				      int value2,
				      int value3)
{
	req->flags = 0;
	req->opcode = SET_LANE_FUN;
	req->datalen = sizeof(req->set_lane_fun);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->set_lane_fun.func = fun;
	req->set_lane_fun.nr_lane = nr_lane;
	req->set_lane_fun.value0 = value0;
	req->set_lane_fun.value1 = value1;
	req->set_lane_fun.value2 = value2;
	req->set_lane_fun.value3 = value3;
}

static inline void
build_ifup_down(struct mbx_fw_cmd_req *req, unsigned int nr_lane, int up)
{
	req->flags = 0;
	req->opcode = IFUP_DOWN;
	req->datalen = sizeof(req->ifup);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->ifup.lane = nr_lane;
	req->ifup.up = up;
}

static inline void build_mbx_sfp_read(struct mbx_fw_cmd_req *req,
				      unsigned int nr_lane,
				      int sfp_addr,
				      int reg,
				      int cnt,
				      void *cookie)
{
	req->flags = 0;
	req->opcode = SFP_MODULE_READ;
	req->datalen = sizeof(req->sfp_read);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->sfp_read.nr_lane = nr_lane;
	req->sfp_read.sfp_adr = sfp_addr;
	req->sfp_read.reg = reg;

	req->sfp_read.cnt = cnt;
}

static inline void build_mbx_sfp_write(struct mbx_fw_cmd_req *req,
				       unsigned int nr_lane,
				       int sfp_addr,
				       int reg,
				       int v)
{
	req->flags = 0;
	req->opcode = SFP_MODULE_WRITE;
	req->datalen = sizeof(req->sfp_write);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->sfp_write.nr_lane = nr_lane;
	req->sfp_write.sfp_adr = sfp_addr;
	req->sfp_write.reg = reg;
	req->sfp_write.val = v;
}

static inline void
build_set_dump(struct mbx_fw_cmd_req *req, int nr_lane, int flag)
{
	req->flags = 0;
	req->opcode = SET_DUMP;
	req->datalen = sizeof(req->set_dump);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->set_dump.flag = flag;
	req->set_dump.nr_lane = nr_lane;
}

/* enum link_event_mask or */
static inline
void build_link_set_event_mask(struct mbx_fw_cmd_req *req,
			       unsigned short event_mask,
			       unsigned short enable,
			       void *cookie)
{
	req->flags = 0;
	req->opcode = SET_EVENT_MASK;
	req->datalen = sizeof(req->stat_event_mask);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->stat_event_mask.event_mask = event_mask;
	req->stat_event_mask.enable_stat = enable;
}

static inline void
build_link_set_loopback_req(struct mbx_fw_cmd_req *req,
			    void *cookie,
			    enum LOOPBACK_LEVEL level,
			    enum LOOPBACK_FORCE_SPEED force_speed)
{
	req->flags = 0;
	req->opcode = SET_LOOPBACK_MODE;
	req->datalen = sizeof(req->loopback);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->loopback.loopback_level = level;
	req->loopback.loopback_type = LOOPBACK_TYPE_LOCAL;
	if (force_speed != LOOPBACK_FORCE_SPEED_NONE) {
		req->loopback.loopback_force_speed = force_speed;
		req->loopback.loopback_force_speed_enable = 1;
	}
}

/*
 * used for debug
 */
static inline void build_set_phy_reg(struct mbx_fw_cmd_req *req,
				     void *cookie,
				     enum PHY_INTERFACE phy_inf,
				     char nr_lane,
				     int reg,
				     int w_data,
				     int recall_qsfp_page)
{
	req->flags = 0;
	req->opcode = SET_PHY_REG;
	req->datalen = sizeof(req->set_phy_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->set_phy_reg.phy_interface = phy_inf;

	req->set_phy_reg.nr_lane = nr_lane;
	req->set_phy_reg.phy_reg_addr = reg;
	req->set_phy_reg.phy_w_data = w_data;

	if (recall_qsfp_page)
		req->set_phy_reg.recall_qsfp_page = 1;
	else
		req->set_phy_reg.recall_qsfp_page = 0;
}

static inline void build_get_phy_reg(struct mbx_fw_cmd_req *req,
				     void *cookie,
				     enum PHY_INTERFACE phy_inf,
				     char nr_lane,
				     int reg)
{
	req->flags = 0;
	req->opcode = GET_PHY_REG;
	req->datalen = sizeof(req->get_phy_reg);
	req->cookie = cookie;
	req->reply_lo = 0;
	req->reply_hi = 0;

	req->get_phy_reg.phy_interface = phy_inf;

	req->get_phy_reg.nr_lane = nr_lane;
	req->get_phy_reg.phy_reg_addr = reg;
}

static inline void
build_phy_link_set(struct mbx_fw_cmd_req *req, unsigned int speeds, int nr_lane)
{
	req->flags = 0;
	req->opcode = PHY_LINK_SET;
	req->datalen = sizeof(req->phy_link_set);
	req->cookie = NULL;
	req->reply_lo = 0;
	req->reply_hi = 0;
	req->phy_link_set.nr_lane = nr_lane;
	req->phy_link_set.adv_speed_mask = speeds;
}

/* =========== errcode======= */
enum MBX_ERR {
	MBX_OK = 0,
	MBX_ERR_NO_PERM,
	MBX_ERR_INVAL_OPCODE,
	MBX_ERR_INVALID_PARAM,
	MBX_ERR_INVALID_ADDR,
	MBX_ERR_INVALID_LEN,
	MBX_ERR_NODEV,
	MBX_ERR_IO,
};

#define TSRN10_LINK_SYNC_MAGIC	(0xA5000000)
#define TSRN10_NIC_DEVICE_LINK (0x3000c)
#define TSRN10_LINK_STATE(n)   BIT(n)
#define TSRN10_LINK_SPEED_STATE(sp, n) \
	(((sp) & GENMASK((11) + ((4) * (n)), (8) + ((4) * (n)))) >> (8 + 4 * (n)))
enum tsrn10_lane_speed {
	TSRN10_LANE_SPEED_10M = 0,
	TSRN10_LANE_SPEED_100M,
	TSRN10_LANE_SPEED_1G,
	TSRN10_LANE_SPEED_10G,
	TSRN10_LANE_SPEED_25G,
	TSRN10_LANE_SPEED_40G,
};

struct tsrn10_hw;

#define TSRN10_ALARM_INTERVAL 50000 /* unit us */
void tsrn10_link_report(struct rte_eth_dev *dev, bool link_en);
int rnp_fw_get_macaddr(struct rte_eth_dev *dev,
		       int pfvfnum,
		       u8 *mac_addr,
		       int nr_lane);
int rnp_mbx_fw_reset_phy(struct rte_eth_dev *dev);
int rnp_fw_get_capablity(struct rte_eth_dev *dev, struct phy_abilities *abil);
int rnp_mbx_link_event_enable(struct rte_eth_dev *dev, int enable);
int rnp_mbx_ifup_down(struct rte_eth_dev *dev, int nr_lane, int up);
int rnp_fw_msg_handler(struct tsrn10_eth_adapter *adapter);
int rnp_mbx_get_capability(struct rte_eth_dev *dev,
			   int *lane_mask,
			   int *nic_mode);
int rnp_mbx_sfp_module_eeprom_info(struct rte_eth_dev *dev,
				   int nr_lane,
				   int sfp_addr,
				   int reg,
				   int data_len,
				   char *buf);
int rnp_mbx_get_lane_stat(struct rte_eth_dev *dev, int nr_lane);
int rnp_mbx_phy_link_set(struct rte_eth_dev *dev, int nr_lane, int speeds);

int rnp_mbx_phy_read(struct rte_eth_dev *dev, u32 reg, u32 *val);
int rnp_mbx_phy_write(struct rte_eth_dev *dev, u32 reg, u32 val);

void *tsrn10_memzone_reserve(const char *name, unsigned int size);
int rnp_mbx_set_dump(struct rte_eth_dev *dev, int flag);
int tsrn10_setup_link_fiber(struct rte_eth_dev *dev, struct tsrn10_phy_cfg *cfg);
#endif
