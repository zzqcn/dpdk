#ifndef TSRN10_MAC_REGS_H_
#define TSRN10_MAC_REGS_H_

#include "tsrn10_common.h"
#define TSRN10_MAC_TX_CFG		(0x0)

/* Transmitter Enable */
#define TSRN10_MAC_TE			BIT(0)
/* Jabber Disable */
#define TSRN10_MAC_JD			BIT(16)
#define TSRN10_SPEED_SEL_1G		(BIT(30) | BIT(29) | BIT(28))
#define TSRN10_SPEED_SEL_10G		BIT(30)
#define TSRN10_SPEED_SEL_40G		(0)
#define TSRN10_MAC_RX_CFG		(0x4)
/* Receiver Enable */
#define TSRN10_MAC_RE			BIT(0)
/* Automatic Pad or CRC Stripping */
#define TSRN10_MAC_ACS			BIT(1)
/* CRC stripping for Type packets */
#define TSRN10_MAC_CST			BIT(2)
/* Disable CRC Check */
#define TSRN10_MAC_DCRCC		BIT(3)
/* Enable Max Frame Size Limit */
#define TSRN10_MAC_GPSLCE		BIT(6)
/* Watchdog Disable */
#define TSRN10_MAC_WD			BIT(7)
/* Jumbo Packet Support En */
#define TSRN10_MAC_JE			BIT(8)
/* Loopback Mode */
#define TSRN10_MAC_LM			BIT(10)
/* Giant Packet Size Limit */
#define TSRN10_MAC_GPSL_MASK		GENMASK(29, 16)
#define TSRN10_MAC_MAX_GPSL		(1518)
#define TSRN10_MAC_CPSL_SHIFT		(16)

#define TSRN10_MAC_PKT_FLT_CTRL		(0x8)

/* Receive All */
#define TSRN10_MAC_RA			BIT(31)
/* Pass Control Packets */
#define TSRN10_MAC_PCF			GENMASK(7, 6)
#define TSRN10_MAC_PCF_OFFSET		(6)
/* Mac Filter ALL Ctrl Frame */
#define TSRN10_MAC_PCF_FAC		(0)
/* Mac Forward ALL Ctrl Frame Except Pause */
#define TSRN10_MAC_PCF_NO_PAUSE		(1)
/* Mac Forward All Ctrl Pkt */
#define TSRN10_MAC_PCF_PA		(2)
/* Mac Forward Ctrl Frame Match Unicast */
#define TSRN10_MAC_PCF_PUN		(3)
/* Promiscuous Mode */
#define TSRN10_MAC_PROMISC_EN		BIT(0)
/* Hash Unicast */
#define TSRN10_MAC_HUC			BIT(1)
/* Hash Multicast */
#define TSRN10_MAC_HMC			BIT(2)
/*  Pass All Multicast */
#define TSRN10_MAC_PM			BIT(4)
/* Disable Broadcast Packets */
#define TSRN10_MAC_DBF			BIT(5)
/* Hash or Perfect Filter */
#define TSRN10_MAC_HPF			BIT(10)
#define TSRN10_MAC_VTFE			BIT(16)
/* Interrupt Status */
#define TSRN10_MAC_INT_STATUS		_MAC_(0xb0)
#define TSRN10_MAC_LS_MASK		GENMASK(25, 24)
#define TSRN10_MAC_LS_UP		(0)
#define TSRN10_MAC_LS_LOCAL_FAULT	BIT(25)
#define TSRN10_MAC_LS_REMOT_FAULT	(BIT(25) | BIT(24))
/* Unicast Mac Hash Table */
#define TSRN10_MAC_UC_HASH_TB(n)	_MAC_(0x10 + ((n) * 0x4))


#define TSRN10_MAC_LPI_CTRL		(0xd0)

/* PHY Link Status Disable */
#define TSRN10_MAC_PLSDIS		BIT(18)
/* PHY Link Status */
#define TSRN10_MAC_PLS			BIT(17)

/* MAC VLAN CTRL Strip REG */
#define TSRN10_MAC_VLAN_TAG             (0x50)

/* En Inner VLAN Strip Action */
#define TSRN10_MAC_EIVLS                GENMASK(29, 28)
/* Inner VLAN Strip Action Shift */
#define TSRN10_MAC_IV_EIVLS_SHIFT       (28)
/* Inner Vlan Don't Strip*/
#define TSRN10_MAC_IV_STRIP_NONE        (0x0)
/* Inner Vlan Strip When Filter Match Success */
#define TSRN10_MAC_IV_STRIP_PASS        (0x1)
/* Inner Vlan STRIP When Filter Match FAIL */
#define TSRN10_MAC_IV_STRIP_FAIL        (0x2)
/* Inner Vlan STRIP Always */
#define TSRN10_MAC_IV_STRIP_ALL         (0X3)
/* VLAN Strip Mode Ctrl Shift */
#define TSRN10_VLAN_TAG_CTRL_EVLS_SHIFT (21)
/* En Double Vlan Processing */
#define TSRN10_MAC_VLAN_EDVLP           BIT(26)
/* VLAN Tag Hash Table Match Enable */
#define TSRN10_MAC_VLAN_VTHM            BIT(25)
/*  Enable VLAN Tag in Rx status */
#define TSRN10_MAC_VLAN_EVLRXS          BIT(24)
/* Disable VLAN Type Check */
#define TSRN10_MAC_VLAN_DOVLTC          BIT(20)
/* Enable S-VLAN */
#define TSRN10_MAC_VLAN_ESVL            BIT(18)
/* Enable 12-Bit VLAN Tag Comparison Filter */
#define TSRN10_MAC_VLAN_ETV             BIT(16)
#define TSRN10_MAC_VLAN_HASH_EN		GENMASK(15, 0)
#define TSRN10_MAC_VLAN_VID             GENMASK(15, 0)
/* VLAN Don't Strip */
#define TSRN10_MAC_VLAN_STRIP_NONE      (0x0 << TSRN10_VLAN_TAG_CTRL_EVLS_SHIFT)
/* VLAN Filter Success Then STRIP */
#define TSRN10_MAC_VLAN_STRIP_PASS      (0x1 << TSRN10_VLAN_TAG_CTRL_EVLS_SHIFT)
/* VLAN Filter Failed Then STRIP */
#define TSRN10_MAC_VLAN_STRIP_FAIL      (0x2 << TSRN10_VLAN_TAG_CTRL_EVLS_SHIFT)
/* All Vlan Will Stip */
#define TSRN10_MAC_VLAN_STRIP_ALL       (0x3 << TSRN10_VLAN_TAG_CTRL_EVLS_SHIFT)

#define TSRN10_MAC_VLAN_HASH_TB		(0x58)
#define TSRN10_MAC_VLAN_HASH_MASK	GENMASK(15, 0)

/* MAC VLAN CTRL INSERT REG */
#define TSRN10_MAC_VLAN_INCL            (0x60)
#define TSRN10_MAC_INVLAN_INCL		(0x64)

/* VLAN Tag Input */
/* VLAN_Tag Insert From Description */
#define TSRN10_MAC_VLAN_VLTI            BIT(20)
/* C-VLAN or S-VLAN */
#define TSRN10_MAC_VLAN_CSVL            BIT(19)
#define TSRN10_MAC_VLAN_INSERT_CVLAN    (0 << 19)
#define TSRN10_MAC_VLAN_INSERT_SVLAN    (1 << 19)
/* VLAN Tag Control in Transmit Packets */
#define TSRN10_MAC_VLAN_VLC             GENMASK(17, 16)
/* VLAN Tag Control Offset Bit */
#define TSRN10_MAC_VLAN_VLC_SHIFT       (16)
/* Don't Anything ON TX VLAN*/
#define TSRN10_MAC_VLAN_VLC_NONE        (0x0 << TSRN10_MAC_VLAN_VLC_SHIFT)
/* MAC Delete VLAN */
#define TSRN10_MAC_VLAN_VLC_DEL         (0x1 << TSRN10_MAC_VLAN_VLC_SHIFT)
/* MAC Add VLAN */
#define TSRN10_MAC_VLAN_VLC_ADD         (0x2 << TSRN10_MAC_VLAN_VLC_SHIFT)
/* MAC Replace VLAN */
#define TSRN10_MAC_VLAN_VLC_REPLACE     (0x3 << TSRN10_MAC_VLAN_VLC_SHIFT)
/* VLAN Tag for Transmit Packets For Insert/Remove */
#define TSRN10_MAC_VLAN_VLT             GENMASK(15, 0)
/* TX Peer TC Flow Ctrl */

#define TSRN10_MAC_Q0_TX_FC(n)		(0x70 + ((n) * 0x4))

/* Edit Pause Time */
#define TSRN10_MAC_FC_PT		GENMASK(31, 16)
#define TSRN10_MAC_FC_PT_OFFSET		(16)
/*  Disable Zero-Quanta Pause */
#define TSRN10_MAC_FC_DZPQ		BIT(7)
/* Pause Low Threshold */
#define TSRN10_MAC_FC_PLT		GENMASK(6, 4)
#define TSRN10_MAC_FC_PLT_OFFSET	(4)
#define TSRN10_MAC_FC_PLT_4_SLOT	(0)
#define TSRN10_MAC_FC_PLT_28_SLOT	(1)
#define TSRN10_MAC_FC_PLT_36_SLOT	(2)
#define TSRN10_MAC_FC_PLT_144_SLOT	(3)
#define TSRN10_MAC_FC_PLT_256_SLOT	(4)
/* Transmit Flow Control Enable */
#define TSRN10_MAC_FC_TEE		BIT(1)
/* Transmit Flow Control Busy Immediately */
#define TSRN10_MAC_FC_FCB		BIT(0)
/* Mac RX Flow Ctrl*/

#define TSRN10_MAC_RX_FC		(0x90)

/* Rx Priority Based Flow Control Enable */
#define TSRN10_MAC_RX_FC_PFCE		BIT(8)
/* Unicast Pause Packet Detect */
#define TSRN10_MAC_RX_FC_UP		BIT(1)
/* Receive Flow Control Enable */
#define TSRN10_MAC_RX_FC_RFE		BIT(0)

/* Rx Mac Address Base */
#define TSRN10_MAC_ADDR_DEF_HI		_MAC_(0x0300)

#define TSRN10_MAC_AE			BIT(31)
#define TSRN10_MAC_ADDR_LO(n)		_MAC_((0x0304) + ((n) * 0x8))
#define TSRN10_MAC_ADDR_HI(n)		_MAC_((0x0300) + ((n) * 0x8))

/* Mac Manage Counts */
#define TSRN10_MMC_CTRL			_MAC_(0x0800)
#define TSRN10_MMC_RSTONRD		BIT(2)
/* Tx Good And Bad Bytes Base */
#define TSRN10_MMC_TX_GBOCTGB		_MAC_(0x0814)
/* Tx Good And Bad Frame Num Base */
#define TSRN10_MMC_TX_GBFRMB		_MAC_(0x081c)
/* Tx Good Boradcast Frame Num Base */
#define TSRN10_MMC_TX_BCASTB		_MAC_(0x0824)
/* Tx Good Multicast Frame Num Base */
#define TSRN10_MMC_TX_MCASTB		_MAC_(0x082c)
/* Tx 64Bytes Frame Num */
#define TSRN10_MMC_TX_64_BYTESB		_MAC_(0x0834)
#define TSRN10_MMC_TX_65TO127_BYTESB	_MAC_(0x083c)
#define TSRN10_MMC_TX_128TO255_BYTEB	_MAC_(0x0844)
#define TSRN10_MMC_TX_256TO511_BYTEB	_MAC_(0x084c)
#define TSRN10_MMC_TX_512TO1023_BYTEB	_MAC_(0x0854)
#define TSRN10_MMC_TX_1024TOMAX_BYTEB	_MAC_(0x085c)
/* Tx Good And Bad Unicast Frame Num Base */
#define TSRN10_MMC_TX_GBUCASTB		_MAC_(0x0864)
/* Tx Good And Bad Multicast Frame Num Base */
#define TSRN10_MMC_TX_GBMCASTB		_MAC_(0x086c)
/* Tx Good And Bad Broadcast Frame NUM Base */
#define TSRN10_MMC_TX_GBBCASTB		_MAC_(0x0874)
/* Tx Frame Underflow Error */
#define TSRN10_MMC_TX_UNDRFLWB		_MAC_(0x087c)
/* Tx Good Frame Bytes Base */
#define TSRN10_MMC_TX_GBYTESB		_MAC_(0x0884)
/* Tx Good Frame Num Base*/
#define TSRN10_MMC_TX_GBRMB		_MAC_(0x088c)
/* Tx Good Pause Frame Num Base */
#define TSRN10_MMC_TX_PAUSEB		_MAC_(0x0894)
/* Tx Good Vlan Frame Num Base */
#define TSRN10_MMC_TX_VLANB		_MAC_(0x089c)

/* Rx Good And Bad Frames Num Base */
#define TSRN10_MMC_RX_GBFRMB		_MAC_(0x0900)
/* Rx Good And Bad Frames Bytes Base */
#define TSRN10_MMC_RX_GBOCTGB		_MAC_(0x0908)
/* Rx Good Framse Bytes Base */
#define TSRN10_MMC_RX_GOCTGB		_MAC_(0x0910)
/* Rx Good Broadcast Frames Num Base */
#define TSRN10_MMC_RX_BCASTGB		_MAC_(0x0918)
/* Rx Good Multicast Frames Num Base */
#define TSRN10_MMC_RX_MCASTGB		_MAC_(0x0920)
/* Rx Crc Error Frames Num Base */
#define TSRN10_MMC_RX_CRCERB		_MAC_(0x0928)
/* Rx Less Than 64Byes with Crc Err Base*/
#define TSRN10_MMC_RX_RUNTERB		_MAC_(0x0930)
/* Recive Jumbo Frame Error */
#define TSRN10_MMC_RX_JABBER_ERR        _MAC_(0x0934)
/* Shorter Than 64Bytes without Any Errora Base */
#define TSRN10_MMC_RX_USIZEGB		_MAC_(0x0938)
/* Len Oversize Than Support */
#define TSRN10_MMC_RX_OSIZEGB		_MAC_(0x093c)
/* Rx 64Byes Frame Num Base */
#define TSRN10_MMC_RX_64_BYTESB		_MAC_(0x0940)
/* Rx 65Bytes To 127Bytes Frame Num Base */
#define TSRN10_MMC_RX_65TO127_BYTESB	_MAC_(0x0948)
/* Rx 128Bytes To 255Bytes Frame Num Base */
#define TSRN10_MMC_RX_128TO255_BYTESB	_MAC_(0x0950)
/* Rx 256Bytes To 511Bytes Frame Num Base */
#define TSRN10_MMC_RX_256TO511_BYTESB	_MAC_(0x0958)
/* Rx 512Bytes To 1023Bytes Frame Num Base */
#define TSRN10_MMC_RX_512TO1203_BYTESB	_MAC_(0x0960)
/* Rx Len Bigger Than 1024Bytes Base */
#define TSRN10_MMC_RX_1024TOMAX_BYTESB	_MAC_(0x0968)
/* Rx Unicast Frame Good Num Base */
#define TSRN10_MMC_RX_UCASTGB		_MAC_(0x0970)
/* Rx Length Error Of Frame Part */
#define TSRN10_MMC_RX_LENERRB		_MAC_(0x0978)
/* Rx received with a Length field not equal to the valid frame size */
#define TSRN10_MMC_RX_OUTOF_RANGE       _MAC_(0x0980)
/* Rx Pause Frame Good Num Base */
#define TSRN10_MMC_RX_PAUSEB		_MAC_(0x0988)
/* Rx Vlan Frame Good Num Base */
#define TSRN10_MMC_RX_VLANGB		_MAC_(0x0998)
/* Rx With A Watchdog Timeout Err Frame Base */
#define TSRN10_MMC_RX_WDOGERRB		_MAC_(0x09a0)

/* 1588 */
#define TSRN10_MAC_TS_CTRL                 _MAC_(0X0d00)
#define TSRN10_MAC_SUB_SECOND_INCREMENT    _MAC_(0x0d04)
#define TSRN10_MAC_SYS_TIME_SEC_CFG        _MAC_(0x0d08)
#define TSRN10_MAC_SYS_TIME_NANOSEC_CFG    _MAC_(0x0d0c)
#define TSRN10_MAC_SYS_TIME_SEC_UPDATE     _MAC_(0x0d10)
#define TSRN10_MAC_SYS_TIME_NANOSEC_UPDATE _MAC_(0x0d14)
#define TSRN10_MAC_TS_ADDEND               _MAC_(0x0d18)
#define TSRN10_MAC_TS_STATS                _MAC_(0x0d20)
#define TSRN10_MAC_INTERRUPT_ENABLE        _MAC_(0x00b4)

#endif /* TSRN10_MAC_REGS_H */
