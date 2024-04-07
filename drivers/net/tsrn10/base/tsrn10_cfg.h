#ifndef TSRN10_CFG_H_51CZEWUD
#define TSRN10_CFG_H_51CZEWUD

/* nic/cfg/cfg_define.v 0x20200805  */

/* ETH Channel Registers Address */
#define ETH_RESET                   0x8000
#define TSRN10_NIC_RESET            (0x0010)
#define TSRN10_TX_QINQ_WORKAROUND   (0x801c)

/* 1588 timestamp */
#define TIMESTAMP_ENA               0x8010
#define	ADDEND_UPDT_EVENT_TRIG      0x8014
#define INIT_EVENT_TRIG             0x8018
#define UPDT_EVENT_TRIG             0x801c
#define SUB_SECOND_INCREMENT        0x8020
#define TIME_SECOND                 0x8024
#define TIME_NANOSECOND             0x8028
#define TIME_SECOND_UPDATE          0x802c
#define TIME_NANOSECOND_UPDATE      0x8030
#define TIMESTAMP_ADDEND            0x8034
#define TIMESTAMP_SEL               0x8038

/*== flowctrl==  */
#define VERSION_FLOWCTRL            0x9000
#define TYPE_FLOWCTRL               0x9004
#define PORT0_PRI_MAP               0x9008
#define PORT1_PRI_MAP               0x900C
#define PORT2_PRI_MAP               0x9010
#define PORT3_PRI_MAP               0x9014
#define ENA_CFGBL_FLOWCTRL          0x9018

#endif /* end of include guard: TSRN10_CFG_H_51CZEWUD */
