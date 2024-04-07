#ifndef _TSRN10_LOGS_H_
#define _TSRN10_LOGS_H_

extern int tsrn10_logtype_pmd;


#ifdef DEBUG
#define TSRN10_DESC_DEBUG(fmt, args...) printf(fmt,  ##args)
#else
#define TSRN10_DESC_DEBUG(fmt, args...)
#endif

#define TSRN10_PMD_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_##level, tsrn10_logtype_pmd, \
			"tsrn10_net: (%d) " fmt, __LINE__, ##args)
#define TSRN10_PMD_DEBUG(fmt, args...) \
	rte_log(RTE_LOG_DEBUG, tsrn10_logtype_pmd, \
			"tsrn10_net: %s: (%d) " fmt "\n", \
			__func__, __LINE__, ##args)

#ifdef RX_DEBUG
    #define rx_debug_printf printf
#else
    #define rx_debug_printf(fmt, args...)
#endif

#ifdef TX_DEBUG
    #define tx_debug_printf printf
#else
    #define tx_debug_printf(fmt, args...)
#endif

#define TSRN10_PMD_CRIT(fmt, args...) \
	TSRN10_PMD_LOG(CRIT, fmt, ## args)
#define TSRN10_PMD_INFO(fmt, args...) \
	TSRN10_PMD_LOG(INFO, fmt, ## args)
#define TSRN10_PMD_NOTICE(fmt, args...) \
	TSRN10_PMD_LOG(NOTICE, fmt, ## args)
#define TSRN10_PMD_ERR(fmt, args...) \
	TSRN10_PMD_LOG(ERR, fmt, ## args)
#define TSRN10_PMD_WARN(fmt, args...) \
	TSRN10_PMD_LOG(WARNING, fmt, ## args)

#define PMD_DRV_LOG  TSRN10_PMD_LOG
#define PMD_FUNC_LOG TSRN10_PMD_LOG

/* DP Logs, toggled out at compile time if level lower than current level */
#define TSRN10_PMD_DP_LOG(level, fmt, args...) \
	RTE_LOG_DP(level, PMD, fmt, ## args)

#define TSRN10_PMD_DP_DEBUG(fmt, args...) \
	TSRN10_PMD_DP_LOG(DEBUG, fmt, ## args)
#define TSRN10_PMD_DP_INFO(fmt, args...) \
	TSRN10_PMD_DP_LOG(INFO, fmt, ## args)
#define TSRN10_PMD_DP_WARN(fmt, args...) \
	TSRN10_PMD_DP_LOG(WARNING, fmt, ## args)
#ifndef __KERNEL__
#define printk printf
#endif

#ifdef RTE_LIBRTE_TSRN10_DEBUG_RX
#define PMD_RX_LOG(level, fmt, args...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)
#else
#define PMD_RX_LOG(level, fmt, args...) do { } while (0)
#endif

#ifdef RTE_LIBRTE_TSRN10_DEBUG_TX
#define PMD_TX_LOG(level, fmt, args...) \
	RTE_LOG(level, PMD, "%s(): " fmt "\n", __func__, ## args)
#else
#define PMD_TX_LOG(level, fmt, args...) do { } while (0)
#endif

#define PMD_INIT_LOG(level, fmt, args...) \
	rte_log(RTE_LOG_ ## level, tsrn10_logtype_pmd, \
			"PMD: %s(): " fmt "\n", __func__, ##args)

#ifdef RTE_LIBRTE_TSRN10_DEBUG_INIT
#define PMD_INIT_FUNC_TRACE() PMD_INIT_LOG(DEBUG, " >>")
#else
#define PMD_INIT_FUNC_TRACE()   do { } while (0)
#endif

#ifdef RX_DEBUG
#define rx_debug_printk printk
#else
#define rx_debug_printk(...)
#endif

#ifdef IRQ_DEBUG
#define irq_debug_printk printk
#else
#define irq_debug_printk(...)
#endif

#ifdef TX_DEBUG
#define tx_debug_printk printk
#else
#define tx_debug_printk(...)
#endif

#ifdef DEBUG
#define debug_printk printk
#else
#define debug_printk(...)
#endif
#endif /* _TSRN10_LOGS_H_*/
