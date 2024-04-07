#ifndef __RTE_COMPANT_H_
#define __RTE_COMPANT_H_

#include <rte_ip.h>
#include <rte_version.h>
#include <rte_config.h>
#include <rte_ethdev.h>
#include <rte_memzone.h>

#define RTE_ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */
#define RTE_ETHER_TYPE_LEN  2 /**< Length of Ethernet type field. */
#define RTE_ETHER_CRC_LEN   4 /**< Length of Ethernet CRC. */
#define RTE_ETHER_HDR_LEN   \
	(RTE_ETHER_ADDR_LEN * 2 + \
	 RTE_ETHER_TYPE_LEN) /**< Length of Ethernet header. */
#define RTE_ETHER_MIN_LEN   64    /**< Minimum frame len, including CRC. */
#define RTE_ETHER_MAX_LEN   1518  /**< Maximum frame len, including CRC. */
#define RTE_ETHER_MTU       \
	(RTE_ETHER_MAX_LEN - RTE_ETHER_HDR_LEN - \
	 RTE_ETHER_CRC_LEN) /**< Ethernet MTU. */

/* We cannot use rte_cpu_to_be_16() on a constant in a switch/case */
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
#define _htons(x) ((uint16_t)((((x) & 0x00ffU) << 8) | (((x) & 0xff00U) >> 8)))
#else
#define _htons(x) (x)
#endif

#define RTE_ETHER_ADDR_LEN  6

#define RTE_ETHER_ADDR_LEN  6 /**< Length of Ethernet address. */

/*
 * The following types should be used when handling values according to a
 * specific byte ordering, which may differ from that of the host CPU.
 *
 * Libraries, public APIs and applications are encouraged to use them for
 * documentation purposes.
 */
typedef uint16_t rte_be16_t; /**< 16-bit big-endian value. */
typedef uint32_t rte_be32_t; /**< 32-bit big-endian value. */
typedef uint64_t rte_be64_t; /**< 64-bit big-endian value. */
typedef uint16_t rte_le16_t; /**< 16-bit little-endian value. */
typedef uint32_t rte_le32_t; /**< 32-bit little-endian value. */
typedef uint64_t rte_le64_t; /**< 64-bit little-endian value. */

#if RTE_VERSION_NUM(2, 2, 0, 16) >= RTE_VERSION
#if RTE_VERSION_NUM(2, 1, 0, 16) == RTE_VERSION
#include "tsrn10_logs.h"
static void
rte_eth_copy_pci_info(struct rte_eth_dev *eth_dev, struct rte_pci_device *pci_dev)
{
	if (eth_dev == NULL || pci_dev == NULL) {
		PMD_DRV_LOG(ERR, "NULL pointer eth_dev=%p pci_dev=%p\n",
				eth_dev, pci_dev);
		return;
	}

	eth_dev->pci_dev = pci_dev;
}
#endif

#ifdef RTE_ARCH_X86_64
/**
 * Compiler barrier.
 *
 * Guarantees that operation reordering does not occur at compile time
 * for operations directly before and after the barrier.
 */
#define rte_mb() _mm_mfence()

#define rte_wmb() _mm_sfence()

#define rte_rmb() _mm_lfence()

#define rte_smp_wmb() rte_compiler_barrier()

#define rte_smp_rmb() rte_compiler_barrier()
#endif /* RTE_ARCH_X86_64 */

#ifdef RTE_ARCH_ARM64
#define dsb(opt) do { asm volatile("dsb " #opt : : : "memory"); } while (0)
#define dmb(opt) do { asm volatile("dmb " #opt : : : "memory"); } while (0)

#define rte_mb() dsb(sy)

#define rte_wmb() dsb(st)

#define rte_rmb() dsb(ld)

#define rte_smp_mb() dmb(ish)

#define rte_smp_wmb() dmb(ishst)

#define rte_smp_rmb() dmb(ishld)

#define rte_io_mb() rte_mb()

#define rte_io_wmb() rte_wmb()

#define rte_io_rmb() rte_rmb()

#define rte_cio_wmb() dmb(oshst)

#define rte_cio_rmb() dmb(oshld)
#endif /* RTE_ARCH_ARM64 */

#ifdef RTE_ARCH_ARM
#define rte_mb()  __sync_synchronize()

#define rte_wmb() do { asm volatile ("dmb st" : : : "memory"); } while (0)

#define rte_rmb() __sync_synchronize()

#define rte_smp_mb() rte_mb()

#define rte_smp_wmb() rte_wmb()

#define rte_smp_rmb() rte_rmb()

#define rte_io_mb() rte_mb()

#define rte_io_wmb() rte_wmb()

#define rte_io_rmb() rte_rmb()

#define rte_cio_wmb() rte_wmb()

#define rte_cio_rmb() rte_rmb()
#endif /* RTE_ARCH_ARM64 */

#ifdef RTE_ARCH_PPC_64
#define rte_mb()  do { asm volatile("sync" : : : "memory"); } while (0)

#define rte_wmb() do { asm volatile("sync" : : : "memory"); } while (0)

#define rte_rmb() do { asm volatile("sync" : : : "memory"); } while (0)

#define rte_smp_mb() rte_mb()

#define rte_smp_wmb() rte_wmb()

#define rte_smp_rmb() rte_rmb()

#define rte_io_mb() rte_mb()

#define rte_io_wmb() rte_wmb()

#define rte_io_rmb() rte_rmb()

#define rte_cio_wmb() rte_wmb()

#define rte_cio_rmb() rte_rmb()

#endif /* RTE_ARCH_PPC_64 */
/*
 * Rings setup and release.
 *
 * TDBA/RDBA should be aligned on 16 byte boundary. But TDLEN/RDLEN should be
 * multiple of 128 bytes. So we align TDBA/RDBA on 128 byte boundary. This will
 * also optimize cache line size effect. H/W supports up to cache line size 128.
 */
#define TSRN10_ALIGN 128
/*
 * Create memzone for HW rings. malloc can't be used as the physical address is
 * needed. If the memzone is already created, then this function returns a ptr
 * to the old one.
 */
static const struct rte_memzone *__attribute__((cold))
ring_dma_zone_reserve(struct rte_eth_dev *dev, const char *ring_name,
		      uint16_t queue_id, uint32_t ring_size, int socket_id)
{
	char z_name[RTE_MEMZONE_NAMESIZE];
	const struct rte_memzone *mz;

	snprintf(z_name, sizeof(z_name), "%s_%s_%d_%d",
			dev->driver->pci_drv.name, ring_name,
			dev->data->port_id, queue_id);

	mz = rte_memzone_lookup(z_name);
	if (mz)
		return mz;

#ifdef RTE_LIBRTE_XEN_DOM0
	return rte_memzone_reserve_bounded(z_name, ring_size,
			socket_id, 0, TSRN10_ALIGN, RTE_PGSIZE_2M);
#else
	return rte_memzone_reserve_aligned(z_name, ring_size,
			socket_id, 0, TSRN10_ALIGN);
#endif
}
/**
 * RX/TX queue states
 */
#define RTE_ETH_QUEUE_STATE_STOPPED 0
#define RTE_ETH_QUEUE_STATE_STARTED 1

/**
 * VLAN types to indicate if it is for single VLAN, inner VLAN or outer VLAN.
 * Note that single VLAN is treated the same as inner VLAN.
 */
enum rte_vlan_type {
	ETH_VLAN_TYPE_UNKNOWN = 0,
	ETH_VLAN_TYPE_INNER, /**< Inner VLAN. */
	ETH_VLAN_TYPE_OUTER, /**< Single VLAN, or outer VLAN. */
	ETH_VLAN_TYPE_MAX,
};
#endif /* RTE_VERSION < 2.2.0 */

#if RTE_VERSION_NUM(16, 4, 0, 0) > RTE_VERSION
#define ETH_SPEED_NUM_NONE         0 /**< Not defined */
#define ETH_SPEED_NUM_10M         10 /**<  10 Mbps */
#define ETH_SPEED_NUM_100M       100 /**< 100 Mbps */
#define ETH_SPEED_NUM_1G        1000 /**<   1 Gbps */
#define ETH_SPEED_NUM_2_5G      2500 /**< 2.5 Gbps */
#define ETH_SPEED_NUM_5G        5000 /**<   5 Gbps */
#define ETH_SPEED_NUM_10G      10000 /**<  10 Gbps */
#define ETH_SPEED_NUM_20G      20000 /**<  20 Gbps */
#define ETH_SPEED_NUM_25G      25000 /**<  25 Gbps */
#define ETH_SPEED_NUM_40G      40000 /**<  40 Gbps */
#define ETH_SPEED_NUM_50G      50000 /**<  50 Gbps */
#define ETH_SPEED_NUM_56G      56000 /**<  56 Gbps */
#define ETH_SPEED_NUM_100G    100000 /**< 100 Gbps */

/* Utility constants */
#define ETH_LINK_DOWN           0 /**< Link is down. */
#define ETH_LINK_UP             1 /**< Link is up. */
#define ETH_LINK_FIXED          0 /**< No autonegotiation. */
#define ETH_LINK_AUTONEG        1 /**< Autonegotiated. */

/**
 * Return the DMA address of the beginning of the mbuf data
 *
 * @param mb
 *   The pointer to the mbuf.
 * @return
 *   The physical address of the beginning of the mbuf data
 */
static inline phys_addr_t
rte_mbuf_data_dma_addr(const struct rte_mbuf *mb)
{
	return mb->buf_physaddr + mb->data_off;
}

#define rte_prefetch_non_temporal(p) do { } while (0);
#endif /* RTE_VERSION < 16.04 */

#if RTE_VERSION_NUM(16, 4, 0, 16) >= RTE_VERSION
static inline struct rte_mbuf *
rte_rxmbuf_alloc(struct rte_mempool *mp)
{
	struct rte_mbuf *m;

	m = __rte_mbuf_raw_alloc(mp);
	__rte_mbuf_sanity_check_raw(m, 0);

	return m;
}
#define rte_mbuf_raw_alloc rte_rxmbuf_alloc
#endif /*  RTE_VERSION < 16.04 */

#if RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
#define RTE_PTYPE_L2_ETHER_VLAN         (0x00000006)
#endif /* RTE_VERSION < 16.07 */

#if RTE_VERSION_NUM(16, 11, 0, 0) > RTE_VERSION
#define PKT_TX_TUNNEL_VXLAN   (0x1ULL << 45)
#define PKT_TX_TUNNEL_MASK    (0xFULL << 45)
#define PKT_TX_TUNNEL_GRE     (0x2ULL << 45)

#define PKT_RX_L4_CKSUM_GOOD (0)
#define PKT_RX_IP_CKSUM_GOOD (0)

static void
rte_delay_us_block(unsigned int us)
{
	const uint64_t start = rte_get_timer_cycles();
	const uint64_t ticks = (uint64_t)us * rte_get_timer_hz() / 1E6;
	while ((rte_get_timer_cycles() - start) < ticks)
		rte_pause();
}

#define PCI_PRI_STR_SIZE sizeof("XXXXXXXX:XX:XX.X")
#endif /* RTE_VERSION < 16.11 */

#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
#ifndef strlcpy
/*
 * @internal
 * DPDK-specific version of strlcpy for systems without
 * libc or libbsd copies of the function
 */
static inline size_t
rte_strlcpy(char *dst, const char *src, size_t size)
{
	return (size_t)snprintf(dst, size, "%s", src);
}
#define strlcpy(dst, src, size) rte_strlcpy(dst, src, size)
#endif /* strlcpy */
#endif /* RTE_VERSION < 18.05 */

#if RTE_VERSION_NUM(17, 2, 0, 0) > RTE_VERSION
enum rte_flow_item_type {
	/**
	 * [META]
	 *
	 * End marker for item lists. Prevents further processing of items,
	 * thereby ending the pattern.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_END,

	/**
	 * [META]
	 *
	 * Used as a placeholder for convenience. It is ignored and simply
	 * discarded by PMDs.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_VOID,

	/**
	 * [META]
	 *
	 * Inverted matching, i.e. process packets that do not match the
	 * pattern.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_INVERT,

	/**
	 * Matches any protocol in place of the current layer, a single ANY
	 * may also stand for several protocol layers.
	 *
	 * See struct rte_flow_item_any.
	 */
	RTE_FLOW_ITEM_TYPE_ANY,

	/**
	 * [META]
	 *
	 * Matches packets addressed to the physical function of the device.
	 *
	 * If the underlying device function differs from the one that would
	 * normally receive the matched traffic, specifying this item
	 * prevents it from reaching that device unless the flow rule
	 * contains a PF action. Packets are not duplicated between device
	 * instances by default.
	 *
	 * No associated specification structure.
	 */
	RTE_FLOW_ITEM_TYPE_PF,

	/**
	 * [META]
	 *
	 * Matches packets addressed to a virtual function ID of the device.
	 *
	 * If the underlying device function differs from the one that would
	 * normally receive the matched traffic, specifying this item
	 * prevents it from reaching that device unless the flow rule
	 * contains a VF action. Packets are not duplicated between device
	 * instances by default.
	 *
	 * See struct rte_flow_item_vf.
	 */
	RTE_FLOW_ITEM_TYPE_VF,

	/**
	 * [META]
	 *
	 * Matches packets coming from the specified physical port of the
	 * underlying device.
	 *
	 * The first PORT item overrides the physical port normally
	 * associated with the specified DPDK input port (port_id). This
	 * item can be provided several times to match additional physical
	 * ports.
	 *
	 * See struct rte_flow_item_port.
	 */
	RTE_FLOW_ITEM_TYPE_PORT,

	/**
	 * Matches a byte string of a given length at a given offset.
	 *
	 * See struct rte_flow_item_raw.
	 */
	RTE_FLOW_ITEM_TYPE_RAW,

	/**
	 * Matches an Ethernet header.
	 *
	 * See struct rte_flow_item_eth.
	 */
	RTE_FLOW_ITEM_TYPE_ETH,

	/**
	 * Matches an 802.1Q/ad VLAN tag.
	 *
	 * See struct rte_flow_item_vlan.
	 */
	RTE_FLOW_ITEM_TYPE_VLAN,

	/**
	 * Matches an IPv4 header.
	 *
	 * See struct rte_flow_item_ipv4.
	 */
	RTE_FLOW_ITEM_TYPE_IPV4,

	/**
	 * Matches an IPv6 header.
	 *
	 * See struct rte_flow_item_ipv6.
	 */
	RTE_FLOW_ITEM_TYPE_IPV6,

	/**
	 * Matches an ICMP header.
	 *
	 * See struct rte_flow_item_icmp.
	 */
	RTE_FLOW_ITEM_TYPE_ICMP,

	/**
	 * Matches a UDP header.
	 *
	 * See struct rte_flow_item_udp.
	 */
	RTE_FLOW_ITEM_TYPE_UDP,

	/**
	 * Matches a TCP header.
	 *
	 * See struct rte_flow_item_tcp.
	 */
	RTE_FLOW_ITEM_TYPE_TCP,

	/**
	 * Matches a SCTP header.
	 *
	 * See struct rte_flow_item_sctp.
	 */
	RTE_FLOW_ITEM_TYPE_SCTP,

	/**
	 * Matches a VXLAN header.
	 *
	 * See struct rte_flow_item_vxlan.
	 */
	RTE_FLOW_ITEM_TYPE_VXLAN,

	/**
	 * Matches a E_TAG header.
	 *
	 * See struct rte_flow_item_e_tag.
	 */
	RTE_FLOW_ITEM_TYPE_E_TAG,

	/**
	 * Matches a NVGRE header.
	 *
	 * See struct rte_flow_item_nvgre.
	 */
	RTE_FLOW_ITEM_TYPE_NVGRE,
};

struct rte_flow_action_rss {
	const struct rte_eth_rss_conf *rss_conf; /**< RSS parameters. */
	uint16_t num; /**< Number of entries in queue[]. */
	uint16_t queue[]; /**< Queues indices to use. */
};

/**
 * Verbose error types.
 *
 * Most of them provide the type of the object referenced by struct
 * rte_flow_error.cause.
 */
enum rte_flow_error_type {
	RTE_FLOW_ERROR_TYPE_NONE, /**< No error. */
	RTE_FLOW_ERROR_TYPE_UNSPECIFIED, /**< Cause unspecified. */
	RTE_FLOW_ERROR_TYPE_HANDLE, /**< Flow rule (handle). */
	RTE_FLOW_ERROR_TYPE_ATTR_GROUP, /**< Group field. */
	RTE_FLOW_ERROR_TYPE_ATTR_PRIORITY, /**< Priority field. */
	RTE_FLOW_ERROR_TYPE_ATTR_INGRESS, /**< Ingress field. */
	RTE_FLOW_ERROR_TYPE_ATTR_EGRESS, /**< Egress field. */
	RTE_FLOW_ERROR_TYPE_ATTR, /**< Attributes structure. */
	RTE_FLOW_ERROR_TYPE_ITEM_NUM, /**< Pattern length. */
	RTE_FLOW_ERROR_TYPE_ITEM, /**< Specific pattern item. */
	RTE_FLOW_ERROR_TYPE_ACTION_NUM, /**< Number of actions. */
	RTE_FLOW_ERROR_TYPE_ACTION, /**< Specific action. */
};

struct rte_flow_item {
	enum rte_flow_item_type type; /**< Item type. */
	const void *spec; /**< Pointer to item specification structure. */
	const void *last; /**< Defines an inclusive range (spec to last). */
	const void *mask; /**< Bit-mask applied to spec and last. */
};

/**
 * Verbose error structure definition.
 *
 * This object is normally allocated by applications and set by PMDs, the
 * message points to a constant string which does not need to be freed by
 * the application, however its pointer can be considered valid only as long
 * as its associated DPDK port remains configured. Closing the underlying
 * device or unloading the PMD invalidates it.
 *
 * Both cause and message may be NULL regardless of the error type.
 */
struct rte_flow_error {
	enum rte_flow_error_type type; /**< Cause field and error types. */
	const void *cause; /**< Object responsible for the error. */
	const char *message; /**< Human-readable error message. */
};

#include <rte_per_lcore.h>

RTE_DECLARE_PER_LCORE(int, _rte_errno); /**< Per core error number. */

/**
 * Error number value, stored per-thread, which can be queried after
 * calls to certain functions to determine why those functions failed.
 *
 * Uses standard values from errno.h wherever possible, with a small number
 * of additional possible values for RTE-specific conditions.
 */
#define rte_errno RTE_PER_LCORE(_rte_errno)


/**
 * Initialize generic flow error structure.
 *
 * This function also sets rte_errno to a given value.
 *
 * @param[out] error
 *   Pointer to flow error structure (may be NULL).
 * @param code
 *   Related error code (rte_errno).
 * @param type
 *   Cause field and error types.
 * @param cause
 *   Object responsible for the error.
 * @param message
 *   Human-readable error message.
 *
 * @return
 *   Error code.
 */
static inline int
rte_flow_error_set(struct rte_flow_error *error,
		   int code,
		   enum rte_flow_error_type type,
		   const void *cause,
		   const char *message)
{
	if (error) {
		*error = (struct rte_flow_error){
			.type = type,
			.cause = cause,
			.message = message,
		};
	}
	rte_errno = code;

	return code;
}

/**
 * RTE_FLOW_ACTION_TYPE_MARK
 *
 * Attaches an integer value to packets and sets PKT_RX_FDIR and
 * PKT_RX_FDIR_ID mbuf flags.
 *
 * This value is arbitrary and application-defined. Maximum allowed value
 * depends on the underlying implementation. It is returned in the
 * hash.fdir.hi mbuf field.
 */
struct rte_flow_action_mark {
	uint32_t id; /**< Integer value to return with packets. */
};
/**
 * RTE_FLOW_ACTION_TYPE_QUEUE
 *
 * Assign packets to a given queue index.
 *
 * Terminating by default.
 */
struct rte_flow_action_queue {
	uint16_t index; /**< Queue index to use. */
};
/**
 * RTE_FLOW_ACTION_TYPE_VF
 *
 * Redirects packets to a virtual function (VF) of the current device.
 *
 * Packets matched by a VF pattern item can be redirected to their original
 * VF ID instead of the specified one. This parameter may not be available
 * and is not guaranteed to work properly if the VF part is matched by a
 * prior flow rule or if packets are not addressed to a VF in the first
 * place.
 *
 * Terminating by default.
 */
struct rte_flow_action_vf {
	uint32_t original:1; /**< Use original VF ID if possible. */
	uint32_t reserved:31; /**< Reserved, must be zero. */
	uint32_t id; /**< VF ID to redirect packets to. */
};
struct rte_flow;

/**
 * Offload the MACsec. This flag must be set by the application to enable
 * this offload feature for a packet to be transmitted.
 */
#define PKT_TX_MACSEC			(1ULL << 44)
#define PKT_RX_VLAN_STRIPPED		(1ULL << 6)

/**
 * Bitmask of all supported packet Tx offload features flags,
 * which can be set for packet.
 */
#define PKT_TX_OFFLOAD_MASK (    \
		PKT_TX_IP_CKSUM |        \
		PKT_TX_L4_MASK |         \
		PKT_TX_OUTER_IP_CKSUM |  \
		PKT_TX_TCP_SEG |         \
		PKT_TX_IEEE1588_TMST |   \
		PKT_TX_QINQ_PKT |        \
		PKT_TX_VLAN_PKT |        \
		PKT_TX_TUNNEL_MASK |     \
		PKT_TX_MACSEC)
#define RTE_ETH_DEV_TO_PCI(eth_dev) ((eth_dev)->pci_dev)
#endif /* RTE_VERSION < 17.02 */
#if RTE_VERSION_NUM(17, 5, 0, 16) > RTE_VERSION
#define rte_pktmbuf_prefree_seg __rte_pktmbuf_prefree_seg
#endif

#if RTE_VERSION_NUM(17, 8, 0, 16) > RTE_VERSION && \
	RTE_VERSION_NUM(17, 2, 0, 16) <= RTE_VERSION
#define RTE_ETH_DEV_TO_PCI(eth_dev) RTE_DEV_TO_PCI((eth_dev)->device)
#endif /* 17.2 < RTE_VERSION < 17.05 */

#if RTE_VERSION_NUM(17, 8, 0, 0) > RTE_VERSION
#define __rte_always_inline inline __attribute__((always_inline))
#endif /* RTE_VERSION < 17.08 */

#if RTE_VERSION_NUM(17, 11, 0, 0) > RTE_VERSION
/* Mbuf dma Address  */
#define rte_mbuf_data_iova(m)      rte_mbuf_data_dma_addr(m)
#define rte_mbuf_data_iova_default rte_mbuf_data_dma_addr_default

#define DEV_RX_OFFLOAD_TIMESTAMP	0x00004000
#define DEV_RX_OFFLOAD_SCATTER		0x00002000
#define DEV_RX_OFFLOAD_JUMBO_FRAME	0x00000800
#define DEV_RX_OFFLOAD_CHECKSUM (DEV_RX_OFFLOAD_IPV4_CKSUM | \
				 DEV_RX_OFFLOAD_UDP_CKSUM | \
				 DEV_RX_OFFLOAD_TCP_CKSUM)
#define DEV_RX_OFFLOAD_VLAN_FILTER      0x00000200
#define DEV_RX_OFFLOAD_VLAN_EXTEND      0x00000400
#define DEV_RX_OFFLOAD_VLAN (DEV_RX_OFFLOAD_VLAN_STRIP | \
			     DEV_RX_OFFLOAD_VLAN_FILTER | \
			     DEV_RX_OFFLOAD_VLAN_EXTEND)
#define DEV_TX_OFFLOAD_MULTI_SEGS	0x00008000
#define DEV_TX_OFFLOAD_GRE_TNL_TSO	0x00000400/**< Used for tunneling packet. */
#define DEV_TX_OFFLOAD_VXLAN_TNL_TSO    0x00000200/**< Used for tunneling packet. */

#define PKT_RX_VLAN			PKT_RX_VLAN_PKT

#endif /* RTE_VERSION < 17.11 */

#if RTE_VERSION_NUM(17, 11, 0, 16) <= RTE_VERSION
#define rte_mbuf_data_dma_addr	   rte_mbuf_data_iova
#endif /* RTE_VERSION > 17.08 */

#if RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
static inline uint64_t
rte_atomic64_exchange(volatile uint64_t *dst, uint64_t val)
{
#if defined(RTE_ARCH_ARM64) && defined(RTE_TOOLCHAIN_CLANG)
	return __atomic_exchange_n(dst, val, __ATOMIC_SEQ_CST);
#else
	return __atomic_exchange_8(dst, val, __ATOMIC_SEQ_CST);
#endif
}
/**
 * @internal
 * Atomically set the link status for the specific device.
 * It is for use by DPDK device driver use only.
 * User applications should not call it
 *
 * @param dev
 *  Pointer to struct rte_eth_dev.
 * @param link
 *  New link status value.
 * @return
 *  Same convention as eth_link_update operation.
 *  0   if link up status has changed
 *  -1  if link up status was unchanged
 */
static inline int
rte_eth_linkstatus_set(struct rte_eth_dev *dev,
		       const struct rte_eth_link *new_link)
{
	volatile uint64_t *dev_link =
		(volatile uint64_t *)&(dev->data->dev_link);
	union {
		uint64_t val64;
		struct rte_eth_link link;
	} orig;

	RTE_BUILD_BUG_ON(sizeof(*new_link) != sizeof(uint64_t));

	orig.val64 = rte_atomic64_exchange(dev_link,
			*(const uint64_t *)new_link);

	return (orig.link.link_status == new_link->link_status) ? -1 : 0;
}
#endif /* RTE_VERSION < 18.05 */

#if RTE_VERSION_NUM(18, 11, 0, 0) > RTE_VERSION
#define DEV_RX_OFFLOAD_SCTP_CKSUM	0x00020000
#define DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM 0x00000040
#define DEV_RX_OFFLOAD_KEEP_CRC		0x00010000
#endif /* RTE_VERSION < 18.11 */
#if RTE_VERSION_NUM(19, 11, 0, 0) > RTE_VERSION
#define DEV_RX_OFFLOAD_RSS_HASH            0x00080000
#endif /* RTE_VERSION < 19.11 */

#if RTE_VERSION_NUM(19, 8, 0, 0) < RTE_VERSION
#define ETHER_MIN_MTU			RTE_ETHER_MIN_MTU
#define ETHER_ADDR_LEN			RTE_ETHER_ADDR_LEN
#define ETHER_CRC_LEN			RTE_ETHER_CRC_LEN
#define ETHER_HDR_LEN			RTE_ETHER_HDR_LEN
#define ETHER_MIN_LEN			RTE_ETHER_MIN_LEN
#define ETHER_MAX_LEN			RTE_ETHER_MAX_LEN
#define ETHER_TYPE_1588			RTE_ETHER_TYPE_1588
#define ETHER_TYPE_VLAN			RTE_ETHER_TYPE_VLAN
#define ETHER_TYPE_IPv4			RTE_ETHER_TYPE_IPV4
#define ETHER_TYPE_IPv6			RTE_ETHER_TYPE_IPV6
#define ETHER_MAX_JUMBO_FRAME_LEN	RTE_ETHER_MAX_JUMBO_FRAME_LEN
#define ETHER_LOCAL_ADMIN_ADDR		RTE_ETHER_LOCAL_ADMIN_ADDR
#define IPV4_MAX_PKT_LEN		RTE_IPV4_MAX_PKT_LEN
#define TCP_SYN_FLAG			RTE_TCP_SYN_FLAG
#define ETHER_MAX_VLAN_ID		RTE_ETHER_MAX_VLAN_ID

#define ipv4_hdr			rte_ipv4_hdr
#define ipv6_hdr			rte_ipv6_hdr

#else /* RTE_VERSION <= 19.05 */
#define RTE_TCP_SYN_FLAG 0x02 /**< Synchronize sequence numbers */
#define rte_ether_addr			ether_addr
#define rte_tcp_hdr			tcp_hdr
#define rte_sctp_hdr			sctp_hdr
#define rte_vlan_hdr			vlan_hdr

#define rte_vxlan_hdr			vxlan_hdr
/**
 * UDP Header
 */
struct rte_udp_hdr {
	rte_be16_t src_port;    /**< UDP source port. */
	rte_be16_t dst_port;    /**< UDP destination port. */
	rte_be16_t dgram_len;   /**< UDP datagram length */
	rte_be16_t dgram_cksum; /**< UDP datagram checksum */
} __attribute__((__packed__));

/**
 * GRE Header
 */
__extension__
struct rte_gre_hdr {
#if RTE_BYTE_ORDER == RTE_LITTLE_ENDIAN
	uint16_t res2:4; /**< Reserved */
	uint16_t s:1;    /**< Sequence Number Present bit */
	uint16_t k:1;    /**< Key Present bit */
	uint16_t res1:1; /**< Reserved */
	uint16_t c:1;    /**< Checksum Present bit */
	uint16_t ver:3;  /**< Version Number */
	uint16_t res3:5; /**< Reserved */
#elif RTE_BYTE_ORDER == RTE_BIG_ENDIAN
	uint16_t c:1;    /**< Checksum Present bit */
	uint16_t res1:1; /**< Reserved */
	uint16_t k:1;    /**< Key Present bit */
	uint16_t s:1;    /**< Sequence Number Present bit */
	uint16_t res2:4; /**< Reserved */
	uint16_t res3:5; /**< Reserved */
	uint16_t ver:3;  /**< Version Number */
#endif
	uint16_t proto;  /**< Protocol Type */
} __attribute__((__packed__));

#define rte_ipv6_hdr			ipv6_hdr
#define rte_ipv4_hdr			ipv4_hdr

#define rte_eth_random_addr		eth_random_addr
#define rte_is_zero_ether_addr		is_zero_ether_addr
#define rte_is_broadcast_ether_addr	is_broadcast_ether_addr
#define rte_is_valid_assigned_ether_addr	is_valid_assigned_ether_addr

#define RTE_ETHER_MIN_MTU 68		/**< Minimum MTU for IPv4 packets, see RFC 791. */
#endif /* RTE_VERSION > 19.05 */

#if RTE_VERSION_NUM(16, 11, 0, 0) < RTE_VERSION && \
	 RTE_VERSION_NUM(18, 5, 0, 0) > RTE_VERSION
#define RTE_FLOW_ERROR_TYPE_ITEM_MASK RTE_FLOW_ERROR_TYPE_ITEM_NUM
#define RTE_FLOW_ERROR_TYPE_ACTION RTE_FLOW_ERROR_TYPE_ACTION
#define RTE_FLOW_ERROR_TYPE_ACTION_CONF RTE_FLOW_ERROR_TYPE_ACTION
#endif

#if RTE_VERSION_NUM(19, 5, 0, 0) > RTE_VERSION
#define RTE_TCP_SYN_FLAG 0x02 /**< Synchronize sequence numbers */
#endif
#if RTE_VERSION_NUM(19, 8, 0, 0) > RTE_VERSION
/**
 * Ethernet header: Contains the destination address, source address
 * and frame type.
 */
struct rte_ether_hdr {
	struct rte_ether_addr d_addr; /**< Destination address. */
	struct rte_ether_addr s_addr; /**< Source address. */
	uint16_t ether_type;      /**< Frame type. */
} __attribute__((__packed__));
#define RTE_ETHER_MIN_MTU 68 /**< Minimum MTU for IPv4 packets, see RFC 791. */
/* Ethernet frame types */
#define RTE_ETHER_TYPE_QINQ 0x88A8 /**< IEEE 802.1ad QinQ tagging. */
#define RTE_ETHER_TYPE_VLAN 0x8100 /**< Arp Protocol. */
#define RTE_ETHER_TYPE_IPV4 0x0800 /**< IPv4 Protocol. */
#define RTE_ETHER_TYPE_IPV6 0x86DD /**< IPv6 Protocol. */
#define RTE_ETHER_TYPE_ARP  0x0806 /**< Arp Protocol. */
#endif /* RTE_VERSION < 19.08 */

#if RTE_VERSION_NUM(21, 5, 0, 0) <= RTE_VERSION && \
	RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
#define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD PKT_RX_OUTER_IP_CKSUM_BAD
#endif /* 21.05 <= RTE_VERIONO < 21.11 */

#if RTE_VERSION_NUM(21, 5, 0, 0) > RTE_VERSION
#define RTE_MBUF_F_RX_OUTER_IP_CKSUM_BAD PKT_RX_EIP_CKSUM_BAD
#endif /* RTE_VERSION < 21.05 */

#if RTE_VERSION_NUM(21, 11, 0, 0) > RTE_VERSION
#define RTE_MBUF_F_TX_TUNNEL_VXLAN	PKT_TX_TUNNEL_VXLAN
#define RTE_MBUF_F_TX_TUNNEL_GRE	PKT_TX_TUNNEL_GRE
#if RTE_VERSION_NUM(18, 2, 0, 0) > RTE_VERSION
#define RTE_MBUF_F_TX_VLAN              PKT_TX_VLAN_PKT
#else
#define RTE_MBUF_F_TX_VLAN              PKT_TX_VLAN
#endif
#define RTE_MBUF_F_TX_QINQ		PKT_TX_QINQ_PKT
#define RTE_MBUF_F_TX_TUNNEL_MASK	PKT_TX_TUNNEL_MASK
#define RTE_MBUF_F_TX_TCP_SEG		PKT_TX_TCP_SEG
#define RTE_MBUF_F_TX_OUTER_IP_CKSUM	PKT_TX_OUTER_IP_CKSUM
#define RTE_MBUF_F_TX_IP_CKSUM		PKT_TX_IP_CKSUM
#define RTE_MBUF_F_TX_UDP_CKSUM		PKT_TX_UDP_CKSUM
#define RTE_MBUF_F_TX_TCP_CKSUM		PKT_TX_TCP_CKSUM
#define RTE_MBUF_F_TX_SCTP_CKSUM	PKT_TX_SCTP_CKSUM
#define RTE_MBUF_F_TX_L4_MASK		PKT_TX_L4_MASK
#define RTE_MBUF_F_TX_IPV4		PKT_TX_IPV4
#define RTE_MBUF_F_TX_IPV6		PKT_TX_IPV6
#define RTE_MBUF_F_TX_OUTER_IPV4	PKT_TX_OUTER_IPV4
#define RTE_MBUF_F_TX_OUTER_IPV6	PKT_TX_OUTER_IPV6
#define RTE_MBUF_F_TX_OFFLOAD_MASK	PKT_TX_OFFLOAD_MASK
#define RTE_MBUF_F_TX_IEEE1588_TMST	PKT_TX_IEEE1588_TMST

#define RTE_MBUF_F_RX_VLAN_STRIPPED	PKT_RX_VLAN_STRIPPED
#define RTE_MBUF_F_RX_IP_CKSUM_GOOD	PKT_RX_IP_CKSUM_GOOD
#define RTE_MBUF_F_RX_IP_CKSUM_BAD	PKT_RX_IP_CKSUM_BAD
#define RTE_MBUF_F_RX_L4_CKSUM_BAD	PKT_RX_L4_CKSUM_BAD
#define RTE_MBUF_F_RX_L4_CKSUM_GOOD	PKT_RX_L4_CKSUM_GOOD
#define RTE_MBUF_F_RX_RSS_HASH		PKT_RX_RSS_HASH
#define RTE_MBUF_F_RX_FDIR		PKT_RX_FDIR
#define RTE_MBUF_F_RX_FDIR_ID		PKT_RX_FDIR_ID
#define RTE_MBUF_F_RX_VLAN		PKT_RX_VLAN
#define RTE_MBUF_F_RX_IEEE1588_PTP	PKT_RX_IEEE1588_PTP
#define RTE_MBUF_F_RX_IEEE1588_TMST	PKT_RX_IEEE1588_TMST
#endif /* RTE_VERSION < 21.11 */

#if RTE_VERSION_NUM(21, 11, 0, 0) <= RTE_VERSION
#define TAILQ_FOREACH_SAFE RTE_TAILQ_FOREACH_SAFE
#endif /* RTE_VERSION > 21.11 */

#if RTE_VERSION_NUM(22, 11, 0, 0) <= RTE_VERSION
#define DEV_RX_OFFLOAD_CHECKSUM		RTE_ETH_RX_OFFLOAD_CHECKSUM
#define DEV_RX_OFFLOAD_IPV4_CKSUM	RTE_ETH_RX_OFFLOAD_IPV4_CKSUM
#define DEV_RX_OFFLOAD_UDP_CKSUM	RTE_ETH_RX_OFFLOAD_UDP_CKSUM
#define DEV_RX_OFFLOAD_TCP_CKSUM	RTE_ETH_RX_OFFLOAD_TCP_CKSUM
#define DEV_RX_OFFLOAD_SCTP_CKSUM	RTE_ETH_RX_OFFLOAD_SCTP_CKSUM
#define DEV_RX_OFFLOAD_OUTER_IPV4_CKSUM	RTE_ETH_RX_OFFLOAD_OUTER_IPV4_CKSUM
#define DEV_RX_OFFLOAD_VLAN_STRIP	RTE_ETH_RX_OFFLOAD_VLAN_STRIP
#define DEV_RX_OFFLOAD_VLAN_FILTER	RTE_ETH_RX_OFFLOAD_VLAN_FILTER
#define DEV_RX_OFFLOAD_VLAN_EXTEND	RTE_ETH_RX_OFFLOAD_VLAN_EXTEND
#define DEV_RX_OFFLOAD_RSS_HASH		RTE_ETH_RX_OFFLOAD_RSS_HASH
#define DEV_RX_OFFLOAD_TIMESTAMP	RTE_ETH_RX_OFFLOAD_TIMESTAMP
#define DEV_RX_OFFLOAD_SCATTER		RTE_ETH_RX_OFFLOAD_SCATTER

#define DEV_TX_OFFLOAD_MBUF_FAST_FREE	RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE
#define DEV_TX_OFFLOAD_IPV4_CKSUM	RTE_ETH_TX_OFFLOAD_IPV4_CKSUM
#define DEV_TX_OFFLOAD_UDP_CKSUM	RTE_ETH_TX_OFFLOAD_UDP_CKSUM
#define DEV_TX_OFFLOAD_TCP_CKSUM	RTE_ETH_TX_OFFLOAD_TCP_CKSUM
#define DEV_TX_OFFLOAD_SCTP_CKSUM	RTE_ETH_TX_OFFLOAD_SCTP_CKSUM
#define DEV_TX_OFFLOAD_OUTER_IPV4_CKSUM	RTE_ETH_TX_OFFLOAD_OUTER_IPV4_CKSUM
#define DEV_TX_OFFLOAD_TCP_TSO		RTE_ETH_TX_OFFLOAD_TCP_TSO
#define DEV_TX_OFFLOAD_VLAN_INSERT	RTE_ETH_TX_OFFLOAD_VLAN_INSERT
#define DEV_TX_OFFLOAD_VXLAN_TNL_TSO	RTE_ETH_TX_OFFLOAD_VXLAN_TNL_TSO
#define DEV_TX_OFFLOAD_GRE_TNL_TSO	RTE_ETH_TX_OFFLOAD_GRE_TNL_TSO
#define DEV_TX_OFFLOAD_QINQ_INSERT	RTE_ETH_TX_OFFLOAD_QINQ_INSERT
#define RTE_ETH_TX_OFFLOAD_MULTI_SEGS	DEV_TX_OFFLOAD_MULTI_SEGS

#define ETH_RSS_IPV4			RTE_ETH_RSS_IPV4
#define ETH_RSS_FRAG_IPV4		RTE_ETH_RSS_FRAG_IPV4
#define ETH_RSS_NONFRAG_IPV4_OTHER	RTE_ETH_RSS_NONFRAG_IPV4_OTHER
#define ETH_RSS_NONFRAG_IPV4_TCP	RTE_ETH_RSS_NONFRAG_IPV4_TCP
#define ETH_RSS_NONFRAG_IPV4_UDP	RTE_ETH_RSS_NONFRAG_IPV4_UDP
#define ETH_RSS_NONFRAG_IPV4_SCTP	RTE_ETH_RSS_NONFRAG_IPV4_SCTP
#define ETH_RSS_IPV6			RTE_ETH_RSS_IPV6
#define ETH_RSS_FRAG_IPV6		RTE_ETH_RSS_FRAG_IPV6
#define ETH_RSS_NONFRAG_IPV6_OTHER	RTE_ETH_RSS_NONFRAG_IPV6_OTHER
#define ETH_RSS_IPV6_EX			RTE_ETH_RSS_IPV6_EX
#define ETH_RSS_IPV6_TCP_EX		RTE_ETH_RSS_IPV6_TCP_EX
#define ETH_RSS_NONFRAG_IPV6_TCP	RTE_ETH_RSS_NONFRAG_IPV6_TCP
#define ETH_RSS_IPV6_UDP_EX		RTE_ETH_RSS_IPV6_UDP_EX
#define ETH_RSS_NONFRAG_IPV6_SCTP	RTE_ETH_RSS_NONFRAG_IPV6_SCTP

#define ETH_RSS_L2_PAYLOAD		RTE_ETH_RSS_L2_PAYLOAD
#define ETH_RSS_PORT			RTE_ETH_RSS_PORT
#define ETH_RSS_VXLAN			RTE_ETH_RSS_VXLAN
#define ETH_RSS_GENEVE			RTE_ETH_RSS_GENEVE
#define ETH_RSS_NVGRE			RTE_ETH_RSS_NVGRE
#define ETH_RSS_GTPU			RTE_ETH_RSS_GTPU
#define ETH_RSS_L3_SRC_ONLY		RTE_ETH_RSS_L3_SRC_ONLY
#define ETH_RSS_L3_DST_ONLY		RTE_ETH_RSS_L3_DST_ONLY
#define ETH_RSS_L4_SRC_ONLY		RTE_ETH_RSS_L4_SRC_ONLY
#define ETH_RSS_L4_DST_ONLY		RTE_ETH_RSS_L4_DST_ONLY
#endif /* RTE_VERSION < 22.11 */
#endif /* __RTE_COMPANT_H_ */
