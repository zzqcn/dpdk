#ifndef __TSRN10_COMMON_H__
#define __TSRN10_COMMON_H__

#include <stdint.h>

#include <rte_byteorder.h>

#include "tsrn10_compat.h"
#define ETH_BASE	(0x000000)
#define __iomem
#define _RING_(off)	((off) + 0x000000)
#define _DMA_(off)	((off))
#define _GLB_(off)	((off) + 0x000000)
#define _NIC_(off)	((off) + 0x000000)
#define _ETH_(off)	((off))
#define _MAC_(off)	((off))

#define BIT(n)		(1UL << (n))
#define BIT64(n)	(1ULL << (n))
#define BITS_PER_LONG   (__SIZEOF_LONG__ * 8)
#define GENMASK(h, l) \
	(((~0UL) << (l)) & (~0UL >> (BITS_PER_LONG - 1 - (h))))

typedef uint8_t     u8;
typedef uint16_t    u16;
typedef uint32_t    u32;
typedef uint64_t    u64;

typedef int32_t     s32;
#define bool        _Bool

#define DIV_ROUND_UP(n, d)	(((n) + (d) - 1) / (d))
#define BITS_PER_BYTE           (8)
#define BITS_TO_LONGS(nr)       DIV_ROUND_UP(nr, BITS_PER_BYTE * sizeof(long))

#define TSRN10_NEXT_ID(q, id)	(((id) + 1) & ((q)->attr.bd_count - 1))
#define TSRN10_NEXT_CL_ID(_q, _n) \
	(((_q)->next_to_clean + (_n)) & ((_q)->attr.bd_count - 1))

#define TSRN10_NEXT_USE_ID(_q, _n) \
	(((_q)->next_to_use + (_n)) & ((_q)->attr.bd_count - 1))

#define TSRN10_NEXT_HEAD(_q, _head_idx) \
	(((_head_idx) + (1)) & ((_q)->attr.bd_count - 1))
#define TSRN10_NEXT_TAIL(_q, _tail_idx) \
	(((_tail_idx) + (1)) & ((_q)->attr.bd_count - 1))

#define TSRN10_MAC_BASE	(0x100000) /* 0x1020_0000, mac2:0x1022_0000 */

#define VLAN_N_VID			(4096)
#define VLAN_VID_MASK			(0x0fff)
#define VLAN_BITMAP_BIT(vlan_id)	(1UL << ((vlan_id) & 0x3F))
#define VLAN_BITMAP_IDX(vlan_id)	((vlan_id) >> 6)

#endif
