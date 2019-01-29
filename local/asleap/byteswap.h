#ifndef BYTESWAP_H
#define BYTESWAP_H

#define __swab16(x) \
({ \
        uint16_t __x = (x); \
        ((uint16_t)( \
                (((uint16_t)(__x) & (uint16_t)0x00ffU) << 8) | \
                (((uint16_t)(__x) & (uint16_t)0xff00U) >> 8) )); \
})

#define __swab32(x) \
({ \
        uint32_t __x = (x); \
        ((uint32_t)( \
                (((uint32_t)(__x) & (uint32_t)0x000000ffUL) << 24) | \
                (((uint32_t)(__x) & (uint32_t)0x0000ff00UL) <<  8) | \
                (((uint32_t)(__x) & (uint32_t)0x00ff0000UL) >>  8) | \
                (((uint32_t)(__x) & (uint32_t)0xff000000UL) >> 24) )); \
})

#define __swab64(x) \
({ \
        uint64_t __x = (x); \
        ((uint64_t)( \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000000000ffULL) << 56) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000000000ff00ULL) << 40) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000000000ff0000ULL) << 24) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00000000ff000000ULL) <<  8) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x000000ff00000000ULL) >>  8) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x0000ff0000000000ULL) >> 24) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0x00ff000000000000ULL) >> 40) | \
                (uint64_t)(((uint64_t)(__x) & (uint64_t)0xff00000000000000ULL) >> 56) )); \
})

#ifdef WORDS_BIGENDIAN
#warning "Compiling for big-endian"
#define le16_to_cpu(x) __swab16(x)
#define le32_to_cpu(x) __swab32(x)
#define le64_to_cpu(x) __swab64(x)
#else
#define le16_to_cpu(x) (x)
#define le32_to_cpu(x) (x)
#define le64_to_cpu(x) (x)
#endif

#endif /* BYTESWAP_H */
