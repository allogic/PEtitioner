#ifndef KDU_CORE_H
#define KDU_CORE_H

#include <assert.h>

#define KDUAPI

#define KDU_ASSERT(EXPRESSION, MESSAGE) assert(EXPRESSION && MESSAGE);

#define KDU_UNREFERENCED_PARAMETER(VALUE) ((VOID)VALUE)

#define KDU_MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define KDU_MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

#define KDU_ARRAY_COUNT(X) (sizeof(X) / sizeof(X[0]))

#define KDU_PAGE_SIZE 0x1000ULL

#define KDU_ALIGN_DOWN_BY(VALUE, ALIGNMENT) (((DWORD64)VALUE) & ~(((DWORD64)ALIGNMENT) - 1))
#define KDU_ALIGN_UP_BY(VALUE, ALIGNMENT) ((((DWORD64)VALUE) + (((DWORD64)ALIGNMENT) - 1)) & ~(((DWORD64)ALIGNMENT) - 1))

#define KDU_ALIGN_PAGE_DOWN(VALUE) (((DWORD64)VALUE) & ~((KDU_PAGE_SIZE) - 1))
#define KDU_ALIGN_PAGE_UP(VALUE) ((((DWORD64)VALUE) + ((KDU_PAGE_SIZE) - 1)) & ~((KDU_PAGE_SIZE) - 1))

#define KDU_L2B_ENDIAN_16(VALUE) \
	((((VALUE) & 0xFF) << 8) | \
	 (((VALUE) & 0xFF00) >> 8))

#define KDU_B2L_ENDIAN_16(x) \
	((((VALUE) & 0xFF) << 8) | \
	 (((VALUE) & 0xFF00) >> 8))

#define KDU_L2B_ENDIAN_32(VALUE) \
	((((VALUE) & 0xFFUL) << 24) | \
	 (((VALUE) & 0xFF00UL) << 8) | \
	 (((VALUE) & 0xFF0000UL) >> 8) | \
	 (((VALUE) & 0xFF000000UL) >> 24))

#define KDU_B2L_ENDIAN_32(VALUE) \
	((((VALUE) & 0xFFUL) << 24) | \
	 (((VALUE) & 0xFF00UL) << 8) | \
	 (((VALUE) & 0xFF0000UL) >> 8) | \
	 (((VALUE) & 0xFF000000UL) >> 24))

#define KDU_L2B_ENDIAN_64(VALUE) \
	((((VALUE) & 0xFFULL) << 56) | \
	 (((VALUE) & 0xFF00ULL) << 40) | \
	 (((VALUE) & 0xFF0000ULL) << 24) | \
	 (((VALUE) & 0xFF000000ULL) << 8) | \
	 (((VALUE) & 0xFF00000000ULL) >> 8) | \
	 (((VALUE) & 0xFF0000000000ULL) >> 24) | \
	 (((VALUE) & 0xFF000000000000ULL) >> 40) | \
	 (((VALUE) & 0xFF00000000000000ULL) >> 56))

#define KDU_B2L_ENDIAN_64(VALUE) \
	((((VALUE) & 0xFFULL) << 56) | \
	 (((VALUE) & 0xFF00ULL) << 40) | \
	 (((VALUE) & 0xFF0000ULL) << 24) | \
	 (((VALUE) & 0xFF000000ULL) << 8) | \
	 (((VALUE) & 0xFF00000000ULL) >> 8) | \
	 (((VALUE) & 0xFF0000000000ULL) >> 24) | \
	 (((VALUE) & 0xFF000000000000ULL) >> 40) | \
	 (((VALUE) & 0xFF00000000000000ULL) >> 56))

#endif