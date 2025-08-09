#ifndef STDINT_H
#define STDINT_H

// 8-bit
typedef signed char        int8_t;
typedef unsigned char      uint8_t;

// 16-bit
typedef short             int16_t;
typedef unsigned short    uint16_t;

// 32-bit
typedef int               int32_t;
typedef unsigned int      uint32_t;

// 64-bit
typedef long long         int64_t;
typedef unsigned long long uint64_t;

// Pointer-sized (change for 64-bit kernel)
#if defined(__x86_64__) || defined(_M_X64)
typedef uint64_t          uintptr_t;
typedef int64_t           intptr_t;
#else
typedef uint32_t          uintptr_t;
typedef int32_t           intptr_t;
#endif

// Standard limits 
#define INT8_MIN   (-128)
#define INT8_MAX   (127)
#define UINT8_MAX  (255U)

#define INT16_MIN  (-32768)
#define INT16_MAX  (32767)
#define UINT16_MAX (65535U)

#define INT32_MIN  (-2147483647 - 1)
#define INT32_MAX  (2147483647)
#define UINT32_MAX (4294967295U)

#define INT64_MIN  (-9223372036854775807LL - 1)
#define INT64_MAX  (9223372036854775807LL)
#define UINT64_MAX (18446744073709551615ULL)

#endif

