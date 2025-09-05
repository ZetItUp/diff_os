// DiffC/include/strings.h
#pragma once

#include <stddef.h>
#include <string.h>
#include <ctype.h>

#ifdef __cplusplus
extern "C" {
#endif

// Legacy BSD aliases mapped to standard C.

static inline void bzero(void *s, size_t n)
{
    memset(s, 0, n);
}

static inline void bcopy(const void *src, void *dst, size_t n)
{
    // Note: bcopy has reversed arg order vs memcpy/memmove.
    memmove(dst, src, n);
}

static inline int bcmp(const void *s1, const void *s2, size_t n)
{
    return memcmp(s1, s2, n);
}

static inline char *index(const char *s, int c)
{
    return (char *)strchr(s, c);
}

static inline char *rindex(const char *s, int c)
{
    return (char *)strrchr(s, c);
}

// Optional: POSIX ffs (find first set). Some code uses this via <strings.h>.
static inline int ffs(int i)
{
    if (i == 0)
    {
        return 0;
    }

    unsigned int u = (unsigned int)i;
    int pos = 1;

    while ((u & 1u) == 0u)
    {
        u >>= 1;
        pos++;
    }

    return pos;
}

#ifdef __cplusplus
}
#endif

