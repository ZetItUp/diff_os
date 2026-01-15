#include <stddef.h>
#include <stdint.h>

/*
 * Safe-ish string/memory utilities for kernel / libc.
 * All code follows Allman brace style. All comments in English.
 *
 * Notes:
 * - memcpy does NOT support overlapping regions (per C standard). Use memmove.
 * - Prefer strlcpy/strlcat (with capacity) over strcpy/strcat.
 * - utoa_s/itoa_s write with explicit capacity to avoid overflows.
 * - utohex respects the provided output buffer length (including NUL).
 */

void *memset(void *dst, int c, size_t n)
{
    unsigned char *p = (unsigned char *)dst;
    unsigned char uc = (unsigned char)c;

    // Fast path: set in 32-bit chunks if aligned
    if (n >= 32 && ((uintptr_t)p & 3) == 0)
    {
        uint32_t val = (uint32_t)uc | ((uint32_t)uc << 8) | ((uint32_t)uc << 16) | ((uint32_t)uc << 24);
        uint32_t *p32 = (uint32_t *)p;
        size_t chunks = n / 4;

        for (size_t i = 0; i < chunks; i++)
        {
            p32[i] = val;
        }

        p += chunks * 4;
        n -= chunks * 4;
    }

    // Set remaining bytes
    for (size_t i = 0; i < n; i++)
    {
        p[i] = uc;
    }

    return dst;
}

void *memcpy(void *dst, const void *src, size_t n)
{
    /* Undefined if regions overlap. Use memmove if unsure. */
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    // Fast path: copy in 32-bit chunks if both src and dst are aligned
    if (n >= 32 && ((uintptr_t)d & 3) == 0 && ((uintptr_t)s & 3) == 0)
    {
        uint32_t *d32 = (uint32_t *)d;
        const uint32_t *s32 = (const uint32_t *)s;
        size_t chunks = n / 4;

        for (size_t i = 0; i < chunks; i++)
        {
            d32[i] = s32[i];
        }

        // Copy remaining bytes
        d += chunks * 4;
        s += chunks * 4;
        n -= chunks * 4;
    }

    // Copy remaining bytes
    for (size_t i = 0; i < n; i++)
    {
        d[i] = s[i];
    }

    return dst;
}

void *memmove(void *dst, const void *src, size_t n)
{
    unsigned char *d = (unsigned char *)dst;
    const unsigned char *s = (const unsigned char *)src;

    if (d == s || n == 0)
    {
        return dst;
    }

    if (d < s)
    {
        for (size_t i = 0; i < n; i++)
        {
            d[i] = s[i];
        }
    }
    else
    {
        for (size_t i = n; i > 0; i--)
        {
            d[i - 1] = s[i - 1];
        }
    }

    return dst;
}

int memcmp(const void *a, const void *b, size_t n)
{
    const unsigned char *x = (const unsigned char *)a;
    const unsigned char *y = (const unsigned char *)b;

    for (size_t i = 0; i < n; i++)
    {
        if (x[i] != y[i])
        {
            return (int)x[i] - (int)y[i];
        }
    }

    return 0;
}

size_t strlen(const char *s)
{
    size_t i = 0;

    while (s[i] != '\0')
    {
        i++;
    }

    return i;
}

int strcmp(const char *a, const char *b)
{
    while (*a && (*a == *b))
    {
        a++;
        b++;
    }

    return (unsigned char)*a - (unsigned char)*b;
}

int strncmp(const char *a, const char *b, size_t n)
{
    for (size_t i = 0; i < n; i++)
    {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];

        if (ca != cb || ca == '\0' || cb == '\0')
        {
            return (int)ca - (int)cb;
        }
    }

    return 0;
}

char *strchr(const char *s, int c)
{
    char ch = (char)c;

    while (*s != '\0')
    {
        if (*s == ch)
        {
            return (char *)s;
        }

        s++;
    }

    // Also match if searching for NUL terminator
    if (ch == '\0')
    {
        return (char *)s;
    }

    return NULL;
}

char *strrchr(const char *s, int c)
{
    char ch = (char)c;
    const char *last = NULL;

    while (*s != '\0')
    {
        if (*s == ch)
        {
            last = s;
        }

        s++;
    }

    // Also match if searching for NUL terminator
    if (ch == '\0')
    {
        return (char *)s;
    }

    return (char *)last;
}

/* Safer copy/concat with capacity. Prefer these over strcpy/strcat. */
size_t strlcpy(char *dst, const char *src, size_t size)
{
    size_t slen = strlen(src);

    if (size != 0)
    {
        size_t n = (slen >= size) ? (size - 1) : slen;
        if (n > 0)
        {
            memcpy(dst, src, n);
        }
        dst[(size == 0) ? 0 : n] = '\0';
    }

    return slen; /* Always returns length of src */
}

size_t strlcat(char *dst, const char *src, size_t size)
{
    size_t dlen = 0;

    while (dlen < size && dst[dlen] != '\0')
    {
        dlen++;
    }

    size_t slen = strlen(src);

    if (dlen == size)
    {
        return size + slen; /* No space to append */
    }

    size_t space = size - dlen - 1; /* space for new chars (reserve 1 for NUL) */
    size_t n = (slen > space) ? space : slen;

    if (n > 0)
    {
        memcpy(dst + dlen, src, n);
    }

    dst[dlen + n] = '\0';

    return dlen + slen; /* Length we tried to create */
}

/* Dangerous legacy APIs kept for compatibility. Prefer strlcpy/strlcat. */
char *strcpy(char *dst, const char *src)
{
    (void)strlcpy(dst, src, (size_t)-1); /* Best effort; caller must ensure room */
    return dst;
}

char *strncpy(char *dst, const char *src, size_t n)
{
    size_t i = 0;

    for (; i < n && src[i] != '\0'; i++)
    {
        dst[i] = src[i];
    }

    for (; i < n; i++)
    {
        dst[i] = '\0';
    }

    return dst;
}

char *strcat(char *dst, const char *src)
{
    (void)strlcat(dst, src, (size_t)-1); /* Best effort; caller must ensure room */
    return dst;
}

char *strncat(char *dst, const char *src, size_t n)
{
    /* Classic semantics: append up to n chars from src. Risky without capacity. */
    size_t dlen = strlen(dst);

    size_t i = 0;
    for (; i < n && src[i] != '\0'; i++)
    {
        dst[dlen + i] = src[i];
    }

    dst[dlen + i] = '\0';
    return dst;
}

/* Numeric conversions with explicit capacity. Return 0 on success, -1 on error. */
int utoa_s(unsigned int val, char *buf, size_t size, int base)
{
    if (size == 0 || base < 2 || base > 16)
    {
        return -1;
    }

    char tmp[32];
    int i = 0;

    if (val == 0)
    {
        tmp[i++] = '0';
    }
    else
    {
        while (val > 0 && i < (int)sizeof(tmp))
        {
            int d = (int)(val % (unsigned)base);
            tmp[i++] = (d < 10) ? (char)('0' + d) : (char)('a' + d - 10);
            val /= (unsigned)base;
        }
    }

    if ((size_t)(i + 1) > size)
    {
        return -1; /* Not enough room for digits + NUL */
    }

    for (int j = 0; j < i; j++)
    {
        buf[j] = tmp[i - 1 - j];
    }

    buf[i] = '\0';
    return 0;
}

int itoa_s(int value, char *str, size_t size, int base)
{
    if (size == 0 || base < 2 || base > 16)
    {
        return -1;
    }

    unsigned int u = (unsigned int)value;

    if (value < 0 && base == 10)
    {
        u = (unsigned int)(-value);

        if (size < 2)
        {
            return -1;
        }
        *str++ = '-';
        size--;
    }

    if (utoa_s(u, str, size, base) != 0)
    {
        return -1;
    }

    return 0;
}

/* Hex printer that respects output length (including NUL). */
void utohex(uintptr_t val, char *buf, int outlen)
{
    if (outlen <= 0)
    {
        return;
    }

    int max_digits = (int)(sizeof(uintptr_t) * 2); /* 8 on 32-bit, 16 on 64-bit */
    int digits = outlen - 1; /* leave space for NUL */

    if (digits > max_digits)
    {
        digits = max_digits;
    }

    if (digits < 1)
    {
        buf[0] = '\0';
        return;
    }

    for (int i = digits - 1; i >= 0; --i)
    {
        int shift = 4 * i;
        buf[digits - 1 - i] = "0123456789ABCDEF"[(val >> shift) & 0xF];
    }

    buf[digits] = '\0';
}

