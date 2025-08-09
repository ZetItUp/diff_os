#pragma once

#include <stddef.h>

static inline void buf_putc(char **p, size_t *rem, char c)
{
    if (*rem > 1)
    {
        **p = c;
        (*p)++;
        (*rem)--;
    }
}

static inline void buf_puts(char **p, size_t *rem, const char *s)
{
    if (!s) { s = "(null)"; }
    while (*s)
    {
        buf_putc(p, rem, *s++);
    }
}

static inline void buf_putu(char **p, size_t *rem, unsigned v, int base, int upper)
{
    char tmp[32];
    const char *d = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0;

    if (v == 0)
    {
        tmp[i++] = '0';
    }
    else
    {
        while (v && i < (int)sizeof(tmp))
        {
            tmp[i++] = d[v % base];
            v /= base;
        }
    }
    while (i)
    {
        buf_putc(p, rem, tmp[--i]);
    }
}

static inline void buf_putd(char **p, size_t *rem, int v)
{
    if (v < 0)
    {
        buf_putc(p, rem, '-');
        buf_putu(p, rem, (unsigned)(-v), 10, 0);
    }
    else
    {
        buf_putu(p, rem, (unsigned)v, 10, 0);
    }
}

