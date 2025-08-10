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

static inline void buf_putu(char **p, size_t *rem, unsigned v, unsigned base, int upper)
{
    static const char digs_lo[] = "0123456789abcdef";
    static const char digs_up[] = "0123456789ABCDEF";
    const char *digs = upper ? digs_up : digs_lo;

    if (base < 2 || base > 16)
    {
        base = 10;
    }

    char tmp[32];
    unsigned i = 0;

    if (v == 0) 
    {
        tmp[i++] = '0';
    } 
    else 
    {
        while (v) 
        {
            unsigned d = v % base;
        
            tmp[i++] = digs[d];
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

