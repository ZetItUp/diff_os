#pragma once

#include <stddef.h>
#include <stdint.h>

#define FILE_CAN_READ       (1 << 0)
#define FILE_CAN_WRITE      (1 << 1)

typedef struct FILE
{
    int file_descriptor;        // 0, 1, 2  or value from system_open
    int flags;                  // Read/Write, Text/Binary, etc
    int error;                  // Error number
    int eof;                    // End of File
    int ungot;                  // ungetc buffer
    // TODO: Add buffers
} FILE;

#ifndef O_RDONLY
#define O_RDONLY        0x0000
#define O_WRONLY        0x0001
#define O_RDWR          0x0002
#define O_CREAT         0x0100
#define O_TRUNC         0x0200
#define O_APPEND        0x0400
#endif

#ifndef SEEK_SET
#define SEEK_SET        0
#define SEEK_CUR        1
#define SEEK_END        2
#endif

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

