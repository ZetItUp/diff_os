#include "stdarg.h"
#include "stdio.h"
#include "string.h"
#include "stdint.h"
#include "stddef.h"
#include "console.h"

/* Low-level output from your console */
extern void putch(char c);

/* ========= Internal helpers (counted output) ========= */

static inline void out_char(char c, int *count)
{
    putch(c);
    if (count)
    {
        (*count)++;
    }
}

static void out_cstr(const char *s, int *count)
{
    if (!s)
    {
        s = "(null)";
    }

    while (*s)
    {
        out_char(*s++, count);
    }
}

static void out_uint(unsigned int val, int base, int uppercase, int pad, int *count)
{
    char tmp[32];
    const char *digits = uppercase ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0;

    if (val == 0)
    {
        tmp[i++] = '0';
    }
    else
    {
        while (val > 0 && i < (int)sizeof(tmp))
        {
            tmp[i++] = digits[val % (unsigned)base];
            val /= (unsigned)base;
        }
    }

    /* zero padding */
    if (pad > i)
    {
        int need = pad - i;
        while (need-- > 0)
        {
            out_char('0', count);
        }
    }

    while (i > 0)
    {
        out_char(tmp[--i], count);
    }
}

static void out_int(int val, int base, int pad, int *count)
{
    if (val < 0)
    {
        out_char('-', count);
        out_uint((unsigned int)(-val), base, 0, pad, count);
    }
    else
    {
        out_uint((unsigned int)val, base, 0, pad, count);
    }
}

static void out_hex_ptr(uintptr_t p, int nibbles, int *count)
{
    /* Print as 0x + zero-padded hex of fixed nibble width */
    out_char('0', count);
    out_char('x', count);

    for (int i = (nibbles - 1); i >= 0; --i)
    {
        int shift = i * 4;
        int v = (int)((p >> shift) & 0xF);
        out_char("0123456789abcdef"[v], count);
    }
}

/* ========= Public API ========= */

int putchar(int c)
{
    putch((char)c);
    return (unsigned char)c;
}

int puts(const char *str)
{
    int n = 0;

    if (str)
    {
        while (*str)
        {
            out_char(*str++, &n);
        }
    }

    out_char('\n', &n);

    return n;
}

int vprintf(const char *fmt, va_list args)
{
    int written = 0;

    while (*fmt)
    {
        if (*fmt != '%')
        {
            out_char(*fmt++, &written);
            continue;
        }

        fmt++; /* skip '%' */

        /* Optional zero padding: %0NNx */
        int pad = 0;
        if (*fmt == '0')
        {
            fmt++;
            while (*fmt >= '0' && *fmt <= '9')
            {
                pad = pad * 10 + (*fmt - '0');
                fmt++;
            }
        }

        switch (*fmt)
        {
            case 'd':
            {
                int v = va_arg(args, int);
                out_int(v, 10, pad, &written);
            }
            break;

            case 'u':
            {
                unsigned int v = va_arg(args, unsigned int);
                out_uint(v, 10, 0, pad, &written);
            }
            break;

            case 'x':
            {
                unsigned int v = va_arg(args, unsigned int);
                out_uint(v, 16, 0, pad, &written);
            }
            break;

            case 'X':
            {
                unsigned int v = va_arg(args, unsigned int);
                out_uint(v, 16, 1, pad, &written);
            }
            break;

            case 'p':
            {
                uintptr_t p = (uintptr_t)va_arg(args, void *);
                out_hex_ptr(p, (int)(sizeof(uintptr_t) * 2), &written);
            }
            break;

            case 's':
            {
                const char *s = va_arg(args, const char *);
                out_cstr(s, &written);
            }
            break;

            case 'c':
            {
                char c = (char)va_arg(args, int);
                out_char(c, &written);
            }
            break;

            case 'z': /* handle %zu (size_t as unsigned) */
            {
                if (*(fmt + 1) == 'u')
                {
                    fmt++;
                    size_t v = va_arg(args, size_t);
                    out_uint((unsigned int)v, 10, 0, pad, &written);
                }
                else
                {
                    out_char('%', &written);
                    out_char('z', &written);
                }
            }
            break;

            case '%':
                out_char('%', &written);
                break;

            default:
                /* Unknown specifier: print literally */
                out_char('%', &written);
                out_char(*fmt, &written);
                break;
        }

        fmt++;
    }

    return written;
}

int printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int n = vprintf(fmt, args);
    va_end(args);
    return n;
}

/* ======= snprintf-family (buffered) ======= */

static void sbuf_putc(char **buf, size_t *rem, int *count, char c)
{
    if (*rem > 1)
    {
        **buf = c;
        (*buf)++;
        (*rem)--;
    }
    if (count)
    {
        (*count)++;
    }
}

static void sbuf_puts(char **buf, size_t *rem, int *count, const char *s)
{
    if (!s)
    {
        s = "(null)";
    }

    while (*s)
    {
        sbuf_putc(buf, rem, count, *s++);
    }
}

static void sbuf_uint(char **buf, size_t *rem, int *count, unsigned int v, int base, int upper, int pad)
{
    char tmp[32];
    const char *digits = upper ? "0123456789ABCDEF" : "0123456789abcdef";
    int i = 0;

    if (v == 0)
    {
        tmp[i++] = '0';
    }
    else
    {
        while (v > 0 && i < (int)sizeof(tmp))
        {
            tmp[i++] = digits[v % (unsigned)base];
            v /= (unsigned)base;
        }
    }

    if (pad > i)
    {
        int need = pad - i;
        while (need-- > 0)
        {
            sbuf_putc(buf, rem, count, '0');
        }
    }

    while (i > 0)
    {
        sbuf_putc(buf, rem, count, tmp[--i]);
    }
}

static void sbuf_int(char **buf, size_t *rem, int *count, int v, int base, int pad)
{
    if (v < 0)
    {
        sbuf_putc(buf, rem, count, '-');
        sbuf_uint(buf, rem, count, (unsigned int)(-v), base, 0, pad);
    }
    else
    {
        sbuf_uint(buf, rem, count, (unsigned int)v, base, 0, pad);
    }
}

int vsnprintf(char *str, size_t size, const char *fmt, va_list ap)
{
    char *bp = str;
    size_t rem = size;
    int written = 0;

    while (*fmt)
    {
        if (*fmt != '%')
        {
            sbuf_putc(&bp, &rem, &written, *fmt++);
            continue;
        }

        fmt++; /* skip '%' */

        int pad = 0;
        if (*fmt == '0')
        {
            fmt++;
            while (*fmt >= '0' && *fmt <= '9')
            {
                pad = pad * 10 + (*fmt - '0');
                fmt++;
            }
        }

        switch (*fmt)
        {
            case 'd':
                sbuf_int(&bp, &rem, &written, va_arg(ap, int), 10, pad);
                break;

            case 'u':
                sbuf_uint(&bp, &rem, &written, va_arg(ap, unsigned int), 10, 0, pad);
                break;

            case 'x':
                sbuf_uint(&bp, &rem, &written, va_arg(ap, unsigned int), 16, 0, pad);
                break;

            case 'X':
                sbuf_uint(&bp, &rem, &written, va_arg(ap, unsigned int), 16, 1, pad);
                break;

            case 'p':
            {
                uintptr_t p = (uintptr_t)va_arg(ap, void *);
                /* 0x + fixed width */
                sbuf_putc(&bp, &rem, &written, '0');
                sbuf_putc(&bp, &rem, &written, 'x');
                int nibbles = (int)(sizeof(uintptr_t) * 2);
                for (int i = nibbles - 1; i >= 0; --i)
                {
                    int v = (int)((p >> (i * 4)) & 0xF);
                    sbuf_putc(&bp, &rem, &written, "0123456789abcdef"[v]);
                }
            }
            break;

            case 's':
                sbuf_puts(&bp, &rem, &written, va_arg(ap, const char *));
                break;

            case 'c':
                sbuf_putc(&bp, &rem, &written, (char)va_arg(ap, int));
                break;

            case 'z': /* %zu */
                if (*(fmt + 1) == 'u')
                {
                    fmt++;
                    sbuf_uint(&bp, &rem, &written, (unsigned int)va_arg(ap, size_t), 10, 0, pad);
                }
                else
                {
                    sbuf_putc(&bp, &rem, &written, '%');
                    sbuf_putc(&bp, &rem, &written, 'z');
                }
                break;

            case '%':
                sbuf_putc(&bp, &rem, &written, '%');
                break;

            default:
                sbuf_putc(&bp, &rem, &written, '%');
                sbuf_putc(&bp, &rem, &written, *fmt);
                break;
        }

        fmt++;
    }

    if (rem > 0)
    {
        *bp = '\0';
    }
    else if (size > 0)
    {
        str[size - 1] = '\0';
    }

    return written;
}

int snprintf(char *str, size_t size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(str, size, fmt, ap);
    va_end(ap);
    return n;
}

int vsprintf(char *str, const char *fmt, va_list ap)
{
    return vsnprintf(str, (size_t)-1, fmt, ap);
}

int sprintf(char *str, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(str, (size_t)-1, fmt, ap);
    va_end(ap);
    return n;
}

