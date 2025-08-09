#include "stdarg.h"
#include "stddef.h"
#include "stdint.h"
#include "stdio.h"
#include "syscall.h"
#include "diffc_internal.h"

int vsnprintf(char *dst, size_t size, const char *fmt, va_list ap)
{
    char *out = dst;
    size_t rem = size;

    for (const char *f = fmt; *f; f++)
    {
        if (*f != '%')
        {
            buf_putc(&out, &rem, *f);
    
            continue;
        }

        f++; 

        switch (*f)
        {
            case 's':
                buf_puts(&out, &rem, va_arg(ap, const char*));
                break;
            case 'c':
                buf_putc(&out, &rem, (char)va_arg(ap, int));
                break;
            case 'd':
                buf_putd(&out, &rem, va_arg(ap, int));
                break;
            case 'u':
                buf_putu(&out, &rem, va_arg(ap, unsigned), 10, 0);
                break;
            case 'x':
                buf_putu(&out, &rem, va_arg(ap, unsigned), 16, 0);
                break;
            case 'X':
                buf_putu(&out, &rem, va_arg(ap, unsigned), 16, 1);
                break;
            case '%':
                buf_putc(&out, &rem, '%');
                break;
            default:
                buf_putc(&out, &rem, '%');
                buf_putc(&out, &rem, *f);
                break;
        }
    }

    if (rem > 0) 
    { 
        *out = '\0'; 
    }
    else if (size > 0) 
    { 
        dst[size - 1] = '\0'; 
    }

    return (int)(out - dst);
}

int snprintf(char *dst, size_t size, const char *fmt, ...)
{
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(dst, size, fmt, ap);
    va_end(ap);
    
    return n;
}

int putchar(int ch)
{
    system_putchar((unsigned char)ch);
    
    return ch & 0xFF;
}

void print(const char *s)
{
    system_print(s);
}

int puts(const char *s)
{
    if (!s) 
    { 
        s = "(null)"; 
    }

    system_print(s);
    system_putchar('\n');

    return 0;
}

int vprintf(const char *fmt, va_list ap)
{
    char buf[1024];
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);

    system_print(buf);

    return n;
}

int printf(const char *fmt, ...)
{
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);

    system_print(buf);

    return n;
}

