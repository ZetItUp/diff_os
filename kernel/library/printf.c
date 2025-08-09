#include "stdarg.h"
#include "stdio.h"
#include "string.h"
#include "console.h"

extern void putch(char c);

static void append_char(char **buf, size_t *remaining, char c)
{
    if (*remaining > 1) // lämna plats för '\0'
    {
        **buf = c;
        (*buf)++;
        (*remaining)--;
    }
}

static void append_str(char **buf, size_t *remaining, const char *s)
{
    while (*s)
    {
        append_char(buf, remaining, *s++);
    }
}

static void append_uint(char **buf, size_t *remaining, unsigned int val, int base, int uppercase)
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
            tmp[i++] = digits[val % base];
            val /= base;
        }
    }

    // vänd ordningen
    while (i > 0)
    {
        append_char(buf, remaining, tmp[--i]);
    }
}

static void append_int(char **buf, size_t *remaining, int val, int base)
{
    if (val < 0)
    {
        append_char(buf, remaining, '-');
        append_uint(buf, remaining, (unsigned int)(-val), base, 0);
    }
    else
    {
        append_uint(buf, remaining, (unsigned int)val, base, 0);
    }
}

void printf(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
}

void vprintf(const char *fmt, va_list args)
{
    char buffer[32];

    while (*fmt)
    {
        if (*fmt == '%')
        {
            fmt++;

            // Hantera padding (t.ex. %02x, %08x)
            int pad = 0;
            if (*fmt == '0')
            {
                fmt++;
                if (*fmt >= '0' && *fmt <= '9')
                {
                    pad = *fmt - '0';
                    fmt++;
                    if (*fmt >= '0' && *fmt <= '9')
                    {
                        pad = pad * 10 + (*fmt - '0');
                        fmt++;
                    }
                }
            }

            switch (*fmt)
            {
                case 'd':
                {
                    int val = va_arg(args, int);
                    itoa(val, buffer, 10);
                    for (char *s = buffer; *s; s++) putch(*s);
                }
                break;

                case 'u':
                {
                    unsigned int val = va_arg(args, unsigned int);
                    utoa(val, buffer, 10);
                    for (char *s = buffer; *s; s++) putch(*s);
                }
                break;

                case 'z':
                    if (*(fmt + 1) == 'u') 
                    {
                        fmt++;
                        size_t val = va_arg(args, size_t);
                        itoa(val, buffer, 10);  
                        for (char *s = buffer; *s; s++) 
                        {
                            putch(*s);
                        }
                        
                        break;
                    }
                    
                    putch('%');
                    putch('z');
                    break;

                case 'x':
                {
                    unsigned int val = va_arg(args, unsigned int);
                    utoa(val, buffer, 16);

                    // Print with padding if specified
                    int len = strlen(buffer);
                    for (int i = len; i < pad; i++)
                        putch('0');
                    for (char *s = buffer; *s; s++) putch(*s);
                }
                break;

                case 'p':
                {
                    uintptr_t ptr = (uintptr_t)va_arg(args, void*);
                    putch('0'); putch('x');
                    char hexbuf[sizeof(uintptr_t)*2 + 1];
                    utohex(ptr, hexbuf, sizeof(hexbuf));
                    for (char *s = hexbuf; *s; s++) putch(*s);
                }
                break;

                case 's':
                {
                    char *s = va_arg(args, char*);
                    while (*s) putch(*s++);
                }
                break;

                case 'c':
                {
                    char c = (char)va_arg(args, int);
                    putch(c);
                }
                break;

                case '%':
                    putch('%');
                    break;

                default:
                    putch('%');
                    putch(*fmt);
                    break;
            }
        }
        else
        {
            putch(*fmt);
        }
        fmt++;
    }
    va_end(args);
}

int snprintf(char *str, size_t size, const char *format, ...)
{
    va_list args;
    va_start(args, format);

    char *buf_ptr = str;
    size_t remaining = size;

    for (const char *p = format; *p; p++)
    {
        if (*p != '%')
        {
            append_char(&buf_ptr, &remaining, *p);
            continue;
        }

        p++; // hoppa över '%'
        switch (*p)
        {
            case 's':
                append_str(&buf_ptr, &remaining, va_arg(args, const char *));
                break;
            case 'c':
                append_char(&buf_ptr, &remaining, (char)va_arg(args, int));
                break;
            case 'd':
                append_int(&buf_ptr, &remaining, va_arg(args, int), 10);
                break;
            case 'u':
                append_uint(&buf_ptr, &remaining, va_arg(args, unsigned int), 10, 0);
                break;
            case 'x':
                append_uint(&buf_ptr, &remaining, va_arg(args, unsigned int), 16, 0);
                break;
            case 'X':
                append_uint(&buf_ptr, &remaining, va_arg(args, unsigned int), 16, 1);
                break;
            case '%':
                append_char(&buf_ptr, &remaining, '%');
                break;
            default:
                append_char(&buf_ptr, &remaining, '%');
                append_char(&buf_ptr, &remaining, *p);
                break;
        }
    }

    if (remaining > 0)
    {
        *buf_ptr = '\0';
    }
    else if (size > 0)
    {
        str[size - 1] = '\0';
    }

    va_end(args);

    return (int)(buf_ptr - str); // antal tecken skrivna, ej inklusive null
}
