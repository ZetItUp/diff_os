#include "stdarg.h"
#include "stdio.h"
#include "string.h"

extern void putch(char c);

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

    while(*fmt)
    {
        if(*fmt == '%')
        {
            fmt++;

            switch(*fmt)
            {
                case 'd':
                    {
                        int val = va_arg(args, int);
                        itoa(val, buffer, 10);

                        for(char *s = buffer; *s; s++)
                        {
                            putch(*s);
                        }
                    }
                    break;
                case 'x':
                    {
                        int val = va_arg(args, int);
                        itoa(val, buffer, 16);

                        for(char *s = buffer; *s; s++)
                        {
                            putch(*s);
                        }
                    }
                    break;
                case 's':
                    {
                        char *s = va_arg(args, char*);

                        while(*s)
                        {
                            putch(*s++);
                        }
                    }
                    break;
                case 'u':
                    {
                        unsigned int val = va_arg(args, unsigned int);
                        itoa(val, buffer, 10); // använd bas 10

                        for (char *s = buffer; *s; s++)
                        {
                            putch(*s);
                        }
                    }
                    break;
                case 'c':
                    {
                        char c = (char)va_arg(args, int);

                        putch(c);
                    }
                    break;
                case '%':
                    {
                        putch('%');
                    }
                    break;
                default:
                    {
                        putch('%');
                        putch(*fmt);
                    }
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

