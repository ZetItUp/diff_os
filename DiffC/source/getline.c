#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <stdio.h>
#include <syscall.h>

ssize_t getline(char **lineptr, size_t *n)
{
    if (lineptr == NULL || n == NULL)
    {
        return -1;
    }

    if (*lineptr == NULL || *n == 0)
    {
        *n = 64;
        *lineptr = (char *)malloc(*n);
        if (*lineptr == NULL)
        {
            return -1;
        }
    }

    size_t len = 0;

    for (;;)
    {
        uint8_t ch = system_getch();

        /* --- ENTER-hantering (acceptera CR, LF, och scancode 0x1C) --- */
        if (ch == '\r' || ch == '\n' || ch == 0x1C)
        {
            /* Om CRLF: svälj det andra tecknet */
            if (ch == '\r') {
                uint8_t next;
                if (system_trygetch(&next) && next == '\n') {
                    /* svälj LF efter CR */
                }
            }

            system_putchar('\n');
            (*lineptr)[len] = '\0';
            return (ssize_t)len;
        }

        /* Backspace/Delete */
        if (ch == 0x08 || ch == 0x7F)
        {
            if (len > 0)
            {
                len--;
                system_putchar('\b');
                system_putchar(' ');
                system_putchar('\b');
            }
            continue;
        }

        /* Tillåt tab, ignorera övriga kontrolltecken (<0x20) */
        if (ch < 0x20 && ch != '\t')
        {
            continue;
        }

        if (len + 1 >= *n)
        {
            size_t newcap = (*n < 64) ? 64 : (*n * 2);
            char *nb = (char *)realloc(*lineptr, newcap);
            if (nb == NULL)
            {
                (*lineptr)[len] = '\0';
                return (ssize_t)len;
            }
            *lineptr = nb;
            *n = newcap;
        }

        (*lineptr)[len++] = (char)ch;
        system_putchar(ch); /* eko */
    }
}

