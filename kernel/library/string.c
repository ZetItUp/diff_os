#include "string.h"
#include "stddef.h"

int strncmp(const char *s1, const char *s2, unsigned int n)
{
    for(unsigned int i = 0; i < n; i++)
    {
        if(s1[i] != s2[i])
        {
            return (unsigned char)s1[i] - (unsigned char)s2[i];
        }

        if(s1[i] == '\0')
        {
            return 0;
        }
    }

    return 0;
}

char *strncpy(char *dest, const char *src, unsigned int n)
{
    unsigned int i;

    for(i = 0; i < n && src[i] != '\0'; i++)
    {
        dest[i] = src[i];
    }

    for(; i < n; i++)
    {
        dest[i] = '\0';
    }

    return dest;
}

char *strtok(char *str, const char *delim)
{
    static char *last;

    if(str == NULL)
    {
        str = last;
    }

    if(str == NULL)
    {
        return NULL;
    }

    while(*str && strchr(delim, *str))
    {
        str++;
    }

    if(*str == '\0')
    {
        last = NULL;
        return NULL;
    }

    char *token_start = str;

    while(*str && !strchr(delim, *str))
    {
        str++;
    }

    if(*str)
    {
        *str = '\0';
        last = str + 1;
    }
    else
    {
        last = NULL;
    }

    return token_start;
}


char *strchr(const char *str, char c)
{
    while(*str)
    {
        if(*str == c)
        {
            return (char*)str;
        }

        str++;
    }

    return NULL;
}

void itoa(int value, char *str, int base)
{
    char *p = str;
    int is_negative = 0;

    if(value == 0)
    {
        *p++ = '0';
        *p = '\0';

        return;
    }

    if(value < 0 && base == 10)
    {
        is_negative = 1;
        value = -value;
    }

    while(value)
    {
        int digit = value % base;

        *p++ = (digit < 10) ? '0' + digit : 'a' + (digit - 10);
        value /= base;
    }

    if(is_negative)
    {
        *p++ = '-';
    }

    *p = '\0';

    for(char *start = str, *end = p - 1; start < end; start++, end--)
    {
        char tmp = *start;
        *start = *end;
        *end = tmp;
    }
}

