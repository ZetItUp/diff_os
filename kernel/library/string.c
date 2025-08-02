#include "string.h"

size_t strspn(const char *s, const char *accept)
{
    size_t count = 0;
    for (; *s; s++)
    {
        const char *a = accept;
        int found = 0;
        while (*a)
        {
            if (*s == *a)
            {
                found = 1;
                break;
            }
            a++;
        }
        if (!found)
        {
            return count;
        }
        count++;
    }
    return count;
}

size_t strcspn(const char *s, const char *reject)
{
    size_t count = 0;
    for (; *s; s++)
    {
        const char *r = reject;
        while (*r)
        {
            if (*s == *r)
            {
                return count;
            }
            r++;
        }
        count++;
    }
    return count;
}

size_t strlen(const char *s)
{
    size_t len = 0;
    while (s[len])
    {
        len++;
    }
    return len;
}

char *strtok_r(char *str, const char *delim, char **saveptr)
{
    char *start;
    if (str)
    {
        start = str;
    }
    else
    {
        start = *saveptr;
    }

    // Skip leading delimiters
    start += strspn(start, delim);
    if (*start == '\0')
    {
        *saveptr = start;
        return NULL;
    }

    // Find end of token
    char *end = start + strcspn(start, delim);
    if (*end)
    {
        *end = '\0';
        *saveptr = end + 1;
    }
    else
    {
        *saveptr = end;
    }

    return start;
}

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

char *strcpy(char *dst, const char *src)
{
    char *ret = dst;
    
    while ((*dst++ = *src++))
    {
        ; // Kopiera tills nullbyte
    }
    
    return ret;
}

char *strcat(char *dst, const char *src)
{
    char *ret = dst;
    
    while (*dst)
    {
        dst++;
    }
    
    while ((*dst++ = *src++))
    {
        ;
    }
    
    return ret;
}


void *memset(void *dest, int value, size_t count)
{
    unsigned char *ptr = (unsigned char *)dest;
    unsigned char val = (unsigned char)value;

    for(size_t i = 0; i < count; i++)
    {
        ptr[i] = val;
    }

    return dest;
}


