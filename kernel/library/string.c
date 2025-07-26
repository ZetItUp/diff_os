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

void itoa(uint32_t value, char* str) 
{
    char temp[12];
    int i = 0;

    if (value == 0) 
    {
        str[0] = '0';
        str[1] = '\0';

        return;
    }

    while (value > 0) 
    {
        temp[i++] = '0' + (value % 10);
        value /= 10;
    }

    for (int j = 0; j < i; j++) 
    {
        str[j] = temp[i - j - 1];
    }

    str[i] = '\0';
}

