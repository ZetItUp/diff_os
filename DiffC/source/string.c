#include <string.h>
#include <stdlib.h>

int strcmp(const char *s1, const char *s2)
{
    while (*s1 && (*s1 == *s2))
    {
        s1++;
        s2++;
    }

    return *(const unsigned char*)s1 - *(const unsigned char*)s2;
}

char *strrchr(const char *s, int c)
{
    const char *p = s;   
    const char *last = 0;

    if (!s)
    {
        return 0;
    }

    if ((char)c == '\0')
    {
        while (*p)
        {
            p++;
        }

        return (char *)p;
    }

    while (*p)
    {
        if (*p == (char)c)
        {
            last = p;
        }

        p++;
    }

    return (char *)last;
}

char *strdup(const char *s)
{
    const char *src;       // Source pointer
    char *dst;             // Destination pointer
    unsigned int len = 0;  // Byte length

    if (!s)
    {
        return 0;
    }

    // Count length.
    src = s;
    while (*src++)
    {
        len++;
    }

    dst = (char *)malloc((size_t)len + 1u);

    if (!dst)
    {
        return 0;
    }

    // Copy including terminator.
    src = s;

    for (unsigned int i = 0; i <= len; i++)
    {
        dst[i] = src[i];
    }

    return dst;
}

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

    start += strspn(start, delim);
    if (*start == '\0')
    {
        *saveptr = start;
        return NULL;
    }

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

char *strstr(const char *haystack, const char *needle)
{
    char first = *needle;    
    const char *h = haystack; 

    if (first == '\0')
    {

        return (char *)haystack;
    }

    while (*h)
    {
        if (*h == first)
        {
            const char *h1 = h + 1;      
            const char *n1 = needle + 1; 

            while (*h1 && *n1 && *h1 == *n1)
            {
                h1++;
                n1++;
            }

            if (*n1 == '\0')
            {

                return (char *)h;
            }
        }

        h++;
    }


    return 0;
}

int strcasecmp(const char *s1, const char *s2)
{
    unsigned char c1; // First char
    unsigned char c2; // Second char

    // Defensive: treat NULL as empty
    if (!s1 || !s2)
    {
        return (s1 == s2) ? 0 : (s1 ? 1 : -1);
    }

    for (;;)
    {
        c1 = tolower((unsigned char)*s1++);
        c2 = tolower((unsigned char)*s2++);

        if (c1 != c2 || c1 == '\0')
        {

            return (int)c1 - (int)c2;
        }
    }
}

int strncasecmp(const char *s1, const char *s2, size_t n)
{
    unsigned char c1; // First char
    unsigned char c2; // Second char

    // Zero length means equal
    if (n == 0)
    {

        return 0;
    }

    // Defensive: treat NULL as empty
    if (!s1 || !s2)
    {

        return (s1 == s2) ? 0 : (s1 ? 1 : -1);
    }

    for (; n > 0; --n)
    {
        c1 = tolower((unsigned char)*s1++);
        c2 = tolower((unsigned char)*s2++);

        if (c1 != c2 || c1 == '\0')
        {

            return (int)c1 - (int)c2;
        }
    }

    return 0;
}
