#include <string.h>

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

void *memcpy(void *dest, const void *src, unsigned int n)
{
    unsigned char *d = (unsigned char*)dest;
    const unsigned char *s = (const unsigned char*)src;

    while (n--)
    {
        *d++ = *s++;
    }

    return dest;
}
