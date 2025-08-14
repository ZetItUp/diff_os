#include "system/usercopy.h"
#include "paging.h"
#include "string.h"
#include "stdint.h"
#include "stddef.h"

int copy_from_user(void *kdst, const void *usrc, size_t n)
{
    if (!kdst || !usrc)
    {
        return -1;
    }

    if (n == 0)
    {
        return 0;
    }

    if (paging_check_user_range((uint32_t)(uintptr_t)usrc, n) != 0)
    {
        return -1;
    }

    memcpy(kdst, usrc, n);

    return 0;
}

int copy_to_user(void *udst, const void *ksrc, size_t n)
{
    if (!udst || !ksrc)
    {
        return -1;
    }

    if (n == 0)
    {
        return 0;
    }

    if (paging_check_user_range((uint32_t)(uintptr_t)udst, n) != 0)
    {
        return -1;
    }

    memcpy(udst, ksrc, n);

    return 0;
}

int copy_string_from_user(char *kdst, const char *usrc, size_t kdst_sz)
{
    if (!kdst || !usrc || kdst_sz == 0)
    {
        return -1;
    }

    size_t i = 0;

    while (i + 1 < kdst_sz)
    {
        if (paging_check_user_range((uint32_t)(uintptr_t)(usrc + i), 1) != 0)
        {
            return -1;
        }

        char c = usrc[i];
        kdst[i++] = c;

        if (c == '\0')
        {
            return 0;
        }
    }

    kdst[kdst_sz - 1] = '\0';

    return 0;
}

