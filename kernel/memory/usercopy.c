#include <stdint.h>
#include <stddef.h>
#include "system/usercopy.h"
#include "heap.h"
#include "string.h"
#include "paging.h"

static inline int is_user_ptr_range(const void *p, size_t n)
{
    if (n == 0) return 0;

    uintptr_t a = (uintptr_t)p;
    uintptr_t b = a + (n - 1);

    return (a >= USER_MIN) && (b < USER_MAX) && (b >= a);
}

static inline size_t page_chunk(uintptr_t addr, size_t remaining)
{
    size_t off = addr & (PAGE_SIZE_4KB - 1);
    size_t left_in_page = PAGE_SIZE_4KB - off;

    return (remaining < left_in_page) ? remaining : left_in_page;
}

// Demand-map or upgrade flags to be readable (present + USER)
static int ensure_user_readable(uintptr_t uaddr)
{
    uint32_t page_base = (uint32_t)uaddr & ~(PAGE_SIZE_4KB - 1);

    paging_update_flags(page_base, PAGE_SIZE_4KB, PAGE_USER, 0);

    if (paging_check_user_range(page_base, 1) == 0)
    {
        return 0;
    }

    if (paging_handle_demand_fault(page_base) == 0)
    {
        return (paging_check_user_range(page_base, 1) == 0) ? 0 : -1;
    }

    // Last fallback: try to map fresh page
    if (paging_map_user_range(page_base, PAGE_SIZE_4KB, 0) == 0)
    {
        return 0;
    }

    return -1;
}

// Demand-map or upgrade flags to be writable (present + USER + RW)
static int ensure_user_writable(uintptr_t uaddr)
{
    uint32_t page_base = (uint32_t)uaddr & ~(PAGE_SIZE_4KB - 1);

    paging_update_flags(page_base, PAGE_SIZE_4KB, PAGE_USER | PAGE_RW, 0);

    if (paging_check_user_range_writable(page_base, 1) == 0)
    {
        return 0;
    }

    if (paging_handle_demand_fault(page_base) == 0)
    {
        return (paging_check_user_range_writable(page_base, 1) == 0) ? 0 : -1;
    }

    // Last fallback: try to map fresh writable page
    if (paging_map_user_range(page_base, PAGE_SIZE_4KB, 1) == 0)
    {
        return 0;
    }

    return -1;
}

// String helpers

size_t strnlen_user(const char *uptr, size_t max)
{
    if (!uptr || max == 0) return 0;

    size_t n = 0;
    uintptr_t cur = (uintptr_t)uptr;

    if (!is_user_ptr_range(uptr, 1))
    {
        while (n < max && ((const char*)cur)[0] != '\0')
        {
            cur++;
            n++;
        }
        return n;
    }

    while (n < max)
    {
        if (ensure_user_readable(cur) != 0)
        {
            break;
        }

        size_t chunk = page_chunk(cur, max - n);
        const char *p = (const char*)cur;

        for (size_t i = 0; i < chunk; i++)
        {
            if (p[i] == '\0') return n + i;
        }

        cur += chunk;
        n += chunk;
    }

    return n;
}

// Core copy helpers

int copy_from_user(void *dst, const void *usrc, size_t n)
{
    if (n == 0) return 0;
    if (!dst || !usrc) return -1;

    if (!is_user_ptr_range(usrc, n))
    {
        memmove(dst, usrc, n);
        return 0;
    }

    uintptr_t s = (uintptr_t)usrc;
    uintptr_t d = (uintptr_t)dst;
    size_t remaining = n;

    while (remaining)
    {
        if (ensure_user_readable(s) != 0)
        {
            return -1;
        }

        size_t chunk = page_chunk(s, remaining);
        memmove((void*)d, (const void*)s, chunk);

        d += chunk;
        s += chunk;
        remaining -= chunk;
    }

    return 0;
}

int copy_to_user(void *udst, const void *src, size_t n)
{
    if (n == 0) return 0;
    if (!udst || !src) return -1;

    if (!is_user_ptr_range(udst, n))
    {
        memmove(udst, src, n);
        return 0;
    }

    uintptr_t d = (uintptr_t)udst;
    uintptr_t s = (uintptr_t)src;
    size_t remaining = n;

    while (remaining)
    {
        if (ensure_user_writable(d) != 0)
        {
            return -1;
        }

        size_t chunk = page_chunk(d, remaining);
        memmove((void*)d, (const void*)s, chunk);

        d += chunk;
        s += chunk;
        remaining -= chunk;
    }

    return 0;
}

// Higher-level helpers

int copy_string_from_user(char *dst, const char *usrc, size_t dst_size)
{
    if (!dst || !usrc || dst_size == 0) return -1;

    size_t len = strnlen_user(usrc, dst_size - 1);

    if (copy_from_user(dst, usrc, len) < 0) return -1;
    dst[len] = '\0';

    return (int)len;
}

int copy_user_cstr(char **out_kstr, const char *upath, size_t max_len)
{
    if (!out_kstr || !upath || max_len == 0) return -1;
    *out_kstr = NULL;

    size_t n = strnlen_user(upath, max_len - 1);
    char *buf = (char*)kmalloc(n + 1);
    if (!buf) return -1;

    if (copy_from_user(buf, upath, n) != 0)
    {
        kfree(buf);
        return -1;
    }

    buf[n] = '\0';
    *out_kstr = buf;

    return 0;
}

int copy_user_argv(int argc, char **uargv, char ***out_kargv)
{
    if (!out_kargv) return -1;
    *out_kargv = NULL;

    if (argc <= 0 || !uargv)
    {
        char **empty = (char**)kmalloc(sizeof(char*));
        if (!empty) return -1;

        empty[0] = NULL;
        *out_kargv = empty;
        return 0;
    }

    const int MAX_ARGC = 64;
    if (argc > MAX_ARGC) return -1;

    size_t vec_bytes = (size_t)argc * sizeof(char*);
    char **tmp_ptrs = (char**)kmalloc(vec_bytes);
    if (!tmp_ptrs) return -1;

    if (copy_from_user(tmp_ptrs, uargv, vec_bytes) != 0)
    {
        kfree(tmp_ptrs);
        return -1;
    }

    char **kargv = (char**)kmalloc(((size_t)argc + 1) * sizeof(char*));
    if (!kargv)
    {
        kfree(tmp_ptrs);
        return -1;
    }

    for (int i = 0; i < argc; i++)
    {
        char *kstr = NULL;
        if (tmp_ptrs[i])
        {
            if (copy_user_cstr(&kstr, tmp_ptrs[i], 4096) != 0)
            {
                for (int j = 0; j < i; j++)
                {
                    if (kargv[j]) kfree(kargv[j]);
                }
                kfree(kargv);
                kfree(tmp_ptrs);
                return -1;
            }
        }
        else
        {
            kstr = (char*)kmalloc(1);
            if (!kstr)
            {
                for (int j = 0; j < i; j++)
                {
                    if (kargv[j]) kfree(kargv[j]);
                }
                kfree(kargv);
                kfree(tmp_ptrs);
                return -1;
            }
            kstr[0] = '\0';
        }
        kargv[i] = kstr;
    }

    kargv[argc] = NULL;
    kfree(tmp_ptrs);
    *out_kargv = kargv;
    return 0;
}

void free_kargv(char **kargv)
{
    if (!kargv) return;

    for (size_t i = 0; kargv[i] != NULL; i++)
    {
        kfree(kargv[i]);
    }

    kfree(kargv);
}

