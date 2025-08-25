#include <stdint.h>
#include <stddef.h>
#include "system/usercopy.h"
#include "heap.h"
#include "string.h" 

// Compute length of user string up to max characters
size_t strnlen_user(const char *uptr, size_t max)
{
    if (!uptr || max == 0)
    {
        return 0;
    }

    size_t n = 0; // Length counter

    while (n < max && uptr[n] != '\0')
    {
        n++;
    }

    return n;
}

// Copy bytes from user to kernel
int copy_from_user(void *dst, const void *usrc, size_t n)
{
    if (n == 0)
    {
        return 0;
    }

    if (!dst || !usrc)
    {
        return -1;
    }

    // Safe for overlaps
    memmove(dst, usrc, n);

    return 0;
}

// Copy bytes from kernel to user
int copy_to_user(void *udst, const void *src, size_t n)
{
    if (n == 0)
    {
        return 0;
    }

    if (!udst || !src)
    {
        return -1;
    }

    memmove(udst, src, n);

    return 0;
}

// Copy NUL-terminated user string into provided kernel buffer
int copy_string_from_user(char *dst, const char *usrc, size_t dst_size)
{
    if (!dst || !usrc || dst_size == 0)
    {
        return -1;
    }

    size_t len = strnlen_user(usrc, dst_size - 1);

    if (copy_from_user(dst, usrc, len) < 0)
    {
        return -1;
    }

    dst[len] = '\0';

    return (int)len;
}

// Copy a user string into a allocated kernel buffer
int copy_user_cstr(char **out_kstr, const char *upath, size_t max_len)
{
    if (!out_kstr)
    {
        return -1;
    }

    *out_kstr = NULL;

    if (!upath)
    {
        return -1;
    }

    if (max_len == 0)
    {
        return -1;
    }

    // Compute up to max_len - 1 to keep room for NUL
    size_t n = strnlen_user(upath, max_len - 1);
    char *buf = (char*)kmalloc(n + 1);

    if (!buf)
    {
        return -1;
    }

    if (copy_from_user(buf, upath, n) != 0)
    {
        kfree(buf);

        return -1;
    }

    buf[n] = '\0';
    *out_kstr = buf;

    return 0;
}

// Copy argv array from user to kernel
int copy_user_argv(int argc, char **uargv, char ***out_kargv)
{
    if (!out_kargv)
    {
        return -1;
    }

    *out_kargv = NULL;

    if (argc <= 0 || !uargv)
    {
        // Return a valid empty vector
        char **empty = (char**)kmalloc(sizeof(char*));

        if (!empty)
        {
            return -1;
        }

        empty[0] = NULL;
        *out_kargv = empty;

        return 0;
    }

    const int MAX_ARGC = 64;

    if (argc > MAX_ARGC)
    {
        return -1;
    }

    // Copy user pointer array first
    char **tmp_ptrs = (char**)kmalloc((size_t)argc * sizeof(char*));

    if (!tmp_ptrs)
    {
        return -1;
    }

    if (copy_from_user(tmp_ptrs, uargv, (size_t)argc * sizeof(char*)) != 0)
    {
        kfree(tmp_ptrs);

        return -1;
    }

    // Allocate kernel argv
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
            // Limit to 4 KiB per argument
            if (copy_user_cstr(&kstr, tmp_ptrs[i], 4096) != 0)
            {
                for (int j = 0; j < i; j++)
                {
                    if (kargv[j])
                    {
                        kfree(kargv[j]);
                    }
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
                    if (kargv[j])
                    {
                        kfree(kargv[j]);
                    }
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

// Free argv allocated by copy_user_argv
void free_kargv(char **kargv)
{
    if (!kargv)
    {
        return;
    }

    for (size_t i = 0; kargv[i] != NULL; i++)
    {
        kfree(kargv[i]);
    }

    kfree(kargv);

    return;
}

