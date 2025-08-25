#include <stdint.h>
#include <stddef.h>
#include "system/usercopy.h"

// Your kernel's malloc/free headers. Adjust if needed.
#include "heap.h"   // kmalloc, kfree
#include "string.h"  // memcpy, memmove

// ---- Implementation notes ----
// We avoid any static/global caches so repeated calls (like spawning multiple
// programs from a shell) are re-entrant and do not depend on previous state.
// We also always NUL-terminate copied C-strings.
//
// These helpers assume the kernel address space is mapped while handling
// syscalls/interrupts (typical design), so direct loads from user VA are valid
// as long as the calling process has those pages mapped. If your kernel requires
// fault-safe probing, you can replace the raw loads with your own safe accessors.

size_t strnlen_user(const char *uptr, size_t max)
{
    if (!uptr || max == 0) return 0;
    size_t n = 0;
    while (n < max && uptr[n] != '\0') {
        n++;
    }
    return n;
}

int copy_from_user(void *dst, const void *usrc, size_t n)
{
    if (n == 0) return 0;
    if (!dst || !usrc) return -1;
    // Use memmove to be safe with overlaps (rare for user->kernel but harmless).
    memmove(dst, usrc, n);
    return 0;
}

int copy_to_user(void *udst, const void *src, size_t n)
{
    if (n == 0) return 0;
    if (!udst || !src) return -1;
    memmove(udst, src, n);
    return 0;
}

// Copy a NUL-terminated string from userspace into a provided kernel buffer.
// Guarantees NUL-termination. Returns number of bytes copied (excluding NUL)
// on success, or -1 on failure (invalid args or no NUL within dst_size-1).
int copy_string_from_user(char *dst, const char *usrc, size_t dst_size)
{
    if (!dst || !usrc || dst_size == 0)
        return -1;

    // Leave room for the trailing NUL
    int len = strnlen_user(usrc, dst_size - 1);
    if (len < 0)
        return -1;

    if (copy_from_user(dst, usrc, (size_t)len) < 0)
        return -1;

    dst[len] = '\0';
    return len;
}


int copy_user_cstr(char **out_kstr, const char *upath, size_t max_len)
{
    if (!out_kstr) return -1;
    *out_kstr = NULL;
    if (!upath) return -1;

    if (max_len == 0) return -1;
    // Compute up to max_len-1 to guarantee space for NUL.
    size_t n = strnlen_user(upath, max_len - 1);
    char *buf = (char*)kmalloc(n + 1);
    if (!buf) return -1;

    if (copy_from_user(buf, upath, n) != 0) {
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

    if (argc <= 0 || !uargv) {
        // Accept empty argv: return a valid {NULL} array so callers can index safely.
        char **empty = (char**)kmalloc(sizeof(char*));
        if (!empty) return -1;
        empty[0] = NULL;
        *out_kargv = empty;
        return 0;
    }

    // Put a sane upper bound to avoid silly allocations.
    const int MAX_ARGC = 64;
    if (argc > MAX_ARGC) return -1;

    // First, copy the array of user pointers into kernel memory so we don't
    // chase user pointers while modifying kernel state.
    char **tmp_ptrs = (char**)kmalloc((size_t)argc * sizeof(char*));
    if (!tmp_ptrs) return -1;

    if (copy_from_user(tmp_ptrs, uargv, (size_t)argc * sizeof(char*)) != 0) {
        kfree(tmp_ptrs);
        return -1;
    }

    // Allocate kernel argv (argc + 1 for trailing NULL)
    char **kargv = (char**)kmalloc(((size_t)argc + 1) * sizeof(char*));
    if (!kargv) {
        kfree(tmp_ptrs);
        return -1;
    }

    for (int i = 0; i < argc; ++i) {
        char *kstr = NULL;
        if (tmp_ptrs[i]) {
            if (copy_user_cstr(&kstr, tmp_ptrs[i], 4096) != 0) { // 4K per arg limit
                // Roll back already-copied strings
                for (int j = 0; j < i; ++j) {
                    if (kargv[j]) kfree(kargv[j]);
                }
                kfree(kargv);
                kfree(tmp_ptrs);
                return -1;
            }
        } else {
            // NULL entry – represent it as empty string to match many libc argv conventions.
            kstr = (char*)kmalloc(1);
            if (!kstr) {
                for (int j = 0; j < i; ++j) {
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
    for (size_t i = 0; kargv[i] != NULL; ++i) {
        kfree(kargv[i]);
    }
    kfree(kargv);
}
