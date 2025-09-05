#pragma once
#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

// Returns the length of a NUL-terminated string in userspace, up to max.
// If no NUL is found within max, returns max.
size_t strnlen_user(const char *uptr, size_t max);
int zero_user(void *u_dst, size_t n);
// Copy a raw memory block from userspace to kernel.
int copy_from_user(void *dst, const void *usrc, size_t n);

// Copy a raw memory block from kernel to userspace.
int copy_to_user(void *udst, const void *src, size_t n);
int copy_string_from_user(char *dst, const char *usrc, size_t dst_size);

// Allocates a kernel buffer and copies a userspace C-string into it.
// Ensures NUL-termination. On success returns 0 and stores the buffer in *out_kstr.
// Caller must kfree(*out_kstr).
int copy_user_cstr(char **out_kstr, const char *upath, size_t max_len);

// Allocates a kernel argv array (NULL-terminated) and copies argc entries from
// a userspace argv (array of char*). On success returns 0 and stores the array
// in *out_kargv. Caller must kfree the array and each entry (use free_kargv helper).
int copy_user_argv(int argc, char **uargv, char ***out_kargv);

// Helper to free an argv allocated by copy_user_argv.
void free_kargv(char **kargv);

#ifdef __cplusplus
}
#endif
