#pragma once

#include "stdint.h"
#include "stddef.h"

int copy_from_user(void *kernel_dst, const void *user_src, size_t n);
int copy_to_user(void *user_dst, const void *kernel_src, size_t n);
int copy_string_from_user(char *kernel_dst, const char *user_src, size_t kernel_dst_sz);

