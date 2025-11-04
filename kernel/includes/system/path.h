#pragma once

#include "stdint.h"
#include "stddef.h"

int path_normalize(const char *base, const char *input, char *out, size_t out_sz);
uint32_t vfs_root_id(void);
int vfs_resolve_entry(const char *abs_path, int *out_index);
int vfs_resolve_dir(const char *abs_path, uint32_t *out_dir_id);
