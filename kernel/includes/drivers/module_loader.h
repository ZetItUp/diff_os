#pragma once

#include "drivers/ddf.h"
#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "io.h"
#include "pic.h"

extern kernel_exports_t g_exports;

ddf_module_t *load_driver(const char *path);
void *load_ddf_module(const char *path, ddf_header_t **out_header, uint32_t *out_header_offset, uint32_t *out_size);
void *ddf_find_symbol(void *module_base, ddf_header_t *header, const char *name);
