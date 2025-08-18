#pragma once

#include "drivers/ddf.h"
#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "io.h"
#include "pic.h"

void dump_exports_header(const kernel_exports_t *e);
int ptr_in_module(const ddf_module_t *m, const void *ptr);

ddf_module_t *load_driver(const char *path);
void *load_ddf_module(const char *path, ddf_header_t **out_header, uint32_t *out_header_offset, uint32_t *out_size);
void *ddf_find_symbol(void *module_base, ddf_header_t *header, const char *name);
