#pragma once

#include "drivers/ddf.h"
#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "io.h"
#include "pic.h"

extern kernel_exports_t g_exports;

void load_driver(const char *path);
void *load_ddf_module(const char *path);
