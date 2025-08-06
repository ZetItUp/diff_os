#pragma once
#include "diff.h"

#define MAX_PATH_LEN    128

void remove_driver(uint32_t irq_num);
void load_drivers(const FileTable *table, const char *cfg_path);
