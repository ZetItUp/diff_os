#pragma once

#include "stdbool.h"
#include "stdint.h"

bool cpu_has_sse(void);
void cpu_enable_sse(void);
void cpu_init(void);
