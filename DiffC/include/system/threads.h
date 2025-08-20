#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int thread_yield(void);
int thread_sleep_ms(uint32_t milliseconds);
int thread_get_id(void);

#ifdef __cplusplus
}
#endif

