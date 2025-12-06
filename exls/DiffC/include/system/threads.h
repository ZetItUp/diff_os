#pragma once

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

int thread_yield(void);
int thread_sleep_ms(uint32_t milliseconds);
int thread_get_id(void);
int thread_create(void *entry, void *user_stack_top, size_t kernel_stack_bytes);
void thread_exit(void) __attribute__((noreturn));

#ifdef __cplusplus
}
#endif
