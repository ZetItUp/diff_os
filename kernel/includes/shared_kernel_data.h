#pragma once

#include <stdint.h>

// Shared page address in userspace, just below USER_MAX
#define SHARED_KERNEL_DATA_VA 0x7FFE0000u

// Data structure shared between kernel and all user processes
// Kernel writes to this page, userspace can only read
typedef struct shared_kernel_data
{
    volatile uint64_t time_ms;
    volatile uint32_t tick_count;
    volatile uint32_t timer_frequency;
} shared_kernel_data_t;

void shared_kernel_data_init(void);
void shared_kernel_data_update_time(uint64_t milliseconds, uint32_t ticks);
int shared_kernel_data_map_to_process(uint32_t cr3_phys);
