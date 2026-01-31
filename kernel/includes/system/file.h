#pragma once

#include "stdint.h"

#define KERNEL_FILE_DESCRIPTOR_BASE 3
#define KERNEL_FILE_DESCRIPTOR_MAX  32

typedef struct kernel_file_desc
{
    uint8_t used;
    int     filesystem_fd;
    int     flags;
} kernel_file_desc_t;

struct process;

void system_file_close_all_for_process(struct process *process);
