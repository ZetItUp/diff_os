#pragma once

#include <stdint.h>
#include <stddef.h>

typedef struct process_list_entry
{
    int pid;
    int state;
    int open_file_descriptor_count;
} process_list_entry_t;

int rt_process_list(process_list_entry_t *entries, int max_entries);
int rt_process_get_name(int pid, char *buffer, size_t buffer_len);
