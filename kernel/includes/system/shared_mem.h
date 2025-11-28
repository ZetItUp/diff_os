#pragma once

#include "stdint.h"
#include "system/spinlock.h"
#include "system/threads.h"

#define SHARED_MEMORY_MAX_OBJECTS          64
#define SHARED_MEMORY_MAX_PAGES_PER_OBJECT 1024    // 4MB at 4KB pages
#define SHARED_MEMORY_MAX_ALLOWED_PIDS     16

typedef struct
{
    int used;
    int id;
    int owner_pid;

    uint32_t size_bytes;
    uint32_t page_count;
    uint32_t phys_pages[SHARED_MEMORY_MAX_PAGES_PER_OBJECT];

    int refcount;
    int allow_all;
    int allowed_pids[SHARED_MEMORY_MAX_ALLOWED_PIDS];

    struct
    {
        int active;
        int pid;
        uintptr_t va;
    } mappings[SHARED_MEMORY_MAX_ALLOWED_PIDS];
    int mapping_count;

    spinlock_t lock;
} shared_memory_object_t;

int shared_memory_create(uint32_t size_bytes);
int shared_memory_grant(int handle, int pid);
int shared_memory_map(int handle);
int shared_memory_unmap(int handle);
int shared_memory_release(int handle);
void shared_memory_cleanup_process(int pid);
int shared_memory_handle_fault(uintptr_t fault_va);
