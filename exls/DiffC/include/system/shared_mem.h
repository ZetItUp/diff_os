#pragma once

#include <stdint.h>
#include <syscall.h>

static inline int shared_memory_create(uint32_t size_bytes)
{
    return system_shared_memory_create(size_bytes);
}

static inline int shared_memory_grant(int handle, int pid)
{
    return system_shared_memory_grant(handle, pid);
}

static inline int shared_memory_map(int handle)
{
    return system_shared_memory_map(handle);
}

static inline int shared_memory_unmap(int handle)
{
    return system_shared_memory_unmap(handle);
}

static inline int shared_memory_release(int handle)
{
    return system_shared_memory_release(handle);
}

