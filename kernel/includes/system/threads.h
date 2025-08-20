#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

// Types

typedef enum
{
    THREAD_NEW = 0,
    THREAD_RUNNABLE,
    THREAD_RUNNING,
    THREAD_SLEEPING,
    THREAD_ZOMBIE
} thread_state_t;

typedef struct cpu_context
{
    uint32_t edi;
    uint32_t esi;
    uint32_t ebx;
    uint32_t ebp;
    uint32_t eip;
    uint32_t esp;
} cpu_context_t;

typedef struct thread
{
    int thread_id;
    thread_state_t state;
    cpu_context_t context;
    uint32_t kernel_stack_base;
    uint32_t kernel_stack_top;
    struct thread* next;
    void* wait_object;
} thread_t;

// API

int thread_create(void (*entry)(void*), void* argument, size_t kernel_stack_bytes);
thread_t* current_thread(void);
void thread_exit(void) __attribute__((noreturn));
