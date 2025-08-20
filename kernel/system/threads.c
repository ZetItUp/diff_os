// All comments are written in English.
// Allman brace style is used consistently.

#include "system/scheduler.h"
#include "system/threads.h"
#include "heap.h"
#include "string.h"

// State

static int next_thread_id = 1;

extern void thread_entry_thunk(void);

// API

int thread_create(void (*entry)(void*), void* argument, size_t kernel_stack_bytes)
{
    if (kernel_stack_bytes < 4096) { kernel_stack_bytes = 4096; }

    thread_t* thread = (thread_t*)kmalloc(sizeof(thread_t));
    if (!thread) { return -1; }
    memset(thread, 0, sizeof(*thread));

    uint8_t* stack = (uint8_t*)kmalloc(kernel_stack_bytes + 4096);
    if (!stack)
    {
        kfree(thread);
        return -1;
    }

    memset(stack, 0, kernel_stack_bytes);

    thread->thread_id = next_thread_id++;
    thread->state = THREAD_RUNNABLE;

    thread->kernel_stack_base = (uint32_t)(uintptr_t)stack;
    thread->kernel_stack_top  = (uint32_t)(uintptr_t)stack + (uint32_t)kernel_stack_bytes;

    uint32_t* sp = (uint32_t*)(uintptr_t)thread->kernel_stack_top;
    sp = (uint32_t*)((uint32_t)(uintptr_t)sp & ~0xF);

    *(--sp) = (uint32_t)(uintptr_t)argument;                 // arg
    *(--sp) = (uint32_t)(uintptr_t)thread_entry_thunk;       // eip for ret
    *(--sp) = 0;                                             // ebp
    *(--sp) = (uint32_t)(uintptr_t)entry;                    // ebx (entry)
    *(--sp) = 0;                                             // esi
    *(--sp) = 0;                                             // edi

    thread->context.esp = (uint32_t)(uintptr_t)sp;
    thread->context.ebx = (uint32_t)(uintptr_t)entry;
    thread->context.esi = 0;
    thread->context.edi = 0;
    thread->context.ebp = 0;
    thread->context.eip = (uint32_t)(uintptr_t)thread_entry_thunk;

    scheduler_add_thread(thread);
    return thread->thread_id;
}

