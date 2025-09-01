#include "system/threads.h"
#include "system/scheduler.h"
#include "system/process.h"
#include "interfaces.h"
#include "stdio.h"
#include "paging.h"
#include "heap.h"
#include "string.h"
#include "stdint.h"
#include "stddef.h"

extern void thread_entry_thunk(void);

static int g_next_tid = 1; // Next thread id

// Allocate a cleared kernel stack with minimum one page
static void* kstack_alloc(size_t bytes)
{
    if (bytes < 4096)
    {
        bytes = 4096;
    }

    void* p = kmalloc(bytes);
    if (!p)
    {
        printf("[THREAD] kmalloc(%u) failed\n", (unsigned)bytes);
        return (void*)0;
    }

    memset(p, 0, bytes);
    return p;
}

// Prepare initial CPU context so the thread starts at entry(argument)
static void init_thread_context(thread_t* t, void (*entry)(void*), void* argument)
{
    uint32_t esp = t->kernel_stack_top;

    // Align stack to 16 bytes
    esp &= ~0xFu;

    // Stack layout for first switch and RET into thunk
    // [esp+0] return address -> thread_entry_thunk
    // [esp+4] entry
    // [esp+8] argument
    esp -= 12;
    *(uint32_t*)(esp + 0) = (uint32_t)(void*)&thread_entry_thunk;
    *(uint32_t*)(esp + 4) = (uint32_t)(void*)entry;
    *(uint32_t*)(esp + 8) = (uint32_t)(void*)argument;

    // Callee saved registers
    t->context.edi = 0;
    t->context.esi = 0;
    t->context.ebx = 0;
    t->context.ebp = 0;

    // Mirror thunk for debugging and set stack pointer
    t->context.eip = (uint32_t)(void*)&thread_entry_thunk;
    t->context.esp = esp;
}

// Create a thread in the current process
int thread_create(void (*entry)(void*), void* argument, size_t kernel_stack_bytes)
{
    return thread_create_for_process(process_current(), entry, argument, kernel_stack_bytes);
}

// Create a thread in a specific process
int thread_create_for_process(
    struct process* owner,
    void (*entry)(void*),
    void* argument,
    size_t kernel_stack_bytes
)
{
    if (!entry)
    {
        return -1;
    }

    thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));
    if (!t)
    {
        return -2;
    }

    memset(t, 0, sizeof(*t));

    t->thread_id = g_next_tid++;
    t->state = THREAD_NEW;
    t->owner_process = owner;

    // Allocate kernel stack
    void* stack = kstack_alloc(kernel_stack_bytes);
    if (!stack)
    {
        kfree(t);
        return -3;
    }

    t->kernel_stack_base = (uint32_t)(uintptr_t)stack;
    t->kernel_stack_top = t->kernel_stack_base + (uint32_t)kernel_stack_bytes;

    // Build initial context
    init_thread_context(t, entry, argument);

    // Increase live thread count for process
    if (owner)
    {
        owner->live_threads++;
    }

    // Make runnable and enqueue
    t->state = THREAD_READY;
    scheduler_add_thread(t);

    return t->thread_id;
}
// Reap a single zombie thread (free stack + object, dec process count)
void threads_reap_one(thread_t *t)
{
    if (!t)
    {
        return;
    }

    struct process *p = t->owner_process;

    printf("[THREAD] reaping tid=%d pid=%d\n", t->thread_id, p ? p->pid : -1);

    // Free kernel stack
    if (t->kernel_stack_base)
    {
        kfree((void *)(uintptr_t)t->kernel_stack_base);
        t->kernel_stack_base = 0;
        t->kernel_stack_top = 0;
    }

    // Free thread object
    kfree(t);
}

