#include "system/threads.h"
#include "system/scheduler.h"
#include "system/process.h"
#include "interfaces.h"
#include "stdio.h"
#include "paging.h"
#include "heap.h"
#include "string.h"

extern void thread_entry_thunk(void);

static int g_next_tid = 1;

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

static void init_thread_context(thread_t* t, void (*entry)(void*), void* argument)
{
    uint32_t esp = t->kernel_stack_top;

    /* Align stack for good measure */
    esp &= ~0xFu;

    /*
        We expect context_switch() to set ESP to t->context.esp and RET.
        RET must jump to thread_entry_thunk, and on entry the stack must be:
            [esp+0] = entry function (void (*)(void*))
            [esp+4] = argument pointer (void*)
        Therefore we prebuild:
            [esp+0] = &thread_entry_thunk       (RET target)
            [esp+4] = entry
            [esp+8] = argument
        After RET pops the thunk address, the thunk sees [esp]=entry, [esp+4]=arg.
    */
    esp -= 12;
    *(uint32_t*)(esp + 0) = (uint32_t)(void*)&thread_entry_thunk;
    *(uint32_t*)(esp + 4) = (uint32_t)(void*)entry;
    *(uint32_t*)(esp + 8) = (uint32_t)(void*)argument;

    /* Callee-saved registers (defensive init) */
    t->context.edi = 0;
    t->context.esi = 0;
    t->context.ebx = 0;
    t->context.ebp = 0;

    /* Debug-only: eip mirrors the thunk; real control flow is via RET */
    t->context.eip = (uint32_t)(void*)&thread_entry_thunk;
    t->context.esp = esp;
}

int thread_create(void (*entry)(void*), void* argument, size_t kernel_stack_bytes)
{
    return thread_create_for_process(process_current(), entry, argument, kernel_stack_bytes);
}

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

    void* stack = kstack_alloc(kernel_stack_bytes);
    if (!stack)
    {
        kfree(t);

        return -3;
    }

    t->kernel_stack_base = (uint32_t)(uintptr_t)stack;
    t->kernel_stack_top = t->kernel_stack_base + (uint32_t)kernel_stack_bytes;

    init_thread_context(t, entry, argument);

    if (owner)
    {
        owner->live_threads++;
    }

    t->state = THREAD_RUNNABLE;

    scheduler_add_thread(t);

    return t->thread_id;
}

