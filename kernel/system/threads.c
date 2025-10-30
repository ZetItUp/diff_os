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

#ifdef DIFF_DEBUG
#  define TDBG(...) printf(__VA_ARGS__)
#else
#  define TDBG(...) do {} while (0)
#endif

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
#ifdef DIFF_DEBUG
    TDBG("[THREAD] kstack_alloc: %u bytes -> %p .. %p\n",
         (unsigned)bytes, p, (void*)((uintptr_t)p + bytes));
#endif
    return p;
}

// Prepare initial CPU context so the thread starts at entry(argument)
static void init_thread_context(thread_t* t, void (*entry)(void*), void* argument)
{
    uint32_t esp = t->kernel_stack_top;

    // Align to 16 bytes for FXSAVE/ABI sanity
    esp &= ~0xFu;

    // Stack on first entry to thunk:
    // [esp+0] = entry
    // [esp+4] = argument
    esp -= 8;
    *(uint32_t*)(esp + 0) = (uint32_t)(void*)entry;
    *(uint32_t*)(esp + 4) = (uint32_t)(void*)argument;

    // Callee-saved regs
    t->context.edi = 0;
    t->context.esi = 0;
    t->context.ebx = 0;
    t->context.ebp = 0;

    // Start at the thunk, with ESP pointing at [entry][arg]
    t->context.eip = (uint32_t)(void*)&thread_entry_thunk;
    t->context.esp = esp;

    TDBG("[THREAD] init ctx: tid=%d kstack_top=%08x aligned_esp=%08x\n",
         t->thread_id, t->kernel_stack_top, esp);
    TDBG("[THREAD] init ctx: entry=%08x arg=%08x\n",
         (uint32_t)(uintptr_t)entry, (uint32_t)(uintptr_t)argument);
    TDBG("[THREAD] init ctx: eip=%08x esp=%08x ebp=%08x\n",
         t->context.eip, t->context.esp, t->context.ebp);
}

// Create a thread in the current process
int thread_create(void (*entry)(void*), void* argument, size_t kernel_stack_bytes)
{
#ifdef DIFF_DEBUG
    TDBG("[THREAD] create (current proc pid=%d) entry=%p arg=%p kstack=%u\n",
         process_current() ? process_current()->pid : -1,
         (void*)entry, argument, (unsigned)kernel_stack_bytes);
#endif
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
#ifdef DIFF_DEBUG
        TDBG("[THREAD][ERR] thread_create_for_process: null entry\n");
#endif
        return -1;
    }

    thread_t* t = (thread_t*)kmalloc(sizeof(thread_t));
    if (!t)
    {
#ifdef DIFF_DEBUG
        TDBG("[THREAD][ERR] kmalloc(thread_t) failed\n");
#endif
        return -2;
    }

    memset(t, 0, sizeof(*t));

    t->thread_id = g_next_tid++;
    t->state = THREAD_NEW;
    t->owner_process = owner;

#ifdef DIFF_DEBUG
    TDBG("[THREAD] new: tid=%d owner pid=%d\n", t->thread_id, owner ? owner->pid : -1);
#endif

    {
        void *raw = kmalloc(512 + 16);
        
        if (!raw) 
        {
#ifdef DIFF_DEBUG
            TDBG("[THREAD][ERR] kmalloc(fx) failed\n");
#endif
            kfree(t);
            return -3;
        }
        
        uintptr_t p = ((uintptr_t)raw + 15u) & ~15u;

        t->fx_area_raw     = raw;
        t->fx_area_aligned = (void*)p;
        t->fx_valid        = false;

#ifdef DIFF_DEBUG
        TDBG("[THREAD] fx area raw=%p aligned=%p\n", raw, t->fx_area_aligned);
#endif
    }

    // Allocate kernel stack
    void* stack = kstack_alloc(kernel_stack_bytes);
    if (!stack)
    {
        kfree(t);
        return -3;
    }

    t->kernel_stack_base = (uint32_t)(uintptr_t)stack;
    t->kernel_stack_top = t->kernel_stack_base + (uint32_t)kernel_stack_bytes;

#ifdef DIFF_DEBUG
    TDBG("[THREAD] kstack: base=%08x top=%08x bytes=%u\n",
         t->kernel_stack_base, t->kernel_stack_top, (unsigned)kernel_stack_bytes);
#endif

    // Build initial context
    init_thread_context(t, entry, argument);

    // Increase live thread count for process
    if (owner)
    {
        owner->live_threads++;
#ifdef DIFF_DEBUG
        TDBG("[THREAD] owner pid=%d live_threads=%d\n", owner->pid, owner->live_threads);
#endif
    }

    // Make runnable and enqueue
    t->state = THREAD_READY;
    scheduler_add_thread(t);

#ifdef DIFF_DEBUG
    TDBG("[THREAD] add_thread: tid=%d -> READY\n", t->thread_id);
#endif

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

#ifdef DIFF_DEBUG
    printf("[THREAD] reaping tid=%d pid=%d state=%d kstack_base=%08x\n",
           t->thread_id, p ? p->pid : -1, t->state, t->kernel_stack_base);
#endif

    // Free kernel stack
    if (t->kernel_stack_base)
    {
        kfree((void *)(uintptr_t)t->kernel_stack_base);
        t->kernel_stack_base = 0;
        t->kernel_stack_top = 0;
    }

    if (t->fx_area_raw) 
    {
        kfree(t->fx_area_raw);
        t->fx_area_raw = NULL;
        t->fx_area_aligned = NULL;
        t->fx_valid = false;
    }

    // Free thread object
    kfree(t);

#ifdef DIFF_DEBUG
    printf("[THREAD] reap done\n");
#endif
}

