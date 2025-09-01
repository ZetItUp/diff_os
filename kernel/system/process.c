// process.c

#include "stdint.h"
#include "stddef.h"
#include "stdio.h"
#include "string.h"
#include "heap.h"
#include "paging.h"
#include "system/usercopy.h"
#include "system/process.h"
#include "system/threads.h"
#include "system/scheduler.h"
#include "dex/dex.h"
#include "dex/exl.h"

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

extern void enter_user_mode(uint32_t entry_eip, uint32_t user_stack_top) __attribute__((noreturn));

// Read CR3 of current CPU
uint32_t read_cr3_local(void)
{
    uint32_t value;

    __asm__ __volatile__("mov %%cr3, %0" : "=r"(value));

    return value;
}

// Forward declarations
static void user_bootstrap(void *arg);

// Process state
static process_t *g_current = NULL;
static process_t *g_all_head = NULL;
static int g_next_pid = 1;

// Unlink process from global list
static void process_unlink_from_all(process_t *p)
{
    if (!p)
    {
        return;
    }

    if (g_all_head == p)
    {
        g_all_head = p->next;

        return;
    }

    for (process_t *it = g_all_head; it; it = it->next)
    {
        if (it->next == p)
        {
            it->next = p->next;

            return;
        }
    }

    p->next = NULL;
}

// Destroy process and free resources (kernel side only)
void process_destroy(process_t *p)
{
    if (!p)
    {
        return;
    }

    // Switch to kernel CR3 to be safe
    paging_switch_address_space((uint32_t)paging_kernel_cr3_phys());

    // Remove from global list to avoid dangling pointers
    process_unlink_from_all(p);

    if (p->cr3)
    {
        uint32_t old_cr3 = p->cr3;
        p->cr3 = 0;

        // Free PD page only; userspace was freed by waitpid
        paging_destroy_address_space(old_cr3);
    }

    kfree(p);
}

// Link process into global list
static void process_link(process_t *p)
{
    p->next = g_all_head;
    g_all_head = p;
}

// Allocate zeroed process object
static process_t *process_alloc(void)
{
    process_t *p = (process_t *)kmalloc(sizeof(process_t));

    if (!p)
    {
        return NULL;
    }

    memset(p, 0, sizeof(*p));

    return p;
}

// Switch to user address space and jump to user mode
static void user_bootstrap(void *arg)
{
    user_boot_args_t *a = (user_boot_args_t *)arg;

    uint32_t entry_eip = a->eip; // Entry instruction pointer
    uint32_t user_esp = a->esp;  // User stack pointer
    uint32_t user_cr3 = a->cr3;  // Address space

    kfree(a);

    // Activate user address space
    paging_switch_address_space(user_cr3);

    // Enter user mode and never return
    enter_user_mode(entry_eip, user_esp);

    // Safety fallback
    thread_exit();
}

// Initialize process system with a kernel process
void process_init(void)
{
    process_t *k = process_alloc();

    if (!k)
    {
        printf("[PROC] FATAL: out of memory in process_init\n");

        return;
    }

    // Set kernel process fields
    k->pid = 0;
    k->state = PROCESS_RUNNING;
    k->cr3 = read_cr3_local();
    k->parent = NULL;
    k->exit_code = 0;
    k->live_threads = 0;
    k->main_thread = NULL;
    k->waiter = NULL;

    // Link and set as current
    process_link(k);
    g_current = k;

    DDBG("[PROC] init: kernel pid=%d cr3=%08x\n", k->pid, k->cr3);
}

// Create a kernel process with one thread
process_t *process_create_kernel(void (*entry)(void *),
                                 void *argument,
                                 size_t kstack_bytes)
{
    if (!entry)
    {
        return NULL;
    }

    process_t *p = process_alloc();

    if (!p)
    {
        return NULL;
    }

    // Inherit current address space
    p->pid = g_next_pid++;
    p->state = PROCESS_READY;
    p->cr3 = read_cr3_local();
    p->parent = process_current();
    p->exit_code = 0;
    p->live_threads = 0;
    p->main_thread = NULL;
    p->waiter = NULL;

    process_link(p);

    // Create main thread
    int thread_id = thread_create_for_process(p, entry, argument, kstack_bytes);

    if (thread_id < 0)
    {
        printf("[PROC] create_kernel: thread_create_for_process failed (%d)\n", thread_id);
        p->state = PROCESS_DEAD;

        return NULL;
    }

    return p;
}

// Create a user process in a provided address space
process_t *process_create_user_with_cr3(uint32_t user_eip,
                                        uint32_t user_esp,
                                        uint32_t cr3,
                                        size_t kstack_bytes)
{
    process_t *p = process_alloc();

    if (!p)
    {
        return NULL;
    }

    p->pid = g_next_pid++;
    p->state = PROCESS_READY;
    p->cr3 = cr3;
    p->parent = process_current();
    p->exit_code = 0;
    p->live_threads = 0;
    p->main_thread = NULL;
    p->waiter = NULL;

    process_link(p);

    // Package bootstrap data
    user_boot_args_t *args = (user_boot_args_t *)kmalloc(sizeof(user_boot_args_t));

    if (!args)
    {
        p->state = PROCESS_DEAD;

        return NULL;
    }

    args->eip = user_eip;
    args->esp = user_esp;
    args->cr3 = cr3;

    // Create bootstrap thread that enters user mode
    int thread_id = thread_create_for_process(p, user_bootstrap, args, kstack_bytes);

    if (thread_id < 0)
    {
        printf("[PROC] create_user: thread_create_for_process failed (%d)\n", thread_id);
        p->state = PROCESS_DEAD;
        kfree(args);

        return NULL;
    }

    return p;
}

// Create a user process with a new address space
process_t *process_create_user(uint32_t user_eip,
                               uint32_t user_esp,
                               size_t kstack_bytes)
{
    uint32_t new_cr3 = paging_new_address_space();

    if (!new_cr3)
    {
        printf("[PROC] create_user: paging_new_address_space failed\n");

        return NULL;
    }

    return process_create_user_with_cr3(user_eip, user_esp, new_cr3, kstack_bytes);
}

// Exit current process via its last thread
void process_exit_current(int exit_code)
{
    process_t *p = process_current();

    if (p)
    {
        // Store exit code for wait()
        p->exit_code = exit_code;
    }

    // End current thread, scheduler will handle process state
    thread_exit();
}

// Get current process
process_t *process_current(void)
{
    return g_current;
}

// Set current process
void process_set_current(process_t *p)
{
    g_current = p;
}

// Get pid of a process
int process_pid(const process_t *p)
{
    if (!p)
    {
        return -1;
    }

    return p->pid;
}

// Get CR3 of a process
uint32_t process_cr3(const process_t *p)
{
    if (!p)
    {
        return 0;
    }

    return p->cr3;
}

// Find process by pid
process_t *process_find_by_pid(int pid)
{
    for (process_t *it = g_all_head; it; it = it->next)
    {
        if (it->pid == pid)
        {
            return it;
        }
    }

    return NULL;
}

// Wait for a child to become zombie and reap it
int system_wait_pid(int pid, int *u_status)
{
    process_t *self = process_current();
    process_t *child = process_find_by_pid(pid);

    if (!self || !child)
    {
        return -1;
    }

    if (child->parent != self)
    {
        return -1;
    }

    // One waiter per child
    if (child->waiter && child->waiter != current_thread())
    {
        return -1;
    }

    child->waiter = current_thread();

    // Block until the child is zombie and has no live threads
    while (child->state != PROCESS_ZOMBIE || child->live_threads != 0)
    {
        scheduler_block_current_until_wakeup();
    }

    // Reap all zombie threads owned by the child before freeing its PCB/CR3
    scheduler_reap_owned_zombies(child);

    if (child->live_threads != 0)
    {
        printf("[WAITPID][WARN] child live_threads=%d after reap; forcing zero\n", child->live_threads);
        child->live_threads = 0;
    }

    int status = child->exit_code;

    // Final reap of child userspace (temporary switch inside)
    if (child->cr3)
    {
        paging_free_all_user_in(child->cr3);
    }

    // Destroy PCB + PD page (kernel CR3 switch happens inside)
    process_destroy(child);

    if (u_status)
    {
        // Defensive: ensure we stand in parent's CR3 before touching user memory
        uint32_t cur_cr3 = read_cr3_local();

        if (cur_cr3 != self->cr3)
        {
            printf("[WAITPID][WARN] CR3 mismatch (%08x != %08x). Fixing.\n", cur_cr3, self->cr3);
            paging_switch_address_space(self->cr3);
            process_set_current(self);
        }

        if (copy_to_user(u_status, &status, sizeof(int)) != 0)
        {
            printf("[WAITPID][ERR] failed to copy status to user %p\n", u_status);

            return -1;
        }
    }

    return pid;
}

// Spawn a user process from a path and argv from userspace
int system_process_spawn(const char *upath, int argc, char **uargv)
{
    // Copy path from user
    char *kpath = NULL;

    if (copy_user_cstr(&kpath, upath, 256) != 0)
    {
        return -1;
    }

    // Copy argv from user
    char **kargv = NULL;

    if (copy_user_argv(argc, uargv, &kargv) != 0)
    {
        kfree(kpath);

        return -1;
    }

    // Create process
    int pid = dex_spawn_process(file_table, kpath, argc, kargv);

    // Free temporary buffers
    free_kargv(kargv);
    kfree(kpath);

    return pid;
}

