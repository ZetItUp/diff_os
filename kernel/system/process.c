#include "dex/dex.h"
#include "dex/exl.h"
#include "system/process.h"
#include "system/threads.h"
#include "system/scheduler.h"
#include "system/usercopy.h"
#include "paging.h"
#include "heap.h"
#include "string.h"
#include "stdio.h"
#include "stdint.h"
#include "stddef.h"

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

extern void enter_user_mode(uint32_t entry_eip, uint32_t user_stack_top) __attribute__((noreturn));
static inline uint32_t read_cr3_local(void)
{
    uint32_t v;

    __asm__ __volatile__("mov %%cr3, %0" : "=r"(v));

    return v;
}

/* Forward declarations */
static void user_bootstrap(void *arg);

/* -------------------------------------------------------------------------- */
/* Process object (private, not exposed in header)                            */
/* -------------------------------------------------------------------------- */

static process_t *g_current = NULL;
static process_t *g_all_head = NULL;
static int g_next_pid = 1;

static void process_unlink_from_all(process_t *p) {
    extern process_t *g_all_head; // finns redan i process.c
    if (!p) return;

    if (g_all_head == p) {
        g_all_head = p->next;
    } else {
        for (process_t *it = g_all_head; it; it = it->next) {
            if (it->next == p) {
                it->next = p->next;
                break;
            }
        }
    }
    p->next = NULL;
}
static void process_destroy(process_t *p) {
    if (!p) return;

    // Adressrymden ska redan vara orörd av trådar vid det här laget
    if (p->cr3) {
        exl_invalidate_for_cr3(p->cr3);
        paging_destroy_address_space(p->cr3);
        p->cr3 = 0;
    }

    p->parent = NULL;
    p->waiter = NULL;

    process_unlink_from_all(p);

    // process_t allokerades med kmalloc => frigör
    kfree(p);
}
static void process_link(process_t *p)
{
    p->next = g_all_head;
    g_all_head = p;
}

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
static void user_bootstrap(void *arg)
{
    user_boot_args_t *a = (user_boot_args_t *)arg;

    uint32_t eip = a->eip;
    uint32_t esp = a->esp;
    uint32_t cr3 = a->cr3;

    kfree(a);

    paging_switch_address_space(cr3);

    enter_user_mode(eip, esp);

    /* Should never return; if it does, terminate the thread. */
    thread_exit();
}


/* -------------------------------------------------------------------------- */
/* Public API                                                                 */
/* -------------------------------------------------------------------------- */

void process_init(void)
{
    process_t *k = process_alloc();
    if (!k)
    {
        printf("[PROC] FATAL: out of memory in process_init\n");

        return;
    }

    k->pid = 0;
    k->state = PROCESS_RUNNING;
    k->cr3 = read_cr3_local();
    k->parent = NULL;
    k->exit_code = 0;
    k->live_threads = 0;
    k->main_thread = NULL;
    k->waiter = NULL;

    process_link(k);
    g_current = k;

    DDBG("[PROC] init: kernel pid=%d cr3=%08x\n", k->pid, k->cr3);
}

process_t *process_create_kernel(void (*entry)(void *), void *argument, size_t kstack_bytes)
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

    p->pid = g_next_pid++;
    p->state = PROCESS_READY;
    p->cr3 = read_cr3_local();
    p->parent = process_current();
    p->exit_code = 0;
    p->live_threads = 0;
    p->main_thread = NULL;
    p->waiter = NULL;

    process_link(p);

    int tid = thread_create_for_process(p, entry, argument, kstack_bytes);
    if (tid < 0)
    {
        printf("[PROC] create_kernel: thread_create_for_process failed (%d)\n", tid);
        /* Keep the process linked for debugging, but mark as dead. */
        p->state = PROCESS_DEAD;

        return NULL;
    }

    return p;
}

process_t *process_create_user_with_cr3(uint32_t user_eip, uint32_t user_esp, uint32_t cr3, size_t kstack_bytes)
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

    user_boot_args_t *args = (user_boot_args_t *)kmalloc(sizeof(user_boot_args_t));
    if (!args)
    {
        p->state = PROCESS_DEAD;

        return NULL;
    }

    args->eip = user_eip;
    args->esp = user_esp;
    args->cr3 = cr3;

    int tid = thread_create_for_process(p, user_bootstrap, args, kstack_bytes);
    if (tid < 0)
    {
        printf("[PROC] create_user: thread_create_for_process failed (%d)\n", tid);
        p->state = PROCESS_DEAD;
        kfree(args);

        return NULL;
    }

    return p;
}

process_t *process_create_user(uint32_t user_eip, uint32_t user_esp, size_t kstack_bytes)
{
    uint32_t cr3 = paging_new_address_space();
    if (!cr3)
    {
        printf("[PROC] create_user: paging_new_address_space failed\n");

        return NULL;
    }

    return process_create_user_with_cr3(user_eip, user_esp, cr3, kstack_bytes);
}

void process_exit_current(int exit_code)
{
    process_t *p = process_current();
    if (p) {
        // Spara exitstatus så föräldern kan läsa den i wait().
        p->exit_code = exit_code;
        // Sätt INTE state här; schemaläggaren gör processen ZOMBIE
        // när sista tråden dör (live_threads -> 0) och väcker eventuell waiter.
    }

    // Avsluta den aktuella tråden – schemaläggaren sköter resten.
    thread_exit();
}

process_t *process_current(void)
{
    return g_current;
}

void process_set_current(process_t *p)
{
    g_current = p;
}

int process_pid(const process_t *p)
{
    if (!p)
    {
        return -1;
    }

    return p->pid;
}

uint32_t process_cr3(const process_t *p)
{
    if (!p)
    {
        return 0;
    }

    return p->cr3;
}

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

/* Wait for a specific child PID to terminate (ZOMBIE).
 * Writes exit_code to user pointer if provided.
 * Returns child's pid on success, -1 on error. */
int system_wait_pid(int pid, int *u_status)
{
    process_t *self  = process_current();
    process_t *child = process_find_by_pid(pid);

    if (!self || !child) return -1;
    if (child->parent != self) return -1;

    // En waiter per barn
    if (child->waiter && child->waiter != current_thread()) return -1;
    child->waiter = current_thread();

    // Vänta tills sista tråden dött och processen blivit ZOMBIE
    while (child->state != PROCESS_ZOMBIE || child->live_threads != 0) {
        scheduler_block_current_until_wakeup();
    }

    int status = child->exit_code;

    // Gör den slutliga reap:en här
    process_destroy(child);

    if (u_status) *u_status = status;
    return pid;
}

int system_process_spawn(const char *upath, int argc, char **uargv)
{
    // Copy path from user
    char *kpath = NULL;
    if (copy_user_cstr(&kpath, upath, 256) != 0)
    {
        return -1;
    }


    // Copy argv[] from user (may be NULL if argc==0)
    char **kargv = NULL;
    if (copy_user_argv(argc, uargv, &kargv) != 0)
    {
        kfree(kpath);

        return -1;
    }

    int pid = dex_spawn_process(file_table, kpath, argc, kargv);
    free_kargv(kargv);
    kfree(kpath);

    return pid;
}

