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
#include "system/path.h"
#include "system/spinlock.h"
#include "debug.h"
#include "dex/dex.h"
#include "dex/exl.h"
#include "diff.h"
#include "console.h"
#include "system/messaging.h"
#include "system/shared_mem.h"
#include "interfaces.h"
#include "system/tty.h"

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
static spinlock_t g_proc_lock;

static inline void proc_list_lock(uint32_t *flags)
{
    spin_lock_irqsave(&g_proc_lock, flags);
}

static inline void proc_list_unlock(uint32_t flags)
{
    spin_unlock_irqrestore(&g_proc_lock, flags);
}

static uint32_t process_root_dir_id(void)
{
    if (superblock.root_dir_id != 0)
    {
        return superblock.root_dir_id;
    }

    if (file_table)
    {
        for (int i = 0; i < MAX_FILES; i++)
        {
            const FileEntry *fe = &file_table->entries[i];
            if (fe->entry_id != 0 && fe->type == ENTRY_TYPE_DIR && fe->parent_id == 0)
            {
                return fe->entry_id;
            }
        }
    }

    return 1;
}

static void process_assign_default_cwd(process_t *p)
{
    if (!p)
    {
        return;
    }

    p->cwd_id = process_root_dir_id();
    (void)strlcpy(p->cwd_path, "/", sizeof(p->cwd_path));
}

static void process_inherit_cwd_from_parent(process_t *p, process_t *parent)
{
    if (!p)
    {
        return;
    }

    if (parent)
    {
        p->cwd_id = parent->cwd_id;
        (void)strlcpy(p->cwd_path, parent->cwd_path, sizeof(p->cwd_path));
    }
    else
    {
        process_assign_default_cwd(p);
    }
}

void process_set_exec_root(process_t *p, const char *abs_dir)
{
    if (!p)
    {
        return;
    }

    if (!abs_dir || abs_dir[0] == '\0')
    {
        abs_dir = "/";
    }

    (void)strlcpy(p->exec_root, abs_dir, sizeof(p->exec_root));
}

// Unlink process from global list
static void process_unlink_from_all(process_t *p)
{
    if (!p)
    {
        return;
    }

    uint32_t f;
    proc_list_lock(&f);

    if (g_all_head == p)
    {
        g_all_head = p->next;
        proc_list_unlock(f);
        return;
    }

    for (process_t *it = g_all_head; it; it = it->next)
    {
        if (it->next == p)
        {
            it->next = p->next;
            proc_list_unlock(f);
            return;
        }
    }

    p->next = NULL;
    proc_list_unlock(f);
}

// Clean up per-process resources that are not automatically reaped by wait().
static void process_cleanup_resources(process_t *p)
{
    if (!p || p->resources_cleaned)
    {
        return;
    }

    p->resources_cleaned = 1;

    // Tear down IPC and shared memory owned by the process so other tasks
    // can't keep talking to a dead client.
    messaging_cleanup_process(p->pid);
    shared_memory_cleanup_process(p->pid);
    vbe_release_owner(p->pid);

    // Drop TTY endpoints (refcounted, so shared consoles stay alive).
    if (p->tty_out)
    {
        tty_destroy(p->tty_out);
        p->tty_out = NULL;
    }
    if (p->tty_in)
    {
        tty_destroy(p->tty_in);
        p->tty_in = NULL;
    }

    if (p->resources_kernel)
    {
        kfree(p->resources_kernel);
        p->resources_kernel = NULL;
        p->resources_kernel_size = 0;
    }
}

// Destroy process and free resources (kernel side only)
void process_destroy(process_t *p)
{
    if (!p) return;

    // Vi får inte förstöra en fortfarande RUNNING process här.
    if (p->state == PROCESS_RUNNING) {
        DDBG("[PROC][ERR] process_destroy on RUNNING pid=%d\n", p->pid);
        return;
    }

    // Bevara CR3 (kan vara förälderns user-CR3).
    uint32_t cr3_before = read_cr3_local();

    // Ta bort ur listor så ingen hittar den efter detta.
    process_unlink_from_all(p);

    // Om den har en egen adressrymd: först se till att vi inte står i den,
    // riv sen PD:t. Kernels CR3 får aldrig förstöras.
    if (p->cr3) {
        uint32_t victim = p->cr3;
        p->cr3 = 0;

        // Om vi står i samma CR3 som vi ska riva -> hoppa till kernel först.
        uint32_t kcr3 = (uint32_t)paging_kernel_cr3_phys();
        if (read_cr3_local() == victim) {
            paging_switch_address_space(kcr3);
        }

        // Själva rivningen av PD/tabellerna:
        paging_destroy_address_space(victim);
    }

    // Fria PCB
    process_cleanup_resources(p);

    kfree(p);

    // Återställ CR3 exakt som det var.
    if (read_cr3_local() != cr3_before) {
        paging_switch_address_space(cr3_before);
    }
}
// Link process into global list
static void process_link(process_t *p)
{
    if (!p)
    {
        return;
    }

    uint32_t f;
    proc_list_lock(&f);

    p->next = g_all_head;
        g_all_head = p;

    proc_list_unlock(f);
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
    spinlock_init(&p->lock);

    return p;
}

static int process_alloc_pid(void)
{
    uint32_t f;
    proc_list_lock(&f);

    int pid = g_next_pid++;

    proc_list_unlock(f);

    return pid;
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
    spinlock_init(&g_proc_lock);

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
    k->heap_base = 0;
    k->heap_end = 0;
    k->heap_max = 0;
    k->heap_alloc_next = 0;
    k->reservation_count = 0;
    process_assign_default_cwd(k);
    process_set_exec_root(k, "/");

    // Give the kernel process a default TTY pair so children inherit a live console.
    k->tty_out = tty_create();
    k->tty_in  = tty_create();
    if (!k->tty_out || !k->tty_in)
    {
        printf("[PROC] FATAL: failed to create kernel TTY endpoints\n");
        if (k->tty_out) tty_destroy(k->tty_out);
        if (k->tty_in)  tty_destroy(k->tty_in);
        kfree(k);
        return;
    }

    k->tty_attr = 0x07;

    // Link and set as current
    process_link(k);
    g_current = k;

    DDBG("[PROC] init: kernel pid=%d cr3=%08x\n", k->pid, k->cr3);
}

// Helper for inheriting a tty (or creating new if none)
static tty_t *process_clone_tty(tty_t *parent_tty)
{
    if (parent_tty)
    {
        tty_add_ref(parent_tty);
        return parent_tty;
    }

    return tty_create();
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
    process_t *parent = process_current();
    p->pid = process_alloc_pid();
    p->state = PROCESS_READY;
    p->cr3 = read_cr3_local();
    p->parent = parent;
    p->exit_code = 0;
    p->live_threads = 0;
    p->main_thread = NULL;
    p->waiter = NULL;
    p->tty_out = process_clone_tty(parent ? parent->tty_out : NULL);
    p->tty_in  = process_clone_tty(parent ? parent->tty_in : NULL);
    if (!p->tty_out || !p->tty_in)
    {
        if (p->tty_out) tty_destroy(p->tty_out);
        if (p->tty_in)  tty_destroy(p->tty_in);
        kfree(p);
        return NULL;
    }
    p->tty_attr = parent ? parent->tty_attr : 0x07;
    process_inherit_cwd_from_parent(p, p->parent);
    process_set_exec_root(p, p->parent ? process_exec_root(p->parent) : "/");

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
                                        size_t kstack_bytes,
                                        uintptr_t user_stack_base,
                                        size_t user_stack_size,
                                        uintptr_t heap_base,
                                        uintptr_t heap_end,
                                        uintptr_t heap_max)
{
    process_t *p = process_alloc();

    if (!p)
    {
        return NULL;
    }

    process_t *parent = process_current();
    p->pid = process_alloc_pid();
    p->state = PROCESS_READY;
    p->cr3 = cr3;
    p->parent = parent;
    p->exit_code = 0;
    p->live_threads = 0;
    p->main_thread = NULL;
    p->waiter = NULL;
    p->tty_out = process_clone_tty(parent ? parent->tty_out : NULL);
    p->tty_in  = process_clone_tty(parent ? parent->tty_in : NULL);
    if (!p->tty_out || !p->tty_in)
    {
        if (p->tty_out) tty_destroy(p->tty_out);
        if (p->tty_in)  tty_destroy(p->tty_in);
        kfree(p);
        return NULL;
    }
    p->tty_attr = parent ? parent->tty_attr : 0x07;
    process_inherit_cwd_from_parent(p, p->parent);
    process_set_exec_root(p, p->parent ? process_exec_root(p->parent) : "/");

    process_set_user_stack(p, user_stack_base, user_esp, user_stack_size);
    p->heap_base = heap_base;
    p->heap_end  = heap_end;
    p->heap_max  = heap_max;
    p->heap_alloc_next = heap_base;  // Start allocations from heap base

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
                               size_t kstack_bytes,
                               uintptr_t user_stack_base,
                               size_t user_stack_size,
                               uintptr_t heap_base,
                               uintptr_t heap_end,
                                uintptr_t heap_max)
{
    uint32_t new_cr3 = paging_new_address_space();

    if (!new_cr3)
    {
        printf("[PROC] create_user: paging_new_address_space failed\n");

        return NULL;
    }

    return process_create_user_with_cr3(user_eip,
                                        user_esp,
                                        new_cr3,
                                        kstack_bytes,
                                        user_stack_base,
                                        user_stack_size,
                                        heap_base,
                                        heap_end,
                                        heap_max);
}

// Create an additional user thread in the current process
int system_thread_create_user(uintptr_t user_eip, uintptr_t user_esp, size_t kstack_bytes)
{
    process_t *p = process_current();
    if (!p)
    {
        return -1;
    }

    if (user_eip == 0 || user_esp == 0)
    {
        return -1;
    }

    // Basic userspace validation: ensure entry and stack are in user VA and readable
    if (paging_check_user_range((uint32_t)user_eip, 1) != 0)
    {
        return -1;
    }
    if (paging_check_user_range((uint32_t)(user_esp - 1), 1) != 0)
    {
        return -1;
    }

    user_boot_args_t *args = (user_boot_args_t *)kmalloc(sizeof(user_boot_args_t));
    if (!args)
    {
        return -2;
    }

    args->eip = (uint32_t)user_eip;
    args->esp = (uint32_t)user_esp;
    args->cr3 = p->cr3;

    size_t kstack = kstack_bytes;
    if (kstack < 4096)
    {
        kstack = 4096;
    }

    int tid = thread_create_for_process(p, user_bootstrap, args, kstack);
    if (tid < 0)
    {
        kfree(args);
    }

    return tid;
}

// Exit current process via its last thread
void __attribute__((noreturn)) process_exit_current(int exit_code)
{
    process_t *p = process_current();

    if (p)
    {
        // Store exit code for wait()
        p->exit_code = exit_code;

        process_cleanup_resources(p);
    }

    // Restore console/video to default state before ending the process
    console_restore_text_mode();

    // End current thread, scheduler will handle process state
    thread_exit();

    // Should never return
    for (;;)
    {
        asm volatile("hlt");
    }
}

// Get current process
process_t *process_current(void)
{
    uint32_t f;
    proc_list_lock(&f);
    process_t *p = g_current;
    proc_list_unlock(f);
    return p;
}

// Set current process
void process_set_current(process_t *p)
{
    uint32_t f;
    proc_list_lock(&f);
    g_current = p;
    proc_list_unlock(f);
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

// Copy embedded resources of a process into a user buffer. If user_buf is NULL or buf_len==0,
// returns the size needed (or 0 if none). Returns negative on error.
int system_process_get_resources(int pid, void *user_buf, uint32_t buf_len)
{
    process_t *p = process_find_by_pid(pid);
    if (!p || !p->resources_kernel || p->resources_kernel_size == 0)
    {
        return 0;
    }

    uint32_t sz = p->resources_kernel_size;
    if (!user_buf || buf_len == 0)
    {
        return (int)sz;
    }

    if (buf_len < sz)
    {
        return -2;
    }

    if (copy_to_user(user_buf, p->resources_kernel, sz) != 0)
    {
        return -3;
    }

    return (int)sz;
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
    uint32_t f;
    proc_list_lock(&f);

    for (process_t *it = g_all_head; it; it = it->next)
    {
        if (it->pid == pid)
        {
            proc_list_unlock(f);
            return it;
        }
    }

    proc_list_unlock(f);
    return NULL;
}

void process_set_kernel_stack(process_t *p, uintptr_t base, uintptr_t top, size_t size)
{
    if (!p)
    {
        return;
    }

    uint32_t f;
    spin_lock_irqsave(&p->lock, &f);
    p->kstack_base = base;
    p->kstack_top = top;
    p->kstack_size = size;
    spin_unlock_irqrestore(&p->lock, f);
}

void process_set_user_stack(process_t *p, uintptr_t base, uintptr_t top, size_t size)
{
    if (!p)
    {
        return;
    }

    uint32_t f;
    spin_lock_irqsave(&p->lock, &f);
    p->user_stack_base = base;
    p->user_stack_top = top;
    p->user_stack_size = size;
    spin_unlock_irqrestore(&p->lock, f);
}

void process_set_cwd(process_t *p, uint32_t dir_id, const char *abs_path)
{
    if (!p)
    {
        return;
    }

    p->cwd_id = dir_id ? dir_id : process_root_dir_id();

    if (abs_path && abs_path[0] != '\0')
    {
        (void)strlcpy(p->cwd_path, abs_path, sizeof(p->cwd_path));
    }
    else
    {
        (void)strlcpy(p->cwd_path, "/", sizeof(p->cwd_path));
    }
}

uint32_t process_cwd_id(const process_t *p)
{
    if (!p)
    {
        return process_root_dir_id();
    }

    if (p->cwd_id == 0)
    {
        return process_root_dir_id();
    }

    return p->cwd_id;
}

const char *process_cwd_path(const process_t *p)
{
    if (!p || p->cwd_path[0] == '\0')
    {
        return "/";
    }

    return p->cwd_path;
}

const char *process_exec_root(const process_t *p)
{
    if (!p || p->exec_root[0] == '\0')
    {
        return "/";
    }

    return p->exec_root;
}

// Wait for a child to become zombie and reap it
int system_wait_pid(int pid, int *u_status)
{
    process_t *self  = process_current();
    process_t *child = process_find_by_pid(pid);

    if (!self || !child) {
        return -1;
    }
    if (child->parent != self) {
        return -1; // inte ditt barn
    }

    // Endast en waiter per barn
    if (child->waiter && child->waiter != current_thread()) {
        return -1;
    }
    child->waiter = current_thread();

    // Vänta tills barnet är ZOMBIE och har inga levande trådar kvar
    while (child->state != PROCESS_ZOMBIE || child->live_threads != 0) {
        scheduler_block_current_until_wakeup();
    }

    // Reapa barnets trådar innan vi fortsätter
    scheduler_reap_owned_zombies(child);
    if (child->live_threads != 0) {
        DDBG("[WAITPID][WARN] child live_threads=%d after reap; forcing zero\n", child->live_threads);
        child->live_threads = 0;
    }

    const int status  = child->exit_code;
    const int ret_pid = child->pid;

    // *** Viktigt: skriv status till förälderns userspace med FÖRÄLDERNS CR3 aktiv ***
    if (u_status) {
        int cpy_rc = 0;
        uint32_t saved_cr3 = read_cr3_local();

        // Växla till förälderns adressrymd om nödvändigt
        if (saved_cr3 != self->cr3) {
            paging_switch_address_space(self->cr3);
        }

        cpy_rc = copy_to_user(u_status, &status, sizeof(status));

        // Växla tillbaka till tidigare CR3 om vi bytte
        if (saved_cr3 != self->cr3) {
            paging_switch_address_space(saved_cr3);
        }

        if (cpy_rc != 0) {
            DDBG("[WAITPID][ERR] failed to copy status to user %p\n", u_status);
            return -1;
        }
    }

    // NU är det säkert att riva barnets userspace och PCB
    if (child->cr3) {
        paging_free_all_user_in(child->cr3);
    }

    exl_invalidate_for_cr3(child->cr3);
    process_destroy(child);

    return ret_pid;
}

// Non-blocking variant: reap child if already zombie, otherwise return 0
int system_wait_pid_nohang(int pid, int *u_status)
{
    process_t *self  = process_current();
    process_t *child = process_find_by_pid(pid);

    if (!self || !child)
    {
        return -1;
    }
    if (child->parent != self)
    {
        return -1; // not your child
    }

    // Child still running; do not block.
    if (child->state != PROCESS_ZOMBIE || child->live_threads != 0)
    {
        return 0;
    }

    // Reap any lingering zombie threads first.
    scheduler_reap_owned_zombies(child);
    if (child->live_threads != 0)
    {
        DDBG("[WAITPID][WARN][NOHANG] child live_threads=%d after reap; forcing zero\n", child->live_threads);
        child->live_threads = 0;
    }

    const int status  = child->exit_code;
    const int ret_pid = child->pid;

    if (u_status)
    {
        int cpy_rc = 0;
        uint32_t saved_cr3 = read_cr3_local();

        if (saved_cr3 != self->cr3)
        {
            paging_switch_address_space(self->cr3);
        }

        cpy_rc = copy_to_user(u_status, &status, sizeof(status));

        if (saved_cr3 != self->cr3)
        {
            paging_switch_address_space(saved_cr3);
        }

        if (cpy_rc != 0)
        {
            DDBG("[WAITPID][ERR][NOHANG] failed to copy status to user %p\n", u_status);
            return -1;
        }
    }

    if (child->cr3)
    {
        paging_free_all_user_in(child->cr3);
    }

    exl_invalidate_for_cr3(child->cr3);
    process_destroy(child);

    return ret_pid;
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

    process_t *caller = process_current();
    char norm_path[256];
    const char *base = process_cwd_path(caller);
    if (path_normalize(base, kpath, norm_path, sizeof(norm_path)) != 0)
    {
        kfree(kpath);
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
    // Determine the directory portion of the path for exec_root.
    char exec_dir[256];
    (void)strlcpy(exec_dir, norm_path, sizeof(exec_dir));
    char *slash = NULL;
    for (char *p = exec_dir; *p; ++p)
    {
        if (*p == '/')
        {
            slash = p;
        }
    }
    if (slash == NULL)
    {
        (void)strlcpy(exec_dir, "/", sizeof(exec_dir));
    }
    else if (slash == exec_dir)
    {
        exec_dir[1] = '\0';
    }
    else
    {
        *slash = '\0';
    }

    int pid = dex_spawn_process(file_table, norm_path, argc, kargv, exec_dir, 0);

    // Free temporary buffers
    free_kargv(kargv);
    kfree(kpath);

    return pid;
}
