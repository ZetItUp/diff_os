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
#include "debug.h"
#include "dex/dex.h"
#include "dex/exl.h"
#include "diff.h"
#include "console.h"
#include "system/messaging.h"
#include "system/shared_mem.h"
#include "interfaces.h"

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
    kfree(p);

    // Återställ CR3 exakt som det var.
    if (read_cr3_local() != cr3_before) {
        paging_switch_address_space(cr3_before);
    }
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
    k->heap_base = 0;
    k->heap_end = 0;
    k->heap_max = 0;
    k->reservation_count = 0;
    process_assign_default_cwd(k);
    process_set_exec_root(k, "/");

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
    process_inherit_cwd_from_parent(p, p->parent);
    process_set_exec_root(p, p->parent ? process_exec_root(p->parent) : "/");

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

        int pid = p->pid;
        messaging_cleanup_process(pid);
        shared_memory_cleanup_process(pid);
        vbe_release_owner(pid);
    }

    // Restore console/video to default state before ending the process
    console_restore_text_mode();

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
