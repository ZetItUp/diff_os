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

// Embedded resource format that lives inside DEX files
#define PROCESS_RESOURCE_RS_MAGIC   0x53525845u
#define PROCESS_RESOURCE_RS_VERSION 1u
#define PROCESS_RESOURCE_RS_TYPE_STRING 1u

typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint32_t version;
    uint32_t entry_count;
    uint32_t strtab_off;
    uint32_t strtab_size;
    uint32_t data_off;
} rs_header_t;

typedef struct __attribute__((packed))
{
    uint32_t name_hash;
    uint32_t type;
    uint32_t name_off;
    uint32_t data_off;
    uint32_t data_size;
} rs_entry_t;

static uint32_t rs_fnv1a(const char *s)
{
    uint32_t hash = 0x811C9DC5u;

    if (!s)
    {
        return hash;
    }

    while (*s)
    {
        hash ^= (uint8_t)*s++;
        hash *= 0x01000193u;
    }

    return hash;
}

static const rs_entry_t *process_find_resource_entry(const process_t *p, uint32_t hash)
{
    if (!p || !p->resources_kernel || p->resources_kernel_size < sizeof(rs_header_t))
    {
        return NULL;
    }

    const rs_header_t *header = (const rs_header_t *)p->resources_kernel;

    if (header->magic != PROCESS_RESOURCE_RS_MAGIC || header->version != PROCESS_RESOURCE_RS_VERSION)
    {
        return NULL;
    }

    size_t table_size = (size_t)header->entry_count * sizeof(rs_entry_t);
    size_t needed = sizeof(rs_header_t) + table_size;

    if (needed > p->resources_kernel_size)
    {
        return NULL;
    }

    const uint8_t *table = (const uint8_t *)header + sizeof(rs_header_t);

    for (uint32_t i = 0; i < header->entry_count; ++i)
    {
        const rs_entry_t *entry = (const rs_entry_t *)(table + i * sizeof(rs_entry_t));

        if (entry->name_hash == hash &&
            entry->type == PROCESS_RESOURCE_RS_TYPE_STRING &&
            (size_t)entry->data_off + entry->data_size <= p->resources_kernel_size)
        {
            return entry;
        }
    }

    return NULL;
}

static void process_copy_resource_entry(process_t *p, const rs_entry_t *entry)
{
    if (!p || !entry)
    {
        return;
    }

    const size_t target_size = sizeof(p->name);
    size_t copy_len = entry->data_size;
    const uint8_t *src = p->resources_kernel + entry->data_off;

    if (copy_len >= target_size)
    {
        copy_len = target_size - 1;
    }

    if (copy_len > 0)
    {
        memcpy(p->name, src, copy_len);
    }

    p->name[copy_len] = '\0';
}

static void process_set_default_name(process_t *p, const char *path)
{
    if (!p)
    {
        return;
    }

    const char *base = path;

    if (base)
    {
        for (const char *it = base; *it; ++it)
        {
            if (*it == '/')
            {
                base = it + 1;
            }
        }
    }

    if (!base || *base == '\0')
    {
        base = "process";
    }

    strlcpy(p->name, base, sizeof(p->name));
}

void process_set_name(process_t *p, const char *name)
{
    if (!p)
    {
        return;
    }

    if (!name)
    {
        p->name[0] = '\0';
        return;
    }

    strlcpy(p->name, name, sizeof(p->name));
}

void process_assign_name_from_resources(process_t *p, const char *exec_path)
{
    if (!p)
    {
        return;
    }

    static const char *const keys[] =
    {
        "APPLICATION_TITLE",
        "WINDOW_TITLE"
    };

    for (size_t i = 0; i < sizeof(keys) / sizeof(keys[0]); ++i)
    {
        const rs_entry_t *entry = process_find_resource_entry(p, rs_fnv1a(keys[i]));

        if (entry)
        {
            process_copy_resource_entry(p, entry);
            return;
        }
    }

    process_set_default_name(p, exec_path);
}

const char *process_name(const process_t *p)
{
    static const char empty_name[] = "";

    if (!p)
    {
        return empty_name;
    }

    return p->name;
}

int process_get_name(int pid, char *buf, size_t buf_sz)
{
    if (!buf || buf_sz == 0)
    {
        return -1;
    }

    process_t *target = process_find_by_pid(pid);

    if (!target)
    {
        return -1;
    }

    char temp[NAME_MAX];
    strlcpy(temp, process_name(target), sizeof(temp));

    size_t copy_len = strlen(temp) + 1;

    if (copy_len > buf_sz)
    {
        copy_len = buf_sz;
        temp[copy_len - 1] = '\0';
    }

    if (copy_to_user(buf, temp, copy_len) != 0)
    {
        return -1;
    }

    return (int)(copy_len - 1);
}

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

    tty_release_for_process(p);

    p->resources_cleaned = 1;

    // Tear down IPC and shared memory owned by the process so other tasks
    // can't keep talking to a dead client.
    messaging_cleanup_process(p->pid);
    shared_memory_cleanup_process(p->pid);
    vbe_release_owner(p->pid);

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

void process_reap_orphan_zombies(void)
{
    for (;;)
    {
        process_t *victim = NULL;
        uint32_t f;

        proc_list_lock(&f);
        for (process_t *it = g_all_head; it; it = it->next)
        {
            // Only reap true orphans: zombies whose parent is dead or NULL
            // A zombie with a live parent should wait for waitpid()
            int is_orphan = (it->parent == NULL ||
                             it->parent->state == PROCESS_DEAD ||
                             it->parent->state == PROCESS_ZOMBIE);

            if (it->pid != 0 &&
                it->state == PROCESS_ZOMBIE &&
                it->live_threads == 0 &&
                is_orphan)
            {
                it->state = PROCESS_DEAD;
                victim = it;
                break;
            }
        }
        proc_list_unlock(f);

        if (!victim)
        {
            break;
        }

        if (victim->cr3)
        {
            paging_free_all_user_in(victim->cr3);
        }

        exl_invalidate_for_cr3(victim->cr3);
        process_destroy(victim);
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
    k->tty_output_enabled = 1;
    k->tty_id = 0;
    process_assign_default_cwd(k);
    process_set_exec_root(k, "/");
    process_set_name(k, "kernel");

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
    process_t *parent = process_current();
    p->pid = process_alloc_pid();
    p->state = PROCESS_READY;
    p->cr3 = read_cr3_local();
    p->parent = parent;
    p->exit_code = 0;
    p->live_threads = 0;
    p->main_thread = NULL;
    p->waiter = NULL;
    p->tty_output_enabled = parent ? parent->tty_output_enabled : 1;
    p->tty_id = parent ? parent->tty_id : 0;
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
    p->tty_output_enabled = parent ? parent->tty_output_enabled : 1;
    p->tty_id = parent ? parent->tty_id : 0;
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

        printf("[PROC] exit pid=%d code=%d\n", p->pid, exit_code);

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

int system_process_get_name(int pid, char *user_buf, size_t buf_len)
{
    process_t *p = process_find_by_pid(pid);

    if (!p || !user_buf || buf_len == 0)
    {
        return -1;
    }

    char temp[NAME_MAX];
    strlcpy(temp, process_name(p), sizeof(temp));

    size_t needed = strlen(temp) + 1;
    size_t copy_len = needed;
    if (copy_len > buf_len)
    {
        copy_len = buf_len;
        temp[copy_len - 1] = '\0';
    }

    if (copy_to_user(user_buf, temp, copy_len) != 0)
    {
        return -1;
    }

    return (int)(needed - 1);
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
        printf("[PROC] spawn: copy_user_cstr failed\n");
        return -1;
    }

    process_t *caller = process_current();
    char norm_path[256];
    const char *base = process_cwd_path(caller);
    if (path_normalize(base, kpath, norm_path, sizeof(norm_path)) != 0)
    {
        printf("[PROC] spawn: path_normalize failed (%s)\n", kpath);
        kfree(kpath);
        return -1;
    }

    // Copy argv from user
    char **kargv = NULL;

    if (copy_user_argv(argc, uargv, &kargv) != 0)
    {
        printf("[PROC] spawn: copy_user_argv failed\n");
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

    // Inherit cwd from parent (set_cwd=0), exec_root is still set to executable dir
    int pid = dex_spawn_process(file_table, norm_path, argc, kargv, exec_dir, 0);
    if (pid < 0)
    {
        const char *reason = "unknown";
        switch (pid)
        {
            case -1: reason = "bad args"; break;
            case -2: reason = "file not found"; break;
            case -3: reason = "empty file"; break;
            case -4: reason = "file buffer alloc"; break;
            case -5: reason = "read file failed"; break;
            case -6: reason = "new address space failed"; break;
            case -7: reason = "dex_load failed"; break;
            case -8: reason = "bad user stack"; break;
            case -9: reason = "bad entry"; break;
            case -10: reason = "exit stub failed"; break;
            case -12: reason = "process create failed"; break;
            default: break;
        }
        printf("[PROC] spawn: dex_spawn_process failed rc=%d (%s) path=%s\n",
               pid, reason, norm_path);
    }

    // Free temporary buffers
    free_kargv(kargv);
    kfree(kpath);

    return pid;
}
