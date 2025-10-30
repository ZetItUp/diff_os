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

static inline uint32_t read_cr0(void) { uint32_t v; __asm__ volatile("mov %%cr0,%0":"=r"(v)); return v; }
static inline void     write_cr0(uint32_t v){ __asm__ volatile("mov %0,%%cr0"::"r"(v)); }
static inline uint32_t read_cr4(void) { uint32_t v; __asm__ volatile("mov %%cr4,%0":"=r"(v)); return v; }
static inline void     write_cr4(uint32_t v){ __asm__ volatile("mov %0,%%cr4"::"r"(v)); }

static void sse_enable_once(void)
{
    /* CR0: ställ in MP=1, EM=0 (ingen emulering), [TS=0 om den skulle vara satt] */
    uint32_t cr0 = read_cr0();
    cr0 |=  (1u<<1);   /* MP */
    cr0 &= ~(1u<<2);   /* EM */
    cr0 &= ~(1u<<3);   /* TS */
    write_cr0(cr0);

    /* CR4: OSFXSR=1 och OSXMMEXCPT=1 så OS:et får använda FXSAVE/FXRSTOR + SSE exceptions */
    uint32_t cr4 = read_cr4();
    cr4 |= (1u<<9);    /* OSFXSR */
    cr4 |= (1u<<10);   /* OSXMMEXCPT */
    write_cr4(cr4);

    /* Nolla FPU/SSE till definierat läge */
    __asm__ volatile ("fninit");
#ifdef DIFF_DEBUG
    DDBG("[PROC] SSE enabled (CR0=%08x CR4=%08x)\n", cr0, cr4);
#endif
}

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

#ifdef DIFF_DEBUG
        DDBG("[PROC] unlink head pid=%d\n", p->pid);
#endif
        return;
    }

    for (process_t *it = g_all_head; it; it = it->next)
    {
        if (it->next == p)
        {
            it->next = p->next;

#ifdef DIFF_DEBUG
            DDBG("[PROC] unlink pid=%d after pid=%d\n", p->pid, it->pid);
#endif
            return;
        }
    }

    p->next = NULL;
#ifdef DIFF_DEBUG
    DDBG("[PROC][WARN] unlink: pid=%d not found in list\n", p->pid);
#endif
}

// Destroy process and free resources (kernel side only)
void process_destroy(process_t *p)
{
    if (!p) return;

#ifdef DIFF_DEBUG
    DDBG("[PROC] destroy pid=%d state=%d cr3=%08x parent=%p\n",
         p->pid, p->state, p->cr3, (void*)p->parent);
#endif

    // Vi får inte förstöra en fortfarande RUNNING process här.
    if (p->state == PROCESS_RUNNING) {
#ifdef DIFF_DEBUG
        printf("[PROC][ERR] process_destroy on RUNNING pid=%d\n", p->pid);
#endif
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
#ifdef DIFF_DEBUG
            DDBG("[PROC] destroy: switching CR3 victim->kernel %08x -> %08x\n", victim, kcr3);
#endif
            paging_switch_address_space(kcr3);
        }

        // Själva rivningen av PD/tabellerna:
        paging_destroy_address_space(victim);
#ifdef DIFF_DEBUG
        DDBG("[PROC] destroy: address space %08x destroyed\n", victim);
#endif
    }

    // Fria PCB
    kfree(p);

    // Återställ CR3 exakt som det var.
    if (read_cr3_local() != cr3_before) {
#ifdef DIFF_DEBUG
        DDBG("[PROC] destroy: restoring CR3 %08x\n", cr3_before);
#endif
        paging_switch_address_space(cr3_before);
    }
}
// Link process into global list
static void process_link(process_t *p)
{
    p->next = g_all_head;
    g_all_head = p;
#ifdef DIFF_DEBUG
    DDBG("[PROC] link pid=%d (head=%d)\n", p->pid, g_all_head ? g_all_head->pid : -1);
#endif
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

#ifdef DIFF_DEBUG
    DDBG("[PROC] alloc pcb=%p\n", (void*)p);
#endif

    return p;
}

// --- i user_bootstrap(): ersätt hela funktionen ---
static void user_bootstrap(void *arg)
{
    user_boot_args_t *a = (user_boot_args_t *)arg;

    uint32_t entry_eip = a->eip;
    uint32_t user_esp  = a->esp;
    uint32_t user_cr3  = a->cr3;

    DDBG("[PROC] user_bootstrap: pid=%d eip=%08x esp=%08x cr3=%08x\n",
         process_current() ? process_current()->pid : -1,
         entry_eip, user_esp, user_cr3);

    kfree(a);

    uint32_t before = read_cr3_local();
    if (before != user_cr3) {
        DDBG("[PROC] CR3 switch (bootstrap): %08x -> %08x\n", before, user_cr3);
    }

    // Aktivera userspace
    paging_switch_address_space(user_cr3);

    uint32_t after = read_cr3_local();
    DDBG("[PROC] enter_user_mode: eip=%08x esp=%08x cr3(now)=%08x\n",
         entry_eip, user_esp, after);

    // In i ring3 och kom aldrig tillbaka
    enter_user_mode(entry_eip, user_esp);

    // Om vi ändå skulle hamna här: logga och dö tråden
    DDBG("[PROC][WARN] enter_user_mode returned! tid=%d pid=%d\n",
         current_thread() ? current_thread()->thread_id : -1,
         process_current() ? process_current()->pid : -1);

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

    sse_enable_once();

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

#ifdef DIFF_DEBUG
    DDBG("[PROC] create_kernel: pid=%d parent=%d cr3=%08x entry=%p kstack=%u\n",
         p->pid, p->parent ? p->parent->pid : -1, p->cr3, (void*)entry, (unsigned)kstack_bytes);
#endif

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

#ifdef DIFF_DEBUG
    DDBG("[PROC] create_user_with_cr3: pid=%d eip=%08x esp=%08x cr3=%08x parent=%d\n",
         p->pid, user_eip, user_esp, cr3, p->parent ? p->parent->pid : -1);
#endif

    // Create bootstrap thread that enters user mode
    int thread_id = thread_create_for_process(p, user_bootstrap, args, kstack_bytes);

    DDBG("[PROC] create_user_with_cr3: pid=%d child_tid=%d eip=%08x esp=%08x cr3=%08x\n",
         p->pid, thread_id, user_eip, user_esp, cr3);

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

#ifdef DIFF_DEBUG
    DDBG("[PROC] create_user: new_cr3=%08x\n", new_cr3);
#endif

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
#ifdef DIFF_DEBUG
        DDBG("[PROC] exit_current: pid=%d code=%d\n", p->pid, exit_code);
#endif
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
#ifdef DIFF_DEBUG
    DDBG("[PROC] set_current: pid=%d (prev=%d)\n",
         p ? p->pid : -1, g_current ? g_current->pid : -1);
#endif
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
#ifdef DIFF_DEBUG
            DDBG("[PROC] find_by_pid(%d) -> %p\n", pid, (void*)it);
#endif
            return it;
        }
    }

#ifdef DIFF_DEBUG
    DDBG("[PROC] find_by_pid(%d) -> NULL\n", pid);
#endif
    return NULL;
}

// Wait for a child to become zombie and reap it
int system_wait_pid(int pid, int *u_status)
{
    process_t *self  = process_current();
    process_t *child = process_find_by_pid(pid);

    if (!self || !child) {
#ifdef DIFF_DEBUG
        DDBG("[WAITPID][ERR] self=%p child=%p\n", (void*)self, (void*)child);
#endif
        return -1;
    }
    if (child->parent != self) {
#ifdef DIFF_DEBUG
        DDBG("[WAITPID][ERR] pid=%d is not a child of self pid=%d\n", pid, self->pid);
#endif
        return -1; // inte ditt barn
    }

    // Endast en waiter per barn
    if (child->waiter && child->waiter != current_thread()) {
#ifdef DIFF_DEBUG
        DDBG("[WAITPID][ERR] child pid=%d already waited by tid=%p\n", child->pid, (void*)child->waiter);
#endif
        return -1;
    }
    child->waiter = current_thread();

#ifdef DIFF_DEBUG
    DDBG("[WAITPID] waiting for pid=%d ...\n", child->pid);
#endif

    // Vänta tills barnet är ZOMBIE och har inga levande trådar kvar
    while (child->state != PROCESS_ZOMBIE || child->live_threads != 0) {
        scheduler_block_current_until_wakeup();
    }

    // Reapa barnets trådar innan vi fortsätter
    scheduler_reap_owned_zombies(child);
    if (child->live_threads != 0) {
#ifdef DIFF_DEBUG
        printf("[WAITPID][WARN] child live_threads=%d after reap; forcing zero\n", child->live_threads);
#endif
        child->live_threads = 0;
    }

    const int status  = child->exit_code;
    const int ret_pid = child->pid;

#ifdef DIFF_DEBUG
    DDBG("[WAITPID] pid=%d exited code=%d, copying status to user %p\n", ret_pid, status, (void*)u_status);
#endif

    // *** Viktigt: skriv status till förälderns userspace med FÖRÄLDERNS CR3 aktiv ***
    if (u_status) {
        int cpy_rc = 0;
        uint32_t saved_cr3 = read_cr3_local();

        // Växla till förälderns adressrymd om nödvändigt
        if (saved_cr3 != self->cr3) {
#ifdef DIFF_DEBUG
            DDBG("[WAITPID] switch CR3 for copy: %08x -> %08x\n", saved_cr3, self->cr3);
#endif
            paging_switch_address_space(self->cr3);
        }

        cpy_rc = copy_to_user(u_status, &status, sizeof(status));

        // Växla tillbaka till tidigare CR3 om vi bytte
        if (saved_cr3 != self->cr3) {
            paging_switch_address_space(saved_cr3);
#ifdef DIFF_DEBUG
            DDBG("[WAITPID] restore CR3=%08x\n", saved_cr3);
#endif
        }

        if (cpy_rc != 0) {
#ifdef DIFF_DEBUG
            printf("[WAITPID][ERR] failed to copy status to user %p\n", u_status);
#endif
            return -1;
        }
    }

    // NU är det säkert att riva barnets userspace och PCB
    if (child->cr3) {
#ifdef DIFF_DEBUG
        DDBG("[WAITPID] freeing child userspace cr3=%08x\n", child->cr3);
#endif
        paging_free_all_user_in(child->cr3);
    }

    exl_invalidate_for_cr3(child->cr3);
    process_destroy(child);

#ifdef DIFF_DEBUG
    DDBG("[WAITPID] done -> pid=%d\n", ret_pid);
#endif
    return ret_pid;
}

// Spawn a user process from a path and argv from userspace
int system_process_spawn(const char *upath, int argc, char **uargv)
{
    // Copy path from user
    char *kpath = NULL;

    if (copy_user_cstr(&kpath, upath, 256) != 0)
    {
#ifdef DIFF_DEBUG
        DDBG("[PROC][SPAWN][ERR] copy_user_cstr failed\n");
#endif
        return -1;
    }

    // Copy argv from user
    char **kargv = NULL;

    if (copy_user_argv(argc, uargv, &kargv) != 0)
    {
        kfree(kpath);
#ifdef DIFF_DEBUG
        DDBG("[PROC][SPAWN][ERR] copy_user_argv failed\n");
#endif
        return -1;
    }

#ifdef DIFF_DEBUG
    DDBG("[PROC][SPAWN] path='%s' argc=%d\n", kpath, argc);
#endif

    // Create process
    int pid = dex_spawn_process(file_table, kpath, argc, kargv);

    // Free temporary buffers
    free_kargv(kargv);
    kfree(kpath);

#ifdef DIFF_DEBUG
    DDBG("[PROC][SPAWN] -> pid=%d\n", pid);
#endif

    return pid;
}

