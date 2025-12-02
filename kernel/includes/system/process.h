#pragma once

#include "stdint.h"
#include "stddef.h"
#include "system/threads.h"
#include "system/spinlock.h"

struct tty;

typedef enum process_state
{
    PROCESS_CREATED = 0,
    PROCESS_READY   = 1,
    PROCESS_RUNNING = 2,
    PROCESS_ZOMBIE  = 3,
    PROCESS_DEAD    = 4
} process_state_t;

typedef struct process
{
    int pid;
    process_state_t state;
    uint32_t cr3;
    uint32_t cwd_id;
    char cwd_path[256];
    int exit_code;
    spinlock_t lock;

    struct process *parent;
    struct process *next;

    thread_t *main_thread;
    thread_t *waiter;
    int live_threads;

    // Stack bookkeeping (main kernel stack and active user stack)
    uintptr_t kstack_base;
    uintptr_t kstack_top;
    size_t    kstack_size;
    uintptr_t user_stack_base;
    uintptr_t user_stack_top;
    size_t    user_stack_size;

    // Heap management (per-process)
    uintptr_t heap_base;
    uintptr_t heap_end;
    uintptr_t heap_max;

    // Memory reservations for demand paging (per-process)
    #define MAX_PROCESS_RESERVATIONS 16
    struct {
        uint32_t start;
        uint32_t end;
    } reservations[MAX_PROCESS_RESERVATIONS];
    int reservation_count;

    // Absolute path to the executable (directory component). Used to
    // re-root child processes when resolving relative paths while still
    // allowing the caller's cwd to remain intact.
    char exec_root[256];

    // Per-process tty endpoints (stdout/stderr and stdin)
    struct tty *tty_out;
    struct tty *tty_in;
    uint8_t   tty_attr;
} process_t;

typedef struct user_boot_args
{
    uint32_t eip;
    uint32_t esp;
    uint32_t cr3;
} user_boot_args_t;

void process_init(void);
process_t *process_create_kernel(void (*entry)(void *), void *argument, size_t kstack_bytes);
process_t *process_create_user(uint32_t user_eip,
                               uint32_t user_esp,
                               size_t kstack_bytes,
                               uintptr_t user_stack_base,
                               size_t user_stack_size,
                               uintptr_t heap_base,
                               uintptr_t heap_end,
                               uintptr_t heap_max);
void process_exit_current(int exit_code);
process_t *process_current(void);
int process_pid(const process_t *p);
void process_destroy(process_t *p);
uint32_t process_cr3(const process_t *p);
void process_set_current(process_t *p);
process_t *process_create_user_with_cr3(uint32_t user_eip,
                                        uint32_t user_esp,
                                        uint32_t cr3,
                                        size_t kstack_bytes,
                                        uintptr_t user_stack_base,
                                        size_t user_stack_size,
                                        uintptr_t heap_base,
                                        uintptr_t heap_end,
                                        uintptr_t heap_max);
process_t *process_find_by_pid(int pid);
int system_wait_pid(int pid, int *u_status);
uint32_t read_cr3_local(void);
void process_set_cwd(process_t *p, uint32_t dir_id, const char *abs_path);
uint32_t process_cwd_id(const process_t *p);
const char *process_cwd_path(const process_t *p);
const char *process_exec_root(const process_t *p);
void process_set_exec_root(process_t *p, const char *abs_dir);
void process_set_user_stack(process_t *p, uintptr_t base, uintptr_t top, size_t size);
void process_set_kernel_stack(process_t *p, uintptr_t base, uintptr_t top, size_t size);
