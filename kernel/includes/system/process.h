#pragma once

#include "stdint.h"
#include "stddef.h"
#include "system/threads.h"

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
    int exit_code;

    struct process *parent;
    struct process *next;

    thread_t *main_thread;
    thread_t *waiter;
    int live_threads;
} process_t;

typedef struct user_boot_args
{
    uint32_t eip;
    uint32_t esp;
    uint32_t cr3;
} user_boot_args_t;

void process_init(void);
process_t *process_create_kernel(void (*entry)(void *), void *argument, size_t kstack_bytes);
process_t *process_create_user(uint32_t user_eip, uint32_t user_esp, size_t kstack_bytes);
void process_exit_current(int exit_code);
process_t *process_current(void);
int process_pid(const process_t *p);
uint32_t process_cr3(const process_t *p);
void process_set_current(process_t *p);
process_t *process_create_user_with_cr3(uint32_t user_eip, uint32_t user_esp, uint32_t cr3, size_t kstack_bytes);
process_t *process_find_by_pid(int pid);
int system_wait_pid(int pid, int *u_status);

