#pragma once

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include "system/process.h"
#include "system/threads.h"

void scheduler_add_thread(thread_t *thread);
void scheduler_init(void);
void scheduler_start(void);
void thread_yield(void);
void scheduler_block_current_until_wakeup(void);
void scheduler_wake_owner(void *owner);
void scheduler_reap_owned_zombies(struct process *p);
/* Arch interface */
void context_switch(cpu_context_t *save_context, cpu_context_t *load_context);

