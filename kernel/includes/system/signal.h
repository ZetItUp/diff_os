#pragma once

#include <stdint.h>

struct process;
struct syscall_frame;
struct stack_frame;

#define SIG_MAX 32

#define SIGINT   2
#define SIGILL   4
#define SIGABRT  6
#define SIGFPE   8
#define SIGKILL  9
#define SIGSEGV 11
#define SIGTERM 15

typedef void (*user_sighandler_t)(int);

#define SIG_DFL ((user_sighandler_t)0)
#define SIG_IGN ((user_sighandler_t)1)

typedef struct signal_state
{
    uint32_t pending;
    uint32_t mask;
    user_sighandler_t handlers[SIG_MAX];
    uint32_t trampoline;
} signal_state_t;

int system_signal_set(int sig, user_sighandler_t handler, uint32_t trampoline);
int system_signal_send(int pid, int sig);
int system_signal_setmask(uint32_t mask);
int system_signal_getmask(uint32_t *out);
int system_signal_return(uint32_t frame_ptr, struct syscall_frame *f);

void signal_maybe_deliver_syscall(struct process *p, struct syscall_frame *f);
void signal_maybe_deliver_frame(struct process *p, struct stack_frame *f);
int signal_send_to_process(struct process *p, int sig);
