#include "stdint.h"
#include "stddef.h"
#include "interfaces.h"
#include "console.h"
#include "system/process.h"
#include "system/spinlock.h"

tty_exports_t g_tty = {0};

#define MAX_TTY_DEVICES 32

static spinlock_t s_tty_owner_lock;
static int s_tty_owner_lock_inited = 0;
static int s_tty_owner_pids[MAX_TTY_DEVICES];
static int s_tty_device_count_cache = 1;

static void tty_owner_maybe_init(void)
{
    if (s_tty_owner_lock_inited)
    {
        return;
    }

    spinlock_init(&s_tty_owner_lock);
    s_tty_owner_lock_inited = 1;

    for (int i = 0; i < MAX_TTY_DEVICES; i++)
    {
        s_tty_owner_pids[i] = 0;
    }
}

static void tty_owner_update_count(void)
{
    tty_owner_maybe_init();

    if (!g_tty.tty_device_count)
    {
        s_tty_device_count_cache = s_tty_device_count_cache < 1 ? 1 : s_tty_device_count_cache;
        return;
    }

    int reported = g_tty.tty_device_count();

    if (reported < 1)
    {
        reported = 1;
    }

    if (reported > MAX_TTY_DEVICES)
    {
        reported = MAX_TTY_DEVICES;
    }

    s_tty_device_count_cache = reported;
}
static int current_tty_id(void)
{
    process_t *proc = process_current();

    if (!proc)
    {
        return 0;
    }

    return proc->tty_id;
}

void tty_register(
    int (*read_fn)(int, char*, unsigned),
    int (*write_fn)(int, const char*, unsigned),
    void (*input_fn)(int, char),
    void (*set_canonical_fn)(int, int),
    void (*set_echo_fn)(int, int),
    int (*available_fn)(int),
    int (*read_output_fn)(int, char*, unsigned),
    int (*device_count_fn)(void)
)
{
    g_tty.tty_read = read_fn;
    g_tty.tty_write = write_fn;
    g_tty.tty_input_char = input_fn;
    g_tty.tty_set_canonical = set_canonical_fn;
    g_tty.tty_set_echo = set_echo_fn;
    g_tty.tty_input_available = available_fn;
    g_tty.tty_read_output = read_output_fn;
    g_tty.tty_device_count = device_count_fn;
}

int tty_read(char *buf, unsigned count)
{
    if (!g_tty.tty_read)
    {
        return -1;
    }

    return g_tty.tty_read(current_tty_id(), buf, count);
}

int tty_write(const char *buf, unsigned count)
{
    if (!g_tty.tty_write)
    {
        return -1;
    }

    return g_tty.tty_write(current_tty_id(), buf, count);
}

void tty_input_char(char c)
{
    if (g_tty.tty_input_char)
    {
        g_tty.tty_input_char(current_tty_id(), c);
    }
}

void tty_set_canonical(int enabled)
{
    if (g_tty.tty_set_canonical)
    {
        g_tty.tty_set_canonical(current_tty_id(), enabled);
    }
}

void tty_set_echo(int enabled)
{
    if (g_tty.tty_set_echo)
    {
        g_tty.tty_set_echo(current_tty_id(), enabled);
    }
}

int tty_input_available(void)
{
    if (!g_tty.tty_input_available)
    {
        return 0;
    }

    return g_tty.tty_input_available(current_tty_id());
}

int tty_read_output(char *buf, unsigned count)
{
    if (!g_tty.tty_read_output)
    {
        return 0;
    }

    return g_tty.tty_read_output(current_tty_id(), buf, count);
}

int tty_get_device_count(void)
{
    tty_owner_update_count();

    return s_tty_device_count_cache;
}

int tty_set_current_device(int id)
{
    return tty_claim_for_current(id);
}

int tty_get_current_device(void)
{
    process_t *proc = process_current();

    if (!proc)
    {
        return 0;
    }

    return proc->tty_id;
}

static int tty_owner_allocate_for_process(process_t *proc)
{
    if (!proc)
    {
        return -1;
    }

    tty_owner_update_count();

    if (s_tty_device_count_cache <= 1)
    {
        return -1;
    }

    unsigned long flags;
    spin_lock_irqsave(&s_tty_owner_lock, &flags);

    int candidate = -1;

    for (int i = 1; i < s_tty_device_count_cache; i++)
    {
        if (s_tty_owner_pids[i] == 0)
        {
            candidate = i;
            s_tty_owner_pids[i] = proc->pid;
            break;
        }
    }

    if (candidate >= 0)
    {
        int old_id = proc->tty_id;

        if (old_id >= 0 &&
            old_id < s_tty_device_count_cache &&
            old_id != candidate &&
            s_tty_owner_pids[old_id] == proc->pid)
        {
            s_tty_owner_pids[old_id] = 0;
        }
    }

    spin_unlock_irqrestore(&s_tty_owner_lock, flags);

    if (candidate >= 0)
    {
        proc->tty_id = candidate;
    }

    return candidate;
}

static int tty_owner_claim_for_process(process_t *proc, int id)
{
    if (!proc)
    {
        return -1;
    }

    tty_owner_update_count();

    if (id < 0 || id >= s_tty_device_count_cache)
    {
        return -1;
    }

    unsigned long flags;
    spin_lock_irqsave(&s_tty_owner_lock, &flags);

    int owner = s_tty_owner_pids[id];
    int old_id = proc->tty_id;
    int old_owner = 0;

    if (old_id >= 0 && old_id < s_tty_device_count_cache)
    {
        old_owner = s_tty_owner_pids[old_id];
    }

    if (owner != 0 && owner != proc->pid)
    {
        spin_unlock_irqrestore(&s_tty_owner_lock, flags);
        return -1;
    }

    if (old_id == id)
    {
        s_tty_owner_pids[id] = proc->pid;
        spin_unlock_irqrestore(&s_tty_owner_lock, flags);
        proc->tty_id = id;
        return 0;
    }

    s_tty_owner_pids[id] = proc->pid;

    if (old_id >= 0 &&
        old_id < s_tty_device_count_cache &&
        old_owner == proc->pid)
    {
        s_tty_owner_pids[old_id] = 0;
    }

    spin_unlock_irqrestore(&s_tty_owner_lock, flags);

    proc->tty_id = id;

    return 0;
}

static void tty_owner_release_process(process_t *proc)
{
    if (!proc)
    {
        return;
    }

    int id = proc->tty_id;

    if (id < 0)
    {
        proc->tty_id = 0;
        return;
    }

    tty_owner_update_count();

    if (id >= s_tty_device_count_cache)
    {
        proc->tty_id = 0;
        return;
    }

    unsigned long flags;
    spin_lock_irqsave(&s_tty_owner_lock, &flags);

    if (s_tty_owner_pids[id] == proc->pid)
    {
        s_tty_owner_pids[id] = 0;
    }

    spin_unlock_irqrestore(&s_tty_owner_lock, flags);

    proc->tty_id = 0;
}

int tty_allocate_for_current(void)
{
    return tty_owner_allocate_for_process(process_current());
}

int tty_claim_for_current(int id)
{
    return tty_owner_claim_for_process(process_current(), id);
}

void tty_release_for_process(struct process *proc)
{
    tty_owner_release_process(proc);
}
