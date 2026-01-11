#include "system/irqsw.h"
#include "system/threads.h"
#include "system/scheduler.h"
#include "system/spinlock.h"

#define IRQSW_QUEUE_LEN 64

typedef struct irqsw_entry
{
    irqsw_handler_t handler;
    void *context;
} irqsw_entry_t;

static irqsw_entry_t g_irqsw_queue[IRQSW_QUEUE_LEN];
static uint16_t g_irqsw_head = 0;
static uint16_t g_irqsw_tail = 0;
static uint16_t g_irqsw_count = 0;
static uint32_t g_irqsw_dropped = 0;
static spinlock_t g_irqsw_lock;
static thread_t *g_irqsw_worker = NULL;
static int g_irqsw_initialized = 0;

static int irqsw_dequeue(irqsw_entry_t *entry)
{
    uint32_t flags = 0;
    spin_lock_irqsave(&g_irqsw_lock, &flags);

    if (g_irqsw_count == 0)
    {
        spin_unlock_irqrestore(&g_irqsw_lock, flags);

        return 0;
    }

    *entry = g_irqsw_queue[g_irqsw_head];
    g_irqsw_head = (uint16_t)((g_irqsw_head + 1) % IRQSW_QUEUE_LEN);
    g_irqsw_count--;

    spin_unlock_irqrestore(&g_irqsw_lock, flags);

    return 1;
}

int irqsw_queue(irqsw_handler_t handler, void *context)
{
    if (!handler || !g_irqsw_initialized)
    {
        return -1;
    }

    uint32_t flags = 0;
    spin_lock_irqsave(&g_irqsw_lock, &flags);

    if (g_irqsw_count >= IRQSW_QUEUE_LEN)
    {
        g_irqsw_dropped++;
        spin_unlock_irqrestore(&g_irqsw_lock, flags);

        return -1;
    }

    g_irqsw_queue[g_irqsw_tail].handler = handler;
    g_irqsw_queue[g_irqsw_tail].context = context;
    g_irqsw_tail = (uint16_t)((g_irqsw_tail + 1) % IRQSW_QUEUE_LEN);
    g_irqsw_count++;

    spin_unlock_irqrestore(&g_irqsw_lock, flags);

    if (g_irqsw_worker)
    {
        scheduler_wake_owner(g_irqsw_worker);
    }

    return 0;
}

uint32_t irqsw_dropped_count(void)
{
    uint32_t flags = 0;
    uint32_t dropped = 0;

    spin_lock_irqsave(&g_irqsw_lock, &flags);
    dropped = g_irqsw_dropped;
    spin_unlock_irqrestore(&g_irqsw_lock, flags);

    return dropped;
}

static void irqsw_thread_entry(void *argument)
{
    (void)argument;

    g_irqsw_worker = current_thread();

    for (;;)
    {
        irqsw_entry_t entry;
        int did_work = 0;

        while (irqsw_dequeue(&entry))
        {
            did_work = 1;
            if (entry.handler)
            {
                entry.handler(entry.context);
            }
        }

        if (!did_work)
        {
            scheduler_block_current_until_wakeup();
        }
    }
}

void irqsw_init(void)
{
    if (g_irqsw_initialized)
    {
        return;
    }

    spinlock_init(&g_irqsw_lock);
    g_irqsw_head = 0;
    g_irqsw_tail = 0;
    g_irqsw_count = 0;
    g_irqsw_dropped = 0;
    g_irqsw_worker = NULL;
    g_irqsw_initialized = 1;

    thread_create(irqsw_thread_entry, NULL, 16 * 1024);
}
