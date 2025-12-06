#include "string.h"
#include "system/usercopy.h"
#include "system/process.h"
#include "system/messaging.h"
#include <stdio.h>
#include "system/scheduler.h"
#include "system/spinlock.h"
#include "system/threads.h"

static msg_channel_t g_channels[MESSAGES_MAX_CHANNELS];

static int find_channel_by_id(int id)
{
    for(int i = 0; i < MESSAGES_MAX_CHANNELS; i++)
    {
        if(g_channels[i].used && g_channels[i].id == id)
        {
            return i;
        }
    }  

    return -1;
}

// Create a message channel
int system_msg_create_channel(int id)
{
    int existing = find_channel_by_id(id);

    if(existing >= 0)
    {
        return existing;
    }

    for(int i = 0; i < MESSAGES_MAX_CHANNELS; i++)
    {
        if(!g_channels[i].used)
        {
            memset(&g_channels[i], 0, sizeof(g_channels[i]));
            g_channels[i].used = 1;
            g_channels[i].id = id;
            g_channels[i].owner_pid = process_pid(process_current());
            spinlock_init(&g_channels[i].lock);
            
            return i;
        }
    }

    return -1;
}

int system_msg_connect_channel(int id)
{
    return find_channel_by_id(id);
}

int system_msg_send(int channel_id, const void *buffer, uint32_t len)
{
    if(channel_id < 0 || channel_id >= MESSAGES_MAX_CHANNELS)
    {
        return -1;
    }

    if(len == 0 || len > MESSAGES_MAX)
    {
        return -2;
    }

    // Copy out of userspace before taking locks (kernel always owns its queue payload)
    uint8_t tmp[MESSAGES_MAX];
    if (copy_from_user(tmp, buffer, len) != 0)
    {
        printf("[MSG] send: EFAULT pid=%d va=%p len=%u\n",
               process_current() ? process_current()->pid : -1, buffer, len);
        return -4; // EFAULT
    }

    // Get current thread
    thread_t *self = current_thread();

    for(;;)
    {
        uint32_t flags;
        msg_channel_t *channel = &g_channels[channel_id];

        // Lock thread
        spin_lock_irqsave(&channel->lock, &flags);

        if(!channel->used)
        {
            spin_unlock_irqrestore(&channel->lock, flags);
            return -1;
        }

        // Try to read message if we have any
        if(channel->count < MESSAGES_QUEUE_LEN)
        {
            uint16_t slot = channel->tail;
            channel->sizes[slot] = (uint16_t)len;

            // Copy from the staged kernel buffer into the channel slot
            memcpy(channel->messages[slot], tmp, len);

            channel->tail = (uint16_t)((channel->tail + 1) % MESSAGES_QUEUE_LEN);
            channel->count++;

            // Check if we need to wake recv_waiter
            if(channel->recv_waiter)
            {
                scheduler_wake_owner(channel->recv_waiter);
                channel->recv_waiter = NULL;
            }

            spin_unlock_irqrestore(&channel->lock, flags);

            return (int)len;
        }

        // Sleep until space is available
        channel->send_waiter = self;
        spin_unlock_irqrestore(&channel->lock, flags);

        // Tell the scheduler to block
        scheduler_block_current_until_wakeup();
    }
}

int system_msg_recv(int channel_id, void *buffer, uint32_t buf_len)
{
    if(channel_id < 0 || channel_id >= MESSAGES_MAX_CHANNELS)
    {
        return -1;
    }

    // Get current thread
    thread_t *self = current_thread();

    for(;;)
    {
        uint32_t flags;
        msg_channel_t *channel = &g_channels[channel_id];

        // Lock thread
        spin_lock_irqsave(&channel->lock, &flags);

        if(!channel->used)
        {
            spin_unlock_irqrestore(&channel->lock, flags);
            return -1;
        }

        if(channel->count == 0)
        {
            // Empty: Sleep until we have a sender
            channel->recv_waiter = self;
            spin_unlock_irqrestore(&channel->lock, flags);
            scheduler_block_current_until_wakeup();
            continue;
        }

        uint16_t slot = channel->head;
        uint16_t msg_len = channel->sizes[slot];

        if(buf_len < msg_len)
        {
            spin_unlock_irqrestore(&channel->lock, flags);

            // Caller buffer too small
            return -3;
        }

        if(copy_to_user(buffer, channel->messages[slot], msg_len) != 0)
        {
            spin_unlock_irqrestore(&channel->lock, flags);

            // Bad user buffer
            return -4;
        }

        channel->head = (uint16_t)((channel->head + 1) % MESSAGES_QUEUE_LEN);
        channel->count--;

        // Check if we shoudl wake send_waiter
        if(channel->send_waiter)
        {
            scheduler_wake_owner(channel->send_waiter);
            channel->send_waiter = NULL;
        }

        // Unlock thread
        spin_unlock_irqrestore(&channel->lock, flags);
        
        return (int)msg_len;
    }
}

// Non-blocking receive: returns 0 if no message available
int system_msg_try_recv(int channel_id, void *buffer, uint32_t buf_len)
{
    if(channel_id < 0 || channel_id >= MESSAGES_MAX_CHANNELS)
    {
        return -1;
    }

    uint32_t flags;
    msg_channel_t *channel = &g_channels[channel_id];

    spin_lock_irqsave(&channel->lock, &flags);

    if(!channel->used)
    {
        spin_unlock_irqrestore(&channel->lock, flags);
        return -1;
    }

    if(channel->count == 0)
    {
        spin_unlock_irqrestore(&channel->lock, flags);
        return 0; // no message
    }

    uint16_t slot = channel->head;
    uint16_t msg_len = channel->sizes[slot];

    if(buf_len < msg_len)
    {
        spin_unlock_irqrestore(&channel->lock, flags);
        return -3;
    }

    if(copy_to_user(buffer, channel->messages[slot], msg_len) != 0)
    {
        spin_unlock_irqrestore(&channel->lock, flags);
        return -4;
    }

    channel->head = (uint16_t)((channel->head + 1) % MESSAGES_QUEUE_LEN);
    channel->count--;

    if(channel->send_waiter)
    {
        scheduler_wake_owner(channel->send_waiter);
        channel->send_waiter = NULL;
    }

    spin_unlock_irqrestore(&channel->lock, flags);

    return (int)msg_len;
}

void messaging_cleanup_process(int pid)
{
    for (int i = 0; i < MESSAGES_MAX_CHANNELS; i++)
    {
        msg_channel_t *channel = &g_channels[i];
        if (!channel->used)
        {
            continue;
        }

        uint32_t flags;
        spin_lock_irqsave(&channel->lock, &flags);

        if (channel->owner_pid == pid)
        {
            memset(channel, 0, sizeof(*channel));
        }

        spin_unlock_irqrestore(&channel->lock, flags);
    }
}
