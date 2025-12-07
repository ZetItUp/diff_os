#pragma once

#include "stdint.h"
#include "system/spinlock.h"
#include "system/threads.h"

#define MESSAGES_MAX_CHANNELS    32      
#define MESSAGES_QUEUE_LEN       64
#define MESSAGES_MAX             240     // Maximum payload bytes per message

// Message Channel
typedef struct
{
    int used;
    int id;
    int owner_pid;

    uint16_t head;
    uint16_t tail;
    uint16_t count;

    uint16_t sizes[MESSAGES_QUEUE_LEN];
    uint8_t messages[MESSAGES_QUEUE_LEN][MESSAGES_MAX];

    // Concurrency / wait state
    spinlock_t lock;
    thread_t *recv_waiter;
    thread_t *send_waiter;
} msg_channel_t;

int system_msg_create_channel(int id);        // Create a channel with an id
int system_msg_connect_channel(int id);       // Connect to a channel with an id
int system_msg_send(int chan_id, const void *buffer, uint32_t len);
int system_msg_recv(int chan_id, void *buffer, uint32_t buf_len);
int system_msg_recv_timeout(int chan_id, void *buffer, uint32_t buf_len, uint32_t timeout_ms);
int system_msg_try_recv(int chan_id, void *buffer, uint32_t buf_len);
void messaging_cleanup_process(int pid);
