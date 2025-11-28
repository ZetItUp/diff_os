#include <diffwm/diffwm.h>
#include <diffwm/protocol.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <system/messaging.h>
#include <system/shared_mem.h>
#include <system/threads.h>

static int dwm_mailbox(void)
{
    static int channel = -1;

    if(channel < 0)
    {
        /* Try a few times in case WM not ready yet */
        for (int i = 0; i < 200 && channel < 0; ++i)
        {
            channel = connect_message_channel(DWM_MAILBOX_ID);
            if (channel >= 0) break;
            thread_sleep_ms(10);
        }
    }

    return channel;
}

window_t* window_create(int x, int y, int width, int height, uint32_t flags)
{
    int wm_channel = dwm_mailbox();

    if(wm_channel < 0)
    {
        printf("[diffwm.lib] connect_message_channel failed\n");
        return NULL;
    }

    /* Create a dedicated mailbox for replies/events */
    int mailbox_id = 0x574D0000 | (thread_get_id() & 0xFFFF); /* 'WM' + tid */
    int mailbox = create_message_channel(mailbox_id);
    if(mailbox < 0)
    {
        printf("[diffwm.lib] create_message_channel failed id=0x%x\n", mailbox_id);
        return NULL;
    }

    int bytes = width * height * 4; // This may need to be changed
                                    // Keeping the pitch as 4*ARGB for now
    int handle = shared_memory_create(bytes);

    if(handle < 0)
    {
        printf("[diffwm.lib] shared_memory_create failed (%d bytes)\n", bytes);
        return NULL;
    }

    dwm_msg_t msg = 
    {
        .type = DWM_MSG_CREATE_WINDOW
    };

    msg.create.id = 0;
    msg.create.x = x;
    msg.create.y = y;
    msg.create.width = width;
    msg.create.height = height;
    msg.create.flags = flags;
    msg.create.mailbox_id = mailbox_id;
    msg.create.handle = handle;

    int rc = send_message(wm_channel, &msg, sizeof(msg));
    if(rc < 0)
    {
        printf("[diffwm.lib] send_message CREATE failed rc=%d chan=%d len=%zu\n",
               rc, wm_channel, sizeof(msg));
        return NULL;
    }

    dwm_msg_t reply;
    int rcv = receive_message(mailbox, &reply, sizeof(reply));
    if(rcv < 0)
    {
        printf("[diffwm.lib] receive_message for CREATE failed rc=%d\n", rcv);
        return NULL;
    }

    if(reply.type != DWM_MSG_CREATE_WINDOW || reply.create.id == 0)
    {
        printf("[diffwm.lib] CREATE reply invalid type=%d id=%u\n", reply.type, reply.create.id);
        return NULL;
    }

    int addr = shared_memory_map(handle);
    if(addr < 0)
    {
        printf("[diffwm.lib] shared_memory_map failed handle=%d\n", handle);
        return NULL;
    }

    window_t* win = malloc(sizeof(*win));
    *win = (window_t)
    {
        .id = reply.create.id,
        .handle = handle,
        .pixels = (void*)addr,
        .x = x,
        .y = y,
        .width = width,
        .height = height,
        .pitch = width * 4,
        .mailbox = mailbox,
        .wm_channel = wm_channel
    };

    return win;
}

void window_draw(window_t *window, const void *pixels)
{
    if(!window)
    {
        return;
    }

    int pitch = window->width * 4;

    for(int y = 0; y < window->height; y++)
    {
        memcpy((uint8_t*)window->pixels + y * window->pitch, (const uint8_t*)pixels + y * pitch, pitch);
    }

    dwm_msg_t msg =
    {
        .type = DWM_MSG_DRAW,
        .window_id = window->id,
    };

    send_message(window->wm_channel, &msg, sizeof(msg));
}

int window_poll_event(window_t *window, diff_event_t *event)
{
    dwm_msg_t msg;

    if(receive_message(window->mailbox, &msg, sizeof(msg)) < 0)
    {
        return 0;
    }

    if(msg.type != DWM_MSG_EVENT || msg.window_id != window->id)
    {
        return 0;
    }

    *event = msg.event;

    return 1;
}

void window_destroy(window_t *window)
{
    if(!window)
    {
        return;
    }

    dwm_msg_t msg =
    {
        .type = DWM_MSG_DESTROY_WINDOW,
        .window_id = window->id,
    };

    send_message(window->wm_channel, &msg, sizeof(msg));

    shared_memory_unmap(window->handle);
    shared_memory_release(window->handle);

    free(window);
}
