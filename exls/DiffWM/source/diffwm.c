#include <diffwm.h>
#include <protocol.h>
#include <stdint.h>
#include <stdlib.h>

static int dmw_mailbox(void)
{
    static int channel = -1;

    if(channel < 0)
    {
        channel = connect_message_channel(DWM_MAILBOX_ID);
    }

    return channel;
}

window_t* window_create(int x, int y, int width, int height, uint32_t flags)
{
    int channel = dwm_mailbox();

    if(channel < 0)
    {
        return NULL;
    }

    int bytes = width * height * 4; // This may need to be changed
                                    // Keeping the pitch as 4*ARGB for now
    int handle = shared_memory_create(bytes);

    if(handle < 0)
    {
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
    msg.create.handle = handle;

    if(send_message(channel, &msg, sizeof(msg)) != 0)
    {
        return NULL;
    }

    dwm_msg_t reply;
    if(receive_message(ch, &reply, sizeof(reply)) != 0)
    {
        return NULL;
    }

    if(reply.type != DWM_MSG_CREATE_WINDOW)
    {
        return NULL;
    }

    int addr = shared_memory_map(handle);
    if(addr < 0)
    {
        return NULL;
    }

    window_t* win = malloc(sizeof(*win));
    *win = (window_t)
    {
        .id = reply.create.id,
        .handle = handle,
        .pixels = (void*)addr,
        .width = width,
        .height = height,
        .pitch = width * 4,
        .mailbox = channel
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
        .id = window->id,
    };

    send_message(window->mailbox, &msg, sizeof(msg));
}

int window_poll_event(window_t *window, diffwm_event_t *event)
{
    dwm_msg_t msg;

    if(receive_message(window->mailbox, &msg, sizeof(msg)) != 0)
    {
        return 0;
    }

    if(msg.type != DWM_MSG_EVENT || msg.window_id != win->id)
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
        .id = window->id,
    };

    send_message(window->mailbox, &msg, sizeof(msg));

    shared_memory_unmap(window->handle);
    shared_memory_release(window->handle);

    free(window);
}
