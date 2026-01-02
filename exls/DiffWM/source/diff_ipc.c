#include <diffwm/diff_ipc.h>
#include <diffwm/window.h>
#include <diffwm/window_component.h>
#include <diffwm/protocol.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <system/messaging.h>
#include <system/process.h>
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

static void window_send_damage_message(window_t *window,
                                       int x_position,
                                       int y_position,
                                       int width,
                                       int height)
{
    if (!window || width <= 0 || height <= 0)
    {
        return;
    }

    dwm_msg_t msg = {0};
    msg.type = DWM_MSG_DAMAGE;
    msg.window_id = window->id;
    msg.damage.x_position = (int16_t)x_position;
    msg.damage.y_position = (int16_t)y_position;
    msg.damage.width = (int16_t)width;
    msg.damage.height = (int16_t)height;

    send_message(window->wm_channel, &msg, sizeof(msg));
}

window_t* window_create(int x, int y, int width, int height, uint32_t flags, const char *title)
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

    dwm_msg_t *reply = malloc(sizeof(*reply));
    if(!reply)
    {
        printf("[diffwm.lib] receive buffer alloc failed\n");
        return NULL;
    }

    int rcv = receive_message(mailbox, reply, sizeof(*reply));
    if(rcv < 0)
    {
        printf("[diffwm.lib] receive_message for CREATE failed rc=%d\n", rcv);
        free(reply);
        return NULL;
    }

    if(reply->type != DWM_MSG_CREATE_WINDOW || reply->create.id == 0)
    {
        printf("[diffwm.lib] CREATE reply invalid type=%d id=%u\n",
               reply->type, reply->create.id);
        free(reply);
        return NULL;
    }

    int reply_id = reply->create.id;
    free(reply);

    int addr = shared_memory_map(handle);
    if(addr < 0)
    {
        printf("[diffwm.lib] shared_memory_map failed handle=%d\n", handle);
        return NULL;
    }

    window_t* win = malloc(sizeof(*win));

    /* Initialize base component */
    window_component_init(&win->base, x, y, width, height);

    /* Set window-specific fields */
    win->title = title;
    win->id = reply_id;
    win->handle = handle;
    win->pixels = (void*)addr;
    win->pitch = width * 4;
    win->mailbox = mailbox;
    win->wm_channel = wm_channel;
    win->next = NULL;
    win->flags = flags;
    win->draw_background = (flags & WINDOW_FLAG_NO_BACKGROUND) ? 0 : 1;
    win->presented = 0;
    win->damage_pending = 0;
    win->damage_x_position = 0;
    win->damage_y_position = 0;
    win->damage_width = 0;
    win->damage_height = 0;

    /* Allocate backbuffer for rendering */
    win->backbuffer = malloc((size_t)width * height * sizeof(uint32_t));
    if (!win->backbuffer)
    {
        printf("[diffwm.lib] backbuffer alloc failed\n");
        free(win);
        return NULL;
    }

    /* Initialize child components */
    win->child_count = 0;
    for (int i = 0; i < WINDOW_MAX_CHILDREN; i++)
    {
        win->children[i] = NULL;
    }

    /* Set polymorphic function pointers */
    win->base.update = window_update;
    win->base.draw = window_paint;

    if (title && title[0] != '\0')
    {
        window_set_title(win, title);
    }

    return win;
}

void window_set_title(window_t *window, const char *title)
{
    if (!window || !title)
    {
        return;
    }

    dwm_msg_t msg = {0};
    msg.type = DWM_MSG_SET_TITLE;
    msg.window_id = window->id;
    strncpy(msg.set_title.title, title, DWM_TITLE_MAX - 1);
    msg.set_title.title[DWM_TITLE_MAX - 1] = '\0';

    send_message(window->wm_channel, &msg, sizeof(msg));
}

void window_present(window_t *window, const void *pixels)
{
    if(!window)
    {
        return;
    }

    int pitch = window->base.width * 4;

    // Optimize: if pitch matches, do a single memcpy instead of line-by-line
    if(pixels == window->pixels)
    {
        // Caller already rendered directly into shared memory.
    }
    else if(pitch == window->pitch)
    {
        memcpy(window->pixels, pixels, (size_t)pitch * window->base.height);
    }
    else
    {
        for(int y = 0; y < window->base.height; y++)
        {
            memcpy((uint8_t*)window->pixels + y * window->pitch, (const uint8_t*)pixels + y * pitch, pitch);
        }
    }

    if (!window->presented)
    {
        window->presented = 1;
        window->damage_pending = 0;
        window->damage_x_position = 0;
        window->damage_y_position = 0;
        window->damage_width = 0;
        window->damage_height = 0;

        dwm_msg_t msg = {0};
        msg.type = DWM_MSG_DRAW;
        msg.window_id = window->id;
        send_message(window->wm_channel, &msg, sizeof(msg));
        return;
    }

    if (window->damage_pending)
    {
        int window_width = window->base.width;
        int window_height = window->base.height;

        int x_position_start = window->damage_x_position;
        int y_position_start = window->damage_y_position;
        int x_position_end = x_position_start + window->damage_width;
        int y_position_end = y_position_start + window->damage_height;

        if (x_position_start < 0) x_position_start = 0;
        if (y_position_start < 0) y_position_start = 0;
        if (x_position_end > window_width) x_position_end = window_width;
        if (y_position_end > window_height) y_position_end = window_height;

        window->damage_pending = 0;
        window->damage_x_position = 0;
        window->damage_y_position = 0;
        window->damage_width = 0;
        window->damage_height = 0;

        if (x_position_end > x_position_start && y_position_end > y_position_start)
        {
            window_send_damage_message(window,
                                       x_position_start,
                                       y_position_start,
                                       x_position_end - x_position_start,
                                       y_position_end - y_position_start);
            return;
        }
    }

    dwm_msg_t msg = {0};
    msg.type = DWM_MSG_DRAW;
    msg.window_id = window->id;

    int rc = send_message(window->wm_channel, &msg, sizeof(msg));
    if (rc < 0)
    {
        printf("[diffwm.lib] send_message DRAW failed rc=%d chan=%d id=%u\n",
               rc, window->wm_channel, window->id);
    }
}

int window_poll_event(window_t *window, diff_event_t *event)
{
    dwm_msg_t msg;

    if (window)
    {
        window_update(&window->base);
    }

    if(try_receive_message(window->mailbox, &msg, sizeof(msg)) <= 0)
    {
        return 0;
    }

    if (msg.type == DWM_MSG_DESTROY_WINDOW && msg.window_id == window->id)
    {
        window_destroy(window);
        process_exit(0);
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

    if (window->backbuffer)
    {
        free(window->backbuffer);
    }

    free(window);
}

void window_request_focus(window_t *window)
{
    if(!window)
    {
        return;
    }

    dwm_msg_t msg =
    {
        .type = DWM_MSG_REQUEST_FOCUS,
        .window_id = window->id,
    };

    send_message(window->wm_channel, &msg, sizeof(msg));
}
