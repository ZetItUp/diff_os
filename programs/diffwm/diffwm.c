#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <syscall.h>
#include <time.h>
#include <video.h>
#include <system/threads.h>
#include <unistd.h>
#include <system/messaging.h>
#include <system/shared_mem.h>
#include <diffwm/protocol.h>

// Diff Graphics Library
#include <diffgfx/graphics.h>
#include <diffgfx/draw.h>

// List of windows managed
static window_t *g_windows = NULL;
static uint32_t g_next_id = 1;
static int g_mailbox = -1;

// Video mode and backbuffer
static video_mode_info_t g_mode;
static uint32_t *g_backbuffer = NULL;

static window_t* wm_find(uint32_t id)
{
    for(window_t *win = g_windows; win; win = win->next)
    {
        if(win->id == id)
        {
            return win;
        }
    }

    return NULL;
}

static void wm_add_window(window_t *window)
{
    window->next = g_windows;
    g_windows = window;
}

static void wm_remove_window(uint32_t id)
{
    window_t **winp = &g_windows;

    while(*winp)
    {
        if((*winp)->id == id)
        {
            window_t* window = *winp;
            *winp = window->next;
            shared_memory_unmap(window->handle);
            shared_memory_release(window->handle);

            free(window);
            
            return;
        }

        winp = &(*winp)->next;
    }
}

static int wm_create_window(const dwm_window_desc_t *desc, uint32_t *out_id)
{
    printf("[Diff WM] CREATE handle=%d size=%dx%d flags=0x%x\n",
           desc->handle, desc->width, desc->height, desc->flags);

    int client_channel = connect_message_channel(desc->mailbox_id);
    if(client_channel < 0)
    {
        printf("[Diff WM] connect_message_channel mailbox_id=%d failed\n", desc->mailbox_id);
        return -1;
    }

    int map_rc = shared_memory_map(desc->handle);
    if(map_rc < 0)
    {
        printf("[Diff WM] shared_memory_map failed rc=%d handle=%d\n", map_rc, desc->handle);
        return -1;
    }

    void *addr = (void*)(uintptr_t)map_rc;

    if(!addr)
    {
        printf("[Diff WM] shared_memory_map returned NULL handle=%d\n", desc->handle);
        return -1;
    }

    window_t *window = calloc(1, sizeof(*window));

    if(!window)
    {
        shared_memory_unmap(desc->handle);

        printf("[Diff WM] calloc for window failed\n");
        return -1;
    }

    window->id = g_next_id++;
    window->handle = desc->handle;
    window->pixels = addr;
    window->x = desc->x;
    window->y = desc->y;
    window->width = desc->width;
    window->height = desc->height;
    window->pitch = desc->width * 4;
    window->mailbox = client_channel;
    window->wm_channel = g_mailbox;

    wm_add_window(window);
    *out_id = window->id;

    printf("[Diff WM] window created id=%u addr=%p\n", window->id, addr);

    return 0;
}

static void wm_draw_window(const dwm_msg_t *msg)
{
    window_t *window = wm_find(msg->window_id);

    if(!window || !g_backbuffer)
    {
        return;
    }

    int x0 = window->x;
    int y0 = window->y;
    int max_y = (y0 + window->height > g_mode.height) ? (g_mode.height - y0) : window->height;
    int max_x = (x0 + window->width > g_mode.width) ? (g_mode.width - x0) : window->width;

    if(max_x <= 0 || max_y <= 0)
    {
        return;
    }

    for(int y = 0; y < max_y; ++y)
    {
        memcpy((uint8_t*)g_backbuffer + (size_t)(y + y0) * g_mode.width * 4 + (size_t)x0 * 4,
                (uint8_t*)window->pixels + (size_t)y * window->pitch, (size_t)max_x * 4);
    }

    system_video_present(g_backbuffer, (int)g_mode.pitch, (int)g_mode.width, (int)g_mode.height);
}

static void wm_handle_message(const dwm_msg_t *msg)
{
    switch(msg->type)
    {
        case DWM_MSG_CREATE_WINDOW:
            {
                dwm_msg_t reply = {0};
                reply.type = DWM_MSG_CREATE_WINDOW;
                reply.create.id = 0;

                if(wm_create_window(&msg->create, &reply.create.id) != 0)
                {
                    reply.create.id = 0;
                }

                int client_channel = connect_message_channel(msg->create.mailbox_id);
                if(client_channel < 0)
                {
                    printf("[Diff WM] connect_message_channel for reply failed id=%d\n", msg->create.mailbox_id);
                    client_channel = g_mailbox;
                }

                send_message(client_channel, &reply, sizeof(reply));

                break;
            }
        case DWM_MSG_DESTROY_WINDOW:
            {
                wm_remove_window(msg->window_id);
                break;
            }
        case DWM_MSG_DRAW:
            {
                wm_draw_window(msg);
                break;
            }
        case DWM_MSG_EVENT:
            {
                // TODO: Implement
                break;
            }
        default:
            break;
    }
}

int main(void)
{
    printf("[Diff WM] Starting the Window Manager...\n");

    if(system_video_mode_get(&g_mode) < 0)
    {
        printf("[Diff WM] ERROR: No VBE Mode Set!\n");

        return -1;
    }

    g_backbuffer = calloc((size_t)g_mode.width * g_mode.height, sizeof(uint32_t));

    if(!g_backbuffer)
    {
        printf("[Diff WM] ERROR: Could not allocate backbuffer!\n");
        return -2;
    }


    g_mailbox = create_message_channel(DWM_MAILBOX_ID);

    if(g_mailbox < 0)
    {
        printf("[Diff WM] ERROR: Cannot create mailbox!\n");

        return -3;
    }

    /* Fill background to a known color before any client draws */
    for(uint32_t y = 0; y < g_mode.height; ++y)
    {
        for(uint32_t x = 0; x < g_mode.width; ++x)
        {
            g_backbuffer[y * g_mode.width + x] = color_rgb(69, 67, 117);
        }
    }
    system_video_present(g_backbuffer, (int)g_mode.pitch, (int)g_mode.width, (int)g_mode.height);

    /* Launch a demo client window (guitest) */
    const char *client_path = "/programs/guitest/guitest.dex";
    printf("[Diff WM] Spawning client: %s\n", client_path);
    spawn_process(client_path, 0, NULL);

    dwm_msg_t msg;
    while(1)
    {
        if(receive_message(g_mailbox, &msg, sizeof(msg)) > 0)
        {
            printf("Message Received\n");
            wm_handle_message(&msg);
        }

        thread_sleep_ms(1);
    }

    printf("[Diff WM] Exiting Window Manager...\n");
    free(g_backbuffer);

    return 0;
}
