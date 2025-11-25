#pragma once

#include <stdint.h>
#include <diffgfx/graphics.h>

#define DWM_MAILBOX_ID  0x44574D31      // DWM1

typedef enum
{
    DWM_MSG_CREATE_WINDOW = 1,
    DWM_MSG_DESTROY_WINDOW,
    DWM_MSG_DRAW,
    DWM_MSG_EVENT
} dwm_msg_type_t;

typedef struct
{
    uint32_t id;
    int16_t x;
    int16_t y;
    int16_t width;
    int16_t height;
    uint32_t flags;
    int handle;
} dwm_window_desc_t;

typedef struct
{
    dwm_msg_type_t type;
    uint32_t window_id;

    union
    {
        dwm_window_desc_t create;
        struct
        {
            uint32_t seq;
        } draw;
        diffwm_event_t event;
    };
} dwm_msg_t;


