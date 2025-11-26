#pragma once

#include <stdint.h>
#include <stdint.h>

typedef enum
{
    DIFF_EVENT_NONE = 0,
    DIFF_EVENT_KEY,
    DIFF_EVENT_MOUSE
} diff_event_type_t;

typedef struct
{
    diff_event_type_t type;
    uint8_t key;
    int16_t mouse_x;
    int16_t mouse_y;
    uint8_t mouse_buttons;
} diff_event_t;

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
        diff_event_t event;
    };
} dwm_msg_t;
