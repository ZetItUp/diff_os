#pragma once

#include <stdint.h>

/*
 * Window Decoration Metrics
 *
 * These constants define the size of window decorations drawn by the WM.
 * Used by both the window manager and client library to calculate full
 * window bounds (content area + decorations).
 */
#define DWM_TITLEBAR_HEIGHT  22   // Title bar height (font height + padding)
#define DWM_BORDER_WIDTH     2    // Border thickness around window
#define DWM_SHADOW_SIZE      0    // Drop shadow size (disabled)

// Calculate full decorated window dimensions from content dimensions
#define DWM_FRAME_WIDTH(content_w)  ((content_w) + (DWM_BORDER_WIDTH * 2) + DWM_SHADOW_SIZE)
#define DWM_FRAME_HEIGHT(content_h) ((content_h) + DWM_TITLEBAR_HEIGHT + (DWM_BORDER_WIDTH * 2) + DWM_SHADOW_SIZE)

// Calculate content area position relative to frame origin
#define DWM_CONTENT_OFFSET_X  DWM_BORDER_WIDTH
#define DWM_CONTENT_OFFSET_Y  (DWM_TITLEBAR_HEIGHT + DWM_BORDER_WIDTH)

typedef enum
{
    DIFF_EVENT_NONE = 0,
    DIFF_EVENT_KEY,
    DIFF_EVENT_MOUSE,
    DIFF_EVENT_FOCUS_GAINED,
    DIFF_EVENT_FOCUS_LOST
} diff_event_type_t;

typedef enum
{
    MOUSE_ACTION_MOVE = 0,
    MOUSE_ACTION_DOWN,
    MOUSE_ACTION_UP,
    MOUSE_ACTION_CLICK,
    MOUSE_ACTION_DBLCLICK
} mouse_action_t;

// Mouse button flags (matches kernel MOUSE_BTN_*)
#ifndef MOUSE_BTN_LEFT
#define MOUSE_BTN_LEFT   0x01
#define MOUSE_BTN_RIGHT  0x02
#define MOUSE_BTN_MIDDLE 0x04
#endif

// Modifier key flags (matches kernel KB_MOD_*)
#define DIFF_MOD_SHIFT  0x01
#define DIFF_MOD_CTRL   0x02
#define DIFF_MOD_ALT    0x04
#define DIFF_MOD_CAPS   0x08

typedef struct
{
    diff_event_type_t type;
    uint8_t key;
    uint8_t key_pressed;
    uint8_t modifiers;      // DIFF_MOD_* flags
    int16_t mouse_x;
    int16_t mouse_y;
    uint8_t mouse_buttons;
    uint8_t mouse_action;   // mouse_action_t
    uint8_t mouse_button;   // MOUSE_BTN_* mask for the triggering button
} diff_event_t;

#define DWM_MAILBOX_ID  0x44574D31      // DWM1

typedef enum
{
    DWM_MSG_CREATE_WINDOW = 1,
    DWM_MSG_DESTROY_WINDOW,
    DWM_MSG_DRAW,
    DWM_MSG_EVENT,
    DWM_MSG_REQUEST_FOCUS,
    DWM_MSG_FOCUS_CHANGED
} dwm_msg_type_t;

typedef struct
{
    uint32_t id;
    int16_t x;
    int16_t y;
    int16_t width;
    int16_t height;
    uint32_t flags;
    int mailbox_id;     /* Client's reply/event mailbox id */
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
