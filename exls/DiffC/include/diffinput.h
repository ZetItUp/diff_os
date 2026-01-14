#pragma once

#include <syscall.h>

// Keyboard wrapper types
typedef system_key_event_t key_event_t;

// Blocking wait for keyboard event
static inline __attribute__((always_inline)) key_event_t keyboard_event_get(void)
{
    return system_keyboard_event_get();
}

// Non-blocking keyboard event, returns 1 if available
static inline __attribute__((always_inline)) int keyboard_event_try(key_event_t *out)
{
    return system_keyboard_event_try(out);
}

// Mouse wrapper types
typedef system_mouse_event_t mouse_event_t;

// Blocking wait for mouse event
static inline __attribute__((always_inline)) mouse_event_t mouse_event_get(void)
{
    return system_mouse_event_get();
}

// Non-blocking mouse event, returns 1 if available
static inline __attribute__((always_inline)) int mouse_event_try(mouse_event_t *out)
{
    return system_mouse_event_try(out);
}

// Get current mouse position
static inline __attribute__((always_inline)) void mouse_get_pos(int *x, int *y)
{
    system_mouse_get_pos(x, y);
}

// Set mouse position
static inline __attribute__((always_inline)) void mouse_set_pos(int x, int y)
{
    system_mouse_set_pos(x, y);
}

// Set mouse bounds for clamping
static inline __attribute__((always_inline)) void mouse_set_bounds(int max_x, int max_y)
{
    system_mouse_set_bounds(max_x, max_y);
}

// Get buttons currently held down
static inline __attribute__((always_inline)) uint8_t mouse_get_buttons_down(void)
{
    return system_mouse_get_buttons_down();
}

// Get buttons just pressed (rising edge, clears on read)
static inline __attribute__((always_inline)) uint8_t mouse_get_buttons_pressed(void)
{
    return system_mouse_get_buttons_pressed();
}

// Get buttons just released (falling edge, clears on read)
static inline __attribute__((always_inline)) uint8_t mouse_get_buttons_clicked(void)
{
    return system_mouse_get_buttons_clicked();
}
