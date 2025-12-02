#pragma once

/*
 * DiffWM - Window Manager Library
 *
 * Public API:
 *   Low-level IPC (diff_ipc.h):
 *     - window_create()     Create window with WM
 *     - window_destroy()    Destroy window
 *     - window_present()    Send framebuffer to WM
 *     - window_poll_event() Poll for events
 *
 *   High-level components:
 *     - window_init()           Initialize window component
 *     - window_paint()          Polymorphic paint method
 *     - label_init()            Initialize label component
 *     - textbox_init()          Initialize textbox component
 *     - terminal_component_init() Initialize terminal component
 *
 *   Text utilities (text_utils.h):
 *     - text_selection_*()      Text selection management
 *     - text_hit_test()         Hit testing for mouse
 *     - text_render_selection() Render selection highlight
 */

#include <diffwm/protocol.h>
#include <diffwm/window.h>
#include <diffwm/label.h>
#include <diffwm/textbox.h>
#include <diffwm/terminal_component.h>
#include <diffwm/text_utils.h>
#include <diffwm/diff_ipc.h>
