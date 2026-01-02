#include <stdbool.h>
#include <diffwm/window_component.h>
#include <stddef.h>

typedef struct window_component_mouse_state_t
{
    window_component_t *component;
    bool mouse_inside;
    void (*on_mouse_enter)(window_component_t *self);
    void (*on_mouse_leave)(window_component_t *self);
} window_component_mouse_state_t;

// Simple fixed storage to avoid changing the public struct layout.
static window_component_mouse_state_t g_mouse_states[64];

static window_component_mouse_state_t *window_component_mouse_state(window_component_t *self, bool create)
{
    if (!self)
    {
        return NULL;
    }

    for (size_t i = 0; i < sizeof(g_mouse_states) / sizeof(g_mouse_states[0]); i++)
    {
        if (g_mouse_states[i].component == self)
        {
            return &g_mouse_states[i];
        }
    }

    if (!create)
    {
        return NULL;
    }

    for (size_t i = 0; i < sizeof(g_mouse_states) / sizeof(g_mouse_states[0]); i++)
    {
        if (!g_mouse_states[i].component)
        {
            g_mouse_states[i].component = self;
            g_mouse_states[i].mouse_inside = false;
            g_mouse_states[i].on_mouse_enter = NULL;
            g_mouse_states[i].on_mouse_leave = NULL;
            return &g_mouse_states[i];
        }
    }

    return NULL;
}

void window_component_init(window_component_t *window_comp, int x, int y, int width, int height)
{
    window_comp->parent = NULL;
    window_comp->x = x;
    window_comp->y = y;
    window_comp->width = width;
    window_comp->height = height;

    window_comp->visible = true;
    window_comp->enabled = true;

    window_comp->update = window_component_update;
    window_comp->draw = window_component_draw;
    (void)window_component_mouse_state(window_comp, true);
}

void window_component_update(window_component_t *self)
{
    (void)self;
}

void window_component_draw(window_component_t *self)
{
    (void)self;
}

bool window_component_contains(window_component_t *self, int x, int y)
{
    if (!self)
    {
        return false;
    }

    return (x >= self->x && x < self->x + self->width &&
            y >= self->y && y < self->y + self->height);
}

bool window_component_update_mouse(window_component_t *self, int mouse_x, int mouse_y)
{
    if (!self)
    {
        return false;
    }

    window_component_mouse_state_t *state = window_component_mouse_state(self, true);
    if (!state)
    {
        return false;
    }

    bool was_inside = state->mouse_inside;
    bool is_inside = window_component_contains(self, mouse_x, mouse_y);

    state->mouse_inside = is_inside;

    if (is_inside && !was_inside)
    {
        // Mouse entered
        if (state->on_mouse_enter)
        {
            state->on_mouse_enter(self);
        }

        return true;
    }
    else if (!is_inside && was_inside)
    {
        // Mouse left
        if (state->on_mouse_leave)
        {
            state->on_mouse_leave(self);
        }

        return true;
    }

    return false;
}

void window_component_set_mouse_callbacks(window_component_t *self,
                                          void (*on_mouse_enter)(window_component_t *self),
                                          void (*on_mouse_leave)(window_component_t *self))
{
    window_component_mouse_state_t *state = window_component_mouse_state(self, true);
    if (!state)
    {
        return;
    }

    state->on_mouse_enter = on_mouse_enter;
    state->on_mouse_leave = on_mouse_leave;
}
