#include <stdbool.h>
#include <diffwm/window_component.h>
#include <stddef.h>

void window_component_init(window_component_t *window_comp, int x, int y, int width, int height)
{
    window_comp->parent = NULL;
    window_comp->x = x;
    window_comp->y = y;
    window_comp->width = width;
    window_comp->height = height;

    window_comp->visible = true;
    window_comp->enabled = true;

    window_comp->mouse_inside = false;

    window_comp->update = window_component_update;
    window_comp->draw = window_component_draw;

    window_comp->on_mouse_enter = NULL;
    window_comp->on_mouse_leave = NULL;
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

    bool was_inside = self->mouse_inside;
    bool is_inside = window_component_contains(self, mouse_x, mouse_y);

    self->mouse_inside = is_inside;

    if (is_inside && !was_inside)
    {
        // Mouse entered
        if (self->on_mouse_enter)
        {
            self->on_mouse_enter(self);
        }

        return true;
    }
    else if (!is_inside && was_inside)
    {
        // Mouse left
        if (self->on_mouse_leave)
        {
            self->on_mouse_leave(self);
        }

        return true;
    }

    return false;
}
