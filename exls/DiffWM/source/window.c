#include <diffwm/window.h>
#include <diffwm/diff_ipc.h>
#include <diffwm/terminal_component.h>
#include <diffgfx/draw.h>
#include <stddef.h>

void window_init(window_t *window, int x, int y, int width, int height, const char *title)
{
    window_component_init(&window->base, x, y, width, height);

    window->title = title;
    window->backbuffer = NULL;
    window->flags = 0;
    window->draw_background = 1;
    window->presented = 0;
    window->child_count = 0;
    for (int i = 0; i < WINDOW_MAX_CHILDREN; i++)
    {
        window->children[i] = NULL;
    }

    window->id = 0;
    window->handle = -1;
    window->pixels = NULL;
    window->pitch = 0;
    window->mailbox = -1;
    window->wm_channel = -1;
    window->next = NULL;
    window->damage_pending = 0;
    window->damage_x_position = 0;
    window->damage_y_position = 0;
    window->damage_width = 0;
    window->damage_height = 0;

    window->base.update = window_update;
    window->base.draw = window_paint;
}

void window_add_component(window_t *window, window_component_t *component)
{
    if (!window || !component)
        return;

    component->parent = window;

    if (window->child_count < WINDOW_MAX_CHILDREN)
    {
        window->children[window->child_count++] = component;
    }
}

void window_set_background(window_t *window, int enabled)
{
    if (!window)
        return;

    window->draw_background = enabled ? 1 : 0;
}

void window_update(window_component_t *self)
{
    window_t *window = (window_t*)self;

    // Update all child components
    for (int i = 0; i < window->child_count; i++)
    {
        if (window->children[i] && window->children[i]->update)
        {
            window->children[i]->update(window->children[i]);
        }
    }
}

// Fast 32-bit memset
static void memset32(uint32_t *dst, uint32_t val, size_t count)
{
    while (count >= 4)
    {
        dst[0] = val;
        dst[1] = val;
        dst[2] = val;
        dst[3] = val;
        dst += 4;
        count -= 4;
    }
    while (count--)
    {
        *dst++ = val;
    }
}

void window_paint(window_component_t *self)
{
    window_t *window = (window_t*)self;

    if (!self->visible || !window->backbuffer)
        return;

    if (window->draw_background)
    {
        size_t total = (size_t)self->width * self->height;
        memset32(window->backbuffer, color_rgb(192, 192, 192), total);
    }

    // Render all child components
    for (int i = 0; i < window->child_count; i++)
    {
        window_component_t *child = window->children[i];
        if (!child || !child->visible)
            continue;

        // Check if this is a terminal component (has render method)
        // We need to call the specific render function based on type
        // For now, check if it's a terminal_component_t
        if (child->draw == terminal_component_paint)
        {
            terminal_component_t *term = (terminal_component_t*)child;
            terminal_component_render(term, window->backbuffer, self->width);
        }
        else if (child->draw)
        {
            // Call polymorphic draw for other components
            child->draw(child);
        }
    }

    // Present to window manager
    window_present(window, window->backbuffer);
}
