#include <diffwm/window.h>
#include <diffwm/diff_ipc.h>
#include <diffwm/terminal_component.h>
#include <stddef.h>

void window_init(window_t *window, int x, int y, int width, int height, const char *title)
{
    window_component_init(&window->base, x, y, width, height);

    window->title = title;
    window->backbuffer = NULL;
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

    window->base.update = window_update;
    window->base.draw = window_paint;
}

void window_add_component(window_t *window, window_component_t *component)
{
    if (!window || !component)
        return;

    if (window->child_count < WINDOW_MAX_CHILDREN)
    {
        window->children[window->child_count++] = component;
    }
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

void window_paint(window_component_t *self)
{
    window_t *window = (window_t*)self;

    if (!self->visible || !window->backbuffer)
        return;

    // Clear backbuffer to black
    int total = self->width * self->height;
    for (int i = 0; i < total; i++)
    {
        window->backbuffer[i] = 0xFF000000; // Black with alpha
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
