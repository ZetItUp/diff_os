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

    window_comp->update = window_component_update;
    window_comp->draw = window_component_draw;
}

void window_component_update(window_component_t *self)
{

}

void window_component_draw(window_component_t *self)
{

}
