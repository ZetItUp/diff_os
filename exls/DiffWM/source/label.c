#include <diffwm/window_component.h>
#include <diffwm/label.h>

void label_init(label_t *label, int x, int y, const char *text)
{
    window_component_init(&label->base, x, y, 0, 0);

    label->text = text;

    label->base.update = label_update;
    label->base.draw = label_draw;
}

void label_update(window_component_t *self)
{

}

void label_draw(window_component_t *self)
{
    label_t *label = (label_t*)self;

    if(!self->visible)
    {
        return;
    }

    // Draw label
}
