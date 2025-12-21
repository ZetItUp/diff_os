// Label component helpers
#include <diffwm/label.h>
#include <diffwm/window.h>
#include <difffonts/fonts.h>
#include <string.h>

// Use a small default font once for all labels
static font_t *label_default_font(void)
{
    static font_t *font = NULL;
    if (!font)
    {
        font = font_load_bdf("/system/fonts/spleen-6x12.bdf");
    }
    return font;
}

void label_init(label_t *label, int x, int y, const char *text)
{
    if (!label)
    {
        return;
    }

    font_t *font = label_default_font();
    int width = 0;
    int height = 0;

    if (font)
    {
        const char *t = text ? text : "";
        width = (int)strlen(t) * font_width(font);
        height = font_height(font);
    }

    if (width <= 0)  width = 1;
    if (height <= 0) height = 1;

    window_component_init(&label->base, x, y, width, height);
    label->text = text ? text : "";

    label->base.update = label_update;
    label->base.draw = label_draw;
}

void label_set_text(label_t *label, const char *text)
{
    if (!label)
    {
        return;
    }

    label->text = text ? text : "";
}

void label_update(window_component_t *self)
{
    (void)self;
}

void label_draw(window_component_t *self)
{
    if (!self)
    {
        return;
    }

    label_t *label = (label_t*)self;
    window_t *parent = self->parent;
    font_t *font = label_default_font();

    if (!parent || !parent->backbuffer || !font)
    {
        return;
    }

    const char *text = label->text ? label->text : "";
    font_draw_text(font,
                   parent->backbuffer,
                   parent->base.width,
                   self->x,
                   self->y,
                   text,
                   0xFF000000);
}
