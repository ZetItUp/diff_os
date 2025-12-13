#include <diffwm/picture_component.h>
#include <diffwm/window.h>
#include <string.h>

static inline int clamp_int(int v, int lo, int hi_excl)
{
    if (v < lo) return lo;
    if (v >= hi_excl) return hi_excl - 1;
    return v;
}

void picture_component_init(picture_component_t *pic,
                            int x,
                            int y,
                            int width,
                            int height,
                            const uint32_t *pixels,
                            int stride_pixels)
{
    if (!pic)
    {
        return;
    }

    window_component_init(&pic->base, x, y, width, height);
    pic->pixels = pixels;
    pic->stride = stride_pixels > 0 ? stride_pixels : width;

    pic->base.update = picture_component_update;
    pic->base.draw = picture_component_draw;
}

void picture_component_set_image(picture_component_t *pic,
                                 const uint32_t *pixels,
                                 int width,
                                 int height,
                                 int stride_pixels)
{
    if (!pic)
    {
        return;
    }

    pic->pixels = pixels;
    pic->base.width = width;
    pic->base.height = height;
    if (stride_pixels > 0)
    {
        pic->stride = stride_pixels;
    }
}

void picture_component_update(window_component_t *self)
{
    (void)self;
}

void picture_component_draw(window_component_t *self)
{
    if (!self)
    {
        return;
    }

    picture_component_t *pic = (picture_component_t *)self;
    window_t *parent = self->parent;

    if (!parent || !parent->backbuffer || !pic->pixels)
    {
        return;
    }

    const int dst_w = parent->base.width;
    const int dst_h = parent->base.height;

    // Compute clamped destination rect
    int x0 = clamp_int(self->x, 0, dst_w);
    int y0 = clamp_int(self->y, 0, dst_h);
    int x1 = clamp_int(self->x + self->width, 0, dst_w);
    int y1 = clamp_int(self->y + self->height, 0, dst_h);

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0)
    {
        return;
    }

    // Calculate source offset if the component is partially clipped
    int src_x = x0 - self->x;
    int src_y = y0 - self->y;

    const uint32_t *src = pic->pixels + (size_t)src_y * pic->stride + src_x;
    uint32_t *dst = parent->backbuffer + (size_t)y0 * dst_w + x0;

    for (int y = 0; y < draw_h; ++y)
    {
        memcpy(dst, src, (size_t)draw_w * sizeof(uint32_t));
        src += pic->stride;
        dst += dst_w;
    }
}
