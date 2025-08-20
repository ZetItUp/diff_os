#include "interfaces.h"
#include "console.h"
#include "graphics/vbe_text.h"
#include "stdint.h"

extern unsigned char current_attrib;
extern int console_is_vbe_active(void);

static inline unsigned char make_attr(uint8_t fg, uint8_t bg)
{
    return (unsigned char)((bg << 4) | (fg & 0x0F));
}

int console_set_colors_kernel(uint8_t fg, uint8_t bg)
{
    if (fg > 15 || bg > 15)
    {
        return -1;
    }

    unsigned char attrib = make_attr(fg, bg);
    set_color(attrib);

    return 0;
}

void console_get_colors_kernel(uint8_t *out_fg, uint8_t *out_bg)
{
    if (out_fg)
    {
        *out_fg = (uint8_t)(current_attrib & 0x0F);
    }

    if (out_bg)
    {
        *out_bg = (uint8_t)((current_attrib >> 4) & 0x0F);
    }
}

