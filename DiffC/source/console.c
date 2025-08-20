#include <console.h>
#include <syscall.h>

int console_set_color(uint8_t fg, uint8_t bg)
{
    return system_console_set_color(fg, bg);
}

int console_get_color(uint8_t *fg, uint8_t *bg)
{
    uint32_t color = 0;
    int ret = system_console_get_color(&color);
    
    if (ret == 0)
    {
        if (fg)
        {
            *fg = (uint8_t)(color & 0xFF);
        }

        if (bg)
        {
            *bg = (uint8_t)((color >> 8) & 0xFF);
        }
    }
    
    return ret;
}

int console_set_bgcolor(uint8_t bg)
{
    bg &= 0x0F;

    uint8_t cur_fg = 0;
    int ret = console_get_color(&cur_fg, NULL);
    
    if (ret != 0)
    {
        return ret;
    }

    return console_set_color(cur_fg, bg);
}

int console_get_bgcolor(uint8_t *bg)
{
    if (!bg)
    {
        return -1;
    }

    uint8_t tmp_bg = 0;
    int ret = console_get_color(NULL, &tmp_bg);
    
    if (ret != 0)
    {
        return ret;
    }

    *bg = (uint8_t)(tmp_bg & 0xFF);
    
    return 0;    
}

int console_set_fgcolor(uint8_t fg)
{
    fg &= 0x0F;

    uint8_t cur_bg = 0;
    int ret = console_get_color(NULL, &cur_bg);
    
    if (ret != 0)
    {
        return ret;
    }

    return console_set_color(fg, cur_bg);
}

int console_get_fgcolor(uint8_t *fg)
{
    if (!fg)
    {
        return -1;
    }

    uint8_t tmp_fg = 0;
    int ret = console_get_color(&tmp_fg, NULL);
    
    if (ret != 0)
    {
        return ret;
    }

    *fg = (uint8_t)(tmp_fg & 0xFF);
    
    return 0;
}
