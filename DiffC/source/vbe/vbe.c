#include <vbe/vbe.h>

int vbe_graphics_mode(void)
{
    return system_video_get_graphics_mode();
}

int vbe_set_video_mode(int width, int height, int bpp)
{
    return system_video_mode_set(width, height, bpp);
}

int vbe_present(const void *argb32, int pitch_bytes, int width, int height)
{
    return system_video_present(argb32, pitch_bytes, width, height);
}

int vbe_toggle_graphics_mode(void)
{
    return system_video_toggle_graphics_mode();
}
