#pragma once

#include <stdint.h>

typedef struct
{
    uint32_t width;
    uint32_t height;
    uint32_t bpp;
    uint32_t pitch;
} video_mode_info_t;
