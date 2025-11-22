#pragma once

// Primitives
typedef struct 
{
    int x;
    int y;
    int width;
    int height;
} rect_t;

// Color Helpers
typedef struct
{
    uint8_t r;
    uint8_t g;
    uint8_t b;
    uint8_t a;
} color_t;

static inline uint32_t color_to_argb(color_t c)
{
    return ((uint32_t)c.a << 24)
         | ((uint32_t)c.r << 16)
         | ((uint32_t)c.g << 8)
         | ((uint32_t)c.b);
}

static inline uint32_t color_rgb(uint8_t r, uint8_t g, uint8_t b)
{
    return 0xFF000000u
         | ((uint32_t)r << 16)
         | ((uint32_t)g << 8)
         | (uint32_t)b;
}

static inline uint32_t color_rgba(uint8_t r, uint8_t g, uint8_t b, uint8_t a)
{
    return ((uint32_t)a << 24)
         | ((uint32_t)r << 16)
         | ((uint32_t)g << 8)
         | (uint32_t)b;
}
