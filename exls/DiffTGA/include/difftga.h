#pragma once

#include <stdint.h>
#include <stddef.h>

/* TGA image structure - pixels in ARGB format (0xAARRGGBB) */
typedef struct {
    uint32_t width;
    uint32_t height;
    uint32_t *pixels;  /* ARGB format, compatible with DiffWM */
} tga_image_t;

/* Load TGA from file path */
tga_image_t *tga_load(const char *path);

/* Load TGA from memory buffer */
tga_image_t *tga_load_mem(const void *data, size_t size);

/* Free TGA image and its pixel data */
void tga_free(tga_image_t *img);
