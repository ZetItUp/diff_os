#include "graphics/vbe_graphics.h"
#include "graphics/vbe_text.h"
#include "interfaces.h"
#include "stdint.h"
#include "paging.h"
#include "stdio.h"
#include "console.h"
#include "string.h"
#include "io.h"

vbe_exports_t g_vbe = {0};

void vbe_register(uint32_t phys_base, uint32_t width, uint32_t height, uint32_t bpp, uint32_t pitch)
{
    uint64_t fb_bytes = (uint64_t)pitch * (uint64_t)height;

    // Sanity check on framebuffer size
    if (fb_bytes == 0 || fb_bytes > 0x20000000ull)
    {
        printf("[VBE] Invalid framebuffer size: pitch=%u height=%u\n", pitch, height);

        return;
    }

    // Map linear framebuffer into VA
    void *fb = kernel_map_physical_addr(phys_base, (uint32_t)fb_bytes, PAGE_RW | PAGE_PCD | PAGE_PWT);

    if (fb == NULL)
    {
        printf("[VBE] Failed to map LFB phys=0x%08x size=%u\n", phys_base, (uint32_t)fb_bytes);

        return;
    }

    g_vbe.frame_buffer = fb;
    g_vbe.phys_base = phys_base;
    g_vbe.width = width;
    g_vbe.height = height;
    g_vbe.bpp = bpp;
    g_vbe.pitch = pitch;

    // Switch console to VBE and replay old text
    if (!console_is_vbe_active())
    {
        console_use_vbe(1);
        console_flush_log();
    }

    vbe_text_set_colors(0xFFAAAAAA, 0xFF000000);
    vbe_text_clear(0xFF000000);
    console_flush_log();
}

static inline uint32_t min_u32(uint32_t a, uint32_t b)
{
    return (a < b) ? a : b;
}

void vbe_clear(uint32_t argb)
{
    if (g_vbe.frame_buffer == NULL || g_vbe.bpp != 32)
    {
        return;
    }

    uint8_t *base = (uint8_t*)g_vbe.frame_buffer;
    uint32_t stride32 = g_vbe.pitch >> 2;               // Pixels per row by pitch
    uint32_t row_px = min_u32(g_vbe.width, stride32);   // Don’t write past mapped row

    for (uint32_t y = 0; y < g_vbe.height; y++)
    {
        uint32_t *row = (uint32_t*)(base + y * g_vbe.pitch);

        for (uint32_t x = 0; x < row_px; x++)
        {
            row[x] = argb;
        }
    }
}

void vbe_putpixel(uint32_t x, uint32_t y, uint32_t argb)
{
    if (g_vbe.frame_buffer == NULL || g_vbe.bpp != 32)
    {
        return;
    }

    if (x >= g_vbe.width || y >= g_vbe.height)
    {
        return;
    }

    uint32_t stride32 = g_vbe.pitch >> 2;

    if (x >= stride32)   // Pitch smaller than logical width
    {
        return;
    }

    uint8_t *base = (uint8_t*)g_vbe.frame_buffer;
    uint32_t *row = (uint32_t*)(base + y * g_vbe.pitch);
    row[x] = argb;
}

void vbe_fill_rect(uint32_t x, uint32_t y, uint32_t w, uint32_t h, uint32_t argb)
{
    if (g_vbe.frame_buffer == NULL || g_vbe.bpp != 32)
    {
        return;
    }

    if (x >= g_vbe.width || y >= g_vbe.height)
    {
        return;
    }

    if (x + w > g_vbe.width)
    {
        w = g_vbe.width - x;
    }

    if (y + h > g_vbe.height)
    {
        h = g_vbe.height - y;
    }

    uint8_t *base = (uint8_t*)g_vbe.frame_buffer;
    uint32_t stride32 = g_vbe.pitch >> 2;

    uint32_t max_w_on_row = (x < stride32) ? (stride32 - x) : 0;
    w = min_u32(w, max_w_on_row);

    for (uint32_t yy = 0; yy < h; yy++)
    {
        uint32_t *row = (uint32_t*)(base + (y + yy) * g_vbe.pitch);

        for (uint32_t xx = 0; xx < w; xx++)
        {
            row[x + xx] = argb;
        }
    }
}

