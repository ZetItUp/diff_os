#include "graphics/vbe_graphics.h"
#include "graphics/vbe_text.h"
#include "system/usercopy.h"
#include "interfaces.h"
#include "stdint.h"
#include "paging.h"
#include "stdio.h"
#include "console.h"
#include "string.h"
#include "io.h"

#ifndef VBE_DISPI_IOPORT_INDEX
#define VBE_DISPI_IOPORT_INDEX 0x01CE
#define VBE_DISPI_IOPORT_DATA  0x01CF
#define VBE_DISPI_INDEX_ID      0x0
#define VBE_DISPI_INDEX_XRES    0x1
#define VBE_DISPI_INDEX_YRES    0x2
#define VBE_DISPI_INDEX_BPP     0x3
#define VBE_DISPI_INDEX_ENABLE  0x4
#define VBE_DISPI_INDEX_BANK    0x5
#define VBE_DISPI_INDEX_VIRT_WIDTH  0x6
#define VBE_DISPI_INDEX_VIRT_HEIGHT 0x7
#define VBE_DISPI_INDEX_X_OFFSET    0x8
#define VBE_DISPI_INDEX_Y_OFFSET    0x9

#define VBE_DISPI_ID5           0xB0C5
#define VBE_DISPI_ENABLED       0x01
#define VBE_DISPI_LFB_ENABLED   0x40
#define VBE_DISPI_NOCLEARMEM    0x80
#endif

vbe_exports_t g_vbe = {0};

static inline void vbe_write_reg(uint16_t idx, uint16_t val) 
{
    outw(VBE_DISPI_IOPORT_INDEX, idx);
    outw(VBE_DISPI_IOPORT_DATA,  val);
}

static inline uint16_t vbe_read_reg(uint16_t idx) 
{
    outw(VBE_DISPI_IOPORT_INDEX, idx);

    return inw(VBE_DISPI_IOPORT_DATA);
}
static inline void vbe_enable(uint16_t flags) 
{
    vbe_write_reg(VBE_DISPI_INDEX_ENABLE, flags);
}

int system_video_present_user(const void *user_ptr, int pitch_bytes, int packed_wh)
{
    if (g_vbe.frame_buffer == NULL || g_vbe.bpp != 32)
    {
        return -1;
    }

    int w = (packed_wh >> 16) & 0xFFFF;
    int h =  packed_wh         & 0xFFFF;

    if (w <= 0 || h <= 0 || pitch_bytes <= 0)
    {
        return -1;
    }

    // Clamp against current mode
    uint32_t max_w = (uint32_t)w;
    uint32_t max_h = (uint32_t)h;

    if (max_w > g_vbe.width)  max_w = g_vbe.width;
    if (max_h > g_vbe.height) max_h = g_vbe.height;

    // Bytes per row to copy (cap by LFB pitch to avoid overrun)
    uint32_t row_bytes = max_w * 4u;

    if (row_bytes > g_vbe.pitch)
    {
        row_bytes = g_vbe.pitch;
    }

    uint8_t *dst_base = (uint8_t*)g_vbe.frame_buffer;
    const uint8_t *src_user = (const uint8_t*)user_ptr;

    for (uint32_t y = 0; y < max_h; y++)
    {
        void *dst = dst_base + y * g_vbe.pitch;
        const void *src = src_user + (uint32_t)y * (uint32_t)pitch_bytes;

        // copy_from_user(dst_kernel, src_user, n) -> 0 on success
        if (copy_from_user(dst, src, row_bytes) != 0)
        {
            return -1;
        }
    }

    return 0;
}

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

int vbe_set_mode(uint32_t w, uint32_t h, uint32_t bpp)
{
    if (!(bpp == 8 || bpp == 15 || bpp == 16 || bpp == 24 || bpp == 32))
        return -1;
    
    if (w == 0 || h == 0 || w > 8192 || h > 8192) 
        return -1;

    vbe_write_reg(VBE_DISPI_INDEX_ID, VBE_DISPI_ID5);
    vbe_enable(0); 

    // synlig yta
    vbe_write_reg(VBE_DISPI_INDEX_XRES, (uint16_t)w);
    vbe_write_reg(VBE_DISPI_INDEX_YRES, (uint16_t)h);
    vbe_write_reg(VBE_DISPI_INDEX_BPP,  (uint16_t)bpp);

    // spegla till virtuell yta
    vbe_write_reg(VBE_DISPI_INDEX_VIRT_WIDTH,  (uint16_t)w);
    vbe_write_reg(VBE_DISPI_INDEX_VIRT_HEIGHT, (uint16_t)h);
    vbe_write_reg(VBE_DISPI_INDEX_X_OFFSET, 0);
    vbe_write_reg(VBE_DISPI_INDEX_Y_OFFSET, 0);
    vbe_write_reg(VBE_DISPI_INDEX_BANK, 0);

    vbe_enable((uint16_t)(VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM));

    uint16_t rw = vbe_read_reg(VBE_DISPI_INDEX_XRES);
    uint16_t rh = vbe_read_reg(VBE_DISPI_INDEX_YRES);
    uint16_t rb = vbe_read_reg(VBE_DISPI_INDEX_BPP);
    
    if (rw != (uint16_t)w || rh != (uint16_t)h || rb != (uint16_t)bpp) 
        return -1;

    uint16_t vwid = vbe_read_reg(VBE_DISPI_INDEX_VIRT_WIDTH);
    uint16_t vhgt = vbe_read_reg(VBE_DISPI_INDEX_VIRT_HEIGHT);
    uint16_t min_w = (uint16_t)w, min_h = (uint16_t)h;
    int need_fix = 0;
    
    if (vwid == 0 || vwid < min_w || vwid > 8192) 
    { 
        vwid = min_w; 
        need_fix = 1; 
    }
    
    if (vhgt == 0 || vhgt < min_h || vhgt > 8192) 
    { 
        vhgt = min_h; 
        need_fix = 1; 
    }
    
    if (need_fix) 
    {
        vbe_enable(0);
        vbe_write_reg(VBE_DISPI_INDEX_VIRT_WIDTH,  vwid);
        vbe_write_reg(VBE_DISPI_INDEX_VIRT_HEIGHT, vhgt);
        vbe_write_reg(VBE_DISPI_INDEX_X_OFFSET, 0);
        vbe_write_reg(VBE_DISPI_INDEX_Y_OFFSET, 0);
        vbe_write_reg(VBE_DISPI_INDEX_BANK, 0);
        vbe_enable((uint16_t)(VBE_DISPI_ENABLED | VBE_DISPI_LFB_ENABLED | VBE_DISPI_NOCLEARMEM));
    }

    return 0;
}

int system_video_mode_set(int w, int h, int bpp)
{
    if (!(bpp == 8 || bpp == 15 || bpp == 16 || bpp == 24 || bpp == 32))
        return -1;
    
    if (w == 0 || h == 0 || w > 8192 || h > 8192) 
        return -1;
    
    if (g_vbe.phys_base == 0) 
        return -1;

    if (vbe_set_mode(w, h, bpp) != 0) 
        return -1;

    uint16_t rx = vbe_read_reg(VBE_DISPI_INDEX_XRES);
    uint16_t ry = vbe_read_reg(VBE_DISPI_INDEX_YRES);
    uint16_t rbpp = vbe_read_reg(VBE_DISPI_INDEX_BPP);
    uint16_t vwid = vbe_read_reg(VBE_DISPI_INDEX_VIRT_WIDTH);
    uint16_t vhgt = vbe_read_reg(VBE_DISPI_INDEX_VIRT_HEIGHT);

    if (vwid == 0 || vwid < rx || vwid > 8192) 
        vwid = rx;
    
    if (vhgt == 0 || vhgt < ry || vhgt > 8192) 
        vhgt = ry;

    uint32_t bpp_bytes = ((uint32_t)rbpp + 7u) / 8u;
    uint32_t pitch_bytes = (uint32_t)vwid * bpp_bytes;

    vbe_register(g_vbe.phys_base, rx, ry, rbpp, pitch_bytes);

    return 0;
}
