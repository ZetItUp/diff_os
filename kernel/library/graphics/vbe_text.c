// All comments are written in English (per user preference).
// Allman brace style is used consistently.

#include "graphics/vbe_text.h"
#include "interfaces.h"
#include "stdint.h"
#include "stddef.h"
#include "string.h"
#include "io.h"

#define VGA_SEQ_INDEX 0x3C4
#define VGA_SEQ_DATA  0x3C5
#define VGA_GC_INDEX  0x3CE
#define VGA_GC_DATA   0x3CF

#ifndef VBE_PIXFMT_BGRX
#define VBE_PIXFMT_BGRX 1
#endif

static uint8_t g_vga_rom_ascii[96][16];
static int g_vga_rom_have=0;

static inline uint8_t vga_get(uint16_t idx_port,uint16_t data_port,uint8_t index)
{
    outb(idx_port,index);
    return inb(data_port);
}

static inline void vga_set(uint16_t idx_port,uint16_t data_port,uint8_t index,uint8_t value)
{
    outb(idx_port,index);
    outb(data_port,value);
}

static void vga_begin_font_access(uint8_t *sav_seq2,uint8_t *sav_seq4,
                                  uint8_t *sav_gc4,uint8_t *sav_gc5,uint8_t *sav_gc6)
{
    *sav_seq2=vga_get(VGA_SEQ_INDEX,VGA_SEQ_DATA,0x02);
    *sav_seq4=vga_get(VGA_SEQ_INDEX,VGA_SEQ_DATA,0x04);
    *sav_gc4 =vga_get(VGA_GC_INDEX ,VGA_GC_DATA ,0x04);
    *sav_gc5 =vga_get(VGA_GC_INDEX ,VGA_GC_DATA ,0x05);
    *sav_gc6 =vga_get(VGA_GC_INDEX ,VGA_GC_DATA ,0x06);

    vga_set(VGA_SEQ_INDEX,VGA_SEQ_DATA,0x02,0x04);
    vga_set(VGA_SEQ_INDEX,VGA_SEQ_DATA,0x04,0x06);
    vga_set(VGA_GC_INDEX ,VGA_GC_DATA ,0x04,0x02);
    vga_set(VGA_GC_INDEX ,VGA_GC_DATA ,0x05,0x00);
    vga_set(VGA_GC_INDEX ,VGA_GC_DATA ,0x06,0x04);
}

static void vga_end_font_access(uint8_t sav_seq2,uint8_t sav_seq4,
                                uint8_t sav_gc4,uint8_t sav_gc5,uint8_t sav_gc6)
{
    vga_set(VGA_SEQ_INDEX,VGA_SEQ_DATA,0x02,sav_seq2);
    vga_set(VGA_SEQ_INDEX,VGA_SEQ_DATA,0x04,sav_seq4);
    vga_set(VGA_GC_INDEX ,VGA_GC_DATA ,0x04,sav_gc4);
    vga_set(VGA_GC_INDEX ,VGA_GC_DATA ,0x05,sav_gc5);
    vga_set(VGA_GC_INDEX ,VGA_GC_DATA ,0x06,sav_gc6);
}

/* Dump only ASCII 0x20..0x7F directly to out96x16 to avoid large stack arrays */
static int vga_dump_font_ascii_8x16_direct(uint8_t out96x16[96][16])
{
    if (!out96x16)
    {
        return 0;
    }

    uint8_t sav_seq2,sav_seq4,sav_gc4,sav_gc5,sav_gc6;
    vga_begin_font_access(&sav_seq2,&sav_seq4,&sav_gc4,&sav_gc5,&sav_gc6);

    volatile const uint8_t *vram=(volatile const uint8_t*)0xA0000;

    int stride=32;
    {
        volatile const uint8_t *test=vram+(0x41u*32u);
        int nonzero=0;
        for (int i=0;i<16;i++){ if (test[i]!=0){ nonzero=1; break; } }
        if (!nonzero){ stride=16; }
    }

    for (int ch=0x20; ch<=0x7F; ch++)
    {
        volatile const uint8_t *src=vram+(uint32_t)ch*(uint32_t)stride;
        uint8_t *dst=&out96x16[ch-0x20][0];
        for (int r=0;r<16;r++){ dst[r]=(uint8_t)src[r]; }
    }

    vga_end_font_access(sav_seq2,sav_seq4,sav_gc4,sav_gc5,sav_gc6);
    return 1;
}

static void build_visible_box_fallback(uint8_t out96x16[96][16])
{
    for (int i=0;i<96;i++)
    {
        for (int r=0;r<16;r++)
        {
            out96x16[i][r]=(r==0||r==15)?0x7E:0x42;
        }
    }
}

static inline uint32_t min_u32(uint32_t a,uint32_t b){ return (a<b)?a:b; }

static uint32_t s_fg=0xFFFFFFFFu;
static uint32_t s_bg=0xFF000000u;
static uint32_t s_fg_px=0x00FFFFFFu;
static uint32_t s_bg_px=0x00000000u;

static uint8_t       s_rom_font[96][16];
static const uint8_t (*s_font)[16]=NULL;

static uint32_t s_cx=0;
static uint32_t s_cy=0;
static uint32_t s_cell_w=8;
static uint32_t s_cell_h=16;
static uint32_t s_cols=0;
static uint32_t s_rows=0;

static inline uint32_t fb_pack_argb(uint32_t argb)
{
    uint32_t r=(argb>>16)&0xFF;
    uint32_t g=(argb>>8)&0xFF;
    uint32_t b=(argb>>0)&0xFF;
#if VBE_PIXFMT_BGRX
    return (b)|(g<<8)|(r<<16)|0x00000000u;
#else
    return (argb&0x00FFFFFFu);
#endif
}

static void scroll_if_needed(void)
{
    if (s_cy<s_rows){ return; }
    if (!g_vbe.frame_buffer||g_vbe.bpp!=32){ return; }

    uint8_t *base=(uint8_t*)g_vbe.frame_buffer;
    uint32_t shift_bytes=g_vbe.pitch*s_cell_h;
    uint32_t total_bytes=g_vbe.pitch*g_vbe.height;

    if (shift_bytes>=total_bytes)
    {
        memset(base,0,total_bytes);
    }
    else
    {
        for (uint32_t i=0;i<total_bytes-shift_bytes;i++){ base[i]=base[i+shift_bytes]; }

        uint32_t stride32=g_vbe.pitch>>2;
        uint32_t row_px=min_u32(g_vbe.width,stride32);

        for (uint32_t y=g_vbe.height-s_cell_h; y<g_vbe.height; y++)
        {
            uint32_t *row=(uint32_t*)(base+y*g_vbe.pitch);
            for (uint32_t x=0;x<row_px;x++){ row[x]=s_bg_px; }
        }
    }
    s_cy=s_rows-1;
}

int vga_capture_rom_font_early(void)
{
    if (g_vga_rom_have){ return 1; }

    if (vga_dump_font_ascii_8x16_direct(g_vga_rom_ascii))
    {
        g_vga_rom_have=1;
        return 1;
    }

    build_visible_box_fallback(g_vga_rom_ascii);
    g_vga_rom_have=1;
    return 0;
}

static inline void putpixel(uint32_t x,uint32_t y,uint32_t packed_px)
{
    if (!g_vbe.frame_buffer||g_vbe.bpp!=32){ return; }
    uint32_t stride32=g_vbe.pitch>>2;
    if (x>=g_vbe.width||y>=g_vbe.height||x>=stride32){ return; }
    uint8_t *base=(uint8_t*)g_vbe.frame_buffer;
    uint32_t *row=(uint32_t*)(base+y*g_vbe.pitch);
    row[x]=packed_px;
}

static void draw_glyph(char c,uint32_t x,uint32_t y)
{
    if ((unsigned char)c<0x20||(unsigned char)c>0x7F){ c='?'; }
    if (!g_vbe.frame_buffer||g_vbe.bpp!=32){ return; }

    const uint8_t *glyph=s_font[(unsigned char)c-0x20];
    uint32_t stride32=g_vbe.pitch>>2;
    if (x>=g_vbe.width||y>=g_vbe.height||x>=stride32){ return; }

    uint32_t draw_w=min_u32(8u,min_u32(g_vbe.width-x,stride32-x));
    uint32_t draw_h=min_u32(16u,g_vbe.height-y);

    uint8_t *base=(uint8_t*)g_vbe.frame_buffer;

    for (uint32_t gy=0; gy<draw_h; gy++)
    {
        uint32_t *row=(uint32_t*)(base+(y+gy)*g_vbe.pitch)+x;
        uint8_t bits=glyph[gy];
        for (uint32_t gx=0; gx<draw_w; gx++)
        {
            row[gx]=(bits&(0x80u>>gx))?s_fg_px:s_bg_px;
        }
    }
}

int vbe_text_init(void)
{
    if (!g_vbe.frame_buffer||g_vbe.pitch==0||g_vbe.width==0||g_vbe.height==0){ return 0; }
    if (g_vbe.bpp!=32){ return 0; }

    s_cell_w=8;
    s_cell_h=16;

    if (g_vga_rom_have)
    {
        s_font=(const uint8_t (*)[16])g_vga_rom_ascii;
    }
    else if (vga_capture_rom_font_early())
    {
        s_font=(const uint8_t (*)[16])g_vga_rom_ascii;
    }
    else
    {
        build_visible_box_fallback(s_rom_font);
        s_font=(const uint8_t (*)[16])s_rom_font;
    }

    s_cols=g_vbe.width/s_cell_w;
    s_rows=g_vbe.height/s_cell_h;
    if (s_cols==0||s_rows==0){ return 0; }

    s_cx=0;
    s_cy=0;
    s_fg_px=fb_pack_argb(s_fg);
    s_bg_px=fb_pack_argb(s_bg);
    return 1;
}

void vbe_text_clear(uint32_t argb_bg)
{
    if (!g_vbe.frame_buffer||g_vbe.bpp!=32){ return; }
    s_bg=argb_bg;
    s_bg_px=fb_pack_argb(argb_bg);

    uint8_t *base=(uint8_t*)g_vbe.frame_buffer;
    uint32_t stride32=g_vbe.pitch>>2;
    uint32_t row_px=min_u32(g_vbe.width,stride32);

    for (uint32_t y=0;y<g_vbe.height;y++)
    {
        uint32_t *row=(uint32_t*)(base+y*g_vbe.pitch);
        for (uint32_t x=0;x<row_px;x++){ row[x]=s_bg_px; }
    }
}

void vbe_text_set_colors(uint32_t argb_fg,uint32_t argb_bg)
{
    s_fg=argb_fg;
    s_bg=argb_bg;
    s_fg_px=fb_pack_argb(argb_fg);
    s_bg_px=fb_pack_argb(argb_bg);
}

void vbe_text_set_cursor(uint32_t cx,uint32_t cy)
{
    s_cx=(s_cols==0)?0:((cx<s_cols)?cx:(s_cols-1));
    s_cy=(s_rows==0)?0:((cy<s_rows)?cy:(s_rows-1));
}

void vbe_text_get_cursor(uint32_t *out_x,uint32_t *out_y)
{
    if (out_x){ *out_x=s_cx; }
    if (out_y){ *out_y=s_cy; }
}

void vbe_text_putchar(char c)
{
    if (!g_vbe.frame_buffer||g_vbe.bpp!=32||s_cols==0||s_rows==0){ return; }

    if (c=='\r'){ s_cx=0; return; }
    if (c=='\n'){ s_cx=0; s_cy++; scroll_if_needed(); return; }
    if (c=='\t')
    {
        uint32_t next=(s_cx+4)&~3u;
        while (s_cx<next){ vbe_text_putchar(' '); }
        return;
    }
    if (c=='\b')
    {
        if (s_cx>0)
        {
            s_cx--;
            uint32_t px=s_cx*s_cell_w;
            uint32_t py=s_cy*s_cell_h;
            uint32_t stride32=g_vbe.pitch>>2;
            if (px<g_vbe.width&&px<stride32&&py<g_vbe.height)
            {
                uint32_t draw_w=min_u32(s_cell_w,min_u32(g_vbe.width-px,stride32-px));
                uint32_t draw_h=min_u32(s_cell_h,g_vbe.height-py);
                for (uint32_t yy=0; yy<draw_h; yy++)
                {
                    uint32_t *row=(uint32_t*)((uint8_t*)g_vbe.frame_buffer+(py+yy)*g_vbe.pitch)+px;
                    for (uint32_t xx=0; xx<draw_w; xx++){ row[xx]=s_bg_px; }
                }
            }
        }
        return;
    }

    if ((unsigned char)c<0x20||(unsigned char)c>0x7F){ c='?'; }

    uint32_t px=s_cx*s_cell_w;
    uint32_t py=s_cy*s_cell_h;
    draw_glyph(c,px,py);

    s_cx++;
    if (s_cx>=s_cols){ s_cx=0; s_cy++; scroll_if_needed(); }
}

