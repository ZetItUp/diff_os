#include <difffonts/fonts.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

typedef struct
{
    int encoding;
    int dwidth;
    int bbx_w;
    int bbx_h;
    int bbx_xoff;
    int bbx_yoff;
    uint8_t *bitmap;   // packed bits, row-major, width rounded up to bytes
} glyph_t;

typedef struct
{
    font_type_t type;
    int width;
    int height;
    glyph_t *glyphs[256];
    glyph_t *fallback;
} font_bdf_t;

struct font
{
    font_type_t type;
    void *impl;
};

static void glyph_free(glyph_t *g)
{
    if (!g) return;
    if (g->bitmap) free(g->bitmap);
    free(g);
}

static void font_bdf_free(font_bdf_t *bdf)
{
    if (!bdf) return;
    for (int i = 0; i < 256; ++i)
    {
        if (bdf->glyphs[i])
        {
            glyph_free(bdf->glyphs[i]);
            bdf->glyphs[i] = NULL;
        }
    }
    if (bdf->fallback)
    {
        glyph_free(bdf->fallback);
        bdf->fallback = NULL;
    }
    free(bdf);
}

void font_destroy(font_t *font)
{
    if (!font) return;

    if (font->type == FONT_TYPE_BDF)
    {
        font_bdf_free((font_bdf_t *)font->impl);
    }

    free(font);
}

int font_width(const font_t *font)
{
    if (!font || !font->impl) return 0;
    if (font->type == FONT_TYPE_BDF) return ((font_bdf_t*)font->impl)->width;
    return 0;
}

int font_height(const font_t *font)
{
    if (!font || !font->impl) return 0;
    if (font->type == FONT_TYPE_BDF) return ((font_bdf_t*)font->impl)->height;
    return 0;
}

static int hex_digit(char c)
{
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
    if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
    return -1;
}

static int parse_hex_row(const char *s, uint8_t *out, int bytes)
{
    for (int i = 0; i < bytes; ++i)
    {
        int hi = hex_digit(s[i * 2]);
        int lo = hex_digit(s[i * 2 + 1]);
        if (hi < 0 || lo < 0) return -1;
        out[i] = (uint8_t)((hi << 4) | lo);
    }
    return 0;
}

static glyph_t* parse_glyph(FILE *fp, int font_bbx_w, int font_bbx_h)
{
    char line[256];
    glyph_t *g = (glyph_t*)calloc(1, sizeof(*g));
    if (!g) return NULL;

    int have_enc = 0, have_dwidth = 0, have_bbx = 0, have_bitmap = 0;
    int bitmap_rows = 0;
    int row_bytes = 0;

    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "ENDCHAR", 7) == 0)
        {
            break;
        }
        else if (strncmp(line, "ENCODING", 8) == 0)
        {
            g->encoding = atoi(line + 9);
            have_enc = 1;
        }
        else if (strncmp(line, "DWIDTH", 6) == 0)
        {
            g->dwidth = atoi(line + 7);
            have_dwidth = 1;
        }
        else if (strncmp(line, "BBX", 3) == 0)
        {
            sscanf(line + 4, "%d %d %d %d", &g->bbx_w, &g->bbx_h, &g->bbx_xoff, &g->bbx_yoff);
            have_bbx = 1;
        }
        else if (strncmp(line, "BITMAP", 6) == 0)
        {
            // Use font-level BBX if glyph BBX missing
            if (!have_bbx)
            {
                g->bbx_w = font_bbx_w;
                g->bbx_h = font_bbx_h;
                g->bbx_xoff = 0;
                g->bbx_yoff = 0;
                have_bbx = 1;
            }
            row_bytes = (g->bbx_w + 7) / 8;
            g->bitmap = (uint8_t*)malloc((size_t)row_bytes * (size_t)g->bbx_h);
            if (!g->bitmap)
            {
                glyph_free(g);
                return NULL;
            }
            memset(g->bitmap, 0, (size_t)row_bytes * (size_t)g->bbx_h);

            bitmap_rows = 0;
            while (bitmap_rows < g->bbx_h && fgets(line, sizeof(line), fp))
            {
                if (line[0] == '\n' || line[0] == '\r')
                    continue;
                if ((int)strlen(line) < row_bytes * 2)
                    break;
                if (parse_hex_row(line, g->bitmap + bitmap_rows * row_bytes, row_bytes) != 0)
                    break;
                bitmap_rows++;
            }
            have_bitmap = 1;
        }
    }

    if (!have_enc || !have_dwidth || !have_bbx || !have_bitmap || bitmap_rows != g->bbx_h)
    {
        glyph_free(g);
        return NULL;
    }

    return g;
}

font_t *font_load_bdf(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        printf("[difffonts] failed to open %s\n", path);
        return NULL;
    }

    char line[256];
    int font_bbx_w = 0, font_bbx_h = 0;
    font_bdf_t *bdf = (font_bdf_t*)calloc(1, sizeof(*bdf));
    if (!bdf)
    {
        fclose(fp);
        return NULL;
    }
    bdf->type = FONT_TYPE_BDF;

    while (fgets(line, sizeof(line), fp))
    {
        if (strncmp(line, "FONTBOUNDINGBOX", 15) == 0)
        {
            sscanf(line + 16, "%d %d", &font_bbx_w, &font_bbx_h);
            bdf->width = font_bbx_w;
            bdf->height = font_bbx_h;
        }
        else if (strncmp(line, "STARTCHAR", 9) == 0)
        {
            glyph_t *g = parse_glyph(fp, font_bbx_w, font_bbx_h);
            if (!g)
            {
                continue;
            }
            if (g->encoding >= 0 && g->encoding < 256)
            {
                bdf->glyphs[g->encoding] = g;
            }
            else
            {
                if (!bdf->fallback)
                {
                    bdf->fallback = g;
                }
                else
                {
                    glyph_free(g);
                }
            }
        }
    }

    fclose(fp);

    if (font_bbx_w <= 0 || font_bbx_h <= 0)
    {
        font_bdf_free(bdf);
        return NULL;
    }

    font_t *font = (font_t*)calloc(1, sizeof(*font));
    if (!font)
    {
        font_bdf_free(bdf);
        return NULL;
    }
    font->type = FONT_TYPE_BDF;
    font->impl = bdf;
    return font;
}

static glyph_t *pick_glyph(const font_bdf_t *bdf, unsigned char c)
{
    glyph_t *g = bdf->glyphs[c];
    if (!g) g = bdf->fallback;
    return g;
}

void font_draw_text(const font_t *font,
                    uint32_t *dst,
                    int pitch_pixels,
                    int x,
                    int y,
                    const char *text,
                    uint32_t fg_argb)
{
    if (!font || !text || !dst) return;
    if (font->type != FONT_TYPE_BDF) return;
    const font_bdf_t *bdf = (const font_bdf_t*)font->impl;
    int pen_x = x;
    int pen_y = y;

    for (const unsigned char *p = (const unsigned char*)text; *p; ++p)
    {
        unsigned char ch = *p;
        if (ch == '\n')
        {
            pen_x = x;
            pen_y += bdf->height;
            continue;
        }

        glyph_t *g = pick_glyph(bdf, ch);
        if (!g)
        {
            pen_x += bdf->width;
            continue;
        }

        int row_bytes = (g->bbx_w + 7) / 8;
        for (int gy = 0; gy < g->bbx_h; ++gy)
        {
            const uint8_t *row = g->bitmap + gy * row_bytes;
            uint32_t *dst_row = dst + (pen_y + gy + g->bbx_yoff) * pitch_pixels + (pen_x + g->bbx_xoff);

            int bit = 7;
            int byte_idx = 0;
            for (int gx = 0; gx < g->bbx_w; ++gx)
            {
                if (row[byte_idx] & (1u << (7 - (gx & 7))))
                {
                    dst_row[gx] = fg_argb;
                }
                if (((gx + 1) & 7) == 0) byte_idx++;
            }
        }

        pen_x += (g->dwidth > 0) ? g->dwidth : bdf->width;
    }
}
