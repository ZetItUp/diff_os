#include <difftga.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* TGA Header structure (18 bytes) */
typedef struct __attribute__((packed)) {
    uint8_t  id_length;
    uint8_t  colormap_type;
    uint8_t  image_type;
    uint16_t colormap_origin;
    uint16_t colormap_length;
    uint8_t  colormap_depth;
    uint16_t x_origin;
    uint16_t y_origin;
    uint16_t width;
    uint16_t height;
    uint8_t  pixel_depth;
    uint8_t  image_descriptor;
} tga_header_t;

/* Image types */
#define TGA_TYPE_TRUECOLOR     2
#define TGA_TYPE_RLE_TRUECOLOR 10

/* Convert BGR(A) pixel to ARGB */
static inline uint32_t bgr_to_argb(uint8_t b, uint8_t g, uint8_t r, uint8_t a)
{
    return ((uint32_t)a << 24) | ((uint32_t)r << 16) | ((uint32_t)g << 8) | (uint32_t)b;
}

/* Read pixel from buffer based on depth */
static inline uint32_t read_pixel(const uint8_t **src, int depth)
{
    uint8_t b = (*src)[0];
    uint8_t g = (*src)[1];
    uint8_t r = (*src)[2];
    uint8_t a = 0xFF;

    if (depth == 32) {
        a = (*src)[3];
        *src += 4;
    } else {
        *src += 3;
    }

    return bgr_to_argb(b, g, r, a);
}

/* Decode uncompressed TGA */
static int decode_uncompressed(const uint8_t *src, uint32_t *pixels,
                               int width, int height, int depth)
{
    int pixel_count = width * height;

    for (int i = 0; i < pixel_count; i++) {
        pixels[i] = read_pixel(&src, depth);
    }

    return 1;
}

/* Decode RLE compressed TGA */
static int decode_rle(const uint8_t *src, const uint8_t *end, uint32_t *pixels,
                      int width, int height, int depth)
{
    int pixel_count = width * height;
    int i = 0;

    while (i < pixel_count && src < end) {
        uint8_t packet = *src++;
        int count = (packet & 0x7F) + 1;

        if (packet & 0x80) {
            /* RLE packet: repeat single pixel */
            uint32_t pixel = read_pixel(&src, depth);
            for (int j = 0; j < count && i < pixel_count; j++) {
                pixels[i++] = pixel;
            }
        } else {
            /* Raw packet: read multiple pixels */
            for (int j = 0; j < count && i < pixel_count; j++) {
                pixels[i++] = read_pixel(&src, depth);
            }
        }
    }

    return (i == pixel_count);
}

/* Flip image vertically (for bottom-left origin) */
static void flip_vertical(uint32_t *pixels, int width, int height)
{
    uint32_t *row = malloc(width * sizeof(uint32_t));
    if (!row) return;

    for (int y = 0; y < height / 2; y++) {
        int top = y * width;
        int bottom = (height - 1 - y) * width;

        memcpy(row, &pixels[top], width * sizeof(uint32_t));
        memcpy(&pixels[top], &pixels[bottom], width * sizeof(uint32_t));
        memcpy(&pixels[bottom], row, width * sizeof(uint32_t));
    }

    free(row);
}

tga_image_t *tga_load_mem(const void *data, size_t size)
{
    if (!data || size < sizeof(tga_header_t)) {
        return NULL;
    }

    const uint8_t *ptr = (const uint8_t *)data;
    const tga_header_t *hdr = (const tga_header_t *)ptr;

    /* Validate image type */
    if (hdr->image_type != TGA_TYPE_TRUECOLOR &&
        hdr->image_type != TGA_TYPE_RLE_TRUECOLOR) {
        return NULL;
    }

    /* Validate pixel depth */
    if (hdr->pixel_depth != 24 && hdr->pixel_depth != 32) {
        return NULL;
    }

    /* Validate dimensions */
    if (hdr->width == 0 || hdr->height == 0) {
        return NULL;
    }

    /* Allocate image structure */
    tga_image_t *img = malloc(sizeof(tga_image_t));
    if (!img) {
        return NULL;
    }

    img->width = hdr->width;
    img->height = hdr->height;
    img->pixels = malloc(img->width * img->height * sizeof(uint32_t));

    if (!img->pixels) {
        free(img);
        return NULL;
    }

    /* Calculate pixel data offset */
    size_t data_offset = sizeof(tga_header_t) + hdr->id_length;
    if (hdr->colormap_type) {
        int colormap_bytes = (hdr->colormap_depth + 7) / 8;
        data_offset += hdr->colormap_length * colormap_bytes;
    }

    if (data_offset >= size) {
        free(img->pixels);
        free(img);
        return NULL;
    }

    const uint8_t *pixel_data = ptr + data_offset;
    const uint8_t *end = ptr + size;
    int success;

    /* Decode pixels */
    if (hdr->image_type == TGA_TYPE_TRUECOLOR) {
        success = decode_uncompressed(pixel_data, img->pixels,
                                      img->width, img->height, hdr->pixel_depth);
    } else {
        success = decode_rle(pixel_data, end, img->pixels,
                             img->width, img->height, hdr->pixel_depth);
    }

    if (!success) {
        free(img->pixels);
        free(img);
        return NULL;
    }

    /* Flip if origin is bottom-left (bit 5 of descriptor = 0) */
    if (!(hdr->image_descriptor & 0x20)) {
        flip_vertical(img->pixels, img->width, img->height);
    }

    return img;
}

tga_image_t *tga_load(const char *path)
{
    FILE *fp = fopen(path, "rb");
    if (!fp) {
        return NULL;
    }

    /* Get file size */
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (file_size <= 0) {
        fclose(fp);
        return NULL;
    }

    /* Read entire file */
    uint8_t *data = malloc(file_size);
    if (!data) {
        fclose(fp);
        return NULL;
    }

    size_t read = fread(data, 1, file_size, fp);
    fclose(fp);

    if (read != (size_t)file_size) {
        free(data);
        return NULL;
    }

    /* Parse TGA */
    tga_image_t *img = tga_load_mem(data, file_size);
    free(data);

    return img;
}

void tga_free(tga_image_t *img)
{
    if (img) {
        if (img->pixels) {
            free(img->pixels);
        }
        free(img);
    }
}
