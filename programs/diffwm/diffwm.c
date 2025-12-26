#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <syscall.h>
#include <time.h>
#include <vbe/vbe.h>
#include <video.h>
#include <system/threads.h>
#include <system/process.h>
#include <unistd.h>
#include <system/messaging.h>
#include <system/shared_mem.h>
#include <diffwm/protocol.h>
#include <difffonts/fonts.h>
#include <dirent.h>

// Diff Graphics Library
#include <diffgfx/graphics.h>
#include <diffgfx/draw.h>

// DiffTGA for loading TGA images
#include <difftga.h>

// Internal headers
#include "wm_internal.h"
#include "event.h"
#include "theme.h"
#include "settings.h"
#include "titlebar.h"

// Resource parsing (matches rsbuild.py output)
#define RS_MAGIC      0x53525845u /* 'EXRS' */
#define RS_VERSION    1
#define RS_TYPE_STRING 1
#define RS_TYPE_U32    2
#define RS_TYPE_BLOB   3

#define DEX_MAGIC 0x58454400u  // "DEX\0"

#define APP_ICON_KIND_NONE     0
#define APP_ICON_KIND_EMBEDDED 1
#define APP_ICON_KIND_PATH     2

typedef struct __attribute__((packed)) dex_header
{
    uint32_t magic;
    uint32_t version_major;
    uint32_t version_minor;
    uint32_t entry_offset;
    uint32_t text_offset;
    uint32_t text_size;
    uint32_t rodata_offset;
    uint32_t rodata_size;
    uint32_t data_offset;
    uint32_t data_size;
    uint32_t bss_size;
    uint32_t import_table_offset;
    uint32_t import_table_count;
    uint32_t reloc_table_offset;
    uint32_t reloc_table_count;
    uint32_t symbol_table_offset;
    uint32_t symbol_table_count;
    uint32_t strtab_offset;
    uint32_t strtab_size;
    uint32_t resources_offset;
    uint32_t resources_size;
    uint32_t reserved[6];
} dex_header_t;

typedef struct __attribute__((packed)) rs_header
{
    uint32_t magic;
    uint32_t version;
    uint32_t entry_count;
    uint32_t strtab_off;
    uint32_t strtab_size;
    uint32_t data_off;
} rs_header_t;

typedef struct __attribute__((packed)) rs_entry
{
    uint32_t name_hash;
    uint32_t type;
    uint32_t name_off;
    uint32_t data_off;
    uint32_t data_size;
} rs_entry_t;

// List of windows managed
static wm_window_t *g_windows = NULL;
static uint32_t g_next_id = 1;
static int g_mailbox = -1;
static wm_window_t *g_focused = NULL;
static void wm_draw_window(const dwm_msg_t *msg);
static void wm_apply_window_resources(wm_window_t *window, int client_mailbox_channel);
static void wm_draw_cursor(void);
static int wm_update_mouse(void);
static void wm_remove_window(uint32_t id);

// Event system context
static mouse_state_t g_mouse_state;
static click_state_t g_click_state;
static event_context_t g_event_ctx;

// Accessors for event.c
wm_window_t *wm_get_windows(void) { return g_windows; }
wm_window_t *wm_get_focused(void) { return g_focused; }
void wm_set_focused(wm_window_t *window) { g_focused = window; }
void wm_request_close(wm_window_t *window)
{
    if (!window)
    {
        return;
    }

    dwm_msg_t msg = {0};
    msg.type = DWM_MSG_DESTROY_WINDOW;
    msg.window_id = window->id;
    send_message(window->mailbox, &msg, sizeof(msg));
    wm_remove_window(window->id);
}

// Video mode and backbuffer
static video_mode_info_t g_mode;
static uint32_t *g_buffers[2] = { NULL, NULL };
static int g_active_fb = 0;
static uint32_t *g_backbuffer = NULL;
static uint32_t g_backbuffer_stride = 0; // pixels per line
static size_t g_backbuffer_bytes = 0;
static wm_window_t *g_prev_focus = NULL;
static volatile int g_focus_dirty = 0;
static uint64_t g_last_present_ms = 0;

// Cursor theme and state
static cursor_theme_t g_cursor_theme;
static cursor_type_t g_current_cursor = CURSOR_NORMAL;

// Dirty rectangle tracking
#define MAX_DIRTY_RECTS 16
typedef struct {
    int x, y, w, h;
} dirty_rect_t;

static dirty_rect_t g_dirty_rects[MAX_DIRTY_RECTS];
static int g_dirty_count = 0;
static volatile int g_needs_redraw = 0;
void wm_mark_needs_redraw(void) { g_needs_redraw = 1; }
static void wm_redraw_focus_dirty(void);
static int g_disable_dirty_mark = 0;
static int rects_touch_or_overlap(int ax, int ay, int aw, int ah,
                                  int bx, int by, int bw, int bh)
{
    return aw > 0 && ah > 0 && bw > 0 && bh > 0 &&
           ax <= bx + bw && ax + aw >= bx &&
           ay <= by + bh && ay + ah >= by;
}

static dirty_rect_t rect_union(dirty_rect_t a, dirty_rect_t b)
{
    int x0 = (a.x < b.x) ? a.x : b.x;
    int y0 = (a.y < b.y) ? a.y : b.y;
    int x1 = (a.x + a.w > b.x + b.w) ? a.x + a.w : b.x + b.w;
    int y1 = (a.y + a.h > b.y + b.h) ? a.y + a.h : b.y + b.h;
    dirty_rect_t r = { x0, y0, x1 - x0, y1 - y0 };
    return r;
}

// Resource helpers
static uint32_t rs_fnv1a(const char *s)
{
    uint32_t h = 0x811C9DC5u;
    if (!s) return h;
    while (*s)
    {
        h ^= (uint8_t)(*s++);
        h *= 0x01000193u;
    }
    return h;
}

static const rs_entry_t *rs_find_entry(const rs_header_t *hdr, const uint8_t *blob, const char *key)
{
    if (!hdr || !blob || !key) return NULL;
    uint32_t hash = rs_fnv1a(key);
    const uint8_t *table = (const uint8_t *)hdr + sizeof(rs_header_t);
    for (uint32_t i = 0; i < hdr->entry_count; ++i)
    {
        const rs_entry_t *e = (const rs_entry_t *)(table + i * sizeof(rs_entry_t));
        if (e->name_hash == hash)
        {
            return e;
        }
    }
    return NULL;
}

static char *rs_get_string(const uint8_t *blob, size_t sz, const char *key)
{
    if (!blob || sz < sizeof(rs_header_t)) return NULL;
    const rs_header_t *hdr = (const rs_header_t *)blob;
    if (hdr->magic != RS_MAGIC || hdr->version != RS_VERSION)
    {
        return NULL;
    }
    const rs_entry_t *e = rs_find_entry(hdr, blob, key);
    if (!e || e->type != RS_TYPE_STRING) return NULL;
    if (e->data_off + e->data_size > sz) return NULL;
    size_t len = e->data_size;
    char *s = malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, blob + e->data_off, len);
    s[len] = '\0';

    // Strip surrounding quotes if present
    if (len >= 2 && s[0] == '\"' && s[len - 1] == '\"')
    {
        memmove(s, s + 1, len - 2);
        s[len - 2] = '\0';
    }

    return s;
}

static const uint8_t *rs_get_blob(const uint8_t *blob, size_t sz, const char *key, uint32_t *out_sz)
{
    if (out_sz) *out_sz = 0;
    if (!blob || sz < sizeof(rs_header_t)) return NULL;
    const rs_header_t *hdr = (const rs_header_t *)blob;
    if (hdr->magic != RS_MAGIC || hdr->version != RS_VERSION)
    {
        return NULL;
    }
    const rs_entry_t *e = rs_find_entry(hdr, blob, key);
    if (!e || e->type != RS_TYPE_BLOB) return NULL;
    if (e->data_off + e->data_size > sz) return NULL;
    if (out_sz) *out_sz = e->data_size;
    return blob + e->data_off;
}

static uint8_t *wm_fetch_process_resources(int pid, uint32_t *out_sz)
{
    if (out_sz) *out_sz = 0;
    int needed = process_get_resources(pid, NULL, 0);
    if (needed <= 0 || needed > (1 << 20))
    {
        return NULL;
    }
    uint8_t *buf = malloc((size_t)needed);
    if (!buf)
    {
        return NULL;
    }
    int got = process_get_resources(pid, buf, (uint32_t)needed);
    if (got != needed)
    {
        free(buf);
        return NULL;
    }
    if (out_sz) *out_sz = (uint32_t)needed;
    return buf;
}

static void wm_apply_window_resources(wm_window_t *window, int client_mailbox_channel)
{
    if (!window) return;
    if (window->title_overridden) return;

    // Get the owner PID of the client mailbox
    int owner_pid = message_channel_owner(client_mailbox_channel);
    if (owner_pid <= 0) return;

    uint32_t rsz = 0;
    uint8_t *rblob = wm_fetch_process_resources(owner_pid, &rsz);
    if (!rblob) return;

    // Try to get WINDOW_TITLE first, then APPLICATION_TITLE
    char *title = rs_get_string(rblob, rsz, "WINDOW_TITLE");
    if (!title)
    {
        title = rs_get_string(rblob, rsz, "APPLICATION_TITLE");
    }

    if (title)
    {
        strncpy(window->title, title, sizeof(window->title) - 1);
        window->title[sizeof(window->title) - 1] = '\0';
        free(title);
    }
    else
    {
        strncpy(window->title, "Window", sizeof(window->title) - 1);
    }

    free(rblob);
}

// Compute bounding box of a window including borders and titlebar
void wm_get_decor_bounds(const wm_window_t *win, int *x, int *y, int *w, int *h)
{
    titlebar_get_decor_bounds(win, (int)g_mode.width, (int)g_mode.height, x, y, w, h);
}

// Add a dirty rectangle (will be merged/clipped later)
void wm_add_dirty_rect(int x, int y, int w, int h)
{
    if (g_disable_dirty_mark)
    {
        return;
    }

    // Clamp to screen
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int)g_mode.width) w = (int)g_mode.width - x;
    if (y + h > (int)g_mode.height) h = (int)g_mode.height - y;
    if (w <= 0 || h <= 0) return;

    dirty_rect_t incoming = { x, y, w, h };

    for (int i = 0; i < g_dirty_count; ++i)
    {
        dirty_rect_t *r = &g_dirty_rects[i];
        if (rects_touch_or_overlap(r->x, r->y, r->w, r->h,
                                   incoming.x, incoming.y, incoming.w, incoming.h))
        {
            dirty_rect_t merged = rect_union(*r, incoming);
            g_dirty_rects[i] = merged;

            for (int j = 0; j < g_dirty_count; )
            {
                if (j == i)
                {
                    ++j;
                    continue;
                }
                dirty_rect_t *o = &g_dirty_rects[j];
                if (rects_touch_or_overlap(merged.x, merged.y, merged.w, merged.h,
                                           o->x, o->y, o->w, o->h))
                {
                    merged = rect_union(merged, *o);
                    g_dirty_rects[i] = merged;
                    g_dirty_rects[j] = g_dirty_rects[g_dirty_count - 1];
                    g_dirty_count--;
                    continue;
                }
                ++j;
            }

            g_needs_redraw = 1;
            return;
        }
    }

    // If full, just mark entire screen dirty
    if (g_dirty_count >= MAX_DIRTY_RECTS)
    {
        g_dirty_rects[0].x = 0;
        g_dirty_rects[0].y = 0;
        g_dirty_rects[0].w = (int)g_mode.width;
        g_dirty_rects[0].h = (int)g_mode.height;
        g_dirty_count = 1;
        return;
    }

    g_dirty_rects[g_dirty_count] = incoming;
    g_dirty_count++;
    g_needs_redraw = 1;
}

// Present only dirty region (bounding box of all dirty rects) to the screen
static void wm_request_present(void)
{
    if (!g_backbuffer || g_backbuffer_bytes == 0 || g_dirty_count == 0)
    {
        return;
    }

    // Calculate bounding box of all dirty rects
    int min_x = g_dirty_rects[0].x;
    int min_y = g_dirty_rects[0].y;
    int max_x = g_dirty_rects[0].x + g_dirty_rects[0].w;
    int max_y = g_dirty_rects[0].y + g_dirty_rects[0].h;

    for (int i = 1; i < g_dirty_count; i++)
    {
        dirty_rect_t *r = &g_dirty_rects[i];
        if (r->x < min_x) min_x = r->x;
        if (r->y < min_y) min_y = r->y;
        if (r->x + r->w > max_x) max_x = r->x + r->w;
        if (r->y + r->h > max_y) max_y = r->y + r->h;
    }

    int w = max_x - min_x;
    int h = max_y - min_y;

    // Copy only the dirty region to framebuffer
    // Calculate pointer to start of dirty region in backbuffer
    uint32_t *src = g_backbuffer + (size_t)min_y * g_backbuffer_stride + min_x;

    // Use syscall with offset pointer and adjusted dimensions
    // The pitch stays the same (full row width), but we start from offset
    system_video_present_region(src, (int)g_mode.pitch, min_x, min_y, w, h);

    g_dirty_count = 0;
    g_needs_redraw = 0;
}

static int rects_intersect(int ax, int ay, int aw, int ah, int bx, int by, int bw, int bh)
{
    return aw > 0 && ah > 0 && bw > 0 && bh > 0 &&
           ax < bx + bw && ax + aw > bx &&
           ay < by + bh && ay + ah > by;
}

typedef struct app_icon_info
{
    char name[NAME_MAX];
    uint8_t kind;
    const uint8_t *data;
    uint32_t data_len;
} app_icon_info_t;

static int wm_parse_app_icon_blob(const uint8_t *data, size_t data_sz, app_icon_info_t *out)
{
    if (!data || data_sz < 8 || !out) return 0;

    uint16_t name_len = (uint16_t)(data[0] | (data[1] << 8));
    uint8_t kind = data[2];
    uint32_t payload_len = (uint32_t)(data[4] |
                                      (data[5] << 8) |
                                      (data[6] << 16) |
                                      (data[7] << 24));
    size_t offset = 8;
    if (offset + name_len > data_sz) return 0;
    size_t copy_len = name_len;
    if (copy_len >= sizeof(out->name)) copy_len = sizeof(out->name) - 1;
    if (copy_len > 0)
    {
        memcpy(out->name, data + offset, copy_len);
    }
    out->name[copy_len] = '\0';
    offset += name_len;
    if (offset + payload_len > data_sz) return 0;

    out->kind = kind;
    out->data = data + offset;
    out->data_len = payload_len;
    return (kind != APP_ICON_KIND_NONE && payload_len > 0);
}

static int wm_read_all(int fd, void *buf, size_t size)
{
    uint8_t *dst = (uint8_t *)buf;
    size_t total = 0;
    while (total < size)
    {
        long r = system_read(fd, dst + total, (unsigned long)(size - total));
        if (r <= 0)
        {
            return -1;
        }
        total += (size_t)r;
    }
    return 0;
}

static uint8_t *wm_load_dex_resources(const char *path, uint32_t *out_sz)
{
    if (out_sz) *out_sz = 0;
    if (!path || !path[0]) return NULL;

    int fd = system_open(path, 0, 0);
    if (fd < 0) return NULL;

    dex_header_t hdr;
    if (wm_read_all(fd, &hdr, sizeof(hdr)) != 0)
    {
        system_close(fd);
        return NULL;
    }

    if (hdr.magic != DEX_MAGIC || hdr.resources_offset == 0 || hdr.resources_size == 0)
    {
        system_close(fd);
        return NULL;
    }

    long file_size = system_lseek(fd, 0, SEEK_END);
    if (file_size < 0)
    {
        system_close(fd);
        return NULL;
    }

    if ((uint32_t)file_size < hdr.resources_offset + hdr.resources_size)
    {
        system_close(fd);
        return NULL;
    }

    if (system_lseek(fd, (long)hdr.resources_offset, SEEK_SET) < 0)
    {
        system_close(fd);
        return NULL;
    }

    uint8_t *buf = malloc(hdr.resources_size);
    if (!buf)
    {
        system_close(fd);
        return NULL;
    }

    if (wm_read_all(fd, buf, hdr.resources_size) != 0)
    {
        free(buf);
        system_close(fd);
        return NULL;
    }

    system_close(fd);
    if (out_sz) *out_sz = hdr.resources_size;
    return buf;
}

static int wm_path_has_suffix(const char *path, const char *suffix)
{
    if (!path || !suffix) return 0;
    size_t len = strlen(path);
    size_t slen = strlen(suffix);
    if (slen == 0 || len < slen) return 0;
    return strcmp(path + (len - slen), suffix) == 0;
}

static tga_image_t *wm_load_icon_from_rs_blob(const uint8_t *blob, size_t sz)
{
    uint32_t icon_sz = 0;
    const uint8_t *icon_blob = rs_get_blob(blob, sz, "APPLICATION_ICON", &icon_sz);
    if (!icon_blob || icon_sz == 0) return NULL;

    app_icon_info_t info;
    memset(&info, 0, sizeof(info));
    if (!wm_parse_app_icon_blob(icon_blob, icon_sz, &info))
    {
        return NULL;
    }

    if (info.kind == APP_ICON_KIND_PATH)
    {
        char path[256];
        size_t copy_len = info.data_len;
        if (copy_len >= sizeof(path)) copy_len = sizeof(path) - 1;
        if (copy_len == 0) return NULL;
        memcpy(path, info.data, copy_len);
        path[copy_len] = '\0';
        return tga_load(path);
    }
    if (info.kind == APP_ICON_KIND_EMBEDDED)
    {
        return tga_load_mem(info.data, info.data_len);
    }

    return NULL;
}

static tga_image_t *wm_load_icon_from_dex(const char *path)
{
    uint32_t rsz = 0;
    uint8_t *rblob = wm_load_dex_resources(path, &rsz);
    if (!rblob) return NULL;
    tga_image_t *img = wm_load_icon_from_rs_blob(rblob, rsz);
    free(rblob);
    return img;
}

static void wm_apply_app_title_from_dex(const char *path, char *out, size_t out_sz)
{
    if (!path || !out || out_sz == 0) return;
    uint32_t rsz = 0;
    uint8_t *rblob = wm_load_dex_resources(path, &rsz);
    if (!rblob) return;

    char *title = rs_get_string(rblob, rsz, "APPLICATION_TITLE");
    if (!title)
    {
        title = rs_get_string(rblob, rsz, "WINDOW_TITLE");
    }

    if (title)
    {
        strncpy(out, title, out_sz - 1);
        out[out_sz - 1] = '\0';
        free(title);
    }

    free(rblob);
}

// Desktop icons
#ifndef DT_LNK
#define DT_LNK 10
#endif

#define DESKTOP_MAX_ICONS 64
#define DESKTOP_ICON_MARGIN 21
#define DESKTOP_ICON_COL_GAP 5
#define DESKTOP_ICON_ROW_GAP 5
#define DESKTOP_ICON_LABEL_GAP 4

typedef struct desktop_icon
{
    char name[NAME_MAX];
    char path[256];
    char launch_path[256];
    uint8_t type;
    tga_image_t *icon_img;
    int icon_x;
    int icon_y;
    int bbox_x;
    int bbox_y;
    int bbox_w;
    int bbox_h;
    int label_x;
    int label_y;
    int selected;
} desktop_icon_t;

static desktop_icon_t g_desktop_icons[DESKTOP_MAX_ICONS];
static int g_desktop_icon_count = 0;
static char g_desktop_root[256] = {0};
static tga_image_t *g_desktop_default_icon = NULL;

static void wm_desktop_layout_icons(void)
{
    if (g_desktop_icon_count <= 0)
    {
        return;
    }

    font_t *title_font = titlebar_get_font();
    int font_w = title_font ? font_width(title_font) : 0;
    int font_h = title_font ? font_height(title_font) : 0;
    int label_h = title_font ? font_h : 0;

    int x = DESKTOP_ICON_MARGIN;
    int y = DESKTOP_ICON_MARGIN;

    for (int i = 0; i < g_desktop_icon_count; ++i)
    {
        desktop_icon_t *icon = &g_desktop_icons[i];
        tga_image_t *img = icon->icon_img ? icon->icon_img : g_desktop_default_icon;
        int icon_w = img ? (int)img->width : 32;
        int icon_h = img ? (int)img->height : 32;
        int text_w = (title_font && icon->name[0]) ? (int)strlen(icon->name) * font_w : 0;
        int bbox_w = icon_w;
        int bbox_x = x;

        if (text_w > icon_w)
        {
            int shift = (text_w - icon_w) / 2;
            bbox_x = x - shift;
            if (bbox_x < 0) bbox_x = 0;
            bbox_w = text_w;
        }

        int total_h = icon_h + (label_h ? (DESKTOP_ICON_LABEL_GAP + label_h) : 0);

        icon->icon_x = x;
        icon->icon_y = y;
        icon->bbox_x = bbox_x;
        icon->bbox_y = y;
        icon->bbox_w = bbox_w;
        icon->bbox_h = total_h;
        icon->label_x = x + (icon_w - text_w) / 2;
        if (icon->label_x < 0) icon->label_x = 0;
        icon->label_y = y + icon_h + DESKTOP_ICON_LABEL_GAP;

        y += total_h + DESKTOP_ICON_ROW_GAP;
        if (y + total_h > (int)g_mode.height)
        {
            y = DESKTOP_ICON_MARGIN;
            x += icon_w + DESKTOP_ICON_COL_GAP;
        }
    }
}

static void wm_desktop_load_icons(void)
{
    g_desktop_icon_count = 0;
    g_desktop_root[0] = '\0';

    const char *paths[] = { "/users/default/desktop", "/desktop", "/home/desktop" };
    DIR *dir = NULL;
    for (int i = 0; i < (int)(sizeof(paths) / sizeof(paths[0])); ++i)
    {
        dir = opendir(paths[i]);
        if (dir)
        {
            strncpy(g_desktop_root, paths[i], sizeof(g_desktop_root) - 1);
            g_desktop_root[sizeof(g_desktop_root) - 1] = '\0';
            break;
        }
    }

    if (!dir)
    {
        return;
    }

    struct dirent ent;
    while (g_desktop_icon_count < DESKTOP_MAX_ICONS && readdir(dir, &ent) == 0)
    {
        if (ent.d_name[0] == '\0' ||
            (ent.d_name[0] == '.' && ent.d_name[1] == '\0') ||
            (ent.d_name[0] == '.' && ent.d_name[1] == '.' && ent.d_name[2] == '\0'))
        {
            continue;
        }

        desktop_icon_t *icon = &g_desktop_icons[g_desktop_icon_count++];
        memset(icon, 0, sizeof(*icon));
        strncpy(icon->name, ent.d_name, sizeof(icon->name) - 1);
        icon->type = ent.d_type;
        snprintf(icon->path, sizeof(icon->path), "%s/%s", g_desktop_root, ent.d_name);
        snprintf(icon->launch_path, sizeof(icon->launch_path), "%s", icon->path);

        if (icon->type == DT_LNK)
        {
            char target[256];
            int rc = system_readlink(icon->path, target, sizeof(target));
            if (rc > 0)
            {
                strncpy(icon->launch_path, target, sizeof(icon->launch_path) - 1);
                icon->launch_path[sizeof(icon->launch_path) - 1] = '\0';
            }
        }

        if (wm_path_has_suffix(icon->launch_path, ".dex"))
        {
            icon->icon_img = wm_load_icon_from_dex(icon->launch_path);
            wm_apply_app_title_from_dex(icon->launch_path, icon->name, sizeof(icon->name));
        }
    }

    closedir(dir);
    wm_desktop_layout_icons();
}

static void wm_blit_tga_alpha(const tga_image_t *img, int dst_x, int dst_y)
{
    if (!img || !img->pixels || !g_backbuffer) return;

    int img_w = (int)img->width;
    int img_h = (int)img->height;

    int x0 = dst_x;
    int y0 = dst_y;
    int x1 = dst_x + img_w;
    int y1 = dst_y + img_h;

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > (int)g_mode.width) x1 = (int)g_mode.width;
    if (y1 > (int)g_mode.height) y1 = (int)g_mode.height;

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0) return;

    int src_x = x0 - dst_x;
    int src_y = y0 - dst_y;

    for (int y = 0; y < draw_h; ++y)
    {
        uint32_t *dst = g_backbuffer + (size_t)(y0 + y) * g_backbuffer_stride + x0;
        uint32_t *src = img->pixels + (size_t)(src_y + y) * img_w + src_x;

        for (int x = 0; x < draw_w; ++x)
        {
            uint32_t pixel = src[x];
            uint8_t alpha = (pixel >> 24) & 0xFF;

            if (alpha == 0xFF)
            {
                dst[x] = pixel;
            }
            else if (alpha > 0)
            {
                uint32_t bg = dst[x];
                uint32_t inv = 255 - alpha;

                uint32_t r = (((pixel >> 16) & 0xFF) * alpha + ((bg >> 16) & 0xFF) * inv) / 255;
                uint32_t g = (((pixel >> 8) & 0xFF) * alpha + ((bg >> 8) & 0xFF) * inv) / 255;
                uint32_t b = ((pixel & 0xFF) * alpha + (bg & 0xFF) * inv) / 255;

                dst[x] = 0xFF000000 | (r << 16) | (g << 8) | b;
            }
        }
    }
}

static void wm_blit_tga_alpha_tinted(const tga_image_t *img, int dst_x, int dst_y, uint32_t tint)
{
    if (!img || !img->pixels || !g_backbuffer) return;

    int img_w = (int)img->width;
    int img_h = (int)img->height;

    int x0 = dst_x;
    int y0 = dst_y;
    int x1 = dst_x + img_w;
    int y1 = dst_y + img_h;

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > (int)g_mode.width) x1 = (int)g_mode.width;
    if (y1 > (int)g_mode.height) y1 = (int)g_mode.height;

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0) return;

    int src_x = x0 - dst_x;
    int src_y = y0 - dst_y;

    uint32_t tr = (tint >> 16) & 0xFF;
    uint32_t tg = (tint >> 8) & 0xFF;
    uint32_t tb = tint & 0xFF;

    for (int y = 0; y < draw_h; ++y)
    {
        uint32_t *dst = g_backbuffer + (size_t)(y0 + y) * g_backbuffer_stride + x0;
        uint32_t *src = img->pixels + (size_t)(src_y + y) * img_w + src_x;

        for (int x = 0; x < draw_w; ++x)
        {
            uint32_t pixel = src[x];
            uint8_t alpha = (pixel >> 24) & 0xFF;

            if (alpha == 0)
            {
                continue;
            }

            // Apply tint using additive blend (lighten effect)
            uint32_t pr = (pixel >> 16) & 0xFF;
            uint32_t pg = (pixel >> 8) & 0xFF;
            uint32_t pb = pixel & 0xFF;

            // Blend tint with pixel (screen blend for lightening)
            pr = pr + ((255 - pr) * tr) / 512;
            pg = pg + ((255 - pg) * tg) / 512;
            pb = pb + ((255 - pb) * tb) / 512;

            if (pr > 255) pr = 255;
            if (pg > 255) pg = 255;
            if (pb > 255) pb = 255;

            uint32_t tinted = 0xFF000000 | (pr << 16) | (pg << 8) | pb;

            if (alpha == 0xFF)
            {
                dst[x] = tinted;
            }
            else
            {
                uint32_t bg = dst[x];
                uint32_t inv = 255 - alpha;

                uint32_t r = (pr * alpha + ((bg >> 16) & 0xFF) * inv) / 255;
                uint32_t g = (pg * alpha + ((bg >> 8) & 0xFF) * inv) / 255;
                uint32_t b = (pb * alpha + (bg & 0xFF) * inv) / 255;

                dst[x] = 0xFF000000 | (r << 16) | (g << 8) | b;
            }
        }
    }
}

static void wm_draw_desktop_icons(int clip_x, int clip_y, int clip_w, int clip_h)
{
    if (g_desktop_icon_count <= 0)
    {
        return;
    }

    font_t *title_font = titlebar_get_font();

    for (int i = 0; i < g_desktop_icon_count; ++i)
    {
        desktop_icon_t *icon = &g_desktop_icons[i];
        if (!rects_intersect(clip_x, clip_y, clip_w, clip_h,
                             icon->bbox_x, icon->bbox_y, icon->bbox_w, icon->bbox_h))
        {
            continue;
        }

        tga_image_t *img = icon->icon_img ? icon->icon_img : g_desktop_default_icon;
        if (img)
        {
            if (icon->selected)
            {
                wm_blit_tga_alpha_tinted(img, icon->icon_x, icon->icon_y, ICON_TINT_SELECTED);
            }
            else
            {
                wm_blit_tga_alpha(img, icon->icon_x, icon->icon_y);
            }
        }

        if (title_font && icon->name[0])
        {
            uint32_t text_color = icon->selected ? ICON_TINT_SELECTED : 0xFFFFFFFF;
            font_draw_text(title_font,
                           g_backbuffer,
                           g_backbuffer_stride,
                           icon->label_x,
                           icon->label_y,
                           icon->name,
                           text_color);
        }
    }
}

static int wm_desktop_icon_at(int x, int y)
{
    for (int i = 0; i < g_desktop_icon_count; ++i)
    {
        desktop_icon_t *icon = &g_desktop_icons[i];
        if (x >= icon->bbox_x && x < icon->bbox_x + icon->bbox_w &&
            y >= icon->bbox_y && y < icon->bbox_y + icon->bbox_h)
        {
            return i;
        }
    }

    return -1;
}

static void wm_desktop_deselect_all(void)
{
    for (int i = 0; i < g_desktop_icon_count; ++i)
    {
        if (g_desktop_icons[i].selected)
        {
            g_desktop_icons[i].selected = 0;
            wm_add_dirty_rect(g_desktop_icons[i].bbox_x, g_desktop_icons[i].bbox_y,
                              g_desktop_icons[i].bbox_w, g_desktop_icons[i].bbox_h);
        }
    }
}

int wm_desktop_handle_single_click(int x, int y)
{
    int idx = wm_desktop_icon_at(x, y);

    // Deselect all icons first
    wm_desktop_deselect_all();

    if (idx < 0)
    {
        // Clicked on empty space - just deselect
        wm_mark_needs_redraw();
        return 0;
    }

    // Select the clicked icon
    g_desktop_icons[idx].selected = 1;
    wm_add_dirty_rect(g_desktop_icons[idx].bbox_x, g_desktop_icons[idx].bbox_y,
                      g_desktop_icons[idx].bbox_w, g_desktop_icons[idx].bbox_h);
    wm_mark_needs_redraw();
    return 1;
}

int wm_desktop_handle_click(int x, int y)
{
    int idx = wm_desktop_icon_at(x, y);
    if (idx < 0)
    {
        return 0;
    }

    desktop_icon_t *icon = &g_desktop_icons[idx];
    if (icon->type == DT_DIR)
    {
        return 0;
    }

    const char *launch_path = icon->launch_path[0] ? icon->launch_path : icon->path;

    int pid = spawn_process(launch_path, 0, NULL);
    return (pid >= 0) ? 1 : 0;
}

static void wm_fill_bg_region(int x, int y, int w, int h)
{
    if (!g_backbuffer) return;

    // Clamp
    if (x < 0) { w += x; x = 0; }
    if (y < 0) { h += y; y = 0; }
    if (x + w > (int)g_mode.width) w = (int)g_mode.width - x;
    if (y + h > (int)g_mode.height) h = (int)g_mode.height - y;
    if (w <= 0 || h <= 0) return;

    const uint32_t bg = color_rgb(69, 67, 117);
    for (int row = y; row < y + h; row++)
    {
        uint32_t *dst = g_backbuffer + (size_t)row * g_backbuffer_stride + x;
        for (int col = 0; col < w; col++)
        {
            dst[col] = bg;
        }
    }

}

// Repaint background and any windows intersecting the current dirty area
static void wm_repaint_dirty_region(void)
{
    if (g_dirty_count == 0)
    {
        return;
    }

    // Compute bounding box of current dirty rects
    int min_x = g_dirty_rects[0].x;
    int min_y = g_dirty_rects[0].y;
    int max_x = g_dirty_rects[0].x + g_dirty_rects[0].w;
    int max_y = g_dirty_rects[0].y + g_dirty_rects[0].h;

    for (int i = 1; i < g_dirty_count; i++)
    {
        dirty_rect_t *r = &g_dirty_rects[i];
        if (r->x < min_x) min_x = r->x;
        if (r->y < min_y) min_y = r->y;
        if (r->x + r->w > max_x) max_x = r->x + r->w;
        if (r->y + r->h > max_y) max_y = r->y + r->h;
    }

    int dirty_w = max_x - min_x;
    int dirty_h = max_y - min_y;

    // Temporarily suppress dirty marking during repaint
    g_disable_dirty_mark = 1;

    wm_fill_bg_region(min_x, min_y, dirty_w, dirty_h);
    wm_draw_desktop_icons(min_x, min_y, dirty_w, dirty_h);

    // Collect windows so we can paint bottom-to-top (oldest first).
    wm_window_t *win_stack[128];
    int win_count = 0;
    for (wm_window_t *win = g_windows; win && win_count < 128; win = win->next)
    {
        win_stack[win_count++] = win;
    }

    // Paint all non-focused windows first (oldest → newest)
    for (int i = win_count - 1; i >= 0; --i)
    {
        wm_window_t *win = win_stack[i];
        if (win == g_focused)
        {
            continue;
        }
        int wx, wy, ww, wh;
        wm_get_decor_bounds(win, &wx, &wy, &ww, &wh);

        if (rects_intersect(min_x, min_y, dirty_w, dirty_h, wx, wy, ww, wh))
        {
            dwm_msg_t msg = {0};
            msg.window_id = win->id;
            wm_draw_window(&msg);
        }
    }

    // Draw focused window last so its border stays on top.
    if (g_focused)
    {
        wm_window_t *fwin = g_focused;
        int wx, wy, ww, wh;
        wm_get_decor_bounds(fwin, &wx, &wy, &ww, &wh);

        if (rects_intersect(min_x, min_y, dirty_w, dirty_h, wx, wy, ww, wh))
        {
            dwm_msg_t msg = {0};
            msg.window_id = fwin->id;
            wm_draw_window(&msg);
        }
    }

    g_disable_dirty_mark = 0;

    // Collapse dirty list to the bounding box we just repainted
    g_dirty_rects[0].x = min_x;
    g_dirty_rects[0].y = min_y;
    g_dirty_rects[0].w = dirty_w;
    g_dirty_rects[0].h = dirty_h;
    g_dirty_count = 1;
}

// Try to present, rate-limited to ~60 FPS (16ms). Returns 1 if presented.
static int wm_try_present(void)
{
    if (!g_needs_redraw)
    {
        return 0;
    }

    uint64_t now = monotonic_ms();
    if (now < g_last_present_ms)
    {
        g_last_present_ms = now;
    }
    // Rate limit to ~60 FPS (16ms between frames)
    if (now - g_last_present_ms < 16)
    {
        return 0;
    }

    wm_redraw_focus_dirty();
    wm_repaint_dirty_region();
    wm_draw_cursor();  // Draw cursor on top of everything
    wm_request_present();
    g_last_present_ms = now;
    return 1;
}

wm_window_t* wm_find(uint32_t id)
{
    for(wm_window_t *win = g_windows; win; win = win->next)
    {
        if(win->id == id)
        {
            return win;
        }
    }

    return NULL;
}

// Move window to front of list (bring to top of z-order)
static void wm_bring_to_front(wm_window_t *window)
{
    if (!window || g_windows == window) return;

    // Find and unlink window from current position
    wm_window_t **pp = &g_windows;
    while (*pp && *pp != window)
    {
        pp = &(*pp)->next;
    }
    if (*pp == window)
    {
        *pp = window->next;
        // Insert at front
        window->next = g_windows;
        g_windows = window;
    }
}

// Set focus to a specific window, sending events to old and new focused windows
void wm_set_focus(wm_window_t *window)
{
    if (g_focused == window)
    {
        if (window)
        {
            wm_bring_to_front(window);
            g_event_ctx.windows = g_windows;
            g_event_ctx.focused = window;
            if (!window->focus_notified)
            {
                event_send_focus(window, 1);
                window->focus_notified = 1;
            }
        }
        return;
    }

    wm_window_t *old_focus = g_focused;

    // Notify old focused window it lost focus
    if (g_focused)
    {
        event_send_focus(g_focused, 0);
    }

    // Bring window to front of z-order
    wm_bring_to_front(window);
    g_event_ctx.windows = g_windows;

    g_focused = window;
    g_event_ctx.focused = window;

    // Notify new focused window it gained focus
    if (g_focused)
    {
        event_send_focus(g_focused, 1);
        g_focused->focus_notified = 1;
    }

    g_prev_focus = old_focus;
    g_focus_dirty = 1; // Need to repaint borders for focus change

    // Immediately redraw focus-sensitive decorations and present
    // wm_redraw_focus_dirty() now clears and draws directly, so no need
    // for wm_repaint_dirty_region() which would erase our drawings
    wm_redraw_focus_dirty();
    wm_draw_cursor();
    wm_request_present();
}

static void wm_add_window(wm_window_t *window)
{
    window->next = g_windows;
    g_windows = window;

    // New windows automatically get focus, but don't send focus events yet
    // (the client hasn't received its CREATE reply, so it can't handle events)
    // However, we DO need to repaint the old focused window's decorations
    wm_window_t *old_focus = g_focused;
    g_focused = window;
    g_event_ctx.focused = window;
    g_event_ctx.windows = g_windows;

    // Repaint old window with unfocused decorations
    if (old_focus)
    {
        int dx, dy, dw, dh;
        wm_get_decor_bounds(old_focus, &dx, &dy, &dw, &dh);
        wm_fill_bg_region(dx, dy, dw, dh);

        dwm_msg_t msg = {0};
        msg.window_id = old_focus->id;
        wm_draw_window(&msg);

        wm_add_dirty_rect(dx, dy, dw, dh);

        // Present immediately so decorations update is visible
        wm_draw_cursor();
        wm_request_present();

        // Send focus lost event to the old window
        event_send_focus(old_focus, 0);
    }

    // Mark the new window's decorated bounds as dirty so it renders on first present.
    int nx, ny, nw, nh;
    wm_get_decor_bounds(window, &nx, &ny, &nw, &nh);
    wm_add_dirty_rect(nx, ny, nw, nh);

    g_needs_redraw = 1;
}

// Fast inline memset32 for WM
static inline void wm_memset32(uint32_t *dst, uint32_t val, size_t count)
{
    while (count >= 4)
    {
        dst[0] = val; dst[1] = val; dst[2] = val; dst[3] = val;
        dst += 4;
        count -= 4;
    }
    while (count--)
    {
        *dst++ = val;
    }
}

// Clear a region of the backbuffer to the desktop background color
void wm_clear_region(int x, int y, int w, int h)
{
    if (!g_backbuffer) return;

    const uint32_t bg = color_rgb(69, 67, 117);

    // Clamp to screen bounds
    int x0 = (x < 0) ? 0 : x;
    int y0 = (y < 0) ? 0 : y;
    int x1 = x + w;
    int y1 = y + h;
    if (x1 > (int)g_mode.width) x1 = (int)g_mode.width;
    if (y1 > (int)g_mode.height) y1 = (int)g_mode.height;

    int row_width = x1 - x0;
    int row_height = y1 - y0;
    if (row_width <= 0 || row_height <= 0) return;

    for (int row = y0; row < y1; row++)
    {
        uint32_t *dst = g_backbuffer + (size_t)row * g_backbuffer_stride + x0;
        wm_memset32(dst, bg, (size_t)row_width);
    }

    // Mark cleared region as dirty
    wm_add_dirty_rect(x0, y0, row_width, row_height);
}

// Draw the mouse cursor at the current position
static void wm_draw_cursor(void)
{
    const cursor_t *cursor = theme_get_cursor(&g_cursor_theme, g_current_cursor);
    if (!cursor || !cursor->image || !g_backbuffer) return;

    tga_image_t *img = cursor->image;
    int cursor_w = (int)img->width;
    int cursor_h = (int)img->height;

    // Calculate draw position with hotspot offset
    int draw_x = g_mouse_state.x - cursor->hotspot_x;
    int draw_y = g_mouse_state.y - cursor->hotspot_y;

    // Clamp to screen bounds
    int x0 = draw_x;
    int y0 = draw_y;
    int x1 = draw_x + cursor_w;
    int y1 = draw_y + cursor_h;

    if (x0 < 0) x0 = 0;
    if (y0 < 0) y0 = 0;
    if (x1 > (int)g_mode.width) x1 = (int)g_mode.width;
    if (y1 > (int)g_mode.height) y1 = (int)g_mode.height;

    int draw_w = x1 - x0;
    int draw_h = y1 - y0;
    if (draw_w <= 0 || draw_h <= 0) return;

    // Offset into source image if x0/y0 were clamped
    int src_x = x0 - draw_x;
    int src_y = y0 - draw_y;

    for (int y = 0; y < draw_h; y++)
    {
        uint32_t *dst = g_backbuffer + (size_t)(y0 + y) * g_backbuffer_stride + x0;
        uint32_t *src = img->pixels + (size_t)(src_y + y) * cursor_w + src_x;

        for (int x = 0; x < draw_w; x++)
        {
            uint32_t pixel = src[x];
            uint8_t alpha = (pixel >> 24) & 0xFF;

            if (alpha == 0xFF)
            {
                dst[x] = pixel;
            }
            else if (alpha > 0)
            {
                uint32_t bg = dst[x];
                uint32_t inv = 255 - alpha;

                uint32_t r = (((pixel >> 16) & 0xFF) * alpha + ((bg >> 16) & 0xFF) * inv) / 255;
                uint32_t g = (((pixel >> 8) & 0xFF) * alpha + ((bg >> 8) & 0xFF) * inv) / 255;
                uint32_t b = ((pixel & 0xFF) * alpha + (bg & 0xFF) * inv) / 255;

                dst[x] = 0xFF000000 | (r << 16) | (g << 8) | b;
            }
        }
    }
}

// Update mouse position and mark areas dirty
static int wm_update_mouse(void)
{
    int moved = 0;
    // Get current mouse position from kernel
    system_mouse_get_pos(&g_mouse_state.x, &g_mouse_state.y);

    if (g_mouse_state.x != g_mouse_state.prev_x || g_mouse_state.y != g_mouse_state.prev_y)
    {
        moved = 1;
        const cursor_t *cursor = theme_get_cursor(&g_cursor_theme, g_current_cursor);
        int cursor_w = cursor && cursor->image ? (int)cursor->image->width : 16;
        int cursor_h = cursor && cursor->image ? (int)cursor->image->height : 16;
        int hotspot_x = cursor ? cursor->hotspot_x : 0;
        int hotspot_y = cursor ? cursor->hotspot_y : 0;

        // Clear old cursor position (restore background)
        if (g_mouse_state.prev_x >= 0)
        {
            wm_clear_region(g_mouse_state.prev_x - hotspot_x, g_mouse_state.prev_y - hotspot_y,
                            cursor_w, cursor_h);
        }

        // Mark new cursor position as dirty
        wm_add_dirty_rect(g_mouse_state.x - hotspot_x, g_mouse_state.y - hotspot_y,
                          cursor_w, cursor_h);

        g_mouse_state.prev_x = g_mouse_state.x;
        g_mouse_state.prev_y = g_mouse_state.y;
        g_needs_redraw = 1;
    }

    return moved;
}

// Repaint focus-related window decorations.
// Clears and redraws both the previously focused and newly focused windows
// to update their decoration colors (title bar, border).
static void wm_redraw_focus_dirty(void)
{
    if (!g_focus_dirty)
    {
        return;
    }

    // Clear and redraw the previously focused window (now unfocused)
    if (g_prev_focus)
    {
        int dx, dy, dw, dh;
        wm_get_decor_bounds(g_prev_focus, &dx, &dy, &dw, &dh);

        // Clear the decoration area to background
        wm_fill_bg_region(dx, dy, dw, dh);

        // Redraw the window with unfocused decorations
        dwm_msg_t msg = {0};
        msg.window_id = g_prev_focus->id;
        wm_draw_window(&msg);

        wm_add_dirty_rect(dx, dy, dw, dh);
    }

    // Clear and redraw the newly focused window
    if (g_focused)
    {
        int dx, dy, dw, dh;
        wm_get_decor_bounds(g_focused, &dx, &dy, &dw, &dh);

        // Clear the decoration area to background
        wm_fill_bg_region(dx, dy, dw, dh);

        // Redraw the window with focused decorations
        dwm_msg_t msg = {0};
        msg.window_id = g_focused->id;
        wm_draw_window(&msg);

        wm_add_dirty_rect(dx, dy, dw, dh);
    }

    g_focus_dirty = 0;
}

static void wm_remove_window(uint32_t id)
{
    wm_window_t **winp = &g_windows;

    while(*winp)
    {
        if((*winp)->id == id)
        {
            wm_window_t* window = *winp;

            // Get full decorated bounds (includes titlebar, border, shadow)
            int wx, wy, ww, wh;
            wm_get_decor_bounds(window, &wx, &wy, &ww, &wh);

            *winp = window->next;
            shared_memory_unmap(window->handle);
            shared_memory_release(window->handle);

            if (g_focused == window)
            {
                // Focus the next window in the list, if any
                g_focused = NULL;
                if (g_windows)
                {
                    wm_set_focus(g_windows);
                }
            }
            if (g_prev_focus == window)
            {
                g_prev_focus = NULL;
            }

            free(window);

            // Clear the full decorated region and present immediately
            wm_clear_region(wx, wy, ww, wh);
            wm_repaint_dirty_region();
            wm_draw_cursor();
            wm_request_present();

            return;
        }

        winp = &(*winp)->next;
    }
}

static int wm_create_window(const dwm_window_desc_t *desc, uint32_t *out_id)
{
    int client_channel = connect_message_channel(desc->mailbox_id);
    if(client_channel < 0)
    {
        return -1;
    }

    int map_rc = shared_memory_map(desc->handle);

    if(map_rc < 0)
    {
        return -1;
    }

    void *addr = (void*)(uintptr_t)map_rc;

    if(!addr)
    {
        return -1;
    }

    wm_window_t *window = calloc(1, sizeof(*window));

    if(!window)
    {
        shared_memory_unmap(desc->handle);
        return -1;
    }

    window->id = g_next_id++;
    window->handle = desc->handle;
    window->pixels = addr;
    window->x = desc->x;
    window->y = desc->y;
    window->width = desc->width;
    window->height = desc->height;
    window->flags = desc->flags;
    window->pitch = desc->width * 4;
    window->mailbox = client_channel;
    window->wm_channel = g_mailbox;
    window->drew_once = 0;
    window->focus_notified = 0;
    window->client_drawn = 0;
    window->title_overridden = 0;
    window->titlebar_hover_button = 0;
    window->titlebar_pressed_button = 0;
    strncpy(window->title, "Window", sizeof(window->title) - 1);

    // Try to get window title from client's resources
    wm_apply_window_resources(window, client_channel);

    wm_add_window(window);
    *out_id = window->id;

    return 0;
}

static void wm_draw_window(const dwm_msg_t *msg)
{
    wm_window_t *window = wm_find(msg->window_id);

    if(!window || !g_backbuffer)
    {
        return;
    }

    int x0 = window->x;
    int y0 = window->y;
    int max_y = (y0 + (int)window->height > (int)g_mode.height) ? ((int)g_mode.height - y0) : (int)window->height;
    int max_x = (x0 + (int)window->width > (int)g_mode.width) ? ((int)g_mode.width - x0) : (int)window->width;

    if(max_x <= 0 || max_y <= 0)
    {
        return;
    }

    uint32_t *src = (uint32_t*)window->pixels;
    uint32_t src_stride = (uint32_t)(window->pitch / 4);
    uint32_t *dst = g_backbuffer + (size_t)y0 * g_backbuffer_stride + (size_t)x0;

    // Copy window pixels to backbuffer
    size_t row_bytes = (size_t)max_x * sizeof(uint32_t);
    if(src_stride == (uint32_t)max_x && g_backbuffer_stride == (uint32_t)max_x)
    {
        memcpy(dst, src, row_bytes * (size_t)max_y);
    }
    else
    {
        for(int y = 0; y < max_y; ++y)
        {
            memcpy(dst, src, row_bytes);
            src += src_stride;
            dst += g_backbuffer_stride;
        }
    }

    // Draw titlebar and window frame decorations
    const int is_focused = (window == g_focused);
    titlebar_draw(window, g_backbuffer, g_backbuffer_stride,
                  (int)g_mode.width, (int)g_mode.height, is_focused);

    // Mark dirty area covering window, borders, and title bar
    int dirty_x0, dirty_y0, dirty_w, dirty_h;
    wm_get_decor_bounds(window, &dirty_x0, &dirty_y0, &dirty_w, &dirty_h);
    wm_add_dirty_rect(dirty_x0, dirty_y0, dirty_w, dirty_h);

    window->drew_once = 1;
}

static void wm_handle_message(const dwm_msg_t *msg)
{
    switch(msg->type)
    {
        case DWM_MSG_CREATE_WINDOW:
            {
                dwm_msg_t *reply = calloc(1, sizeof(*reply));
                if (!reply)
                {
                    break;
                }

                reply->type = DWM_MSG_CREATE_WINDOW;
                reply->create.id = 0;

                if(wm_create_window(&msg->create, &reply->create.id) != 0)
                {
                    reply->create.id = 0;
                }

                int client_channel = connect_message_channel(msg->create.mailbox_id);
                if(client_channel < 0)
                {
                    client_channel = g_mailbox;
                }

                send_message(client_channel, reply, sizeof(*reply));

                wm_window_t *created_window = wm_find(reply->create.id);
                if (created_window)
                {
                    wm_set_focus(created_window);
                }

                free(reply);

                break;
            }
        case DWM_MSG_DESTROY_WINDOW:
            {
                wm_remove_window(msg->window_id);
                break;
            }
        case DWM_MSG_DRAW:
            {
                wm_window_t *window = wm_find(msg->window_id);
                if (window)
                {
                    int first_client_draw = !window->client_drawn;
                    window->client_drawn = 1;
                    int dx, dy, dw, dh;
                    wm_get_decor_bounds(window, &dx, &dy, &dw, &dh);
                    wm_add_dirty_rect(dx, dy, dw, dh);
                    if (first_client_draw)
                    {
                        wm_repaint_dirty_region();
                        wm_draw_cursor();
                        wm_request_present();
                    }
                }
                g_needs_redraw = 1;  // Mark as dirty for batched rendering
                break;
            }
        case DWM_MSG_DAMAGE:
            {
                wm_window_t *window = wm_find(msg->window_id);
                if (!window)
                {
                    break;
                }

                if (msg->damage.width <= 0 || msg->damage.height <= 0)
                {
                    break;
                }

                int first_client_draw = !window->client_drawn;
                window->client_drawn = 1;

                // Redraw full decorations to avoid missing borders/title during partial updates.
                int decor_x_position = 0;
                int decor_y_position = 0;
                int decor_width = 0;
                int decor_height = 0;
                wm_get_decor_bounds(window,
                                    &decor_x_position,
                                    &decor_y_position,
                                    &decor_width,
                                    &decor_height);

                wm_add_dirty_rect(decor_x_position,
                                  decor_y_position,
                                  decor_width,
                                  decor_height);
                if (first_client_draw)
                {
                    wm_repaint_dirty_region();
                    wm_draw_cursor();
                    wm_request_present();
                }
                g_needs_redraw = 1;
                break;
            }
        case DWM_MSG_EVENT:
            {
                // Events are sent from WM to clients, not the other way
                break;
            }
        case DWM_MSG_REQUEST_FOCUS:
            {
                wm_window_t *window = wm_find(msg->window_id);
                if (window)
                {
                    wm_set_focus(window);
                }
                break;
            }
        case DWM_MSG_SET_TITLE:
            {
                wm_window_t *window = wm_find(msg->window_id);
                if (window)
                {
                    strncpy(window->title, msg->set_title.title, sizeof(window->title) - 1);
                    window->title[sizeof(window->title) - 1] = '\0';
                    window->title_overridden = 1;

                    int dx, dy, dw, dh;
                    wm_get_decor_bounds(window, &dx, &dy, &dw, &dh);
                    wm_add_dirty_rect(dx, dy, dw, dh);
                    wm_mark_needs_redraw();
                }
                break;
            }
        default:
            break;
    }
}

int main(void)
{
    vbe_toggle_graphics_mode();
    system_console_disable();

    if(system_video_mode_get(&g_mode) < 0)
    {
        return -1;
    }

    g_backbuffer_stride = (uint32_t)(g_mode.pitch / 4);
    if (g_backbuffer_stride < g_mode.width) g_backbuffer_stride = g_mode.width;
    g_backbuffer_bytes = (size_t)g_backbuffer_stride * g_mode.height * sizeof(uint32_t);

    // Allocate double buffers and start drawing into buffer 0.
    for (int i = 0; i < 2; ++i)
    {
        g_buffers[i] = calloc((size_t)g_backbuffer_stride * g_mode.height, sizeof(uint32_t));
        if (!g_buffers[i])
        {
            return -2;
        }
    }
    g_backbuffer = g_buffers[g_active_fb];

    // Load cursor theme
    if (theme_load(&g_cursor_theme, "/system/themes/default.theme") < 0)
    {
        // Theme load failed, but we can continue without cursors
    }

    // Initialize titlebar (loads window skin and title font)
    titlebar_init();
    g_desktop_default_icon = tga_load("/system/graphics/icons/empty_file.tga");

    // Set mouse bounds and center cursor
    system_mouse_set_bounds((int)g_mode.width, (int)g_mode.height);
    system_mouse_set_pos((int)g_mode.width / 2, (int)g_mode.height / 2);
    g_mouse_state.x = (int)g_mode.width / 2;
    g_mouse_state.y = (int)g_mode.height / 2;
    g_mouse_state.buttons_down = system_mouse_get_buttons_down();

    // Initialize event system
    g_event_ctx.mouse = &g_mouse_state;
    g_event_ctx.clicks = &g_click_state;
    g_event_ctx.focused = NULL;
    g_event_ctx.windows = NULL;
    g_event_ctx.screen_width = (int)g_mode.width;
    g_event_ctx.screen_height = (int)g_mode.height;
    event_init(&g_event_ctx);

    g_mailbox = create_message_channel(DWM_MAILBOX_ID);

    if(g_mailbox < 0)
    {
        return -3;
    }

    /* Fill background to a known color before any client draws */
    const uint32_t bg = color_rgb(69, 67, 117);
    size_t total = (size_t)g_backbuffer_stride * g_mode.height;
    for (int b = 0; b < 2; ++b)
    {
        uint32_t *dst = g_buffers[b];
        size_t n = total;
        // Fast unrolled fill
        while (n >= 8)
        {
            dst[0] = bg; dst[1] = bg; dst[2] = bg; dst[3] = bg;
            dst[4] = bg; dst[5] = bg; dst[6] = bg; dst[7] = bg;
            dst += 8;
            n -= 8;
        }
        while (n--)
        {
            *dst++ = bg;
        }

        g_backbuffer = g_buffers[b];
    }
    g_backbuffer = g_buffers[g_active_fb];

    wm_desktop_load_icons();

    // Initialize previous mouse position for dirty tracking
    g_mouse_state.prev_x = g_mouse_state.x;
    g_mouse_state.prev_y = g_mouse_state.y;

    wm_draw_desktop_icons(0, 0, (int)g_mode.width, (int)g_mode.height);

    // Draw initial cursor
    wm_draw_cursor();

    // Initial full-screen present
    system_video_present(g_backbuffer, (int)g_mode.pitch, (int)g_mode.width, (int)g_mode.height);
    g_last_present_ms = monotonic_ms();

    const char *client_path = "/programs/gdterm/gdterm.dex";
    spawn_process(client_path, 0, NULL);

    dwm_msg_t *msg = (dwm_msg_t *)malloc(sizeof(dwm_msg_t));
    if (!msg)
    {
        return -4;
    }

    // Message handling loop with blocking receive + timeout
    // This avoids busy-polling: we block until a message arrives or timeout expires.
    // Timeout allows us to periodically check for keyboard events even when no messages.
    int msg_count = 0;
    const uint32_t RECV_TIMEOUT_MS = 16; // ~60 FPS max, allows keyboard polling

    for(;;)
    {
        // Block until message arrives or timeout (16ms = ~60Hz input polling)
        int rc = receive_message_timeout(g_mailbox, msg, sizeof(*msg), RECV_TIMEOUT_MS);

        if (rc > 0)
        {
            // Got a message - process it
            wm_handle_message(msg);
            msg_count++;

            // Drain any additional queued messages without blocking
            while (msg_count < 64 && try_receive_message(g_mailbox, msg, sizeof(*msg)) > 0)
            {
                wm_handle_message(msg);
                msg_count++;

                // Batch renders: update screen every 4 messages or on explicit draw
                if (g_needs_redraw && (msg_count >= 4 || msg->type == DWM_MSG_DRAW))
                {
                    wm_try_present();
                    msg_count = 0;
                }
            }
        }

        // Update mouse position and check for movement
        int mouse_moved = wm_update_mouse();

        // Update event context with current state
        g_event_ctx.windows = g_windows;
        g_event_ctx.focused = g_focused;

        // Process mouse events with proper consumption
        event_process_mouse(&g_event_ctx, mouse_moved);

        // Flush any pending redraw (either from messages or timeout)
        if (g_needs_redraw)
        {
            wm_try_present();
            msg_count = 0;
        }

        // Deliver keyboard events to the currently focused window
        event_process_keyboard(&g_event_ctx);
    }

    free(g_backbuffer);
    free(msg);

    return 0;
}
