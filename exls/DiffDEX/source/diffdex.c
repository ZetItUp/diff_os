#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dex/dex.h>
#include <diffdex/diffdex.h>

/* Resource blob layout produced by tools/rsbuild.py */
#define RS_MAGIC      0x53525845u /* 'DEXRS' truncated */
#define RS_VERSION    1

#define RS_TYPE_STRING 1
#define RS_TYPE_U32    2
#define RS_TYPE_BLOB   3

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

static uint32_t fnv1a_32(const char *s)
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

static int load_file(const char *path, uint8_t **out_buf, size_t *out_sz)
{
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    rewind(f);
    uint8_t *buf = (uint8_t *)malloc((size_t)sz);
    if (!buf) { fclose(f); return -1; }
    size_t rd = fread(buf, 1, (size_t)sz, f);
    fclose(f);
    if (rd != (size_t)sz)
    {
        free(buf);
        return -1;
    }
    *out_buf = buf;
    *out_sz = (size_t)sz;
    return 0;
}

static int load_resources_blob(const uint8_t *dex_data, size_t dex_sz, uint8_t **rs_blob, size_t *rs_sz)
{
    if (!dex_data || dex_sz < sizeof(dex_header_t) || !rs_blob || !rs_sz)
        return -1;

    const dex_header_t *hdr = (const dex_header_t *)dex_data;
    if (hdr->magic != DEX_MAGIC || hdr->version_major != DEX_VERSION_MAJOR || hdr->version_minor != DEX_VERSION_MINOR)
        return -1;

    if (hdr->resources_size == 0)
        return -2;

    uint32_t off = hdr->resources_offset;
    uint32_t sz  = hdr->resources_size;
    if (off >= dex_sz || sz == 0 || off + sz > dex_sz)
        return -1;

    uint8_t *buf = (uint8_t *)malloc(sz);
    if (!buf) return -1;
    memcpy(buf, dex_data + off, sz);
    *rs_blob = buf;
    *rs_sz = sz;
    return 0;
}

static const rs_entry_t *find_entry(const rs_header_t *hdr, const uint8_t *blob, const char *name)
{
    if (!hdr || !blob || !name) return NULL;
    const uint32_t name_hash = fnv1a_32(name);
    const uint8_t *table = (const uint8_t *)hdr + sizeof(rs_header_t);
    for (uint32_t i = 0; i < hdr->entry_count; ++i)
    {
        const rs_entry_t *e = (const rs_entry_t *)(table + i * sizeof(rs_entry_t));
        if (e->name_hash == name_hash)
            return e;
    }
    return NULL;
}

static char *dup_string(const void *src, size_t len)
{
    char *s = (char *)malloc(len + 1);
    if (!s) return NULL;
    memcpy(s, src, len);
    s[len] = '\0';
    return s;
}

static int parse_resource_blob(const uint8_t *blob, size_t sz, const rs_header_t **out_hdr)
{
    if (!blob || sz < sizeof(rs_header_t) || !out_hdr)
        return -1;
    const rs_header_t *hdr = (const rs_header_t *)blob;
    if (hdr->magic != RS_MAGIC || hdr->version != RS_VERSION)
        return -1;
    /* basic bounds checks */
    if (hdr->strtab_off >= sz || hdr->data_off >= sz)
        return -1;
    *out_hdr = hdr;
    return 0;
}

static char *get_string_resource(const char *dex_path, const char *key)
{
    uint8_t *dex_buf = NULL;
    size_t dex_sz = 0;
    if (load_file(dex_path, &dex_buf, &dex_sz) != 0)
        return NULL;

    uint8_t *rs_buf = NULL;
    size_t rs_sz = 0;
    char *result = NULL;

    if (load_resources_blob(dex_buf, dex_sz, &rs_buf, &rs_sz) == 0)
    {
        const rs_header_t *rhdr = NULL;
        if (parse_resource_blob(rs_buf, rs_sz, &rhdr) == 0)
        {
            const rs_entry_t *e = find_entry(rhdr, rs_buf, key);
            if (e && e->type == RS_TYPE_STRING && e->data_off + e->data_size <= rs_sz)
            {
                result = dup_string(rs_buf + e->data_off, e->data_size);
            }
        }
    }

    free(rs_buf);
    free(dex_buf);
    return result;
}

static int get_u32_resource(const char *dex_path, const char *key, uint32_t *out)
{
    uint8_t *dex_buf = NULL;
    size_t dex_sz = 0;
    if (load_file(dex_path, &dex_buf, &dex_sz) != 0)
        return -1;

    uint8_t *rs_buf = NULL;
    size_t rs_sz = 0;
    int rc = -1;

    if (load_resources_blob(dex_buf, dex_sz, &rs_buf, &rs_sz) == 0)
    {
        const rs_header_t *rhdr = NULL;
        if (parse_resource_blob(rs_buf, rs_sz, &rhdr) == 0)
        {
            const rs_entry_t *e = find_entry(rhdr, rs_buf, key);
            if (e && e->type == RS_TYPE_U32 && e->data_off + e->data_size <= rs_sz && e->data_size >= 4)
            {
                uint32_t val = 0;
                memcpy(&val, rs_buf + e->data_off, sizeof(uint32_t));
                if (out) *out = val;
                rc = 0;
            }
        }
    }

    free(rs_buf);
    free(dex_buf);
    return rc;
}

char *diffdex_get_resource_string(const char *dex_path, const char *key)
{
    return get_string_resource(dex_path, key);
}

int diffdex_get_resource_u32(const char *dex_path, const char *key, uint32_t *out)
{
    return get_u32_resource(dex_path, key, out);
}

char *diffdex_get_application_title(const char *dex_path)
{
    return get_string_resource(dex_path, "APPLICATION_TITLE");
}

char *diffdex_get_window_title(const char *dex_path)
{
    return get_string_resource(dex_path, "WINDOW_TITLE");
}

int diffdex_get_application_version(const char *dex_path, uint32_t *major, uint32_t *minor)
{
    uint32_t maj = 0, min = 0;
    int rc1 = get_u32_resource(dex_path, "APPLICATION_VERSION_MAJOR", &maj);
    int rc2 = get_u32_resource(dex_path, "APPLICATION_VERSION_MINOR", &min);
    if (rc1 == 0 && rc2 == 0)
    {
        if (major) *major = maj;
        if (minor) *minor = min;
        return 0;
    }
    return -1;
}
