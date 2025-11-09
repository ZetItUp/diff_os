#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

typedef unsigned char uint8_t;

#define TESTDATA_PATH "/programs/filetest/testdata.bin"
#define SAMPLE_WAD_PATH "/programs/filetest/testwad.bin"
#define DOOM_WAD_PATH "/games/doom/doom1.wad"
typedef struct __attribute__((packed))
{
    uint32_t magic;
    uint32_t count;
    uint16_t crc;
} header_t;

typedef struct __attribute__((packed))
{
    char identification[4];
    uint32_t numlumps;
    uint32_t infotableofs;
} wad_header_t;

typedef struct __attribute__((packed))
{
    uint32_t filepos;
    uint32_t size;
    char name[8];
} wad_lump_t;

static void hexdump(const void *data, size_t len)
{
    const uint8_t *p = (const uint8_t *)data;
    for (size_t i = 0; i < len; ++i)
    {
        printf("%02X", p[i]);
        if ((i + 1) % 16 == 0)
        {
            putchar('\n');
        }
        else
        {
            putchar(' ');
        }
    }
    if (len % 16 != 0)
    {
        putchar('\n');
    }
}

static void trim_lump_name(const char src[8], char out[9])
{
    memcpy(out, src, 8);
    out[8] = '\0';

    for (int i = 7; i >= 0; --i)
    {
        if (out[i] == ' ' || out[i] == '\0')
        {
            out[i] = '\0';
        }
        else
        {
            break;
        }
    }
}

static int run_basic_test(void)
{
    FILE *f = fopen(TESTDATA_PATH, "rb");
    if (!f)
    {
        printf("failed to open %s\n", TESTDATA_PATH);
        return 1;
    }

    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);

    printf("size=%ld bytes\n", size);
    printf("binary:\n");

    uint8_t buffer[128];
    size_t n;
    while ((n = fread(buffer, 1, sizeof(buffer), f)) > 0)
    {
        hexdump(buffer, n);
    }

    fseek(f, 0, SEEK_SET);
    printf("\nlines:\n");

    char line[64];
    while (fgets(line, sizeof(line), f))
    {
        line[strcspn(line, "\r\n")] = '\0';
        printf("%s\n", line);
    }

    fseek(f, 0, SEEK_SET);
    header_t hdr;
    size_t rc = fread(&hdr, sizeof(hdr), 1, f);
    if (rc == 1)
    {
        printf("\nSTRUCT magic=%08X count=%u crc=%u\n",
               (unsigned)hdr.magic, (unsigned)hdr.count, (unsigned)hdr.crc);
    }
    else
    {
        printf("\nSTRUCT read failed\n");
    }

    fclose(f);
    return 0;
}

static void make_name8(const char *src, char out[8])
{
    memset(out, 0, 8);
    size_t len = strlen(src);
    if (len > 8)
    {
        len = 8;
    }
    memcpy(out, src, len);
}

static unsigned wad_hash_name(const char name[8])
{
    unsigned result = 5381;
    for (int i = 0; i < 8 && name[i] != '\0'; ++i)
    {
        int c = name[i];
        if (c >= 'a' && c <= 'z')
        {
            c = c - 'a' + 'A';
        }
        result = ((result << 5) ^ result) ^ (unsigned)c;
    }
    return result;
}

static int names_equal(const char a[8], const char b[8])
{
    for (int i = 0; i < 8; ++i)
    {
        unsigned char ca = (unsigned char)a[i];
        unsigned char cb = (unsigned char)b[i];
        if (ca >= 'a' && ca <= 'z')
        {
            ca = ca - 'a' + 'A';
        }
        if (cb >= 'a' && cb <= 'z')
        {
            cb = cb - 'a' + 'A';
        }
        if (ca != cb)
        {
            return 0;
        }
        if (ca == 0)
        {
            return 1;
        }
    }
    return 1;
}

static int find_lump_linear(const wad_lump_t *dir, uint32_t count, const char label8[8])
{
    for (uint32_t i = 0; i < count; ++i)
    {
        if (names_equal(dir[i].name, label8))
        {
            return (int)i;
        }
    }
    return -1;
}

static int dump_lump_payload(FILE *f, const wad_lump_t *lump)
{
    if (fseek(f, lump->filepos, SEEK_SET) != 0)
    {
        return -1;
    }

    uint32_t want = lump->size;
    if (want > 48)
    {
        want = 48;
    }

    uint8_t scratch[64];
    size_t got = fread(scratch, 1, want, f);
    if (got != want)
    {
        return -1;
    }

    hexdump(scratch, got);
    return 0;
}

static int find_lump_hash(const wad_lump_t *dir, uint32_t count, const char label8[8])
{
    unsigned hash_size = count ? count : 1;
    int *heads = malloc(sizeof(int) * hash_size);
    int *next = malloc(sizeof(int) * count);
    if (!heads || !next)
    {
        free(heads);
        free(next);
        return -1;
    }

    for (uint32_t i = 0; i < hash_size; ++i)
    {
        heads[i] = -1;
    }

    for (uint32_t i = 0; i < count; ++i)
    {
        unsigned hash = wad_hash_name(dir[i].name) % hash_size;
        next[i] = heads[hash];
        heads[hash] = (int)i;
    }

    unsigned lookup_hash = wad_hash_name(label8) % hash_size;
    int idx = heads[lookup_hash];
    while (idx >= 0)
    {
        if (names_equal(dir[idx].name, label8))
        {
            break;
        }
        idx = next[idx];
    }

    free(heads);
    free(next);
    return idx;
}

static int run_wad_test(const char *path, int verbose_dir)
{
    FILE *f = fopen(path, "rb");
    if (!f)
    {
        printf("failed to open %s\n", path);
        return 1;
    }

    wad_header_t header;
    if (fread(&header, sizeof(header), 1, f) != 1)
    {
        printf("failed to read WAD header\n");
        fclose(f);
        return 1;
    }

    printf("\n== WAD directory smoke-test ==\n");
    char ident[5];
    memcpy(ident, header.identification, 4);
    ident[4] = '\0';

    printf("ident=%s num_lumps=%u dir_ofs=%u\n",
           ident,
           (unsigned)header.numlumps,
           (unsigned)header.infotableofs);

    if (fseek(f, header.infotableofs, SEEK_SET) != 0)
    {
        printf("failed to seek to directory\n");
        fclose(f);
        return 1;
    }

    wad_lump_t *dir = malloc(header.numlumps * sizeof(wad_lump_t));
    if (!dir)
    {
        printf("malloc failed for directory\n");
        fclose(f);
        return 1;
    }

    if (fread(dir, sizeof(wad_lump_t), header.numlumps, f) != header.numlumps)
    {
        printf("failed to read directory entries\n");
        free(dir);
        fclose(f);
        return 1;
    }

    if (verbose_dir)
    {
        for (uint32_t i = 0; i < header.numlumps; ++i)
        {
            char name[9];
            trim_lump_name(dir[i].name, name);
            printf("  [%02u] name=%-8s filepos=%u size=%u\n",
                   (unsigned)i, name[0] ? name : "(blank)",
                   (unsigned)dir[i].filepos,
                   (unsigned)dir[i].size);
        }
    }
    else
    {
        uint32_t limit = header.numlumps < 10 ? header.numlumps : 10;
        for (uint32_t i = 0; i < limit; ++i)
        {
            char name[9];
            trim_lump_name(dir[i].name, name);
            printf("  [%02u] name=%-8s filepos=%u size=%u\n",
                   (unsigned)i, name[0] ? name : "(blank)",
                   (unsigned)dir[i].filepos,
                   (unsigned)dir[i].size);
        }
        if (header.numlumps > limit)
        {
            printf("  ... (%u total entries)\n", (unsigned)header.numlumps);
        }
    }

    const char *need[] = {"IMPXA1", "ETTNA1", "POSSA1", "E1M8"};
    size_t failures = 0;

    for (size_t i = 0; i < sizeof(need) / sizeof(need[0]); ++i)
    {
        char label8[8];
        make_name8(need[i], label8);

        int idx_linear = find_lump_linear(dir, header.numlumps, label8);
        int idx_hash = find_lump_hash(dir, header.numlumps, label8);

        printf("lookup %s -> linear=%d hash=%d\n", need[i], idx_linear, idx_hash);

        if (idx_linear >= 0)
        {
            printf("  filepos=%u size=%u\n",
                   (unsigned)dir[idx_linear].filepos,
                   (unsigned)dir[idx_linear].size);

            if (dump_lump_payload(f, &dir[idx_linear]) != 0)
            {
                printf("  failed to read payload for %s\n", need[i]);
                ++failures;
            }
        }
        else
        {
            ++failures;
        }
    }

    free(dir);
    fclose(f);
    return (int)failures;
}

int main(void)
{
    int rc = 0;
    rc += run_basic_test();
    rc += run_wad_test(SAMPLE_WAD_PATH, 1);
    rc += run_wad_test(DOOM_WAD_PATH, 0);
    return rc;
}
