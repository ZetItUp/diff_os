#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#define WAD_PATH "/games/doom/doom1.wad"
#define CHUNK_SIZE 8192u

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

typedef struct wad_hash_entry_s
{
    uint32_t index;
    struct wad_hash_entry_s *next;
} wad_hash_entry_t;

static wad_lump_t *s_directory = NULL;
static uint32_t s_num_lumps = 0;
static wad_hash_entry_t **s_hash = NULL;
static uint32_t s_hash_size = 0;

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

static unsigned wad_hash_name(const char *name)
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

static int wad_name_matches(const char lump[8], const char *name)
{
    for (int i = 0; i < 8; ++i)
    {
        unsigned char c1 = (unsigned char)lump[i];
        unsigned char c2 = (unsigned char)name[i];

        if (c1 >= 'a' && c1 <= 'z')
        {
            c1 = (unsigned char)(c1 - 'a' + 'A');
        }
        if (c2 >= 'a' && c2 <= 'z')
        {
            c2 = (unsigned char)(c2 - 'a' + 'A');
        }

        if (c2 == '\0')
        {
            return c1 == '\0';
        }

        if (c1 != c2)
        {
            return 0;
        }

        if (c1 == '\0')
        {
            return 1;
        }
    }

    return name[8] == '\0';
}

static void wad_free_hash(void)
{
    if (s_hash != NULL)
    {
        for (uint32_t i = 0; i < s_hash_size; ++i)
        {
            wad_hash_entry_t *entry = s_hash[i];
            while (entry)
            {
                wad_hash_entry_t *next = entry->next;
                free(entry);
                entry = next;
            }
        }

        free(s_hash);
        s_hash = NULL;
        s_hash_size = 0;
    }
}

static void wad_build_hash(void)
{
    wad_free_hash();

    if (s_num_lumps == 0)
    {
        return;
    }

    s_hash_size = s_num_lumps;
    s_hash = calloc(s_hash_size, sizeof(*s_hash));

    if (!s_hash)
    {
        printf("[testwad] failed to allocate hash table\n");
        s_hash_size = 0;
        return;
    }

    for (uint32_t i = 0; i < s_num_lumps; ++i)
    {
        unsigned hash = wad_hash_name(s_directory[i].name) % s_hash_size;
        wad_hash_entry_t *node = malloc(sizeof(*node));

        if (!node)
        {
            printf("[testwad] hash node allocation failed\n");
            continue;
        }

        node->index = i;
        node->next = s_hash[hash];
        s_hash[hash] = node;
    }
}

static int wad_check_num_for_name(const char *name)
{
    if (s_hash != NULL && s_hash_size > 0)
    {
        unsigned hash = wad_hash_name(name) % s_hash_size;
        for (wad_hash_entry_t *entry = s_hash[hash]; entry; entry = entry->next)
        {
            if (wad_name_matches(s_directory[entry->index].name, name))
            {
                return (int)entry->index;
            }
        }
    }

    for (int i = (int)s_num_lumps - 1; i >= 0; --i)
    {
        if (wad_name_matches(s_directory[i].name, name))
        {
            return i;
        }
    }

    return -1;
}

static void wad_probe_name(const char *name)
{
    int lump = wad_check_num_for_name(name);

    if (lump < 0)
    {
        printf("[testwad] lookup %-8s -> NOT FOUND\n", name);
    }
    else
    {
        char trimmed[9];
        trim_lump_name(s_directory[lump].name, trimmed);
        printf("[testwad] lookup %-8s -> lump=%d name=%s pos=%u size=%u\n",
               name,
               lump,
               trimmed,
               (unsigned)s_directory[lump].filepos,
               (unsigned)s_directory[lump].size);
    }
}

int main(void)
{
    printf("[testwad] opening %s\n", WAD_PATH);

    FILE *wad = fopen(WAD_PATH, "rb");
    if (!wad)
    {
        printf("[testwad] failed to open WAD\n");
        return 1;
    }

    if (fseek(wad, 0, SEEK_END) != 0)
    {
        printf("[testwad] failed to seek end\n");
        fclose(wad);
        return 1;
    }

    long file_size = ftell(wad);
    if (file_size < 0)
    {
        printf("[testwad] ftell failed\n");
        fclose(wad);
        return 1;
    }
    rewind(wad);

    wad_header_t header;
    if (fread(&header, sizeof(header), 1, wad) != 1)
    {
        printf("[testwad] failed to read header\n");
        fclose(wad);
        return 1;
    }

    printf("[testwad] ident=%.4s numlumps=%u infotableofs=%u size=%ld\n",
           header.identification,
           (unsigned)header.numlumps,
           (unsigned)header.infotableofs,
           file_size);

    if (header.numlumps == 0)
    {
        printf("[testwad] header numlumps is zero\n");
        fclose(wad);
        return 1;
    }

    s_directory = malloc(header.numlumps * sizeof(wad_lump_t));
    if (!s_directory)
    {
        printf("[testwad] malloc dir failed\n");
        fclose(wad);
        return 1;
    }

    if (fseek(wad, header.infotableofs, SEEK_SET) != 0)
    {
        printf("[testwad] failed to seek to directory\n");
        free(s_directory);
        fclose(wad);
        return 1;
    }

    if (fread(s_directory, sizeof(wad_lump_t), header.numlumps, wad) != header.numlumps)
    {
        printf("[testwad] failed to read directory\n");
        free(s_directory);
        fclose(wad);
        return 1;
    }

    s_num_lumps = header.numlumps;
    wad_build_hash();

    const char *probe_names[] = {
        "F_START",
        "F_END",
        "F1_START",
        "F1_END",
        "FLOOR7_1",
        "FLOOR3_3",
        "FLOOR5_4",
        "FLOOR6_2",
        "FLOOR4_8",
        "TLITE6_1",
        "TLITE6_4",
        "TLITE6_5",
        "TLITE6_6",
        NULL
    };

    for (const char **name = probe_names; *name; ++name)
    {
        wad_probe_name(*name);
    }

    int firstflat = wad_check_num_for_name("F_START") + 1;
    int lastflat = wad_check_num_for_name("F_END") - 1;
    if (firstflat >= 0 && lastflat >= firstflat)
    {
        printf("[testwad] flat range: first=%d last=%d count=%d\n",
               firstflat, lastflat, lastflat - firstflat + 1);
    }
    else
    {
        printf("[testwad] flat markers missing or invalid\n");
    }

    uint8_t *chunk = malloc(CHUNK_SIZE);
    if (!chunk)
    {
        printf("[testwad] malloc chunk failed\n");
        free(s_directory);
        fclose(wad);
        return 1;
    }

    unsigned long long total_read = 0;
    unsigned long long errors = 0;

    for (uint32_t i = 0; i < header.numlumps; ++i)
    {
        const wad_lump_t *l = &s_directory[i];
        unsigned long long end_offset = (unsigned long long)l->filepos + (unsigned long long)l->size;

        char namebuf[9];
        trim_lump_name(l->name, namebuf);

        if (end_offset > (unsigned long long)file_size)
        {
            printf("[testwad] lump %u (%s) out of bounds (end=%llu size=%u)\n",
                   (unsigned)i, namebuf, end_offset, (unsigned)l->size);
            ++errors;
            continue;
        }

        if (fseek(wad, l->filepos, SEEK_SET) != 0)
        {
            printf("[testwad] lump %u (%s) seek failed\n", (unsigned)i, namebuf);
            ++errors;
            continue;
        }

        uint32_t remaining = l->size;
        uint32_t checksum = 0;

        while (remaining > 0)
        {
            size_t step = remaining > CHUNK_SIZE ? CHUNK_SIZE : remaining;
            size_t got = fread(chunk, 1, step, wad);
            if (got != step)
            {
                printf("[testwad] lump %u (%s) read failed (wanted %zu got %zu)\n",
                       (unsigned)i, namebuf, step, got);
                ++errors;
                break;
            }

            for (size_t j = 0; j < got; ++j)
            {
                checksum = (checksum * 33u) ^ chunk[j];
            }

            remaining -= (uint32_t)got;
            total_read += got;
        }

        if (remaining == 0)
        {
            printf("[testwad] lump %u (%s) size=%u checksum=%08x\n",
                   (unsigned)i, namebuf, (unsigned)l->size, checksum);
        }
    }

    printf("[testwad] finished lumps=%u bytes_read=%u errors=%u\n",
           (unsigned)header.numlumps,
           total_read,
           errors);

    free(chunk);
    wad_free_hash();
    free(s_directory);
    fclose(wad);
    return errors ? 1 : 0;
}
