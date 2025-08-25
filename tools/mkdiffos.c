#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR_SIZE 512
#define RESERVED_STAGE2_SECTORS 31
#define FS_START_LBA 2048
#define PARTITION_TYPE 0xC8
#define MAX_FILES 256
#define MAX_FILENAME_LEN 256

typedef enum
{
    ENTRY_TYPE_INVALID = 0,
    ENTRY_TYPE_FILE = 1,
    ENTRY_TYPE_DIR  = 2
} EntryType;

typedef struct
{
    uint32_t entry_id;
    uint32_t parent_id;
    EntryType type;
    char filename[MAX_FILENAME_LEN];
    uint32_t start_sector;
    uint32_t sector_count;
    uint32_t file_size_bytes;
    uint32_t created_timestamp;
    uint32_t modified_timestamp;
    uint8_t reserved[32];
} __attribute__((packed)) FileEntry;

typedef struct
{
    uint32_t magic;
    uint32_t version;
    uint32_t total_sectors;
    uint32_t file_table_sector;
    uint32_t file_table_size;          // sectors
    uint32_t file_table_bitmap_sector;
    uint32_t file_table_bitmap_size;   // sectors
    uint32_t sector_bitmap_sector;
    uint32_t sector_bitmap_size;       // sectors
    uint32_t root_dir_id;
    uint32_t feature_flags;
    uint8_t reserved[480];
} __attribute__((packed)) SuperBlock;

/* ----------- Viktigt: on-disk tabell = ENBART entries[] ----------- */
typedef struct
{
    FileEntry entries[MAX_FILES];
} FileTableOnDisk;

/* Bygghjälp: håll koll på count i RAM, men skriv inte 'count' till disk */
typedef struct
{
    FileEntry entries[MAX_FILES];
    int count; /* RAM-only */
} BuildTable;

/* Prototyper */
static void add_dir_recursive(const char *host_path, uint32_t parent_id,
                              BuildTable *table, int skip_kernel_bin);
static void build_full_file_path(BuildTable *table, int idx, char *out, size_t outlen);
static void write_zeros(FILE *f, size_t sectors);

static void add_dir_recursive(const char *host_path, uint32_t parent_id,
                              BuildTable *table, int skip_kernel_bin)
{
    DIR *dir = opendir(host_path);
    if (!dir)
    {
        return;
    }

    struct dirent *ent;

    while ((ent = readdir(dir)) != NULL)
    {
        if (!strcmp(ent->d_name, ".") || !strcmp(ent->d_name, ".."))
        {
            continue;
        }

        char fullpath[512];
        snprintf(fullpath, sizeof(fullpath), "%s/%s", host_path, ent->d_name);

        struct stat st = {0};
        if (stat(fullpath, &st) < 0)
        {
            continue;
        }

        if (S_ISDIR(st.st_mode))
        {
            /* Undvik dubblett: 'system' under root skapas manuellt i main(). */
            if (parent_id == 1 && strcmp(ent->d_name, "system") == 0)
            {
                continue;
            }

            int idx = table->count;
            if (idx >= MAX_FILES) { closedir(dir); return; }

            table->entries[idx].entry_id  = idx + 1;
            table->entries[idx].parent_id = parent_id;
            table->entries[idx].type      = ENTRY_TYPE_DIR;
            snprintf(table->entries[idx].filename, MAX_FILENAME_LEN, "%s", ent->d_name);
            table->entries[idx].start_sector   = 0;
            table->entries[idx].sector_count   = 0;
            table->entries[idx].file_size_bytes= 0;
            table->count++;

            add_dir_recursive(fullpath, (uint32_t)(idx + 1), table, (parent_id == 2) ? 1 : 0);
        }
        else if (S_ISREG(st.st_mode))
        {
            if (skip_kernel_bin && strcmp(ent->d_name, "kernel.bin") == 0)
            {
                continue;
            }

            int idx = table->count;
            if (idx >= MAX_FILES) { closedir(dir); return; }

            table->entries[idx].entry_id  = idx + 1;
            table->entries[idx].parent_id = parent_id;
            table->entries[idx].type      = ENTRY_TYPE_FILE;
            snprintf(table->entries[idx].filename, MAX_FILENAME_LEN, "%s", ent->d_name);
            table->entries[idx].file_size_bytes = (uint32_t)st.st_size;
            table->entries[idx].start_sector    = 0;
            table->entries[idx].sector_count    = 0;
            table->count++;
        }
    }

    closedir(dir);
}

static void build_full_file_path(BuildTable *table, int idx, char *out, size_t outlen)
{
    char tmp[1024] = "";
    int current = idx;

    while (current >= 0 && table->entries[current].parent_id != 0)
    {
        char t[1024];

        if (strlen(tmp) == 0)
        {
            snprintf(t, sizeof(t), "%s", table->entries[current].filename);
        }
        else
        {
            snprintf(t, sizeof(t), "%s/%s", table->entries[current].filename, tmp);
        }

        strcpy(tmp, t);

        int parent_idx = -1;
        for (int i = 0; i < table->count; ++i)
        {
            if (table->entries[i].entry_id == table->entries[current].parent_id)
            {
                parent_idx = i;
                break;
            }
        }
        current = parent_idx;
    }

    snprintf(out, outlen, "image/%s", tmp);
}

static void write_zeros(FILE *f, size_t sectors)
{
    uint8_t buffer[SECTOR_SIZE] = {0};
    for (size_t i = 0; i < sectors; i++)
    {
        fwrite(buffer, SECTOR_SIZE, 1, f);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 6)
    {
        printf("Usage: %s <output.img> <size_mb> <boot.bin> <stage2loader file> <kernel.bin>\n", argv[0]);
        return 1;
    }

    const char *out_name    = argv[1];
    int size_mb             = atoi(argv[2]);
    const char *boot_file   = argv[3];
    const char *stage2_file = argv[4];
    const char *kernel_file = argv[5];

    if (size_mb < 8)
    {
        printf("Image size must be at least 8 MB\n");
        return 1;
    }

    uint32_t total_sectors = (uint32_t)(size_mb * 1024 * 1024 / SECTOR_SIZE);

    FILE *kernel = fopen(kernel_file, "rb");
    if (!kernel)
    {
        perror("kernel.bin");
        return 1;
    }
    fseek(kernel, 0, SEEK_END);
    long kernel_size = ftell(kernel);
    fseek(kernel, 0, SEEK_SET);
    fclose(kernel);

    /* Bygg tabellen i RAM */
    BuildTable table = {0};
    table.entries[0].entry_id  = 1;
    table.entries[0].parent_id = 0;
    table.entries[0].type      = ENTRY_TYPE_DIR;
    snprintf(table.entries[0].filename, MAX_FILENAME_LEN, "/");
    table.count = 1;

    table.entries[1].entry_id  = 2;
    table.entries[1].parent_id = 1;
    table.entries[1].type      = ENTRY_TYPE_DIR;
    snprintf(table.entries[1].filename, MAX_FILENAME_LEN, "system");
    table.count = 2;

    table.entries[2].entry_id  = 3;
    table.entries[2].parent_id = 2;
    table.entries[2].type      = ENTRY_TYPE_FILE;
    snprintf(table.entries[2].filename, MAX_FILENAME_LEN, "kernel.bin");
    table.entries[2].file_size_bytes = (uint32_t)kernel_size;
    table.count = 3;

    /* Lägg in allt under image/system (hoppa över kernel.bin där) och sedan resten under image */
    add_dir_recursive("image/system", 2, &table, 1);
    add_dir_recursive("image",        1, &table, 0);

    /* --- Metadata layout --- */
    uint32_t file_table_bytes        = (uint32_t)(MAX_FILES * sizeof(FileEntry));           /* <-- på disk: ENDAST entries */
    uint32_t file_table_size         = (file_table_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE;  /* i sektorer */
    uint32_t file_table_bitmap_bytes = (uint32_t)((MAX_FILES + 7) / 8);                     /* 256 filer -> 32 byte */
    uint32_t file_table_bitmap_size  = (file_table_bitmap_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE; /* 1 sektor */
    uint32_t sector_bitmap_size      = (uint32_t)((total_sectors / 8 + SECTOR_SIZE - 1) / SECTOR_SIZE);

    uint32_t sb_sector               = FS_START_LBA;
    uint32_t file_table_sector       = sb_sector + 1;
    uint32_t file_table_bitmap_sector= file_table_sector + file_table_size;
    uint32_t sector_bitmap_sector    = file_table_bitmap_sector + file_table_bitmap_size;
    uint32_t next_sector             = sector_bitmap_sector + sector_bitmap_size;

    /* Lägg ut alla filer sekventiellt efter bitmaps */
    for (int i = 0; i < table.count; i++)
    {
        if (table.entries[i].type != ENTRY_TYPE_FILE)
        {
            continue;
        }

        uint32_t file_sectors = (table.entries[i].file_size_bytes + SECTOR_SIZE - 1) / SECTOR_SIZE;
        table.entries[i].start_sector = next_sector;
        table.entries[i].sector_count = file_sectors;
        next_sector += file_sectors;
    }

    FILE *out = fopen(out_name, "wb+");
    if (!out)
    {
        perror("Failed to create image");
        return 1;
    }

    /* Skriv MBR + partition */
    FILE *boot = fopen(boot_file, "rb");
    if (!boot)
    {
        perror("Unable to open boot.bin");
        return 1;
    }

    uint8_t mbr[SECTOR_SIZE] = {0};
    fread(mbr, 1, 446, boot);
    fclose(boot);

    uint8_t *pt = mbr + 446;
    memset(pt, 0, 64);
    pt[0] = 0x80;
    pt[4] = PARTITION_TYPE;
    *(uint32_t *)(pt + 8)  = FS_START_LBA;
    *(uint32_t *)(pt + 12) = total_sectors - FS_START_LBA;
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    fwrite(mbr, 1, SECTOR_SIZE, out);

    /* Skriv stage2 direkt efter MBR, padda till RESERVED_STAGE2_SECTORS */
    FILE *stage2 = fopen(stage2_file, "rb");
    if (!stage2)
    {
        perror("Unable to find stage2 file");
        return 1;
    }

    uint8_t buffer[SECTOR_SIZE];
    size_t rd;
    int sectors_written = 0;
    while ((rd = fread(buffer, 1, SECTOR_SIZE, stage2)) > 0)
    {
        fwrite(buffer, 1, rd, out);
        sectors_written++;
    }
    fclose(stage2);

    if (sectors_written < RESERVED_STAGE2_SECTORS)
    {
        write_zeros(out, RESERVED_STAGE2_SECTORS - sectors_written);
    }

    /* Padda fram till FS_START_LBA */
    uint32_t used = 1 + RESERVED_STAGE2_SECTORS;
    write_zeros(out, FS_START_LBA - used);

    /* Superblock */
    SuperBlock sb = {0};
    sb.magic                     = 0x44494646; // "DIFF"
    sb.version                   = 1;
    sb.total_sectors             = total_sectors;
    sb.file_table_sector         = file_table_sector;
    sb.file_table_size           = file_table_size;
    sb.file_table_bitmap_sector  = file_table_bitmap_sector;
    sb.file_table_bitmap_size    = file_table_bitmap_size;
    sb.sector_bitmap_sector      = sector_bitmap_sector;
    sb.sector_bitmap_size        = sector_bitmap_size;
    sb.root_dir_id               = 1;

    fseek(out, (long)sb_sector * SECTOR_SIZE, SEEK_SET);
    fwrite(&sb, sizeof(sb), 1, out);
    if (sizeof(sb) < SECTOR_SIZE)
    {
        uint8_t zero_buf[SECTOR_SIZE] = {0};
        fwrite(zero_buf, 1, SECTOR_SIZE - sizeof(sb), out);
    }

    /* File table (på disk: ENDAST entries[]) */
    fseek(out, (long)file_table_sector * SECTOR_SIZE, SEEK_SET);
    FileTableOnDisk on_disk = {0};
    /* kopiera byggtabellen in i on-disk buffern */
    for (int i = 0; i < MAX_FILES; ++i)
    {
        on_disk.entries[i] = table.entries[i];
    }
    fwrite(&on_disk, sizeof(on_disk), 1, out);

    /* Filtabells-bitmap (1 sektor nollad räcker; vill du: set bits för i< table.count) */
    fseek(out, (long)file_table_bitmap_sector * SECTOR_SIZE, SEEK_SET);
    write_zeros(out, file_table_bitmap_size);

    /* Sektorbimap (nollad). Läsning funkar; för allokering senare får du sätta bits. */
    write_zeros(out, sector_bitmap_size);

    /* Skriv filinnehåll */
    for (int i = 0; i < table.count; i++)
    {
        if (table.entries[i].type != ENTRY_TYPE_FILE)
        {
            continue;
        }

        FILE *f = NULL;

        if (i == 2) /* kernel.bin under /system */
        {
            f = fopen(kernel_file, "rb");
        }
        else
        {
            char path[1024];
            build_full_file_path(&table, i, path, sizeof(path));
            printf("Writing %s -> sector %u\n", path, table.entries[i].start_sector);
            f = fopen(path, "rb");
            if (!f)
            {
                printf("COULD NOT OPEN %s\n", path);
            }
        }

        if (!f)
        {
            continue;
        }

        fseek(out, (long)table.entries[i].start_sector * SECTOR_SIZE, SEEK_SET);

        while ((rd = fread(buffer, 1, SECTOR_SIZE, f)) > 0)
        {
            fwrite(buffer, 1, rd, out);
        }

        fclose(f);
    }

    /* Padda till full storlek */
    long current  = ftell(out);
    long expected = (long)total_sectors * SECTOR_SIZE;
    if (current < expected)
    {
        long remaining = expected - current;
        while (remaining > 0)
        {
            size_t chunk = remaining > SECTOR_SIZE ? SECTOR_SIZE : (size_t)remaining;
            memset(buffer, 0, chunk);
            fwrite(buffer, 1, chunk, out);
            remaining -= (long)chunk;
        }
    }

    fclose(out);
    printf("[MKDIFF OS] Image created: %s\n", out_name);

    return 0;
}

