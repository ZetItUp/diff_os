/*
 * DiffFS (Different Filesystem)
 * by ZetItUp, 2025
 */
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
#define MAX_FILENAME_LEN 64

typedef enum
{
    ENTRY_TYPE_INVALID = 0,
    ENTRY_TYPE_FILE = 1,
    ENTRY_TYPE_DIR = 2
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
    uint32_t file_table_size;
    uint32_t file_table_bitmap_sector;
    uint32_t file_table_bitmap_size;
    uint32_t sector_bitmap_sector;
    uint32_t sector_bitmap_size;
    uint32_t root_dir_id;
    uint32_t feature_flags;
    uint8_t reserved[480];
} __attribute__((packed)) SuperBlock;

typedef struct
{
    FileEntry entries[MAX_FILES];
} FileTable;

// Bara scanna, ingen skrivning, bygg relativ path!
void add_dir_recursive(const char *host_path, const char *rel_path,
                       int parent_id, FileTable *table, int *file_entry_index)
{
    DIR *dir = opendir(host_path);
    if (!dir) return;

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char full_host[512];
        snprintf(full_host, sizeof(full_host), "%s/%s", host_path, ent->d_name);

        char rel_entry[MAX_FILENAME_LEN];
        if (strlen(rel_path) > 0)
            snprintf(rel_entry, sizeof(rel_entry), "%s/%s", rel_path, ent->d_name);
        else
            snprintf(rel_entry, sizeof(rel_entry), "%s", ent->d_name);

        struct stat st;
        if (stat(full_host, &st) < 0)
            continue;

        if (*file_entry_index >= MAX_FILES) {
            fprintf(stderr, "FileTable FULL! Avbryter vid %d\n", *file_entry_index);
            closedir(dir);
            exit(1);
        }

        if (S_ISDIR(st.st_mode))
        {
            int this_id = *file_entry_index + 1;
            table->entries[*file_entry_index].entry_id = this_id;
            table->entries[*file_entry_index].parent_id = parent_id;
            table->entries[*file_entry_index].type = ENTRY_TYPE_DIR;
            snprintf(table->entries[*file_entry_index].filename, MAX_FILENAME_LEN, "%s", rel_entry);
            table->entries[*file_entry_index].filename[MAX_FILENAME_LEN-1] = 0;
            (*file_entry_index)++;
            add_dir_recursive(full_host, rel_entry, this_id, table, file_entry_index);
        }
        else if (S_ISREG(st.st_mode))
        {
            if (strcmp(ent->d_name, "kernel.bin") == 0)
                continue; // Kernel läggs separat

            table->entries[*file_entry_index].entry_id = *file_entry_index + 1;
            table->entries[*file_entry_index].parent_id = parent_id;
            table->entries[*file_entry_index].type = ENTRY_TYPE_FILE;
            snprintf(table->entries[*file_entry_index].filename, MAX_FILENAME_LEN, "%s", rel_entry);
            table->entries[*file_entry_index].filename[MAX_FILENAME_LEN-1] = 0;
            (*file_entry_index)++;
        }
    }
    closedir(dir);
}

void write_zeros(FILE *f, size_t sectors)
{
    uint8_t buffer[SECTOR_SIZE] = {0};
    for (size_t i = 0; i < sectors; i++)
        fwrite(buffer, SECTOR_SIZE, 1, f);
}

int main(int argc, char *argv[])
{
    if (argc != 6)
    {
        printf("Usage: %s <output.img> <size_mb> <boot.bin> <stage2loader file> <kernel.bin>\n", argv[0]);
        return 1;
    }

    const char *out_name = argv[1];
    int size_mb = atoi(argv[2]);
    const char *boot_file = argv[3];
    const char *stage2_file = argv[4];
    const char *kernel_file = argv[5];

    if (size_mb < 8)
    {
        printf("Image size must be at least 8 MB\n");
        return 1;
    }

    uint32_t total_sectors = (size_mb * 1024 * 1024) / SECTOR_SIZE;

    // ---------- PASS 1: Scanna katalog och bygg FileTable ----------
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

    uint32_t kernel_sectors = (kernel_size + SECTOR_SIZE - 1) / SECTOR_SIZE;

    FileTable table = {0};
    // ROOT
    table.entries[0].entry_id = 1;
    table.entries[0].parent_id = 0;
    table.entries[0].type = ENTRY_TYPE_DIR;
    strcpy(table.entries[0].filename, "/");

    // /system
    table.entries[1].entry_id = 2;
    table.entries[1].parent_id = 1;
    table.entries[1].type = ENTRY_TYPE_DIR;
    strcpy(table.entries[1].filename, "system");

    // /system/kernel.bin
    table.entries[2].entry_id = 3;
    table.entries[2].parent_id = 2;
    table.entries[2].type = ENTRY_TYPE_FILE;
    strcpy(table.entries[2].filename, "system/kernel.bin");
    table.entries[2].sector_count = kernel_sectors;
    table.entries[2].file_size_bytes = (uint32_t)kernel_size;

    int file_entry_index = 3;
    add_dir_recursive("image/system", "system", 2, &table, &file_entry_index);

    // Beräkna metadata-sektorer
    uint32_t file_table_size = (sizeof(FileTable) + SECTOR_SIZE - 1) / SECTOR_SIZE;
    uint32_t file_table_bitmap_size = 1;
    uint32_t sector_bitmap_size = (total_sectors / 8 + SECTOR_SIZE - 1) / SECTOR_SIZE;

    uint32_t sb_sector = FS_START_LBA;
    uint32_t file_table_sector = sb_sector + 1;
    uint32_t file_table_bitmap_sector = file_table_sector + file_table_size;
    uint32_t sector_bitmap_sector = file_table_bitmap_sector + file_table_bitmap_size;
    uint32_t kernel_start = sector_bitmap_sector + sector_bitmap_size;
    uint32_t next_sector = kernel_start + kernel_sectors;

    // Sätt start_sector och sektorinfo för filer
    for (int i = 3; i < file_entry_index; i++)
    {
        char path[512];
        snprintf(path, sizeof(path), "image/%s", table.entries[i].filename);
        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
        {
            long file_size = st.st_size;
            uint32_t sectors = (file_size + SECTOR_SIZE - 1) / SECTOR_SIZE;
            table.entries[i].start_sector = next_sector;
            table.entries[i].sector_count = sectors;
            table.entries[i].file_size_bytes = (uint32_t)file_size;
            next_sector += sectors;
        }
    }
    table.entries[2].start_sector = kernel_start;

    // --------- Skapa imagen ----------
    FILE *out = fopen(out_name, "wb+");
    if (!out)
    {
        perror("Failed to create image");
        return 1;
    }

    // 1. Skriv MBR
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
    *(uint32_t *)(pt + 8) = FS_START_LBA;
    *(uint32_t *)(pt + 12) = total_sectors - FS_START_LBA;
    mbr[510] = 0x55;
    mbr[511] = 0xAA;
    fwrite(mbr, 1, SECTOR_SIZE, out);

    // 2. Skriv Stage2
    FILE *stage2 = fopen(stage2_file, "rb");
    if (!stage2)
    {
        perror("Unable to find stage2 file");
        return 1;
    }
    uint8_t buffer[SECTOR_SIZE];
    size_t read;
    int sectors_written = 0;
    while ((read = fread(buffer, 1, SECTOR_SIZE, stage2)) > 0)
    {
        fwrite(buffer, 1, read, out);
        sectors_written++;
    }
    fclose(stage2);

    if (sectors_written < RESERVED_STAGE2_SECTORS)
    {
        write_zeros(out, RESERVED_STAGE2_SECTORS - sectors_written);
    }

    uint32_t used = 1 + RESERVED_STAGE2_SECTORS;
    write_zeros(out, FS_START_LBA - used);

    // 3. Skriv SuperBlock till disk
    SuperBlock sb = {0};
    sb.magic = 0x44494646; // "DIFF"
    sb.version = 1;
    sb.total_sectors = total_sectors;
    sb.file_table_sector = file_table_sector;
    sb.file_table_size = file_table_size;
    sb.file_table_bitmap_sector = file_table_bitmap_sector;
    sb.file_table_bitmap_size = file_table_bitmap_size;
    sb.sector_bitmap_sector = sector_bitmap_sector;
    sb.sector_bitmap_size = sector_bitmap_size;
    sb.root_dir_id = 1;

    fseek(out, (long)sb_sector * SECTOR_SIZE, SEEK_SET);
    fwrite(&sb, sizeof(sb), 1, out);
    if (sizeof(sb) < SECTOR_SIZE)
        write_zeros(out, 1);

    // 4. Skriv FileTable
    fseek(out, (long)file_table_sector * SECTOR_SIZE, SEEK_SET);
    fwrite(&table, sizeof(table), 1, out);

    // 5. Skriv bitmapar
    fseek(out, (long)file_table_bitmap_sector * SECTOR_SIZE, SEEK_SET);
    write_zeros(out, file_table_bitmap_size);
    write_zeros(out, sector_bitmap_size);

    // 6. Skriv kernel.bin
    kernel = fopen(kernel_file, "rb");
    if (!kernel)
    {
        perror("kernel.bin");
        return 1;
    }
    fseek(out, (long)kernel_start * SECTOR_SIZE, SEEK_SET);
    while ((read = fread(buffer, 1, SECTOR_SIZE, kernel)) > 0)
    {
        fwrite(buffer, 1, read, out);
    }
    fclose(kernel);

    // 7. Skriv övriga filer
    for (int i = 3; i < file_entry_index; i++)
    {
        if (table.entries[i].type != ENTRY_TYPE_FILE) continue;
        char path[512];
        snprintf(path, sizeof(path), "image/%s", table.entries[i].filename);
        FILE *f = fopen(path, "rb");
        if (!f) continue;
        fseek(out, (long)table.entries[i].start_sector * SECTOR_SIZE, SEEK_SET);
        while ((read = fread(buffer, 1, SECTOR_SIZE, f)) > 0)
        {
            fwrite(buffer, 1, read, out);
        }
        fclose(f);
    }

    // 8. Fyll ut imagen till rätt storlek
    long current = ftell(out);
    long expected = (long)total_sectors * SECTOR_SIZE;
    if (current < expected)
    {
        long remaining = expected - current;
        while (remaining > 0)
        {
            size_t chunk = remaining > SECTOR_SIZE ? SECTOR_SIZE : remaining;
            memset(buffer, 0, chunk);
            fwrite(buffer, 1, chunk, out);
            remaining -= chunk;
        }
    }

    fclose(out);
    printf("Image created: %s\n", out_name);
    printf("FS initialized with /system/kernel.bin\n");
    return 0;
}

