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

// Recursively add directories/files under host_path, with parent_id
void add_dir_recursive(const char *host_path, uint32_t parent_id, FileTable *table, int *file_entry_index)
{
    DIR *dir = opendir(host_path);
    if (!dir)
    {
        return;
    }

    struct dirent *ent;
    while ((ent = readdir(dir)) != NULL)
    {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
        {
            continue;
        }

        char full_host[512];
        snprintf(full_host, sizeof(full_host), "%s/%s", host_path, ent->d_name);

        struct stat st;
        if (stat(full_host, &st) < 0)
        {
            continue;
        }

        if (*file_entry_index >= MAX_FILES)
        {
            fprintf(stderr, "FileTable FULL! Stopping at %d\n", *file_entry_index);
            closedir(dir);
            exit(1);
        }

        if (S_ISDIR(st.st_mode))
        {
            uint32_t this_id = (uint32_t)(*file_entry_index + 1);
            table->entries[*file_entry_index].entry_id = this_id;
            table->entries[*file_entry_index].parent_id = parent_id;
            table->entries[*file_entry_index].type = ENTRY_TYPE_DIR;
            snprintf(table->entries[*file_entry_index].filename, MAX_FILENAME_LEN, "%s", ent->d_name);
            table->entries[*file_entry_index].filename[MAX_FILENAME_LEN - 1] = 0;
            (*file_entry_index)++;
            add_dir_recursive(full_host, this_id, table, file_entry_index);
        }
        else if (S_ISREG(st.st_mode))
        {
            table->entries[*file_entry_index].entry_id = (uint32_t)(*file_entry_index + 1);
            table->entries[*file_entry_index].parent_id = parent_id;
            table->entries[*file_entry_index].type = ENTRY_TYPE_FILE;
            snprintf(table->entries[*file_entry_index].filename, MAX_FILENAME_LEN, "%s", ent->d_name);
            table->entries[*file_entry_index].filename[MAX_FILENAME_LEN - 1] = 0;
            (*file_entry_index)++;
        }
    }
    closedir(dir);
}

void write_zeros(FILE *f, size_t sectors)
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

    uint32_t total_sectors = (uint32_t)(size_mb * 1024 * 1024 / SECTOR_SIZE);

    // ----- Read kernel.bin size -----
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
    uint32_t kernel_sectors = (uint32_t)((kernel_size + SECTOR_SIZE - 1) / SECTOR_SIZE);

    // ----- Build hierarchical FileTable -----
    FileTable table = {0};
    int file_entry_index = 0;

    // Root directory "/"
    table.entries[file_entry_index].entry_id = (uint32_t)(file_entry_index + 1);
    table.entries[file_entry_index].parent_id = 0;
    table.entries[file_entry_index].type = ENTRY_TYPE_DIR;
    snprintf(table.entries[file_entry_index].filename, MAX_FILENAME_LEN, "/");
    uint32_t root_id = (uint32_t)(file_entry_index + 1);
    file_entry_index++;

    // "system" directory under "/"
    table.entries[file_entry_index].entry_id = (uint32_t)(file_entry_index + 1);
    table.entries[file_entry_index].parent_id = root_id;
    table.entries[file_entry_index].type = ENTRY_TYPE_DIR;
    snprintf(table.entries[file_entry_index].filename, MAX_FILENAME_LEN, "system");
    uint32_t system_id = (uint32_t)(file_entry_index + 1);
    file_entry_index++;

    // "kernel.bin" file under "system"
    table.entries[file_entry_index].entry_id = (uint32_t)(file_entry_index + 1);
    table.entries[file_entry_index].parent_id = system_id;
    table.entries[file_entry_index].type = ENTRY_TYPE_FILE;
    snprintf(table.entries[file_entry_index].filename, MAX_FILENAME_LEN, "kernel.bin");
    table.entries[file_entry_index].sector_count = kernel_sectors;
    table.entries[file_entry_index].file_size_bytes = (uint32_t)kernel_size;
    int kernel_idx = file_entry_index;
    file_entry_index++;

    // Recursively scan "image/system" for directories and files
    add_dir_recursive("image/system", system_id, &table, &file_entry_index);

    // ----- Calculate metadata sector usage -----
    uint32_t file_table_size = (uint32_t)((sizeof(FileTable) + SECTOR_SIZE - 1) / SECTOR_SIZE);
    uint32_t file_table_bitmap_size = 1;
    uint32_t sector_bitmap_size = (uint32_t)((total_sectors / 8 + SECTOR_SIZE - 1) / SECTOR_SIZE);

    uint32_t sb_sector = FS_START_LBA;
    uint32_t file_table_sector = sb_sector + 1;
    uint32_t file_table_bitmap_sector = file_table_sector + file_table_size;
    uint32_t sector_bitmap_sector = file_table_bitmap_sector + file_table_bitmap_size;
    uint32_t kernel_start = sector_bitmap_sector + sector_bitmap_size;
    uint32_t next_sector = kernel_start + kernel_sectors;

    // ----- Assign start_sector and sector_count for files -----
    table.entries[kernel_idx].start_sector = kernel_start;

    for (int i = 0; i < file_entry_index; i++)
    {
        if (table.entries[i].type != ENTRY_TYPE_FILE || i == kernel_idx)
        {
            continue;
        }
        int parent = table.entries[i].parent_id;
        char fullpath[512] = "";
        strcpy(fullpath, table.entries[i].filename);

        while ((uint32_t)parent != root_id)
        {
            int pi = -1;
            for (int j = 0; j < file_entry_index; j++)
            {
                if (table.entries[j].entry_id == (uint32_t)parent)
                {
                    pi = j;
                    break;
                }
            }
            if (pi == -1)
            {
                break;
            }
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s/%s", table.entries[pi].filename, fullpath);
            strcpy(fullpath, tmp);
            parent = table.entries[pi].parent_id;
        }

        char path[512];
        snprintf(path, sizeof(path), "image/%s", fullpath);

        struct stat st;
        if (stat(path, &st) == 0 && S_ISREG(st.st_mode))
        {
            long file_size = st.st_size;
            uint32_t sectors = (uint32_t)((file_size + SECTOR_SIZE - 1) / SECTOR_SIZE);
            table.entries[i].start_sector = next_sector;
            table.entries[i].sector_count = sectors;
            table.entries[i].file_size_bytes = (uint32_t)file_size;
            next_sector += sectors;
        }
    }

    // ----- Create the image file -----
    FILE *out = fopen(out_name, "wb+");
    if (!out)
    {
        perror("Failed to create image");
        return 1;
    }

    // --- 1. Write the MBR ---
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

    // --- 2. Write Stage2 loader ---
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

    // --- 3. Write SuperBlock ---
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
    sb.root_dir_id = root_id;

    fseek(out, (long)sb_sector * SECTOR_SIZE, SEEK_SET);
    fwrite(&sb, sizeof(sb), 1, out);
    if (sizeof(sb) < SECTOR_SIZE)
    {
        write_zeros(out, 1);
    }

    // --- 4. Write FileTable ---
    fseek(out, (long)file_table_sector * SECTOR_SIZE, SEEK_SET);
    fwrite(&table, sizeof(table), 1, out);

    // --- 5. Write bitmaps ---
    fseek(out, (long)file_table_bitmap_sector * SECTOR_SIZE, SEEK_SET);
    write_zeros(out, file_table_bitmap_size);
    write_zeros(out, sector_bitmap_size);

    // --- 6. Write kernel.bin ---
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

    // --- 7. Write all other files ---
    for (int i = 0; i < file_entry_index; i++)
    {
        if (table.entries[i].type != ENTRY_TYPE_FILE || i == kernel_idx)
        {
            continue;
        }

        int parent = table.entries[i].parent_id;
        char fullpath[512] = "";
        strcpy(fullpath, table.entries[i].filename);

        while ((uint32_t)parent != root_id)
        {
            int pi = -1;
            for (int j = 0; j < file_entry_index; j++)
            {
                if (table.entries[j].entry_id == (uint32_t)parent)
                {
                    pi = j;
                    break;
                }
            }
            if (pi == -1)
            {
                break;
            }
            char tmp[512];
            snprintf(tmp, sizeof(tmp), "%s/%s", table.entries[pi].filename, fullpath);
            strcpy(fullpath, tmp);
            parent = table.entries[pi].parent_id;
        }

        char path[512];
        snprintf(path, sizeof(path), "image/%s", fullpath);

        FILE *f = fopen(path, "rb");
        if (!f)
        {
            continue;
        }

        fseek(out, (long)table.entries[i].start_sector * SECTOR_SIZE, SEEK_SET);
        while ((read = fread(buffer, 1, SECTOR_SIZE, f)) > 0)
        {
            fwrite(buffer, 1, read, out);
        }
        fclose(f);
    }

    // --- 8. Pad image to full size ---
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

