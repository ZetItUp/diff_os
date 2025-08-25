#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR_SIZE 512
#define MAX_FILES 256
#define MAX_FILENAME_LEN 256

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

int main(int argc, char *argv[])
{
    if (argc != 2) 
    {
        printf("Usage: %s <diffos.img>\n", argv[0]);
    
        return 1;
    }

    FILE *f = fopen(argv[1], "rb");
    if (!f) 
    {
        perror("fopen");
    
        return 1;
    }


    SuperBlock sb;
    fseek(f, 2048 * SECTOR_SIZE, SEEK_SET);
    fread(&sb, sizeof(sb), 1, f);

    if (sb.magic != 0x44494646) 
    {
        printf("Not a DiffFS image (magic = %08X)\n", sb.magic);
        fclose(f);
    
        return 1;
    }


    FileTable ft;
    fseek(f, sb.file_table_sector * SECTOR_SIZE, SEEK_SET);
    fread(&ft, sizeof(ft), 1, f);

    printf("Files and directories in image:\n\n");
    for (int i = 0; i < MAX_FILES; i++) 
    {
        if (ft.entries[i].entry_id == 0)
        {
            continue;
        }

        printf("%s\t\t\t<%s>  id=%u  parent=%u  size=%u  start=%u\n",
            ft.entries[i].filename,
            ft.entries[i].type == ENTRY_TYPE_DIR ? "DIR" :
            (ft.entries[i].type == ENTRY_TYPE_FILE ? "FILE" : "??"),
            ft.entries[i].entry_id,
            ft.entries[i].parent_id,
            ft.entries[i].file_size_bytes,
            ft.entries[i].start_sector
        );
    }

    fclose(f);
    
    return 0;
}

