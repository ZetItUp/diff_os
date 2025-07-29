/*
 * DiffFS (Different Filesystem)
 * by ZetItUp, 2025
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define SECTOR_SIZE 512
#define RESERVED_STAGE2_SECTORS 31
#define FS_START_LBA 2048
#define PARTITION_TYPE 0xC8        // Let's pretend DiffFS is something from DR-DOS 
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

void write_zeros(FILE *f, size_t sectors) 
{
    uint8_t buffer[SECTOR_SIZE];

    memset(buffer, 0, SECTOR_SIZE);

    for (size_t i = 0; i < sectors; i++) 
    {
        fwrite(buffer, SECTOR_SIZE, 1, f);
    }
}

int main(int argc, char *argv[])
{
    if (argc != 6) {
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

    FILE *out = fopen(out_name, "wb");
    if (!out) 
    {
        perror("Failed to create image");
        
        return 1;
    }

    // Read boot.bin (MBR)
    FILE *boot = fopen(boot_file, "rb");
    if (!boot) 
    { 
        perror("Unable to open boot.bin"); 
    
        return 1; 
    }

    uint8_t mbr[SECTOR_SIZE];
    memset(mbr, 0, SECTOR_SIZE);
    fread(mbr, 1, 446, boot); // 446 bytes bootkod
    fclose(boot);

    // Create partition table
    uint8_t *pt = mbr + 446;
    memset(pt, 0, 64);

    pt[0] = 0x80;                                           // Bootable
    pt[4] = PARTITION_TYPE;                                 // Type
    *(uint32_t *)(pt + 8) = FS_START_LBA;                   // Start LBA
    *(uint32_t *)(pt + 12) = total_sectors - FS_START_LBA;  // Längd
                                                            
    // Add boot signature
    mbr[510] = 0x55;
    mbr[511] = 0xAA;

    // Write MBR
    fwrite(mbr, 1, SECTOR_SIZE, out);

    // Write Stage 2 Loader to the image file
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

    // Padd the rest of the of the reserved area with zeros
    if (sectors_written < RESERVED_STAGE2_SECTORS) 
    {
        write_zeros(out, RESERVED_STAGE2_SECTORS - sectors_written);
    }

    uint32_t used = 1 + RESERVED_STAGE2_SECTORS; // MBR + Stage 2
    write_zeros(out, FS_START_LBA - used);
    
    // Initialize Filesystem
    SuperBlock sb;
    memset(&sb, 0, sizeof(sb));
    
    sb.magic = 0x44494646;          // "DIFF"
    sb.version = 1;
    sb.total_sectors = total_sectors;
    
    sb.file_table_sector = FS_START_LBA + 1;
    sb.file_table_size = (sizeof(FileTable) + SECTOR_SIZE - 1) / SECTOR_SIZE;
    sb.file_table_bitmap_sector = sb.file_table_sector + sb.file_table_size;
    sb.file_table_bitmap_size = 1;

    sb.sector_bitmap_sector = sb.file_table_bitmap_sector + sb.file_table_bitmap_size;
    sb.sector_bitmap_size = (total_sectors / 8 + SECTOR_SIZE - 1) / SECTOR_SIZE;
    sb.root_dir_id = 1;

    // Write superblock
    fseek(out, (long)FS_START_LBA * SECTOR_SIZE, SEEK_SET);
    fwrite(&sb, sizeof(sb), 1, out);
    if (sizeof(sb) < SECTOR_SIZE)
    {
        write_zeros(out, 1);
    }

    // Create FileTable
    FileTable table;
    memset(&table, 0, sizeof(table));

    // Root directory
    table.entries[0].entry_id = 1;
    table.entries[0].parent_id = 0;
    table.entries[0].type = ENTRY_TYPE_DIR;
    strcpy(table.entries[0].filename, "/");

    // /system directory
    table.entries[1].entry_id = 2;
    table.entries[1].parent_id = 1;
    table.entries[1].type = ENTRY_TYPE_DIR;
    strcpy(table.entries[1].filename, "system");

    // Read kernel.bin size
    FILE *kernel = fopen(kernel_file, "rb");
    if (!kernel) 
    { 
        perror("kernel.bin"); 
        
        return 1; 
    }
    
    fseek(kernel, 0, SEEK_END);
    long kernel_size = ftell(kernel);
    fseek(kernel, 0, SEEK_SET);

    // Allocate sectors for kernel
    uint32_t kernel_sectors = (kernel_size + SECTOR_SIZE - 1) / SECTOR_SIZE;
    uint32_t kernel_start = sb.sector_bitmap_sector + sb.sector_bitmap_size;

    // Add kernel.bin entry
    table.entries[2].entry_id = 3;
    table.entries[2].parent_id = 2;
    table.entries[2].type = ENTRY_TYPE_FILE;
    strcpy(table.entries[2].filename, "kernel.bin");
    table.entries[2].start_sector = kernel_start;
    table.entries[2].sector_count = kernel_sectors;
    table.entries[2].file_size_bytes = (uint32_t)kernel_size;

    // Write FileTable
    fseek(out, (long)sb.file_table_sector * SECTOR_SIZE, SEEK_SET);
    fwrite(&table, sizeof(table), 1, out);

    // Zero FileTable bitmap + sector bitmap
    fseek(out, (long)sb.file_table_bitmap_sector * SECTOR_SIZE, SEEK_SET);
    write_zeros(out, sb.file_table_bitmap_size);
    write_zeros(out, sb.sector_bitmap_size);

    // Write kernel.bin content
    fseek(out, (long)kernel_start * SECTOR_SIZE, SEEK_SET);
    while ((read = fread(buffer, 1, SECTOR_SIZE, kernel)) > 0) 
    {
        fwrite(buffer, 1, read, out);
    }
    fclose(kernel);

    // Fill rest with zeros
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
