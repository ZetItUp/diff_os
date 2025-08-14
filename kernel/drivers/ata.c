#include "drivers/ata.h"
#include "io.h"
#include "stdio.h"

#define ATA_PRIMARY_IO 0x1F0
#define ATA_PRIMARY_CTRL 0x3F6
#define SECTOR_SIZE 512

static void ata_io_wait(void)
{
    // Read the status port 4 times
    for(int i = 0; i < 4; i++)
    {
        inb(ATA_PRIMARY_CTRL);
    }
}

static int ata_wait_busy_clear(void)
{
    for(int i = 0; i < 100000; i++)
    {
        uint8_t status = inb(ATA_PRIMARY_IO + 7);

        if(!(status & 0x80))
        {
            // BSY cleared
            return 0;
        }
    }

    return -1;
}

static int ata_wait_drq_set(void)
{
    for(int i = 0; i < 100000; i++)
    {
        uint8_t status = inb(ATA_PRIMARY_IO + 7);

        if(status & 0x08)
        {
            // DRQ set
            return 0;
        }
    }

    return -1;
}

void ata_init(void)
{
    // TODO: IDENTIFY if needed
}

int ata_read(uint32_t lba, uint32_t count, void *buffer)
{
    uint16_t *buf = (uint16_t*)buffer;

    for(uint32_t s = 0; s < count; s++)
    {
        if(ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Busy timeout!\n");

            return s * SECTOR_SIZE;
        }

        outb(ATA_PRIMARY_CTRL, 0x00);
        outb(ATA_PRIMARY_IO + 2, 1);                              // Sector count = 1
        outb(ATA_PRIMARY_IO + 3, (uint8_t)(lba & 0xFF));          // LBA low
        outb(ATA_PRIMARY_IO + 4, (uint8_t)((lba >> 8) & 0xFF));   // LBA mid
        outb(ATA_PRIMARY_IO + 5, (uint8_t)((lba >> 16) & 0xFF));  // LBA high

        // Drive/Head: 0xE0 = master, LBA mode
        outb(ATA_PRIMARY_IO + 6, 0xE0 | ((lba >> 24) & 0x0F));

        // READ SECTORS (0x20)
        outb(ATA_PRIMARY_IO + 7, 0x20);

        if(ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Busy timeout!\n");

            return s * SECTOR_SIZE;
        }

        if(ata_wait_drq_set() < 0)
        {
            printf("[ATA] DRQ timeout!\n");

            return SECTOR_SIZE;
        }

        // Read 256 words (512 bytes)
        for(int i = 0; i < 256; i++)
        {
            *buf++ = inw(ATA_PRIMARY_IO);
        }

        ata_io_wait();

        lba++;
    }

    return count * SECTOR_SIZE;
}

int ata_write(uint32_t lba, uint32_t count, const void *buffer)
{
    const uint16_t *buf = (const uint16_t*)buffer;

    for(uint32_t s = 0; s < count; s++)
    {
        if(ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Write timeout (busy)\n");

            return s * SECTOR_SIZE;
        }

        outb(ATA_PRIMARY_CTRL, 0x00);
        outb(ATA_PRIMARY_IO + 2, 1);                              // Sector count = 1
        outb(ATA_PRIMARY_IO + 3, (uint8_t)(lba & 0xFF));          // LBA low
        outb(ATA_PRIMARY_IO + 4, (uint8_t)((lba >> 8) & 0xFF));   // LBA mid
        outb(ATA_PRIMARY_IO + 5, (uint8_t)((lba >> 16) & 0xFF));  // LBA high
        outb(ATA_PRIMARY_IO + 6, 0xE0 | ((lba >> 24) & 0x0F));    // Drive/Head

        // Write sectors (0x30)
        outb(ATA_PRIMARY_IO + 7, 0x30);

        if(ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Write data timeout (busy)\n");

            return s * SECTOR_SIZE;
        }

        if(ata_wait_drq_set() < 0)
        {
            printf("[ATA] Write data timeout (DRQ)\n");

            return s * SECTOR_SIZE;
        }

        // Write 256 words (512 bytes)
        for(int i = 0; i < 256; i++)
        {
            outw(ATA_PRIMARY_IO, *buf++);
        }

        ata_io_wait();

        lba++;
    }

    return count * SECTOR_SIZE;
}

void ata_identify(void)
{
    // TODO: Implement if needed
}

