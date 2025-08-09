#include "drivers/ata.h"
#include "io.h"
#include "stdio.h"

#define ATA_PRIMARY_IO      0x1F0
#define ATA_PRIMARY_CTRL    0x3F6
#define SECTOR_SIZE         512

static void ata_io_wait(void)
{
    // Do read from status port 4 times
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
            // Busy Clear
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
            // DRQ Set
            return 0;
        }
    }

    return -1;
}

void ata_init(void)
{
    // TODO: ATA Identify?
}

int ata_read(uint32_t lba, uint32_t count, void *buffer)
{
    uint16_t *buf = (uint16_t*)buffer;

    for(uint32_t s = 0; s < count; s++)
    {
        if(ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Busy Timeout!\n");

            return s * SECTOR_SIZE;
        }

        outb(ATA_PRIMARY_CTRL, 0x00);
        outb(ATA_PRIMARY_IO + 2, 1);                                // Sector count = 1
        outb(ATA_PRIMARY_IO + 3, (uint8_t)(lba & 0xFF));            // LBA Low
        outb(ATA_PRIMARY_IO + 4, (uint8_t)((lba >> 8) & 0xFF));     // LBA Mid
        outb(ATA_PRIMARY_IO + 5, (uint8_t)((lba >> 16) & 0xFF));    // LBA High

        // Drive/Head, 0xE0 = Primary, LBA Mode
        outb(ATA_PRIMARY_IO + 6, 0xE0 | ((lba >> 24) & 0x0F));
        
        // Send Read Sectors (0x20)
        outb(ATA_PRIMARY_IO + 7, 0x20);
        
        // Wait for Busy again
        if(ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Busy Timeout!\n");

            return s * SECTOR_SIZE;
        }

        // Wait for DRQ = 1 (Data ready)
        if(ata_wait_drq_set() < 0)
        {
            printf("[ATA] DRQ Timeout!\n");

            return SECTOR_SIZE;
        }

        // Read 512 bytes (256 words)
        for(int i = 0; i < 256; i++)
        {
            *buf++ = inw(ATA_PRIMARY_IO);
        }

        // Wait for IO
        ata_io_wait();

        lba++;
    }

    return count * SECTOR_SIZE;
}

int ata_write(uint32_t lba, uint32_t count, const void *buffer)
{
    const uint16_t *buf = (const uint16_t *)buffer;

    for (uint32_t s = 0; s < count; s++)
    {
        if (ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Write Timeout Busy\n");
            return s * SECTOR_SIZE;
        }

        outb(ATA_PRIMARY_CTRL, 0x00);

        outb(ATA_PRIMARY_IO + 2, 1);
        outb(ATA_PRIMARY_IO + 3, (uint8_t)(lba & 0xFF));
        outb(ATA_PRIMARY_IO + 4, (uint8_t)((lba >> 8) & 0xFF));
        outb(ATA_PRIMARY_IO + 5, (uint8_t)((lba >> 16) & 0xFF));
        outb(ATA_PRIMARY_IO + 6, 0xE0 | ((lba >> 24) & 0x0F));

        // Skicka WRITE SECTORS (0x30)
        outb(ATA_PRIMARY_IO + 7, 0x30);

        if (ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Write Data Timeout Busy\n");
            
            return s * SECTOR_SIZE;
        }

        if (ata_wait_drq_set() < 0)
        {
            printf("[ATA] Write Data Timeout DRQ\n");
            
            return s * SECTOR_SIZE;
        }

        // Skriv 256 ord (512 byte)
        for (int i = 0; i < 256; i++)
            outw(ATA_PRIMARY_IO, *buf++);

        ata_io_wait();

        lba++;
    }

    return count * SECTOR_SIZE;
}

void ata_identify(void)
{
    // TODO: Implement...
}
