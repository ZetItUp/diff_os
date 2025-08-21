#include "drivers/ata.h"
#include "io.h"
#include "stdio.h"
#include "stdint.h"

#define ATA_PRIMARY_IO   0x1F0
#define ATA_PRIMARY_CTRL 0x3F6
#define SECTOR_SIZE      512

static void ata_io_wait(void)
{
    for (int i = 0; i < 4; i++)
    {
        inb(ATA_PRIMARY_CTRL);
    }
}

static int ata_wait_busy_clear(void)
{
    // Wait until BSY (0x80) goes low
    for (int i = 0; i < 100000; i++)
    {
        uint8_t status = inb(ATA_PRIMARY_IO + 7);

        if (!(status & 0x80))
        {
            // Not busy anymore
            return 0;
        }
    }

    printf("[ATA] Timeout: BSY stuck\n");

    return -1;
}

static int ata_wait_drq_set(void)
{
    // Wait until DRQ (0x08) goes high
    for (int i = 0; i < 100000; i++)
    {
        uint8_t status = inb(ATA_PRIMARY_IO + 7);

        if (status & 0x08)
        {
            // Device is ready to transfer data
            return 0;
        }
    }

    printf("[ATA] Timeout: DRQ not set\n");

    return -1;
}

void ata_init(void)
{

}

int ata_read(uint32_t lba, uint32_t count, void *buffer)
{
    uint16_t *buf = (uint16_t*)buffer;

    for (uint32_t s = 0; s < count; s++)
    {
        if (ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Busy timeout\n");

            return (int)(s * SECTOR_SIZE);
        }

        // Use interrupts disabled bit clear
        outb(ATA_PRIMARY_CTRL, 0x00);

        // One sector per command
        outb(ATA_PRIMARY_IO + 2, 1);

        // LBA low, mid, high
        outb(ATA_PRIMARY_IO + 3, (uint8_t)(lba & 0xFF));
        outb(ATA_PRIMARY_IO + 4, (uint8_t)((lba >> 8) & 0xFF));
        outb(ATA_PRIMARY_IO + 5, (uint8_t)((lba >> 16) & 0xFF));

        // Drive/head, primary + LBA mode
        outb(ATA_PRIMARY_IO + 6, 0xE0 | ((lba >> 24) & 0x0F));

        // Read sectors command (0x20)
        outb(ATA_PRIMARY_IO + 7, 0x20);

        if (ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Busy timeout after read cmd\n");

            return (int)(s * SECTOR_SIZE);
        }

        if (ata_wait_drq_set() < 0)
        {
            printf("[ATA] DRQ timeout on read\n");

            return SECTOR_SIZE;
        }

        // Pull 256 words (512 bytes)
        for (int i = 0; i < 256; i++)
        {
            *buf++ = inw(ATA_PRIMARY_IO);
        }

        ata_io_wait();

        lba++;
    }

    return (int)(count * SECTOR_SIZE);
}

int ata_write(uint32_t lba, uint32_t count, const void *buffer)
{
    const uint16_t *buf = (const uint16_t*)buffer;

    for (uint32_t s = 0; s < count; s++)
    {
        if (ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Write timeout (busy)\n");

            return (int)(s * SECTOR_SIZE);
        }

        // Use interrupts disabled bit clear
        outb(ATA_PRIMARY_CTRL, 0x00);

        // One sector per command
        outb(ATA_PRIMARY_IO + 2, 1);

        // LBA low, mid, high
        outb(ATA_PRIMARY_IO + 3, (uint8_t)(lba & 0xFF));
        outb(ATA_PRIMARY_IO + 4, (uint8_t)((lba >> 8) & 0xFF));
        outb(ATA_PRIMARY_IO + 5, (uint8_t)((lba >> 16) & 0xFF));

        // Drive/head, primary + LBA mode
        outb(ATA_PRIMARY_IO + 6, 0xE0 | ((lba >> 24) & 0x0F));

        // Write sectors command (0x30)
        outb(ATA_PRIMARY_IO + 7, 0x30);

        if (ata_wait_busy_clear() < 0)
        {
            printf("[ATA] Write timeout after cmd\n");

            return (int)(s * SECTOR_SIZE);
        }

        if (ata_wait_drq_set() < 0)
        {
            printf("[ATA] Write timeout (DRQ)\n");

            return (int)(s * SECTOR_SIZE);
        }

        // Push 256 words (512 bytes)
        for (int i = 0; i < 256; i++)
        {
            outw(ATA_PRIMARY_IO, *buf++);
        }

        ata_io_wait();

        lba++;
    }

    return (int)(count * SECTOR_SIZE);
}

void ata_identify(void)
{
    // Stub for later
}

