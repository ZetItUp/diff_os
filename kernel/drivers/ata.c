#include "drivers/ata.h"
#include "io.h"
#include "stdio.h"
#include "stdint.h"
#include "string.h"

#define ATA_DEBUG_PROGRESS 0        // sätt 0 för tyst
#define ATA_LOG_EVERY_SECT 64       // progress var 64:e sektor

// ------------------------------
// I/O baser (primär kanal, master)
// ------------------------------
#define ATA_PRIMARY_IO        0x1F0
#define ATA_PRIMARY_CTRL      0x3F6

// Register offsets (task-file)
#define ATA_REG_DATA          0   // RW 16-bit
#define ATA_REG_ERROR         1   // R
#define ATA_REG_FEATURES      1   // W
#define ATA_REG_SECCNT0       2   // W
#define ATA_REG_LBA0          3   // W
#define ATA_REG_LBA1          4   // W
#define ATA_REG_LBA2          5   // W
#define ATA_REG_HDDEVSEL      6   // W
#define ATA_REG_STATUS        7   // R
#define ATA_REG_COMMAND       7   // W

// Device control bits (alternate status / control @ CTRL base)
#define ATA_DC_NIEN           0x02     // 1=maskera IRQ
#define ATA_DC_SRST           0x04     // 1=pulsa för soft reset

// Status bits
#define ATA_SR_ERR            0x01
#define ATA_SR_DRQ            0x08
#define ATA_SR_DF             0x20
#define ATA_SR_BSY            0x80

// Kommandon
#define ATA_CMD_READ_SECTORS  0x20
#define ATA_CMD_WRITE_SECTORS 0x30
#define ATA_CMD_IDENTIFY      0xEC

#ifndef SECTOR_SIZE
#define SECTOR_SIZE 512
#endif

// Hur länge vi väntar i polling-loops (i "iterationer")
// Dessa är CPU-varvsräkningar; vi petar in 400ns-delays så de inte blir *för* täta.
#define ATA_TIMEOUT_BSY_ITERS   2000000u
#define ATA_TIMEOUT_DRQ_ITERS   2000000u

// -------------------------------------------------
// Små hjälpare
// -------------------------------------------------
static inline void ata_io_wait_400ns(void)
{
    // Läs alternate status 4 ggr ≈ 400ns
    (void)inb(ATA_PRIMARY_CTRL);
    (void)inb(ATA_PRIMARY_CTRL);
    (void)inb(ATA_PRIMARY_CTRL);
    (void)inb(ATA_PRIMARY_CTRL);
}

static inline uint8_t ata_status(void)
{
    return inb(ATA_PRIMARY_IO + ATA_REG_STATUS);
}

static void ata_select_master_lba(uint32_t lba28)
{
    // 0xE0 = master + LBA-bitar 24..27
    outb(ATA_PRIMARY_IO + ATA_REG_HDDEVSEL, (uint8_t)(0xE0 | ((lba28 >> 24) & 0x0F)));
    ata_io_wait_400ns();
}

static int ata_wait_not_busy(void)
{
    uint32_t iters = 0;
    for (;;)
    {
        uint8_t s = ata_status();
        if ((s & ATA_SR_BSY) == 0) {
#if ATA_DEBUG_PROGRESS
            printf("[ATA] BSY->0 after %u iters ST=%02x\n", iters, s);
#endif
            return 0;
        }
        if (++iters >= ATA_TIMEOUT_BSY_ITERS) {
            uint8_t err = inb(ATA_PRIMARY_IO + ATA_REG_ERROR);
            printf("[ATA] Timeout: BSY stuck  ST=%02x ERR=%02x (iters=%u)\n", s, err, iters);
            return -1;
        }
        ata_io_wait_400ns();
    }
}

static int ata_wait_drq_ready(void)
{
    uint32_t iters = 0;
    for (;;)
    {
        uint8_t s = ata_status();
        if (s & (ATA_SR_ERR | ATA_SR_DF)) {
            uint8_t err = inb(ATA_PRIMARY_IO + ATA_REG_ERROR);
            printf("[ATA] Device error while wait DRQ  ST=%02x ERR=%02x (iters=%u)\n", s, err, iters);
            return -2;
        }
        if ((s & (ATA_SR_BSY | ATA_SR_DRQ)) == ATA_SR_DRQ) {
#if ATA_DEBUG_PROGRESS
            printf("[ATA] DRQ=1 after %u iters ST=%02x\n", iters, s);
#endif
            return 0;
        }
        if (++iters >= ATA_TIMEOUT_DRQ_ITERS) {
            uint8_t err = inb(ATA_PRIMARY_IO + ATA_REG_ERROR);
            printf("[ATA] Timeout: DRQ not set  ST=%02x ERR=%02x (iters=%u)\n", s, err, iters);
            return -1;
        }
        ata_io_wait_400ns();
    }
}

// -------------------------------------------------
// Publika API
// -------------------------------------------------
void ata_init(void)
{
    // Maskera IRQ (vi kör rent pollande)
    outb(ATA_PRIMARY_CTRL, ATA_DC_NIEN);

    // Kort soft reset-puls
    outb(ATA_PRIMARY_CTRL, (uint8_t)(ATA_DC_NIEN | ATA_DC_SRST));
    ata_io_wait_400ns();
    outb(ATA_PRIMARY_CTRL, ATA_DC_NIEN);

    // Vänta bort eventuell reset-BSY
    (void)ata_wait_not_busy();

    // Testa och logga enhets-ID (valfritt, men bra vid bring-up)
    ata_identify();
}

void ata_identify(void)
{
    // Försök IDENTIFY DET (0xEC) på primär master
    ata_select_master_lba(0);

    // Nollställ fält
    outb(ATA_PRIMARY_IO + ATA_REG_SECCNT0, 0);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA0,    0);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA1,    0);
    outb(ATA_PRIMARY_IO + ATA_REG_LBA2,    0);

    outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_IDENTIFY);
    ata_io_wait_400ns();

    // Om status läser 0, finns ingen enhet
    uint8_t st = ata_status();
    if (st == 0x00)
    {
        printf("[ATA] No device on primary master\n");
        return;
    }

    if (ata_wait_not_busy() != 0)
        return;

    if (ata_wait_drq_ready() != 0)
        return;

    // Läs 512 bytes
    uint16_t idw[256];
    for (int i = 0; i < 256; ++i) idw[i] = inw(ATA_PRIMARY_IO);
    ata_io_wait_400ns();

    // Plocka ut modellsträng: ord 27..46 (40 bytes), byte-swap per ord
    char model[41];
    for (int i = 0; i < 20; ++i)
    {
        uint16_t w = idw[27 + i];
        model[i*2 + 0] = (char)((w >> 8) & 0xFF);
        model[i*2 + 1] = (char)(w & 0xFF);
    }
    model[40] = '\0';

    // Trimma spaces
    for (int i = 39; i >= 0; --i)
    {
        if (model[i] == ' ' || model[i] == '\t' || model[i] == '\r' || model[i] == '\n')
            model[i] = '\0';
        else
            break;
    }

    printf("[ATA] IDENTIFY model: \"%s\"\n", model);
}

int ata_read(uint32_t lba, uint32_t count, void *buffer)
{
    if (count == 0) return 0;
    if (!buffer)    return -1;

    uint8_t  *dstb = (uint8_t*)buffer;
    uint32_t  done = 0;
#if ATA_DEBUG_PROGRESS
    printf("[ATA] Read LBA=%u count=%u\n", lba, count);
#endif
    for (uint32_t s = 0; s < count; ++s)
    {
        // 1) Vänta klart + välj enhet/bana
        if (ata_wait_not_busy() != 0)
            return (int)done;

        // Kör rent pollande; IRQ maskad i init
        outb(ATA_PRIMARY_CTRL, ATA_DC_NIEN);

        ata_select_master_lba(lba);

        // 2) Programmera "1 sektor" + LBA 0..23
        outb(ATA_PRIMARY_IO + ATA_REG_SECCNT0, 1);
        outb(ATA_PRIMARY_IO + ATA_REG_LBA0,    (uint8_t)(lba & 0xFF));
        outb(ATA_PRIMARY_IO + ATA_REG_LBA1,    (uint8_t)((lba >> 8) & 0xFF));
        outb(ATA_PRIMARY_IO + ATA_REG_LBA2,    (uint8_t)((lba >> 16) & 0xFF));

        // 3) Kommando
        outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_READ_SECTORS);

        // 4) Vänta DRQ (fel/timeout loggas)
        if (ata_wait_not_busy() != 0)
            return (int)done;
        if (ata_wait_drq_ready() != 0)
            return (int)done;

        // 5) Läs 512 byte (256 ord)
        uint16_t *bufw = (uint16_t*)dstb;
        for (int i = 0; i < 256; ++i)
            bufw[i] = inw(ATA_PRIMARY_IO);

        ata_io_wait_400ns();

        // 6) Avslut och nästa
        dstb += SECTOR_SIZE;
        lba++;
        done += SECTOR_SIZE;
#if ATA_DEBUG_PROGRESS
        if (((s + 1) % ATA_LOG_EVERY_SECT) == 0)
            printf("[ATA] Read progress: +%u sectors (LBA now %u)\n", ATA_LOG_EVERY_SECT, lba);
#endif
    }

#if ATA_DEBUG_PROGRESS
    printf("[ATA] Read done (%u bytes)\n", done);
#endif
    return (int)done;
}

int ata_write(uint32_t lba, uint32_t count, const void *buffer)
{
    if (count == 0) return 0;
    if (!buffer)    return -1;

    const uint8_t *srcb = (const uint8_t*)buffer;
    uint32_t       done = 0;

    for (uint32_t s = 0; s < count; ++s)
    {
        if (ata_wait_not_busy() != 0)
            return (int)done;

        // Pollande, maskera IRQ
        outb(ATA_PRIMARY_CTRL, ATA_DC_NIEN);

        ata_select_master_lba(lba);

        outb(ATA_PRIMARY_IO + ATA_REG_SECCNT0, 1);
        outb(ATA_PRIMARY_IO + ATA_REG_LBA0,    (uint8_t)(lba & 0xFF));
        outb(ATA_PRIMARY_IO + ATA_REG_LBA1,    (uint8_t)((lba >> 8) & 0xFF));
        outb(ATA_PRIMARY_IO + ATA_REG_LBA2,    (uint8_t)((lba >> 16) & 0xFF));

        outb(ATA_PRIMARY_IO + ATA_REG_COMMAND, ATA_CMD_WRITE_SECTORS);

        if (ata_wait_not_busy() != 0)
            return (int)done;
        if (ata_wait_drq_ready() != 0)
            return (int)done;

        // Skriv 512 byte (256 ord)
        const uint16_t *bufw = (const uint16_t*)srcb;
        for (int i = 0; i < 256; ++i)
            outw(ATA_PRIMARY_IO, bufw[i]);

        ata_io_wait_400ns();

        srcb += SECTOR_SIZE;
        lba++;
        done += SECTOR_SIZE;
    }

    return (int)done;
}

