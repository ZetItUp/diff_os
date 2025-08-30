#pragma once

#include "stdint.h"

#define SECTOR_SIZE     512

int ata_read(uint32_t lba, uint32_t count, void *buffer);
int ata_write(uint32_t lba, uint32_t count, const void *buffer);

void ata_init(void);
void ata_identify(void);

