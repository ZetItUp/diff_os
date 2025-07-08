#ifndef PAGING_H
#define PAGING_H

#include <stdint.h>

extern uint64_t pml4[512];

void init_paging();

#endif
