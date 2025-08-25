#pragma once
#include <stdint.h>

typedef struct __attribute__((packed)) {
    uint16_t link, _r0;
    uint32_t esp0;
    uint16_t ss0, _r1;
    uint32_t esp1;
    uint16_t ss1, _r2;
    uint32_t esp2;
    uint16_t ss2, _r3;
    uint32_t cr3, eip, eflags;
    uint32_t eax, ecx, edx, ebx;
    uint32_t esp, ebp, esi, edi;
    uint16_t es, _r4;
    uint16_t cs, _r5;
    uint16_t ss, _r6;
    uint16_t ds, _r7;
    uint16_t fs, _r8;
    uint16_t gs, _r9;
    uint16_t ldt, _r10;
    uint16_t trap, iobase;
} tss_t;

void tss_init(uint32_t esp0_init);
void tss_set_esp0(uint32_t esp0);

