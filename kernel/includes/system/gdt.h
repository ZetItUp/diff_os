#pragma once
#include <stdint.h>
#include <stddef.h>

/* -------- GDT layout (indexer) --------
 * 0: null
 * 1: kernel code (ring0)
 * 2: kernel data (ring0)
 * 3: user   code (ring3)
 * 4: user   data (ring3)
 * 5: TSS (32-bit available)
 */
enum {
    GDT_IDX_NULL = 0,
    GDT_IDX_KCODE = 1,
    GDT_IDX_KDATA = 2,
    GDT_IDX_UCODE = 3,
    GDT_IDX_UDATA = 4,
    GDT_IDX_TSS   = 5,
    GDT_COUNT     = 6
};

#define GDT_SEL(idx, rpl)   ((uint16_t)(((idx) << 3) | ((rpl) & 0x3)))

/* Exporterade selektorvärden (globala symboler som andra moduler kan länka mot) */
extern uint16_t GDT_KERNEL_CS_SEL; /* 0x08 */
extern uint16_t GDT_KERNEL_DS_SEL; /* 0x10 */
extern uint16_t GDT_USER_CS_SEL;   /* 0x1B */
extern uint16_t GDT_USER_DS_SEL;   /* 0x23 */
extern uint16_t GDT_TSS_SEL;       /* 0x28 */

/* Packade GDT-strukturer */
#pragma pack(push, 1)
typedef struct {
    uint16_t limit_lo;     /* bits 0..15  */
    uint16_t base_lo;      /* bits 0..15  */
    uint8_t  base_mid;     /* bits 16..23 */
    uint8_t  access;       /* type | S | DPL | P */
    uint8_t  gran;         /* limit[16..19] | AVL | L | D/B | G */
    uint8_t  base_hi;      /* bits 24..31 */
} gdt_entry_t;

typedef struct {
    uint16_t limit;
    uint32_t base;
} gdtr_t;
#pragma pack(pop)

/* Initiera och ladda kärnans GDT (byter över till den och flush:ar segment) */
void gdt_init(void);

/* Fyll/uppdatera TSS-deskriptor i GDT (typ=0x89). 'limit' är normalt 104-1.
 * Kräver att gdt_init() redan har kört (så GDT ligger i minnet).
 * Den här gör INTE ltr – låt tss.c göra det efter att SS0/ESP0 satts. */
void gdt_install_tss(uint32_t base, uint32_t limit);

/* Exponera GDT-bas och storlek för kod som vill peta direkt (t.ex. TSS-kod) */
const void* gdt_get_base(void);
uint16_t    gdt_get_size(void);

