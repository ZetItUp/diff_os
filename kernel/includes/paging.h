#pragma once

#include "stddef.h"
#include "stdint.h"

/* ====== Page flags (PTE/PDE) ====== */
#define PAGE_PRESENT    0x1
#define PAGE_RW         0x2
#define PAGE_USER       0x4
#define PAGE_PWT        0x8
#define PAGE_PCD        0x10
/* 32-bit x86 PDE Page Size (4MB) */
#ifndef PDE_PS
#define PDE_PS          0x80u
#endif
#define PAGE_FLAGS_IO   (PAGE_PRESENT | PAGE_RW | PAGE_PWT | PAGE_PCD)

#ifndef PAGE_PS
#define PAGE_PS 0x80u   /* PDE Page Size (1 = 4MB large page) */
#endif

/* ====== CPU control bits (för debug/sanity) ====== */
#ifndef CR0_PG
#define CR0_PG          0x80000000u
#endif
#ifndef CR4_PSE
#define CR4_PSE         0x00000010u
#endif

/* ====== Layout ====== */
#define KERNEL_BASE     0xC0000000u
#define KMAP_PAGES      64

#ifndef KMAP_BASE
#define KMAP_BASE       0xC0600000u
#endif
#ifndef KMAP_PDE_COUNT
#define KMAP_PDE_COUNT  8
#endif

#define KMAP_SIZE       (16u * 1024u * 1024u)  /* 16 MB kmap window */
#define KMAP_PDE_INDEX  ((uint32_t)(KMAP_BASE >> 22))

/* ====== Sizes & limits ====== */
#define PAGE_SIZE        0x1000u     /* 4 KB */
#define PAGE_SIZE_4KB    4096
#define PAGE_ENTRIES     1024         /* 1024 * 4KB = 4MB per PT */
#define BLOCK_SIZE       0x400000     /* 4 MB */
#define MAX_BLOCKS       1024
#define MAX_PHYS_PAGES  (MAX_BLOCKS * (BLOCK_SIZE / PAGE_SIZE_4KB))

#ifndef USER_MIN
#define USER_MIN 0x00100000u
#endif
#ifndef USER_MAX
#define USER_MAX 0x7FFF0000u
#endif

/* ====== Index/align helpers ====== */
#define PDE_INDEX(va)    (((uint32_t)(va)) >> 22)
#define PTE_INDEX(va)    ((((uint32_t)(va)) >> 12) & 0x3FFu)
#define PAGE_ALIGN_UP(x)   (((uint32_t)(x) + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1))
#define PAGE_ALIGN_DOWN(x) (((uint32_t)(x)) & ~(PAGE_SIZE_4KB - 1))

/* ====== BIOS E820 ====== */
typedef struct
{
    uint32_t base_low;
    uint32_t base_high;
    uint32_t length_low;
    uint32_t length_high;
    uint32_t type;       /* 1 = usable RAM */
    uint32_t acpi_ext;
} __attribute__((packed)) e820_entry_t;

/* ====== Extern PD (krävs av andra moduler) ====== */
extern uint32_t page_directory[1024];

/* ====== Init ====== */
void init_paging(uint32_t ram_mb);

/* ====== Mapping / unmapping ====== */
int  map_page(uint32_t virt_addr, uint32_t size);
void unmap_page(uint32_t virt_addr);

int  map_4kb_page(uint32_t virt_addr, uint32_t phys_addr);
int  map_4kb_page_flags(uint32_t virt_addr, uint32_t phys_addr, uint32_t flags);
void unmap_4kb_page(uint32_t virt_addr);

void paging_update_flags(uint32_t addr, uint32_t size, uint32_t set_mask, uint32_t clear_mask);
void paging_set_user(uint32_t addr, uint32_t size);
int  paging_probe_pde_pte(uint32_t va, uint32_t *out_pde, uint32_t *out_pte);

/* ====== Allocation ====== */
int  alloc_region(uint32_t virt_start, uint32_t size_mb);
int  free_region(uint32_t virt_start, uint32_t size_mb);

uint32_t alloc_phys_page(void);
void     free_phys_page(uint32_t addr);

void*    umalloc(size_t size);
void     ufree(void *ptr, size_t size);
int page_is_present(uint32_t va);
int is_user_addr(uint32_t vaddr);

uint32_t paging_new_address_space(void);
void     paging_switch_address_space(uint32_t pd_phys);
void paging_destroy_address_space(uint32_t pd_phys);

/* ====== Utilities ====== */
void paging_flush_tlb(void);

/* ====== Debug ====== */
void paging_dump_range(uint32_t addr, uint32_t size);
int  paging_check_user_range(uint32_t addr, uint32_t size);
void hexdump_bytes(const void *addr, size_t n);
void dump_pde_pte(uint32_t lin);
int  page_present(uint32_t lin);
void dump_err_bits(uint32_t err);

