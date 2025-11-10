#pragma once

#include "stddef.h"
#include "stdint.h"

/* KERNEL_PT_POOL: antal sidtabeller i statisk pool (default 1024) */
#ifndef KERNEL_PT_POOL
#define KERNEL_PT_POOL 128
#endif

#define PAGE_PRESENT    0x1
#define PAGE_RW         0x2
#define PAGE_USER       0x4
#define PAGE_PWT        0x8
#define PAGE_PCD        0x10

#ifndef PAGE_AVL1
#define PAGE_AVL1 0x200u
#endif

#ifndef PAGE_GLOBAL
#define PAGE_GLOBAL 0x100u   // 1 << 8, Global (G) bit
#endif

#ifndef PDE_PS
#define PDE_PS          0x80u
#endif
#define PAGE_FLAGS_IO   (PAGE_PRESENT | PAGE_RW | PAGE_PWT | PAGE_PCD)

#ifndef PAGE_PS
#define PAGE_PS 0x80u
#endif

#ifndef CR0_PG
#define CR0_PG          0x80000000u
#endif
#ifndef CR4_PSE
#define CR4_PSE         0x00000010u
#endif

#define KERNEL_BASE     0xC0000000u
#define KMAP_PAGES      64

#ifndef KMAP_PDE_COUNT
#define KMAP_PDE_COUNT  8
#endif

#define KMAP_SIZE       (16u * 1024u * 1024u)  /* 16 MB kmap window */

#define PAGE_SIZE        0x1000u
#define PAGE_SIZE_4KB    4096
#define PAGE_ENTRIES     1024
#define BLOCK_SIZE       0x400000
#define MAX_BLOCKS       1024
#define MAX_PHYS_PAGES  (MAX_BLOCKS * (BLOCK_SIZE / PAGE_SIZE_4KB))

/* ---- CONSISTENT USER WINDOW ----
 * Identity-mapped low memory is kernel-only; treat user space as >= 4 MiB.
 */
#undef  USER_MIN
#define USER_MIN 0x40000000u

#ifndef USER_MAX
#define USER_MAX 0x7FFF0000u
#endif
/* -------------------------------- */

#define PDE_INDEX(va)    (((uint32_t)(va)) >> 22)
#define PTE_INDEX(va)    ((((uint32_t)(va)) >> 12) & 0x3FFu)
#define PAGE_ALIGN_UP(x)   (((uint32_t)(x) + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1))
#define PAGE_ALIGN_DOWN(x) (((uint32_t)(x)) & ~(PAGE_SIZE_4KB - 1))

typedef struct
{
    uint32_t base_low;
    uint32_t base_high;
    uint32_t length_low;
    uint32_t length_high;
    uint32_t type;
    uint32_t acpi_ext;
} __attribute__((packed)) e820_entry_t;

extern uint32_t page_directory[1024];

void init_paging(uint32_t ram_mb);

int map_page(uint32_t virt_addr, uint32_t size);
void unmap_page(uint32_t virt_addr);

int map_4kb_page(uint32_t virt_addr, uint32_t phys_addr);
int map_4kb_page_flags(uint32_t virt_addr, uint32_t phys_addr, uint32_t flags);
void unmap_4kb_page(uint32_t virt_addr);

void paging_update_flags(uint32_t addr, uint32_t size, uint32_t set_mask, uint32_t clear_mask);
void paging_set_user(uint32_t addr, uint32_t size);
int paging_probe_pde_pte(uint32_t va, uint32_t *out_pde, uint32_t *out_pte);

int paging_map_user_range(uintptr_t vaddr, size_t bytes, int writable);
int paging_unmap_user_range(uintptr_t vaddr, size_t bytes);

int alloc_region(uint32_t virt_start, uint32_t size_mb);
int free_region(uint32_t virt_start, uint32_t size_mb);

uint32_t alloc_phys_page(void);
void free_phys_page(uint32_t addr);

void *umalloc(size_t size);
void ufree(void *ptr, size_t size);
int page_is_present(uint32_t va);
int is_user_addr(uint32_t vaddr);

int paging_handle_page_fault(uint32_t fault_va, uint32_t err);
int paging_handle_demand_fault(uintptr_t fault_va);
int paging_handle_cow_fault(uintptr_t fault_va);
int paging_ensure_pagetable(uint32_t va, uint32_t flags);
int paging_reserve_range(uintptr_t start, size_t size);

void paging_free_all_user(void);
void paging_free_all_user_in(uint32_t cr3_phys);

void paging_user_heap_reset(void);
void paging_set_user_heap(uintptr_t addr);
uintptr_t paging_kernel_cr3_phys(void);
uint32_t paging_new_address_space(void);
void paging_switch_address_space(uint32_t pd_phys);
void paging_destroy_address_space(uint32_t pd_phys);
void paging_flush_tlb(void);

void paging_dump_range(uint32_t addr, uint32_t size);
int  paging_check_user_range(uint32_t addr, uint32_t size);
int  paging_check_user_range_writable(uint32_t addr, uint32_t size);
void hexdump_bytes(const void *addr, size_t n);
void paging_dump_mapping(uint32_t va);
void dump_pde_pte(uint32_t lin);
int  page_present(uint32_t lin);
void dump_err_bits(uint32_t err);

void paging_pt_pool_commit(void);
