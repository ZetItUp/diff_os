/*
 * paging_new.c - Clean x86 paging implementation with multi-process support
 *
 * Architecture:
 * - Recursive page directory mapping at entry 1023
 * - Kernel mapped high (identity + high kernel region)
 * - User space: 0x40000000 - 0x7FFF0000
 * - kmap scratch region accessible from all CR3s
 * - Dynamic page table allocation for user spaces
 */

#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "paging.h"
#include "system/usercopy.h"

// ============================================================================
// CONFIGURATION
// ============================================================================

#define UHEAP_BASE     0x40000000u
#define KMAP_SCRATCH_VA1  0x003FE000u
#define KMAP_SCRATCH_VA2  0x003FF000u

// Recursive PD entry
#define RECURSIVE_PD_ENTRY  1023
#define RECURSIVE_PD_BASE   0xFFFFF000u
#define RECURSIVE_PT_BASE   0xFFC00000u

// Macros
#define ALIGN_UP(x, a)      (((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a)    ((x) & ~((a) - 1))
#define GET_CURRENT_PD()    ((volatile uint32_t*)RECURSIVE_PD_BASE)
#define GET_PT(dir_idx)     ((volatile uint32_t*)(RECURSIVE_PT_BASE + ((dir_idx) << 12)))

// ============================================================================
// DATA STRUCTURES
// ============================================================================

// Main page directory (kernel's)
__attribute__((aligned(4096))) uint32_t page_directory[PAGE_ENTRIES];

// Static page table pool for kernel
__attribute__((aligned(4096))) uint32_t kernel_page_tables[KERNEL_PT_POOL][PAGE_ENTRIES];

// External symbols
extern char __heap_start;
extern char __heap_end;
extern volatile int g_in_irq;

// Physical memory management
static uint32_t max_blocks = 0;
static uint32_t *block_bitmap = NULL;
static uint32_t phys_page_bitmap[(MAX_PHYS_PAGES + 31) / 32];
static uint16_t phys_page_refcnt[MAX_PHYS_PAGES];

// Kernel state
static int pt_next = 1;  // Next free PT in static pool
static uint32_t s_kernel_cr3_phys = 0;
static uint32_t uheap_next = UHEAP_BASE;

// User memory reservations (for demand paging)
typedef struct {
    uint32_t start;
    uint32_t end;
} uresv_t;

#define MAX_USER_RESERVATIONS 32
static uresv_t uresv_list[MAX_USER_RESERVATIONS];
static int uresv_count = 0;

// Debug
static volatile int g_dbg_allow_irq_userpeek = 0;

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

static inline void invlpg(uint32_t va)
{
    asm volatile("invlpg (%0)" :: "r"(va) : "memory");
}

static inline void flush_tlb(void)
{
    uint32_t cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    asm volatile("mov %0, %%cr3" :: "r"(cr3) : "memory");
}

static inline uint32_t get_cr3(void)
{
    uint32_t cr3;
    asm volatile("mov %%cr3, %0" : "=r"(cr3));
    return cr3;
}

static inline int is_user_addr_inline(uint32_t va)
{
    return (va >= USER_MIN && va < USER_MAX);
}

// ============================================================================
// PHYSICAL MEMORY ALLOCATION
// ============================================================================

static void init_phys_bitmap(void)
{
    uint32_t ram_mb = 64;  // Assume 64MB for now
    uint32_t total_pages = (ram_mb * 1024 * 1024) / PAGE_SIZE_4KB;

    for (uint32_t i = 0; i < (total_pages + 31) / 32; i++) {
        phys_page_bitmap[i] = 0;
    }

    // Mark first 4MB as used (kernel + low memory)
    for (uint32_t i = 0; i < (BLOCK_SIZE / PAGE_SIZE_4KB); i++) {
        phys_page_bitmap[i / 32] |= (1u << (i % 32));
        phys_page_refcnt[i] = 1;
    }
}

uint32_t alloc_phys_page(void)
{
    uint32_t total_pages = (64 * 1024 * 1024) / PAGE_SIZE_4KB;

    for (uint32_t i = (BLOCK_SIZE / PAGE_SIZE_4KB); i < total_pages; i++) {
        if (!(phys_page_bitmap[i / 32] & (1u << (i % 32)))) {
            phys_page_bitmap[i / 32] |= (1u << (i % 32));
            phys_page_refcnt[i] = 1;
            return i * PAGE_SIZE_4KB;
        }
    }

    printf("[PAGING] ERROR: Out of physical pages\n");
    return 0;
}

void free_phys_page(uint32_t phys)
{
    if (phys < BLOCK_SIZE) return;  // Don't free low memory

    uint32_t page_idx = phys / PAGE_SIZE_4KB;
    if (page_idx >= MAX_PHYS_PAGES) return;

    if (phys_page_refcnt[page_idx] > 0) {
        phys_page_refcnt[page_idx]--;
        if (phys_page_refcnt[page_idx] == 0) {
            phys_page_bitmap[page_idx / 32] &= ~(1u << (page_idx % 32));
        }
    }
}

// ============================================================================
// KMAP - TEMPORARY PHYSICAL PAGE MAPPING
// ============================================================================

/*
 * kmap_phys: Map a physical page temporarily at a scratch VA
 * Works from any CR3 because kmap PTs are copied to all address spaces
 */
static inline void* kmap_phys(uint32_t phys, int slot)
{
    uint32_t va = slot ? KMAP_SCRATCH_VA2 : KMAP_SCRATCH_VA1;
    uint32_t dir_idx = va >> 22;
    uint32_t tbl_idx = (va >> 12) & 0x3FFu;

    // Access PT via recursive mapping
    volatile uint32_t *pt = GET_PT(dir_idx);
    pt[tbl_idx] = (phys & 0xFFFFF000u) | PAGE_PRESENT | PAGE_RW;
    invlpg(va);

    return (void*)va;
}

static inline void kunmap_phys(int slot)
{
    uint32_t va = slot ? KMAP_SCRATCH_VA2 : KMAP_SCRATCH_VA1;
    uint32_t dir_idx = va >> 22;
    uint32_t tbl_idx = (va >> 12) & 0x3FFu;

    volatile uint32_t *pt = GET_PT(dir_idx);
    pt[tbl_idx] = 0;
    invlpg(va);
}

// Exported wrappers
void* paging_kmap_phys(uint32_t phys, int slot) { return kmap_phys(phys, slot); }
void  paging_kunmap_phys(int slot)              { kunmap_phys(slot); }

// ============================================================================
// PAGE TABLE MANAGEMENT
// ============================================================================

/*
 * Allocate a page table for the given directory index
 * Returns 0 on success, -1 on failure
 */
static int ensure_page_table(uint32_t dir_idx, uint32_t pd_flags)
{
    volatile uint32_t *pd = GET_CURRENT_PD();
    uint32_t pde = pd[dir_idx];

    // Already has PT?
    if ((pde & PAGE_PRESENT) && !(pde & PAGE_PS)) {
        return 0;  // PT already exists
    }

    // Handle 4MB page - need to split
    if ((pde & PAGE_PRESENT) && (pde & PAGE_PS)) {
        printf("[PAGING] ERROR: Can't split 4MB pages yet (di=%u)\n", dir_idx);
        return -1;
    }

    // Determine if this is user space
    int is_user_space = (dir_idx >= (USER_MIN >> 22));
    uint32_t current_cr3 = get_cr3();
    int in_kernel_cr3 = (current_cr3 == s_kernel_cr3_phys) || (s_kernel_cr3_phys == 0);

    uint32_t pt_phys;

    // Use static pool for kernel space, dynamic for user space in user CR3
    if (in_kernel_cr3 || !is_user_space) {
        // Allocate from static pool
        if (pt_next >= KERNEL_PT_POOL) {
            printf("[PAGING] ERROR: Out of kernel PT pool\n");
            return -1;
        }

        uint32_t *pt = kernel_page_tables[pt_next++];
        for (int i = 0; i < PAGE_ENTRIES; i++) pt[i] = 0;

        pt_phys = ((uint32_t)(uintptr_t)pt);  // Kernel is identity mapped
    } else {
        // Allocate physical page for user PT
        pt_phys = alloc_phys_page();
        if (!pt_phys) {
            printf("[PAGING] ERROR: Out of physical memory for PT\n");
            return -1;
        }

        // Zero it using kmap
        uint32_t *pt = (uint32_t*)kmap_phys(pt_phys, 0);
        for (int i = 0; i < PAGE_ENTRIES; i++) pt[i] = 0;
        kunmap_phys(0);
    }

    // Install PT in PD
    pd[dir_idx] = pt_phys | pd_flags | PAGE_PRESENT | PAGE_RW;
    flush_tlb();

    return 0;
}

// ============================================================================
// PAGE MAPPING
// ============================================================================

int map_4kb_page_flags(uint32_t virt_addr, uint32_t phys_addr, uint32_t flags)
{
    uint32_t dir_idx = virt_addr >> 22;
    uint32_t tbl_idx = (virt_addr >> 12) & 0x3FFu;

    // Ensure PT exists
    uint32_t pd_flags = (flags & PAGE_USER) ? PAGE_USER : 0;
    if (ensure_page_table(dir_idx, pd_flags) != 0) {
        return -1;
    }

    // Map the page
    volatile uint32_t *pt = GET_PT(dir_idx);
    pt[tbl_idx] = (phys_addr & 0xFFFFF000u) | (flags & 0xFFFu) | PAGE_PRESENT;
    invlpg(virt_addr);

    return 0;
}

int map_4kb_page(uint32_t virt_addr, uint32_t phys_addr)
{
    uint32_t flags = is_user_addr_inline(virt_addr) ? PAGE_USER | PAGE_RW : PAGE_RW;
    return map_4kb_page_flags(virt_addr, phys_addr, flags);
}

void unmap_4kb_page(uint32_t virt_addr)
{
    uint32_t dir_idx = virt_addr >> 22;
    uint32_t tbl_idx = (virt_addr >> 12) & 0x3FFu;

    volatile uint32_t *pd = GET_CURRENT_PD();
    if (!(pd[dir_idx] & PAGE_PRESENT)) return;
    if (pd[dir_idx] & PAGE_PS) return;  // Can't unmap from 4MB page

    volatile uint32_t *pt = GET_PT(dir_idx);
    uint32_t old_pte = pt[tbl_idx];

    if (old_pte & PAGE_PRESENT) {
        uint32_t phys = old_pte & 0xFFFFF000u;
        free_phys_page(phys);
    }

    pt[tbl_idx] = 0;
    invlpg(virt_addr);
}

int map_page(uint32_t virt_addr, uint32_t size)
{
    // TODO: Handle 4MB pages for large mappings
    // For now, just use 4KB pages

    uint32_t pages = (size + PAGE_SIZE_4KB - 1) / PAGE_SIZE_4KB;
    uint32_t flags = is_user_addr_inline(virt_addr) ? PAGE_USER | PAGE_RW : PAGE_RW;

    for (uint32_t i = 0; i < pages; i++) {
        uint32_t va = virt_addr + (i * PAGE_SIZE_4KB);
        uint32_t phys = alloc_phys_page();
        if (!phys) return -1;

        if (map_4kb_page_flags(va, phys, flags) != 0) {
            return -1;
        }
    }

    return 0;
}

void unmap_page(uint32_t virt_addr)
{
    unmap_4kb_page(virt_addr);
}

// ============================================================================
// USER MEMORY MANAGEMENT
// ============================================================================

int paging_map_user_range(uintptr_t vaddr, size_t bytes, int writable)
{
    if (vaddr < USER_MIN || vaddr >= USER_MAX) return -1;

    uint32_t start = ALIGN_DOWN(vaddr, PAGE_SIZE_4KB);
    uint32_t end = ALIGN_UP(vaddr + bytes, PAGE_SIZE_4KB);
    uint32_t flags = PAGE_USER | (writable ? PAGE_RW : 0);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB) {
        uint32_t phys = alloc_phys_page();
        if (!phys) {
            // TODO: Cleanup on failure
            return -1;
        }

        // Zero the page
        void *p = kmap_phys(phys, 0);
        memset(p, 0, PAGE_SIZE_4KB);
        kunmap_phys(0);

        if (map_4kb_page_flags(va, phys, flags) != 0) {
            free_phys_page(phys);
            return -1;
        }
    }

    return 0;
}

int paging_unmap_user_range(uintptr_t vaddr, size_t bytes)
{
    uint32_t start = ALIGN_DOWN(vaddr, PAGE_SIZE_4KB);
    uint32_t end = ALIGN_UP(vaddr + bytes, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB) {
        unmap_4kb_page(va);
    }

    return 0;
}

// ============================================================================
// DEMAND PAGING
// ============================================================================

int paging_reserve_range(uintptr_t start, size_t size)
{
    if (uresv_count >= MAX_USER_RESERVATIONS) {
        printf("[PAGING] ERROR: Too many user reservations\n");
        return -1;
    }

    uresv_list[uresv_count].start = start;
    uresv_list[uresv_count].end = start + size;
    uresv_count++;

    return 0;
}

static int is_reserved_addr(uint32_t va)
{
    for (int i = 0; i < uresv_count; i++) {
        if (va >= uresv_list[i].start && va < uresv_list[i].end) {
            return 1;
        }
    }
    return 0;
}

int paging_handle_demand_fault(uintptr_t fault_va)
{
    if (!is_reserved_addr(fault_va)) {
        return -1;  // Not a valid demand-paged address
    }

    // Allocate and map a page
    uint32_t va = ALIGN_DOWN(fault_va, PAGE_SIZE_4KB);
    uint32_t phys = alloc_phys_page();
    if (!phys) return -1;

    // Zero the page
    void *p = kmap_phys(phys, 0);
    memset(p, 0, PAGE_SIZE_4KB);
    kunmap_phys(0);

    // Map it
    if (map_4kb_page_flags(va, phys, PAGE_USER | PAGE_RW) != 0) {
        free_phys_page(phys);
        return -1;
    }

    return 0;
}

int paging_handle_cow_fault(uintptr_t fault_va)
{
    // Not implemented yet
    return -1;
}

int paging_handle_page_fault(uint32_t fault_va, uint32_t err)
{
    // Try demand paging
    if (!(err & 0x1)) {  // Page not present
        if (is_user_addr_inline(fault_va)) {
            return paging_handle_demand_fault(fault_va);
        }
    }

    // COW fault (write to read-only page)
    if ((err & 0x3) == 0x3) {  // Present + Write
        return paging_handle_cow_fault(fault_va);
    }

    return -1;
}

// ============================================================================
// ADDRESS SPACE MANAGEMENT
// ============================================================================

void paging_user_heap_reset(void)
{
    uheap_next = UHEAP_BASE;
    uresv_count = 0;
}

uintptr_t paging_kernel_cr3_phys(void)
{
    return s_kernel_cr3_phys;
}

uint32_t paging_new_address_space(void)
{
    // Allocate physical page for new PD
    uint32_t pd_phys = alloc_phys_page();
    if (!pd_phys) {
        printf("[PAGING] ERROR: Can't allocate PD\n");
        return 0;
    }

    // Map and initialize new PD
    uint32_t *new_pd = (uint32_t*)kmap_phys(pd_phys, 0);

    // Copy kernel mappings (everything below USER_MIN)
    for (int i = 0; i < (int)(USER_MIN >> 22); i++) {
        new_pd[i] = page_directory[i];
    }

    // Copy kmap region (for scratch mappings to work)
    uint32_t kmap_di1 = KMAP_SCRATCH_VA1 >> 22;
    uint32_t kmap_di2 = KMAP_SCRATCH_VA2 >> 22;
    new_pd[kmap_di1] = page_directory[kmap_di1];
    if (kmap_di2 != kmap_di1) {
        new_pd[kmap_di2] = page_directory[kmap_di2];
    }

    // Clear user space entries
    for (int i = (USER_MIN >> 22); i < (int)(USER_MAX >> 22); i++) {
        if (i == (int)kmap_di1 || i == (int)kmap_di2) continue;
        new_pd[i] = 0;
    }

    // Setup recursive mapping
    new_pd[RECURSIVE_PD_ENTRY] = pd_phys | PAGE_PRESENT | PAGE_RW;

    kunmap_phys(0);

    return pd_phys;
}

void paging_switch_address_space(uint32_t cr3_phys)
{
    if (!cr3_phys) return;
    asm volatile("mov %0, %%cr3" :: "r"(cr3_phys) : "memory");
}

void paging_destroy_address_space(uint32_t cr3_phys)
{
    if (!cr3_phys || cr3_phys == s_kernel_cr3_phys) return;

    // TODO: Free all user page tables and pages
    // For now, just free the PD
    free_phys_page(cr3_phys);
}

void paging_flush_tlb(void)
{
    flush_tlb();
}

void paging_free_all_user(void)
{
    uint32_t current_cr3 = get_cr3();
    paging_free_all_user_in(current_cr3);
}

void paging_free_all_user_in(uint32_t cr3_phys)
{
    // TODO: Implement properly
    // Clear user reservations for now
    uresv_count = 0;
}

// ============================================================================
// UTILITY/DEBUG FUNCTIONS
// ============================================================================

int paging_ensure_pagetable(uint32_t va, uint32_t flags)
{
    uint32_t dir_idx = va >> 22;
    return ensure_page_table(dir_idx, flags);
}

void paging_update_flags(uint32_t addr, uint32_t size, uint32_t set_mask, uint32_t clear_mask)
{
    uint32_t start = ALIGN_DOWN(addr, PAGE_SIZE_4KB);
    uint32_t end = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB) {
        uint32_t dir_idx = va >> 22;
        uint32_t tbl_idx = (va >> 12) & 0x3FFu;

        volatile uint32_t *pd = GET_CURRENT_PD();
        if (!(pd[dir_idx] & PAGE_PRESENT)) continue;
        if (pd[dir_idx] & PAGE_PS) continue;

        volatile uint32_t *pt = GET_PT(dir_idx);
        if (pt[tbl_idx] & PAGE_PRESENT) {
            pt[tbl_idx] = (pt[tbl_idx] & ~clear_mask) | set_mask;
            invlpg(va);
        }
    }
}

void paging_set_user(uint32_t addr, uint32_t size)
{
    paging_update_flags(addr, size, PAGE_USER, 0);
}

int paging_probe_pde_pte(uint32_t va, uint32_t *out_pde, uint32_t *out_pte)
{
    uint32_t dir_idx = va >> 22;
    uint32_t tbl_idx = (va >> 12) & 0x3FFu;

    volatile uint32_t *pd = GET_CURRENT_PD();
    uint32_t pde = pd[dir_idx];

    if (out_pde) *out_pde = pde;

    if (!(pde & PAGE_PRESENT)) {
        if (out_pte) *out_pte = 0;
        return 0;
    }

    if (pde & PAGE_PS) {
        if (out_pte) *out_pte = 0;
        return 1;  // 4MB page
    }

    volatile uint32_t *pt = GET_PT(dir_idx);
    if (out_pte) *out_pte = pt[tbl_idx];

    return 0;
}

int page_is_present(uint32_t va)
{
    uint32_t pde, pte;
    paging_probe_pde_pte(va, &pde, &pte);

    if (pde & PAGE_PS) return 1;  // 4MB page
    return (pte & PAGE_PRESENT) ? 1 : 0;
}

int page_present(uint32_t lin)
{
    return page_is_present(lin);
}

int is_user_addr(uint32_t vaddr)
{
    return is_user_addr_inline(vaddr);
}

int paging_check_user_range(uint32_t addr, uint32_t size)
{
    if (addr < USER_MIN || (addr + size) > USER_MAX) return 0;

    uint32_t start = ALIGN_DOWN(addr, PAGE_SIZE_4KB);
    uint32_t end = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB) {
        uint32_t pde, pte;
        paging_probe_pde_pte(va, &pde, &pte);

        if (!(pde & PAGE_PRESENT)) return 0;
        if (pde & PAGE_PS) {
            if (!(pde & PAGE_USER)) return 0;
        } else {
            if (!(pte & PAGE_PRESENT) || !(pte & PAGE_USER)) return 0;
        }
    }

    return 1;
}

int paging_check_user_range_writable(uint32_t addr, uint32_t size)
{
    if (!paging_check_user_range(addr, size)) return 0;

    uint32_t start = ALIGN_DOWN(addr, PAGE_SIZE_4KB);
    uint32_t end = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB) {
        uint32_t pde, pte;
        paging_probe_pde_pte(va, &pde, &pte);

        if (pde & PAGE_PS) {
            if (!(pde & PAGE_RW)) return 0;
        } else {
            if (!(pte & PAGE_RW)) return 0;
        }
    }

    return 1;
}

void paging_dbg_allow_irq_userpeek(int enable)
{
    g_dbg_allow_irq_userpeek = enable ? 1 : 0;
}

void paging_pt_pool_commit(void)
{
    // Nothing to do in new design
}

// ============================================================================
// CROSS-CR3 MAPPING (for shared libraries)
// ============================================================================

int paging_map_phys_to_user_in_cr3(uint32_t cr3, uintptr_t user_vaddr,
                                     uint32_t phys_addr, size_t bytes,
                                     int writable, int executable)
{
    if (user_vaddr < USER_MIN || user_vaddr >= USER_MAX) return -1;

    uint32_t old_cr3 = get_cr3();
    paging_switch_address_space(cr3);

    uint32_t start = ALIGN_DOWN(user_vaddr, PAGE_SIZE_4KB);
    uint32_t end = ALIGN_UP(user_vaddr + bytes, PAGE_SIZE_4KB);
    uint32_t flags = PAGE_USER | (writable ? PAGE_RW : 0);
    uint32_t phys = phys_addr & 0xFFFFF000u;

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB, phys += PAGE_SIZE_4KB) {
        if (map_4kb_page_flags(va, phys, flags) != 0) {
            paging_switch_address_space(old_cr3);
            return -1;
        }
    }

    paging_switch_address_space(old_cr3);
    return 0;
}

int paging_unmap_user_range_in_cr3(uint32_t cr3, uintptr_t user_vaddr, size_t bytes)
{
    uint32_t old_cr3 = get_cr3();
    paging_switch_address_space(cr3);

    int result = paging_unmap_user_range(user_vaddr, bytes);

    paging_switch_address_space(old_cr3);
    return result;
}

uintptr_t paging_find_free_user_range_in_cr3(uint32_t cr3, size_t bytes)
{
    uint32_t old_cr3 = get_cr3();
    paging_switch_address_space(cr3);

    uint32_t pages_needed = (bytes + PAGE_SIZE_4KB - 1) / PAGE_SIZE_4KB;
    uint32_t consecutive = 0;
    uintptr_t start_va = 0;

    for (uintptr_t va = USER_MIN; va < USER_MAX; va += PAGE_SIZE_4KB) {
        if (!page_is_present(va)) {
            if (consecutive == 0) start_va = va;
            consecutive++;

            if (consecutive >= pages_needed) {
                paging_switch_address_space(old_cr3);
                return start_va;
            }
        } else {
            consecutive = 0;
        }
    }

    paging_switch_address_space(old_cr3);
    return 0;
}

// ============================================================================
// LEGACY FUNCTIONS (compatibility)
// ============================================================================

void *umalloc(size_t size)
{
    size = ALIGN_UP(size, PAGE_SIZE_4KB);
    uint32_t va = uheap_next;

    if (paging_map_user_range(va, size, 1) != 0) {
        return NULL;
    }

    uheap_next += size;
    return (void*)va;
}

void ufree(void *ptr, size_t size)
{
    if (!ptr) return;
    size = ALIGN_UP(size, PAGE_SIZE_4KB);
    paging_unmap_user_range((uintptr_t)ptr, size);
}

int alloc_region(uint32_t virt_start, uint32_t size_mb)
{
    return map_page(virt_start, size_mb * 1024 * 1024);
}

int free_region(uint32_t virt_start, uint32_t size_mb)
{
    // TODO: Implement
    return 0;
}

// ============================================================================
// DEBUG FUNCTIONS
// ============================================================================

void hexdump_bytes(const void *addr, size_t n)
{
    const uint8_t *p = (const uint8_t*)addr;
    for (size_t i = 0; i < n; i++) {
        if (i > 0 && (i % 16) == 0) printf("\n");
        printf("%02x ", p[i]);
    }
    printf("\n");
}

void paging_dump_mapping(uint32_t va)
{
    uint32_t pde, pte;
    paging_probe_pde_pte(va, &pde, &pte);

    printf("[PAGING] VA=%08x: PDE=%08x PTE=%08x\n", va, pde, pte);
}

void dump_pde_pte(uint32_t lin)
{
    paging_dump_mapping(lin);
}

void paging_dump_range(uint32_t addr, uint32_t size)
{
    printf("[PAGING] Dump range %08x - %08x:\n", addr, addr + size);

    uint32_t start = ALIGN_DOWN(addr, PAGE_SIZE_4KB);
    uint32_t end = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB) {
        uint32_t pde, pte;
        paging_probe_pde_pte(va, &pde, &pte);

        if (pde & PAGE_PRESENT) {
            if (pde & PAGE_PS) {
                printf("  %08x: 4MB page -> phys=%08x\n", va, pde & 0xFFC00000u);
            } else if (pte & PAGE_PRESENT) {
                printf("  %08x: 4KB page -> phys=%08x flags=%c%c%c\n",
                       va, pte & 0xFFFFF000u,
                       (pte & PAGE_USER) ? 'U' : 'K',
                       (pte & PAGE_RW) ? 'W' : 'R',
                       (pte & PAGE_PRESENT) ? 'P' : '-');
            }
        }
    }
}

void dump_err_bits(uint32_t err)
{
    printf("ERR=%08x: %s %s %s %s %s\n", err,
           (err & 0x1) ? "PRESENT" : "NOT-PRESENT",
           (err & 0x2) ? "WRITE" : "READ",
           (err & 0x4) ? "USER" : "SUPERVISOR",
           (err & 0x8) ? "RESERVED" : "",
           (err & 0x10) ? "INSTR-FETCH" : "");
}

// ============================================================================
// INITIALIZATION
// ============================================================================

static void identity_map_low(uint32_t end_addr)
{
    // Use 4MB pages for simplicity
    uint32_t blocks = (end_addr + BLOCK_SIZE - 1) / BLOCK_SIZE;

    for (uint32_t i = 0; i < blocks && i < 256; i++) {
        page_directory[i] = (i * BLOCK_SIZE) | PAGE_PRESENT | PAGE_RW | PAGE_PS;
    }
}

void init_paging(uint32_t ram_mb)
{
    printf("[PAGING] Initializing with %u MB RAM\n", ram_mb);

    // Clear page directory
    for (int i = 0; i < PAGE_ENTRIES; i++) {
        page_directory[i] = 0;
    }

    // Clear PT pool
    for (int i = 0; i < KERNEL_PT_POOL; i++) {
        for (int j = 0; j < PAGE_ENTRIES; j++) {
            kernel_page_tables[i][j] = 0;
        }
    }

    // Initialize physical memory
    init_phys_bitmap();
    max_blocks = (ram_mb * 1024 * 1024) / BLOCK_SIZE;
    block_bitmap = phys_page_bitmap;

    // Identity map low memory (kernel + data)
    uint32_t heap_end = (uint32_t)(uintptr_t)&__heap_end;
    uint32_t id_end = ALIGN_UP(heap_end + 64 * 1024, BLOCK_SIZE);  // +64KB buffer
    identity_map_low(id_end);

    // Setup kmap scratch pages
    uint32_t kmap_di1 = KMAP_SCRATCH_VA1 >> 22;
    uint32_t kmap_di2 = KMAP_SCRATCH_VA2 >> 22;

    if (ensure_page_table(kmap_di1, PAGE_PRESENT | PAGE_RW) != 0) {
        printf("[PAGING] ERROR: Can't create kmap PT\n");
        return;
    }

    if (kmap_di2 != kmap_di1) {
        if (ensure_page_table(kmap_di2, PAGE_PRESENT | PAGE_RW) != 0) {
            printf("[PAGING] ERROR: Can't create kmap PT 2\n");
            return;
        }
    }

    // Setup recursive mapping
    uint32_t pd_phys = (uint32_t)(uintptr_t)page_directory;
    page_directory[RECURSIVE_PD_ENTRY] = pd_phys | PAGE_PRESENT | PAGE_RW;

    // Enable paging
    asm volatile("mov %0, %%cr3" :: "r"(pd_phys) : "memory");

    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= CR0_PG;
    asm volatile("mov %0, %%cr0" :: "r"(cr0) : "memory");

    uint32_t cr4;
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= CR4_PSE;
    asm volatile("mov %0, %%cr4" :: "r"(cr4) : "memory");

    s_kernel_cr3_phys = pd_phys;

    printf("[PAGING] Enabled (CR3=%08x)\n", pd_phys);
}
