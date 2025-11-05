#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "paging.h"
#include "system/usercopy.h"
#include "debug.h"

#define PAGING_DBG(...) DDBG_IF(DEBUG_AREA_PAGING, __VA_ARGS__)

#ifndef UHEAP_BASE
#define UHEAP_BASE 0x40000000u
#endif

#ifndef KMAP_TEMP_VA
#define KMAP_TEMP_VA 0x003FF000u // Temporary mapping page (low VA)
#endif

// Legacy high-VA scratch (not used early anymore, kept for later if you want)
#define KMAP_SCRATCH1 0xFFCFF000
#define KMAP_SCRATCH2 0xFFCFE000

#define UMEM_GUARD_BEFORE  (1u << 0)
#define UMEM_GUARD_AFTER   (1u << 1)
#define UMEM_NOZERO        (1u << 2)
#define UMEM_PINNED        (1u << 3)
#define UMEM_PAGEALIGNED   (1u << 4)

#define PAGE_SIZE_4K  PAGE_SIZE_4KB
#define ALIGN_UP(x, a)   (((x) + ((a) - 1)) & ~((a) - 1))
#define ALIGN_DOWN(x, a) ((x) & ~((a) - 1))

__attribute__((aligned(4096))) uint32_t page_directory[PAGE_ENTRIES];

#ifndef KERNEL_PT_POOL
#define KERNEL_PT_POOL 128
#endif
__attribute__((aligned(4096))) uint32_t kernel_page_tables[KERNEL_PT_POOL][PAGE_ENTRIES];

// Kernel page table pool address range (for identifying static vs dynamic PTs)
static uint32_t kpt_start;
static uint32_t kpt_end;

extern char __heap_start;
extern char __heap_end;

// Bitmaps och refcounts
static uint32_t *block_bitmap;
static uint32_t max_blocks;
static uint32_t phys_page_bitmap[(MAX_PHYS_PAGES + 31) / 32];
static uint16_t phys_page_refcnt[MAX_PHYS_PAGES];

// Scratch-map state
static uint32_t g_kmap_temp_mapped_phys = 0;
static uint32_t uheap_next = UHEAP_BASE;
static uint32_t kmap_va1 = 0;
static uint32_t kmap_va2 = 0;

// Direkta PT-pekare för scratch (för att undvika rekursion)
static uint32_t *g_kmap_pt1 = NULL;
static uint32_t *g_kmap_pt2 = NULL;

typedef struct
{
    uint32_t start;
    uint32_t end;
} uresv_t;

#define MAX_USER_RESERVATIONS 32
static uresv_t uresv_list[MAX_USER_RESERVATIONS];
static int uresv_count = 0;

static int pt_next = 1;
static int pt_bootstrap_next = 1;
extern volatile int g_in_irq;

static volatile int g_dbg_allow_irq_userpeek = 0;
static uint32_t s_kernel_cr3_phys = 0;

void hexdump_bytes(const void *addr, size_t n);

// Lokala helpers
static inline void* kmap_phys(uint32_t phys, int slot);
static inline void  kunmap_phys(int slot);
static int          split_large_pde_to_pt(uint32_t *new_pd, uint32_t di);

// Exporterade wrappers för kmap (om något annan kod förlitar sig på dem)
void* paging_kmap_phys(uint32_t phys, int slot) { return kmap_phys(phys, slot); }
void  paging_kunmap_phys(int slot)              { kunmap_phys(slot); }

// Translate VA and return info
int paging_va_translate_full(uint32_t va, uint32_t *out_page_pa, int *out_user, int *out_rw, int *out_ps);

// Lokala utilities
static int probe_present_and_pa(uint32_t va, uint32_t *out_page_pa);

static inline void invlpg(uint32_t va)
{
    asm volatile("invlpg (%0)" :: "r"(va) : "memory");
}

void paging_dbg_allow_irq_userpeek(int enable)
{
    g_dbg_allow_irq_userpeek = (enable != 0);
}

static inline int is_user_addr_inline(uint32_t vaddr)
{
    return (vaddr >= USER_MIN) && (vaddr < USER_MAX);
}

int is_user_addr(uint32_t vaddr)
{
    return is_user_addr_inline(vaddr);
}

// Core VA->PA translate used by kernel hexdump
static int va_translate(uint32_t va, uint32_t *out_page_pa, int *out_user, int *out_ps)
{
    uint32_t di = va >> 22;
    uint32_t ti = (va >> 12) & 0x3FFu;
    uint32_t pde = page_directory[di];

    if (!(pde & PAGE_PRESENT)) return 0;

    int is_ps = (pde & PAGE_PS) ? 1 : 0;
    int pde_u = (pde & PAGE_USER) ? 1 : 0;
    int userok = pde_u;

    if (is_ps)
    {
        if (out_ps)   *out_ps = 1;
        if (out_user) *out_user = userok;
        if (out_page_pa)
        {
            uint32_t pa = (pde & 0xFFC00000u) | (va & 0x003FF000u);
            *out_page_pa = pa & ~0xFFFu;
        }
        return 1;
    }

    if (out_ps) *out_ps = 0;

    uint32_t pt_phys = pde & 0xFFFFF000u;
    uint32_t *pt = (uint32_t*)kmap_phys(pt_phys, 1);
    uint32_t pte = pt[ti];
    kunmap_phys(1);

    if (!(pte & PAGE_PRESENT)) return 0;

    userok = userok && ((pte & PAGE_USER) != 0);
    if (out_user) *out_user = userok;
    if (out_page_pa) *out_page_pa = (pte & 0xFFFFF000u);
    return 1;
}

static int va_is_user_accessible(uint32_t va)
{
    int user = 0;
    if (!va_translate(va, NULL, &user, NULL)) return 0;
    return user;
}

static int va_is_present(uint32_t va)
{
    return va_translate(va, NULL, NULL, NULL);
}

// ====== Scratch mapping (ingen rekursion) ======
//
// Dessa använder förallokerade PT för kmap_va1/kmap_va2.
// Inga anrop till map_4kb_page_flags() här inne.

static inline void* kmap_phys(uint32_t phys, int slot)
{
    uint32_t va = slot ? kmap_va2 : kmap_va1;
    uint32_t *pt = slot ? g_kmap_pt2 : g_kmap_pt1;

    if (!pt)
    {
        // Failsafe om init skulle vara för tidig (ska inte ske efter init_paging)
        paging_ensure_pagetable(va, PAGE_PRESENT | PAGE_RW);
        pt = (uint32_t*)(page_directory[(va >> 22) & 0x3FF] & 0xFFFFF000u);
        if (slot) g_kmap_pt2 = pt; else g_kmap_pt1 = pt;
    }

    uint32_t ti = (va >> 12) & 0x3FFu;
    pt[ti] = (phys & 0xFFFFF000u) | PAGE_PRESENT | PAGE_RW;
    invlpg(va);
    return (void*)(uintptr_t)va;
}

static inline void kunmap_phys(int slot)
{
    uint32_t va = slot ? kmap_va2 : kmap_va1;
    uint32_t *pt = slot ? g_kmap_pt2 : g_kmap_pt1;

    if (pt)
    {
        uint32_t ti = (va >> 12) & 0x3FFu;
        pt[ti] = 0;
        invlpg(va);
    }
}

// ====== PDE/flags helpers ======

static inline uint32_t pd_flags_from_large(uint32_t pde_large)
{
    uint32_t f = PAGE_PRESENT | PAGE_RW;
    if (pde_large & PAGE_USER) f |= PAGE_USER;
    if (pde_large & PAGE_PCD)  f |= PAGE_PCD;
    if (pde_large & PAGE_PWT)  f |= PAGE_PWT;
    return f;
}

__attribute__((unused)) static int probe_present_and_pa(uint32_t va, uint32_t *out_page_pa)
{
    uint32_t di = va >> 22;
    uint32_t ti = (va >> 12) & 0x3FFu;
    uint32_t pde = page_directory[di];

    if (!(pde & PAGE_PRESENT)) return 0;

    if (pde & PAGE_PS)
    {
        uint32_t pa = (pde & 0xFFC00000u) | (va & 0x003FF000u);
        if (out_page_pa) *out_page_pa = pa;
        return 1;
    }

    uint32_t pt_phys = pde & 0xFFFFF000u;
    uint32_t *pt = (uint32_t*)kmap_phys(pt_phys, 1);
    uint32_t pte = pt[ti];
    kunmap_phys(1);

    if (!(pte & PAGE_PRESENT)) return 0;
    if (out_page_pa) *out_page_pa = (pte & 0xFFFFF000u);
    return 1;
}

// ====== Split 4MB PDE till 4KB-PT ======

static int split_large_pde_to_pt(uint32_t *new_pd, uint32_t di)
{
    uint32_t pde = new_pd[di];
    if (!(pde & PAGE_PRESENT) || !(pde & PAGE_PS)) return 0;

    uint32_t base4m_phys = pde & 0xFFC00000u;
    uint32_t pt_phys = alloc_phys_page();
    if (!pt_phys)
    {
        printf("[PAGING] split_large_pde_to_pt: no phys for PT (di=%u)\n", di);
        return -1;
    }

    uint32_t *pt = (uint32_t*)kmap_phys(pt_phys, 0);
    for (uint32_t i = 0; i < 1024; i++)
    {
        uint32_t e = (base4m_phys + (i << 12)) | PAGE_PRESENT | PAGE_RW;
        if (pde & PAGE_USER) e |= PAGE_USER;
        if (pde & PAGE_PCD)  e |= PAGE_PCD;
        if (pde & PAGE_PWT)  e |= PAGE_PWT;
        pt[i] = e;
    }
    kunmap_phys(0);

    new_pd[di] = (pt_phys & 0xFFFFF000u) | pd_flags_from_large(pde);
    return 0;
}

static inline void flush_tlb(void)
{
    asm volatile("mov %%cr3, %%eax; mov %%eax, %%cr3" ::: "eax", "memory");
}

// ====== Temp map med låg VA (behåller om du använder någonstans) ======

__attribute__((unused)) static void* kmap_temp(uint32_t phys)
{
    if (g_kmap_temp_mapped_phys == phys && page_is_present(KMAP_TEMP_VA))
    {
        return (void*)(uintptr_t)KMAP_TEMP_VA;
    }

    // OBS: använder map_4kb_page_flags; men KMAP_TEMP_VA ligger i låg VA där vi äger PT
    map_4kb_page_flags(KMAP_TEMP_VA, phys, PAGE_PRESENT | PAGE_RW);
    invlpg(KMAP_TEMP_VA);
    g_kmap_temp_mapped_phys = phys;

    return (void*)(uintptr_t)KMAP_TEMP_VA;
}

__attribute__((unused)) static void kunmap_temp(void)
{
    if (page_is_present(KMAP_TEMP_VA))
    {
        unmap_4kb_page(KMAP_TEMP_VA);
        invlpg(KMAP_TEMP_VA);
    }
    g_kmap_temp_mapped_phys = 0;
}

// ====== Bitmap/refcount helpers ======

static inline void set_phys_page(int i){ phys_page_bitmap[i / 32] |= (1u << (i % 32)); }
static inline void clear_phys_page(int i){ phys_page_bitmap[i / 32] &= ~(1u << (i % 32)); }
static inline int  test_phys_page(int i){ return phys_page_bitmap[i / 32] & (1u << (i % 32)); }

static inline int test_block(int i){ return block_bitmap[i / 32] & (1u << (i % 32)); }
static inline void set_block (int i){ block_bitmap[i / 32] |= (1u << (i % 32)); }
static inline void clear_block(int i){ block_bitmap[i / 32] &= ~(1u << (i % 32)); }

static inline void phys_ref_inc_idx(int idx)
{
    if (idx >= 0 && idx < (int)MAX_PHYS_PAGES)
    {
        if (!phys_page_refcnt[idx]) phys_page_refcnt[idx] = 1;
        else                        phys_page_refcnt[idx]++;
    }
}

static inline void phys_ref_dec_idx(int idx)
{
    if (idx >= 0 && idx < (int)MAX_PHYS_PAGES)
    {
        if (phys_page_refcnt[idx] > 0) phys_page_refcnt[idx]--;
        if (phys_page_refcnt[idx] == 0) clear_phys_page(idx);
    }
}

static inline int phys_idx_from_pa(uint32_t pa){ return (int)(pa / PAGE_SIZE_4KB); }

static int find_free_block(void)
{
    for (int i = 0; i < MAX_BLOCKS; i++)
    {
        if (!test_block(i)) return i;
    }
    return -1;
}

int page_present(uint32_t lin){ return page_is_present(lin); }

// ====== PF-err dump ======

void dump_err_bits(uint32_t err)
{
    int P  = !!(err & (1u << 0));
    int W  = !!(err & (1u << 1));
    int U  = !!(err & (1u << 2));
    int R  = !!(err & (1u << 3));
    int I  = !!(err & (1u << 4));
    int PK = !!(err & (1u << 5));
    int SS = !!(err & (1u << 6));

    printf("[PF] err=0x%08x  P=%d W=%d U=%d RSVD=%d IF=%d PK=%d SS=%d\n",
           err, P, W, U, R, I, PK, SS);

    printf("     cause=%s, access=%s, mode=%s\n",
           P ? "protection-violation" : "non-present",
           W ? "write" : "read",
           U ? "user" : "supervisor");
}

// ====== PDE/PTE probe ======

int paging_probe_pde_pte(uint32_t va, uint32_t *out_pde, uint32_t *out_pte)
{
    uint32_t di = va >> 22;
    uint32_t ti = (va >> 12) & 0x3FFu;
    uint32_t pde = page_directory[di];

    if (out_pde) *out_pde = pde;

    if ((pde & PAGE_PRESENT) == 0)
    {
        if (out_pte) *out_pte = 0;
        return -1;
    }

    if (pde & PAGE_PS)
    {
        uint32_t synth_pte = (pde & 0xFFC00000u) | (va & 0x003FF000u);
        synth_pte |= (pde & (PAGE_PRESENT | PAGE_RW | PAGE_USER | PAGE_PCD | PAGE_PWT));
        if (out_pte) *out_pte = synth_pte;
        return 0;
    }

    uint32_t pt_phys = pde & 0xFFFFF000u;
    uint32_t *pt = (uint32_t*)kmap_phys(pt_phys, 1);
    uint32_t pte = pt[ti];
    if (out_pte) *out_pte = pte;
    kunmap_phys(1);
    return 0;
}

int page_is_present(uint32_t va)
{
    uint32_t pde = 0, pte = 0;

    if (paging_probe_pde_pte(va, &pde, &pte) != 0) return 0;
    if ((pde & PAGE_PRESENT) == 0) return 0;
    if (pde & PAGE_PS) return 1;
    if ((pte & PAGE_PRESENT) == 0) return 0;
    return 1;
}

int paging_va_translate_full(uint32_t va,
                             uint32_t *out_page_pa,
                             int *out_user,
                             int *out_rw,
                             int *out_ps)
{
    uint32_t pde = 0, pte = 0;

    if (paging_probe_pde_pte(va, &pde, &pte) != 0) return 0;
    if (!(pde & PAGE_PRESENT)) return 0;

    int ps = (pde & PAGE_PS) ? 1 : 0;
    if (out_ps) *out_ps = ps;

    if (ps)
    {
        uint32_t pa = (pde & 0xFFC00000u) | (va & 0x003FF000u);
        if (out_page_pa) *out_page_pa = (pa & ~0xFFFu);
        if (out_user) *out_user = !!(pde & PAGE_USER);
        if (out_rw)   *out_rw   = !!(pde & PAGE_RW);
        return 1;
    }

    if (!(pte & PAGE_PRESENT)) return 0;

    if (out_page_pa) *out_page_pa = (pte & 0xFFFFF000u);
    if (out_user) *out_user = !!(pde & PAGE_USER) && !!(pte & PAGE_USER);
    if (out_rw)   *out_rw   = !!(pte & PAGE_RW);
    return 1;
}

// ====== User hexdump ======

static void hexdump_user_bytes(uint32_t uaddr, size_t n)
{
    printf("[user bytes @%08x] ", uaddr);

    if (g_in_irq && !g_dbg_allow_irq_userpeek)
    {
        printf("(skipped: IRQ)\n");
        return;
    }

    if (!page_is_present(uaddr))
    {
        printf("(unmapped)\n");
        return;
    }

    if (g_in_irq && g_dbg_allow_irq_userpeek)
    {
        printf("(IRQ override) ");
    }

    uint32_t cur = uaddr;
    uint8_t *map = NULL;
    uint32_t mapped_page_va = 0xFFFFFFFF;

    for (size_t i = 0; i < n; i++, cur++)
    {
        if ((cur & ~0xFFFu) != mapped_page_va)
        {
            if (map) kunmap_phys(0);

            uint32_t pa = 0;
            if (!paging_va_translate_full(cur, &pa, NULL, NULL, NULL))
            {
                printf(".. ");
                break;
            }

            map = (uint8_t*)kmap_phys(pa, 0);
            mapped_page_va = cur & ~0xFFFu;
        }

        uint8_t b = map[cur & 0xFFFu];
        if ((i & 0x0F) == 0) printf("\n  %08x: ", cur);
        printf("%02x ", b);
    }

    if (map) kunmap_phys(0);
    printf("\n");
}

// ====== PT alloc ======

static void alloc_page_table_with_flags(uint32_t dir_index, uint32_t *table, uint32_t flags)
{
    for (int i = 0; i < PAGE_ENTRIES; i++) table[i] = 0;

    uint32_t pd_flags = PAGE_PRESENT | PAGE_RW;
    if (flags & PAGE_USER) pd_flags |= PAGE_USER;
    if (flags & PAGE_PCD)  pd_flags |= PAGE_PCD;
    if (flags & PAGE_PWT)  pd_flags |= PAGE_PWT;

    page_directory[dir_index] = ((uint32_t)table & 0xFFFFF000u) | pd_flags;
}

static void alloc_page_table(uint32_t dir_index, uint32_t *table)
{
    alloc_page_table_with_flags(dir_index, table, 0);
}

// ====== Identity map ======

static void identity_map_range(uint32_t start, uint32_t size)
{
    uint32_t end = start + size;
    for (uint32_t va = start; va < end; va += 0x1000u)
    {
        map_4kb_page_flags(va, va, PAGE_PRESENT | PAGE_RW);
    }
}

// ====== Phys-bitmap init ======

static void init_phys_bitmap(void)
{
    for (int i = 0; i < (int)((MAX_PHYS_PAGES + 31) / 32); i++) phys_page_bitmap[i] = 0;

    // Första 4MB reserveras
    for (int i = 0; i < (BLOCK_SIZE / PAGE_SIZE_4KB); i++)
    {
        set_phys_page(i);
        phys_page_refcnt[i] = 1;
    }
}

// ====== init_paging ======

void init_paging(uint32_t ram_mb)
{
    max_blocks = ram_mb / 4;
    if (max_blocks > MAX_BLOCKS) max_blocks = MAX_BLOCKS;

    static uint32_t bitmap_storage[(MAX_BLOCKS + 31) / 32];
    block_bitmap = bitmap_storage;

    // Initialize kernel page table pool range
    kpt_start = (uint32_t)&kernel_page_tables[0][0];
    kpt_end = (uint32_t)&kernel_page_tables[KERNEL_PT_POOL][0];

    for (int i = 0; i < 1024; i++) page_directory[i] = 0;
    for (int i = 0; i < (int)((max_blocks + 31) / 32); i++) block_bitmap[i] = 0;
    for (int i = (BLOCK_SIZE / PAGE_SIZE_4KB); i < (int)MAX_PHYS_PAGES; i++) phys_page_refcnt[i] = 0;

    init_phys_bitmap();
    alloc_page_table(0, kernel_page_tables[0]);

    uint32_t heap_end = (uint32_t)(uintptr_t)&__heap_end;
    uint32_t id_end = ALIGN_UP(heap_end, PAGE_SIZE_4KB);

    // +64 KB buffert
    uint32_t id_end_plus = id_end + (16 * PAGE_SIZE_4KB);

    // ID-map kernel + early heap
    identity_map_range(0x00000000u, id_end_plus);

    // Markera reserverade fysiska sidor upp till id_end_plus
    uint32_t pages_reserved = id_end_plus / PAGE_SIZE_4KB;
    uint32_t pages_already  = (BLOCK_SIZE / PAGE_SIZE_4KB);
    if (pages_reserved > MAX_PHYS_PAGES) pages_reserved = MAX_PHYS_PAGES;
    for (uint32_t i = pages_already; i < pages_reserved; i++)
    {
        set_phys_page((int)i);
        phys_page_refcnt[i] = 1;
    }

    // Scratch-VA nära slutet av ID-map
    uint32_t kmap_base = id_end_plus + 2 * PAGE_SIZE_4KB;
    kmap_va1 = kmap_base;
    kmap_va2 = kmap_base + PAGE_SIZE_4KB;

    // Säkerställ egna PT för scratch-VAs och cache:a PT-pekare
    paging_ensure_pagetable(kmap_va1, PAGE_PRESENT | PAGE_RW);
    paging_ensure_pagetable(kmap_va2, PAGE_PRESENT | PAGE_RW);
    g_kmap_pt1 = (uint32_t*)(page_directory[(kmap_va1 >> 22) & 0x3FF] & 0xFFFFF000u);
    g_kmap_pt2 = (uint32_t*)(page_directory[(kmap_va2 >> 22) & 0x3FF] & 0xFFFFF000u);

    // Markera 4MB-block upptagna fram till id_end_plus
    int blocks_reserved = (int)((id_end_plus + BLOCK_SIZE - 1) / BLOCK_SIZE);
    if (blocks_reserved > (int)MAX_BLOCKS) blocks_reserved = (int)MAX_BLOCKS;
    for (int b = 0; b < blocks_reserved; b++) set_block(b);

    // Zappa user-PDEs
    uint32_t udi_start = (USER_MIN >> 22);
    uint32_t udi_end   = ((USER_MAX - 1) >> 22);
    for (uint32_t di = udi_start; di <= udi_end; di++) page_directory[di] = 0;

    asm volatile("mov %0, %%cr3" :: "r"(&page_directory) : "memory");
    uint32_t cr4; asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= CR4_PSE; asm volatile("mov %0, %%cr4" :: "r"(cr4));
    uint32_t cr0; asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= CR0_PG; asm volatile("mov %0, %%cr0" :: "r"(cr0));

    // Spara kernel-CR3-phys
    asm volatile("mov %%cr3, %0" : "=r"(s_kernel_cr3_phys));

    // Spara basnivå för PT-poolen efter bootstrap
    pt_bootstrap_next = pt_next;
}

// ====== Map page range (4MB eller 4KB) ======

int map_page(uint32_t virt_addr, uint32_t size)
{
    // 4MB om larm och storlek
    if ((size >= BLOCK_SIZE) && ((virt_addr % BLOCK_SIZE) == 0))
    {
        int user = is_user_addr_inline(virt_addr) ? 1 : 0;
        int blocks = (int)((size + BLOCK_SIZE - 1) / BLOCK_SIZE);

        for (int i = 0; i < blocks; i++)
        {
            uint32_t va_block = virt_addr + (uint32_t)i * BLOCK_SIZE;

            int block = find_free_block();
            if (block < 0) return -2;

            uint32_t phys4m = (uint32_t)block * BLOCK_SIZE;

            uint32_t flags = PAGE_PRESENT | PAGE_RW | PAGE_PS;
            if (user) flags |= PAGE_USER;

            uint32_t di = va_block >> 22;
            page_directory[di] = (phys4m & 0xFFC00000u) | flags;

            set_block(block);
        }

        flush_tlb();
        return 0;
    }

    // 4KB-sidor
    uint32_t pages = (size + PAGE_SIZE_4KB - 1) / PAGE_SIZE_4KB;
    for (uint32_t i = 0; i < pages; i++)
    {
        uint32_t phys_addr = alloc_phys_page();
        if (!phys_addr) return -3;

        uint32_t fl = PAGE_PRESENT | PAGE_RW | (is_user_addr_inline(virt_addr) ? PAGE_USER : 0);
        if (map_4kb_page_flags(virt_addr + (i * PAGE_SIZE_4KB), phys_addr, fl) != 0) return -3;
    }

    flush_tlb();
    return 0;
}

// ====== Map 4KB med flags (splittar 4MB-PDE om nödvändigt) ======

int map_4kb_page_flags(uint32_t virt_addr, uint32_t phys_addr, uint32_t flags)
{
    uint32_t dir_index   = (virt_addr >> 22) & 0x3FFu;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t *table = NULL;
    int need_kunmap = 0;

    uint32_t pde = page_directory[dir_index];

    // Splitta 4MB-PDE till PT om den är satt
    if ((pde & PAGE_PRESENT) && (pde & PAGE_PS))
    {
        if (split_large_pde_to_pt(page_directory, dir_index) != 0)
        {
            printf("[PAGING][ERR] failed to split large PDE at di=%u\n", dir_index);
            return -1;
        }
        pde = page_directory[dir_index];
    }

    uint32_t kpt_start = (uint32_t)kernel_page_tables;
    uint32_t kpt_end   = kpt_start + sizeof(kernel_page_tables);

    if (!(pde & PAGE_PRESENT))
    {
        // Ny PT behövs: dynamisk för PAGE_USER, statisk pool för kernel
        if (flags & PAGE_USER)
        {
            // Allokera PT från fysiskt minne
            uint32_t pt_phys = alloc_phys_page();
            if (!pt_phys)
            {
                printf("[PAGING] ERROR: Out of physical memory for page table (dir=%u)\n", dir_index);
                return -1;
            }

            PAGING_DBG("[PAGING] Allocated dynamic PT phys=%08x for dir=%u va=%08x\n", pt_phys, dir_index, virt_addr);

            // Mappa tillfälligt för att initialisera
            table = (uint32_t*)kmap_phys(pt_phys, 0);
            for (int i = 0; i < PAGE_ENTRIES; i++)
                table[i] = 0;

            // Sätt PDE
            uint32_t pd_flags = PAGE_PRESENT | PAGE_RW;
            if (flags & PAGE_USER) pd_flags |= PAGE_USER;
            if (flags & PAGE_PCD)  pd_flags |= PAGE_PCD;
            if (flags & PAGE_PWT)  pd_flags |= PAGE_PWT;
            page_directory[dir_index] = (pt_phys & 0xFFFFF000u) | pd_flags;

            PAGING_DBG("[PAGING] Set PDE[%u] = %08x\n", dir_index, page_directory[dir_index]);
            
            // Invalidate TLB for this directory entry range
            flush_tlb();

            need_kunmap = 1;
        }
        else
        {
            // Kernel PT: använd statisk pool (identity-mapped)
            if (pt_next >= (int)(sizeof(kernel_page_tables) / sizeof(kernel_page_tables[0])))
            {
                printf("[PAGING] ERROR: Out of page tables (dir=%u)\n", dir_index);
                return -1;
            }

            table = kernel_page_tables[pt_next++];
            alloc_page_table_with_flags(dir_index, table, flags);
        }
    }
    else
    {
        uint32_t pt_phys = pde & 0xFFFFF000u;

        // Kolla om PT är från statisk pool (identity-mapped) eller dynamisk
        if (pt_phys >= kpt_start && pt_phys < kpt_end)
        {
            // Statisk pool: direkt åtkomst
            table = (uint32_t*)pt_phys;
        }
        else
        {
            // Dynamisk PT: måste kmappa
            table = (uint32_t*)kmap_phys(pt_phys, 0);
            need_kunmap = 1;
        }

        if (flags & PAGE_USER) page_directory[dir_index] |= PAGE_USER;
        if (flags & PAGE_PCD)  page_directory[dir_index] |= PAGE_PCD;
        if (flags & PAGE_PWT)  page_directory[dir_index] |= PAGE_PWT;
    }

    uint32_t pte = table[table_index];
    uint32_t desired = (phys_addr & 0xFFFFF000u)
                       | (flags & (PAGE_RW | PAGE_USER | PAGE_PCD | PAGE_PWT))
                       | PAGE_PRESENT;

    if (pte & PAGE_PRESENT)
    {
        uint32_t cur_addr  = pte & 0xFFFFF000u;
        uint32_t cur_flags = pte & 0x00000FFFu;
        uint32_t new_flags = cur_flags | (desired & 0x00000FFFu);

        if (new_flags != cur_flags)
        {
            table[table_index] = cur_addr | new_flags;
            invlpg(virt_addr);
        }

        if (cur_addr != (desired & 0xFFFFF000u))
        {
            int old_idx = phys_idx_from_pa(cur_addr);
            phys_ref_dec_idx(old_idx);

            int new_idx = phys_idx_from_pa(desired & 0xFFFFF000u);
            set_phys_page(new_idx);
            phys_ref_inc_idx(new_idx);

            table[table_index] = desired;
            invlpg(virt_addr);
        }

        if (need_kunmap) kunmap_phys(0);
        return 0;
    }

    int idx = phys_idx_from_pa(phys_addr);
    set_phys_page(idx);
    phys_ref_inc_idx(idx);

    table[table_index] = desired;
    PAGING_DBG("[PAGING] Set PTE[%u][%u] = %08x for va=%08x (PDE=%08x)\n",
               dir_index, table_index, desired, virt_addr, page_directory[dir_index]);
    // Verify the write actually happened
    uint32_t readback = table[table_index];
    if (readback != desired) {
        printf("[PAGING] ERROR: PTE write failed! wrote=%08x read=%08x\n", desired, readback);
    }

    // CRITICAL: Invalidate TLB for this page before unmapping the PT!
    invlpg(virt_addr);

    if (need_kunmap) kunmap_phys(0);
    return 0;
}

int map_4kb_page(uint32_t virt_addr, uint32_t phys_addr)
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t *table = NULL;
    uint32_t user = is_user_addr_inline(virt_addr) ? PAGE_USER : 0;

    uint32_t pde = page_directory[dir_index];
    if ((pde & PAGE_PRESENT) && (pde & PAGE_PS))
    {
        if (split_large_pde_to_pt(page_directory, dir_index) != 0) return -1;
        pde = page_directory[dir_index];
    }

    if (!(pde & PAGE_PRESENT))
    {
        if (pt_next >= (int)(sizeof(kernel_page_tables) / sizeof(kernel_page_tables[0]))) return -1;
        table = kernel_page_tables[pt_next++];
        alloc_page_table_with_flags(dir_index, table, user);
    }
    else
    {
        table = (uint32_t*)(pde & 0xFFFFF000u);
        if (user) page_directory[dir_index] |= PAGE_USER;
    }

    int idx = phys_idx_from_pa(phys_addr);
    set_phys_page(idx);
    phys_ref_inc_idx(idx);

    table[table_index] = (phys_addr & 0xFFFFF000u) | PAGE_PRESENT | PAGE_RW | user;
    invlpg(virt_addr);
    return 0;
}

void unmap_4kb_page(uint32_t virt_addr)
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;

    if (!(page_directory[dir_index] & PAGE_PRESENT)) return;
    if (page_directory[dir_index] & PAGE_PS) return;

    uint32_t *table = (uint32_t*)(page_directory[dir_index] & 0xFFFFF000u);
    uint32_t pte = table[table_index];

    if (!(pte & PAGE_PRESENT)) return;

    uint32_t pa = pte & 0xFFFFF000u;
    int idx = phys_idx_from_pa(pa);
    phys_ref_dec_idx(idx);

    table[table_index] = 0;
    invlpg(virt_addr);
}

void unmap_page(uint32_t virt_addr)
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t entry = page_directory[dir_index];

    if (!(entry & PAGE_PRESENT)) return;

    if (entry & PAGE_PS)
    {
        uint32_t phys_addr = entry & 0xFFC00000u;
        int block = (int)(phys_addr / BLOCK_SIZE);
        clear_block(block);
        page_directory[dir_index] = 0;
        flush_tlb();
        return;
    }

    uint32_t *page_table = (uint32_t*)(entry & 0xFFFFF000u);
    uint32_t pte = page_table[table_index];

    if (pte & PAGE_PRESENT)
    {
        uint32_t pa = pte & 0xFFFFF000u;
        int idx = phys_idx_from_pa(pa);
        phys_ref_dec_idx(idx);
        page_table[table_index] = 0;
    }

    int empty = 1;
    for (int i = 0; i < 1024; i++)
    {
        if (page_table[i] & PAGE_PRESENT) { empty = 0; break; }
    }
    if (empty) page_directory[dir_index] = 0;

    flush_tlb();
}

int map_huge_4mb(uint32_t virt_addr){ return map_page(virt_addr, BLOCK_SIZE); }
int unmap_huge_4mb(uint32_t virt_addr){ unmap_page(virt_addr); flush_tlb(); return 0; }

// ====== Region reserve/free ======

int alloc_region(uint32_t virt_start, uint32_t size_mb)
{
    if ((virt_start % BLOCK_SIZE) != 0) return -1;
    int blocks = (int)((size_mb + 3) / 4);

    for (int i = 0; i < blocks; i++)
    {
        uint32_t virt_addr = virt_start + (uint32_t)i * BLOCK_SIZE;
        int res = map_page(virt_addr, BLOCK_SIZE);
        if (res != 0)
        {
            for (int j = 0; j < i; j++) unmap_page(virt_start + (uint32_t)j * BLOCK_SIZE);
            return res;
        }
    }

    flush_tlb();
    return 0;
}

int free_region(uint32_t virt_start, uint32_t size_mb)
{
    if ((virt_start % BLOCK_SIZE) != 0) return -1;
    int blocks = (int)((size_mb + 3) / 4);
    for (int i = 0; i < blocks; i++) unmap_page(virt_start + (uint32_t)i * BLOCK_SIZE);
    flush_tlb();
    return 0;
}

// ====== Phys page alloc/free ======

uint32_t alloc_phys_page(void)
{
    for (int i = 0; i < MAX_PHYS_PAGES; i++)
    {
        if (!test_phys_page(i))
        {
            set_phys_page(i);
            phys_page_refcnt[i] = 1;
            return (uint32_t)i * PAGE_SIZE_4KB;
        }
    }
    return 0;
}

void free_phys_page(uint32_t addr)
{
    int index = (int)(addr / PAGE_SIZE_4KB);
    if (index < MAX_PHYS_PAGES) phys_ref_dec_idx(index);
}

// ====== Flag helpers ======

void paging_set_user(uint32_t addr, uint32_t size)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end   = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        if (!(page_directory[dir_index] & PAGE_PRESENT)) continue;

        if (page_directory[dir_index] & PAGE_PS)
        {
            page_directory[dir_index] |= PAGE_USER;
            continue;
        }

        page_directory[dir_index] |= PAGE_USER;

        uint32_t pt_phys = page_directory[dir_index] & 0xFFFFF000u;
        uint32_t *table;
        int need_kunmap = 0;

        // Check if PT is in static pool (identity-mapped) or dynamic
        if (pt_phys >= kpt_start && pt_phys < kpt_end) {
            table = (uint32_t*)pt_phys;  // Static pool: direct access
        } else {
            table = (uint32_t*)kmap_phys(pt_phys, 0);  // Dynamic: map it
            need_kunmap = 1;
        }

        table[table_index] |= PAGE_USER;

        if (need_kunmap) kunmap_phys(0);

        invlpg(va);
    }
    flush_tlb();
}

void paging_update_flags(uint32_t addr, uint32_t size, uint32_t set_mask, uint32_t clear_mask)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end   = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        if (!(page_directory[dir_index] & PAGE_PRESENT)) continue;
        if (page_directory[dir_index] & PAGE_PS) continue;

        if (set_mask & PAGE_USER)   page_directory[dir_index] |= PAGE_USER;
        if (clear_mask & PAGE_USER) page_directory[dir_index] &= ~PAGE_USER;

        uint32_t pt_phys = page_directory[dir_index] & 0xFFFFF000u;
        uint32_t *table;
        int need_kunmap = 0;

        // Check if PT is in static pool (identity-mapped) or dynamic
        if (pt_phys >= kpt_start && pt_phys < kpt_end) {
            table = (uint32_t*)pt_phys;  // Static pool: direct access
        } else {
            table = (uint32_t*)kmap_phys(pt_phys, 0);  // Dynamic: map it
            need_kunmap = 1;
        }

        uint32_t pte = table[table_index];
        if (!(pte & PAGE_PRESENT)) {
            if (need_kunmap) kunmap_phys(0);
            continue;
        }

        pte |= set_mask;
        pte &= ~clear_mask;

        table[table_index] = pte;

        if (need_kunmap) kunmap_phys(0);

        invlpg(va);
    }
    flush_tlb();
}

// ====== User allocator ======

static void* umalloc_core(size_t size, size_t alignment, uint32_t flags, int with_guards)
{
    if (!size) return (void*)0;

    if (alignment < PAGE_SIZE_4KB) alignment = PAGE_SIZE_4KB;

    size_t bytes = ALIGN_UP(size, PAGE_SIZE_4KB);
    uint32_t vstart = ALIGN_UP(uheap_next, alignment);
    uint32_t va = vstart;

    if (with_guards && (flags & UMEM_GUARD_BEFORE))
    {
        va += PAGE_SIZE_4KB;
        vstart = va;
    }

    size_t pages = bytes >> 12;

    for (size_t i = 0; i < pages; i++, va += PAGE_SIZE_4KB)
    {
        uint32_t phys = alloc_phys_page();
        if (!phys)
        {
            for (size_t j = 0; j < i; j++)
            {
                uint32_t v = vstart + (uint32_t)j * PAGE_SIZE_4KB;
                unmap_page(v);
            }
            return (void*)0;
        }

        if (map_4kb_page_flags(va, phys, PAGE_PRESENT | PAGE_RW | PAGE_USER) != 0)
        {
            for (size_t j = 0; j <= i; j++)
            {
                uint32_t v = vstart + (uint32_t)j * PAGE_SIZE_4KB;
                unmap_page(v);
            }
            return (void*)0;
        }
    }

    uint32_t vend = vstart + (uint32_t)bytes;
    if (with_guards && (flags & UMEM_GUARD_AFTER)) vend += PAGE_SIZE_4KB;

    if (!(flags & UMEM_NOZERO)) memset((void*)vstart, 0, bytes);

    uheap_next = vend;
    return (void*)vstart;
}

void* umalloc(size_t size){ return umalloc_core(size, PAGE_SIZE_4KB, UMEM_PAGEALIGNED, 0); }

void ufree(void *ptr, size_t size)
{
    if (!ptr || !size) return;

    uint32_t vaddr = (uint32_t)ptr;
    size_t bytes = (size + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1);
    size_t pages = bytes / PAGE_SIZE_4KB;

    for (size_t i = 0; i < pages; i++)
    {
        uint32_t va = vaddr + (uint32_t)(i * PAGE_SIZE_4KB);
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        if (!(page_directory[dir_index] & PAGE_PRESENT)) continue;
        if (page_directory[dir_index] & PAGE_PS) continue;

        uint32_t *table = (uint32_t*)(page_directory[dir_index] & 0xFFFFF000u);
        uint32_t pte = table[table_index];
        if (!(pte & PAGE_PRESENT)) continue;

        free_phys_page(pte & 0xFFFFF000u);
        table[table_index] = 0;
        invlpg(va);
    }

    flush_tlb();
}

void* umalloc_ex(size_t size, size_t alignment, uint32_t flags)
{
    int with_guards = ((flags & (UMEM_GUARD_BEFORE | UMEM_GUARD_AFTER)) != 0) ? 1 : 0;
    return umalloc_core(size, alignment, flags, with_guards);
}

void* umemalign(size_t alignment, size_t size)
{
    return umalloc_ex(size, alignment, UMEM_PAGEALIGNED);
}

void* umalloc_guarded(size_t size)
{
    return umalloc_ex(size, PAGE_SIZE_4KB, UMEM_GUARD_BEFORE | UMEM_GUARD_AFTER);
}

void ufree_secure(void* ptr, size_t size)
{
    if (!ptr || !size) return;

    size_t bytes = ALIGN_UP(size, PAGE_SIZE_4KB);
    memset(ptr, 0, bytes);
    ufree(ptr, size);
}

// ====== Reservation-API ======

static int reservations_add(uint32_t start, uint32_t end)
{
    if (uresv_count >= MAX_USER_RESERVATIONS) return -1;
    uresv_list[uresv_count++] = (uresv_t){ start, end };
    return 0;
}

static int reservations_contains(uint32_t va)
{
    for (int i = 0; i < uresv_count; i++)
    {
        if (va >= uresv_list[i].start && va < uresv_list[i].end) return 1;
    }
    return 0;
}

int paging_reserve_range(uintptr_t start, size_t size)
{
    if (!size) return 0;
    uint32_t s = PAGE_ALIGN_DOWN((uint32_t)start);
    uint32_t e = PAGE_ALIGN_UP((uint32_t)start + (uint32_t)size);
    return reservations_add(s, e);
}

int paging_ensure_pagetable(uint32_t va, uint32_t flags)
{
    uint32_t di = va >> 22;
    uint32_t pde = page_directory[di];

    if (pde & PAGE_PRESENT)
    {
        if (flags & PAGE_USER) page_directory[di] |= PAGE_USER;
        if (flags & PAGE_PCD)  page_directory[di] |= PAGE_PCD;
        if (flags & PAGE_PWT)  page_directory[di] |= PAGE_PWT;
        return 0;
    }

    if (pt_next >= (int)(sizeof(kernel_page_tables) / sizeof(kernel_page_tables[0]))) return -1;
    uint32_t *table = kernel_page_tables[pt_next++];
    alloc_page_table_with_flags(di, table, flags);
    return 0;
}

int paging_map_user_range(uintptr_t vaddr, size_t bytes, int writable)
{
    if (!bytes) return 0;
    uint32_t start = PAGE_ALIGN_DOWN((uint32_t)vaddr);
    uint32_t end   = PAGE_ALIGN_UP  ((uint32_t)vaddr + (uint32_t)bytes);

    uint32_t flags = PAGE_PRESENT | PAGE_USER | (writable ? PAGE_RW : 0);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        if (paging_ensure_pagetable(va, flags) != 0) return -1;

        if (!page_is_present(va))
        {
            uint32_t phys = alloc_phys_page();
            if (!phys) return -1;
            if (map_4kb_page_flags(va, phys, flags) != 0) return -1;
            memset((void*)va, 0, PAGE_SIZE_4KB);
        }
        else
        {
            if (writable) paging_update_flags(va, PAGE_SIZE_4KB, PAGE_RW, 0);
        }
    }
    return 0;
}

int paging_unmap_user_range(uintptr_t vaddr, size_t bytes)
{
    if (!bytes) return 0;
    uint32_t start = PAGE_ALIGN_DOWN((uint32_t)vaddr);
    uint32_t end   = PAGE_ALIGN_UP  ((uint32_t)vaddr + (uint32_t)bytes);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB) unmap_page(va);
    flush_tlb();
    return 0;
}

// ====== Demand-zero / COW ======

int paging_handle_demand_fault(uintptr_t fault_va)
{
    uint32_t fva = (uint32_t)fault_va;
    if (!is_user_addr_inline(fva)) return -1;

    uint32_t page_base = ALIGN_DOWN(fva, PAGE_SIZE_4KB);
    if (!reservations_contains(page_base)) return -1;

    uint32_t phys = alloc_phys_page();
    if (!phys) return -2;

    int rc = map_4kb_page_flags(page_base, phys, PAGE_PRESENT | PAGE_RW | PAGE_USER);
    if (rc != 0)
    {
        free_phys_page(phys);
        return -3;
    }

    void *kptr = kmap_phys(phys, 0);
    if (!kptr)
    {
        unmap_page(page_base);
        free_phys_page(phys);
        return -4;
    }

    memset(kptr, 0, PAGE_SIZE_4KB);
    kunmap_phys(0);
    invlpg(page_base);
    return 0;
}

int paging_mark_cow_range(uint32_t va, size_t size)
{
    uint32_t start = ALIGN_DOWN(va, PAGE_SIZE_4KB);
    uint32_t end   = ALIGN_UP(va + size, PAGE_SIZE_4KB);

    for (uint32_t p = start; p < end; p += PAGE_SIZE_4KB)
    {
        uint32_t pde = 0, pte = 0;
        if (paging_probe_pde_pte(p, &pde, &pte) != 0) return -1;
        if (!(pte & PAGE_PRESENT)) return -1;
        paging_update_flags(p, PAGE_SIZE_4KB, 0, PAGE_RW);
    }
    return 0;
}

int paging_handle_cow_fault(uintptr_t fault_va)
{
    uint32_t fva = (uint32_t)fault_va;
    uint32_t pde = 0, pte = 0;

    if (paging_probe_pde_pte(fva, &pde, &pte) != 0) return -1;
    if (!(pte & PAGE_PRESENT)) return -2;
    if (pte & PAGE_RW) return -3;

    uint32_t page_va = ALIGN_DOWN(fva, PAGE_SIZE_4KB);
    uint32_t old_pa  = pte & 0xFFFFF000u;
    int old_idx = phys_idx_from_pa(old_pa);
    if (old_idx < 0) return -4;

    if (phys_page_refcnt[old_idx] <= 1)
    {
        uint32_t *pt = (uint32_t*)(pde & 0xFFFFF000u);
        pt[(page_va >> 12) & 0x3FFu] = (pte | PAGE_RW);
        invlpg(page_va);
        return 0;
    }

    uint32_t new_pa = alloc_phys_page();
    if (!new_pa) return -5;

    uint32_t temp_va = ALIGN_UP(uheap_next, PAGE_SIZE_4KB);
    uheap_next = temp_va + PAGE_SIZE_4KB;

    if (map_4kb_page_flags(temp_va, new_pa, PAGE_PRESENT | PAGE_RW | PAGE_USER) != 0)
    {
        unmap_page(temp_va);
        free_phys_page(new_pa);
        return -6;
    }

    memcpy((void*)temp_va, (void*)page_va, PAGE_SIZE_4KB);

    uint32_t *pt = (uint32_t*)(pde & 0xFFFFF000u);
    pt[(page_va >> 12) & 0x3FFu] = (new_pa & 0xFFFFF000u) | PAGE_PRESENT | PAGE_RW | (pte & PAGE_USER);

    invlpg(page_va);
    unmap_page(temp_va);
    phys_ref_dec_idx(old_idx);
    return 0;
}

int paging_handle_page_fault(uint32_t fault_va, uint32_t err)
{
    int present = !!(err & 1);
    int write   = !!(err & 2);
    int user    = !!(err & 4);

    if (present && write && user)
    {
        if (paging_handle_cow_fault(fault_va) == 0) return 1;
    }

    if (!present && user)
    {
        if (paging_handle_demand_fault(fault_va) == 0) return 1;
    }

    return 0;
}

// ====== Alias-map ======

int paging_map_alias(uint32_t dst_va, uint32_t src_va, size_t size, uint32_t flags)
{
    uint32_t start_s = ALIGN_DOWN(src_va, PAGE_SIZE_4KB);
    uint32_t start_d = ALIGN_DOWN(dst_va, PAGE_SIZE_4KB);
    uint32_t end     = ALIGN_UP(src_va + size, PAGE_SIZE_4KB);
    uint32_t count   = (end - start_s) / PAGE_SIZE_4KB;

    for (uint32_t i = 0; i < count; i++)
    {
        uint32_t s = start_s + i * PAGE_SIZE_4KB;
        uint32_t d = start_d + i * PAGE_SIZE_4KB;

        uint32_t pde = 0, pte = 0;
        if (paging_probe_pde_pte(s, &pde, &pte) != 0) return -1;
        if (!(pte & PAGE_PRESENT)) return -1;

        uint32_t pa = pte & 0xFFFFF000u;
        int idx = phys_idx_from_pa(pa);
        phys_ref_inc_idx(idx);

        uint32_t map_flags = PAGE_PRESENT | (flags & (PAGE_RW | PAGE_USER | PAGE_PCD | PAGE_PWT));
        if (map_4kb_page_flags(d, pa, map_flags) != 0) return -2;
    }
    return 0;
}

// ====== Dump helpers ======

static void print_pte_line(uint32_t va, uint32_t pde, uint32_t pte)
{
    uint32_t pa = pte & 0xFFFFF000u;
    int P = !!(pte & PAGE_PRESENT);
    int RW = !!(pte & PAGE_RW);
    int US = !!(pte & PAGE_USER);

    printf("[PG] VA=0x%08x PDE=%08x PTE=%08x -> PA=%08x  P=%d RW=%d U=%d\n",
           va, pde, pte, pa, P, RW, US);
}

void paging_dump_range(uint32_t addr, uint32_t size)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end   = (addr + size + PAGE_SIZE_4KB - 1) & ~((uint32_t)PAGE_SIZE_4KB - 1);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t pde = 0, pte = 0;

        if (paging_probe_pde_pte(va, &pde, &pte) != 0 || !(pde & PAGE_PRESENT))
        {
            printf("[PG] VA=0x%08x PDE not present\n", va);
            continue;
        }

        if (pde & PAGE_PS)
        {
            printf("[PG] VA=0x%08x uses 4MB page (skipped)\n", va);
            continue;
        }

        print_pte_line(va, pde, pte);
    }
}

int paging_check_user_range(uint32_t addr, uint32_t size)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end   = (addr + size + PAGE_SIZE_4KB - 1) & ~((uint32_t)PAGE_SIZE_4KB - 1);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t pde = 0, pte = 0;

        if (paging_probe_pde_pte(va, &pde, &pte) != 0)
        {
            if (!reservations_contains(ALIGN_DOWN(va, PAGE_SIZE_4KB)))
            {
                printf("[PG-FAIL] VA=%08x PDE not present\n", va);
                return -1;
            }
            continue;
        }

        if (!(pde & PAGE_PRESENT))
        {
            if (!reservations_contains(ALIGN_DOWN(va, PAGE_SIZE_4KB)))
            {
                printf("[PG-FAIL] VA=%08x PDE not present\n", va);
                return -1;
            }
            continue;
        }

        if (pde & PAGE_PS)
        {
            if (!(pde & PAGE_USER))
            {
                if (!reservations_contains(ALIGN_DOWN(va, PAGE_SIZE_4KB)))
                {
                    printf("[PG-FAIL] VA=%08x 4MB page not USER\n", va);
                    return -1;
                }
            }
            continue;
        }

        if (!(pte & PAGE_PRESENT))
        {
            if (!reservations_contains(ALIGN_DOWN(va, PAGE_SIZE_4KB)))
            {
                printf("[PG-FAIL] VA=%08x PTE not present\n", va);
                return -1;
            }
            continue;
        }

        if (!(pte & PAGE_USER))
        {
            printf("[PG-FAIL] VA=%08x not USER\n", va);
            return -1;
        }
    }
    return 0;
}

int paging_check_user_range_writable(uint32_t addr, uint32_t size)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end   = (addr + size + PAGE_SIZE_4KB - 1) & ~((uint32_t)PAGE_SIZE_4KB - 1);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t pde = 0, pte = 0;

        if (paging_probe_pde_pte(va, &pde, &pte) != 0)
        {
            uint32_t page_base = ALIGN_DOWN(va, PAGE_SIZE_4KB);
            if (reservations_contains(page_base)) continue;
            return -1;
        }

        if(!(pde & PAGE_PRESENT))
        {
            uint32_t page_base = ALIGN_DOWN(va, PAGE_SIZE_4KB);
            if (reservations_contains(page_base)) continue;
            return -1;
        }

        if (pde & PAGE_PS)
        {
            if (!(pde & PAGE_USER)) return -1;
            if (!(pde & PAGE_RW))   return -1;
            continue;
        }

        if(!(pte & PAGE_PRESENT))
        {
            uint32_t page_base = ALIGN_DOWN(va, PAGE_SIZE_4KB);
            if (reservations_contains(page_base)) continue;
            return -1;
        }

        if (!(pte & PAGE_USER)) return -1;
        if (!(pte & PAGE_RW))   return -1;
    }
    return 0;
}

void hexdump_bytes(const void *addr, size_t n)
{
    uint32_t start = (uint32_t)(uintptr_t)addr;

    if (va_is_user_accessible(start))
    {
        hexdump_user_bytes(start, n);
        return;
    }

    if (g_in_irq && !g_dbg_allow_irq_userpeek)
    {
        printf("(skipped: IRQ)\n");
        return;
    }

    if (!n) { printf("\n"); return; }
    if (!va_is_present(start)) { printf("(unmapped)\n"); return; }

    uint32_t cur = start;
    uint32_t cur_page_va = 0xFFFFFFFFu;
    uint32_t cur_page_pa = 0;
    uint8_t *map = NULL;

    int dummy_user = 0, dummy_ps = 0;
    if (!va_translate(cur, &cur_page_pa, &dummy_user, &dummy_ps)) { printf("(unmapped)\n"); return; }

    map = (uint8_t*)kmap_phys(cur_page_pa, 0);
    cur_page_va = cur & ~0xFFFu;

    for (size_t i = 0; i < n; i++, cur++)
    {
        if ((i & 0x0F) == 0) printf("\n  %08x: ", cur);

        if ((cur & ~0xFFFu) != cur_page_va)
        {
            kunmap_phys(0);
            if (!va_is_present(cur)) { printf(".."); break; }

            va_translate(cur, &cur_page_pa, NULL, NULL);
            map = (uint8_t*)kmap_phys(cur_page_pa, 0);
            cur_page_va = cur & ~0xFFFu;
        }

        uint8_t b = map[cur & 0xFFFu];
        printf("%02x ", b);
    }

    if (map) kunmap_phys(0);
    printf("\n");
}

void dump_pde_pte(uint32_t lin)
{
    uint32_t di = lin >> 22;
    uint32_t ti = (lin >> 12) & 0x3FFu;
    uint32_t off = lin & 0xFFFu;

    uint32_t pde = page_directory[di];

    printf("[PDE] idx=%u val=%08x  P=%u RW=%u U=%u PS=%u\n",
           di, pde, !!(pde & 0x001), !!(pde & 0x002), !!(pde & 0x004), !!(pde & 0x080));

    if (!(pde & 0x001))
    {
        printf("[PTE] (no PT present)\n");
        return;
    }

    if (pde & 0x080)
    {
        uint32_t pa = (pde & 0xFFC00000u) | (lin & 0x003FFFFFu);
        printf("[4MB]  PA=%08x  (flags: RW=%u U=%u)\n", pa, !!(pde & 0x002), !!(pde & 0x004));
        return;
    }

    uint32_t *pt = (uint32_t*)(pde & 0xFFFFF000u);
    uint32_t pte = pt[ti];

    printf("[PTE] idx=%u val=%08x  P=%u RW=%u U=%u\n",
           ti, pte, !!(pte & 0x001), !!(pte & 0x002), !!(pte & 0x004));

    if (pte & 0x001)
    {
        uint32_t pa = (pte & 0xFFFFF000u) | off;
        printf("[RESOLVED] LA=%08x -> PA=%08x\n", lin, pa);
    }
}

void paging_dump_mapping(uint32_t va) { dump_pde_pte(va); }
void paging_flush_tlb(void) { flush_tlb(); }

// ====== CR3 helpers ======

uintptr_t paging_kernel_cr3_phys(void) { return (uintptr_t)s_kernel_cr3_phys; }

uint32_t paging_new_address_space(void)
{
    uint32_t pd_phys = alloc_phys_page();
    if (!pd_phys)
    {
        printf("[PAGING] new_address_space: no phys page for PD\n");
        return 0;
    }

    uint32_t *new_pd = (uint32_t*)kmap_phys(pd_phys, 0);
    for (int i = 0; i < 1024; i++)
        new_pd[i] = page_directory[i];

    uint32_t pd_va = (uint32_t)(uintptr_t)page_directory;
    uint32_t pd_di = pd_va >> 22;

    uint32_t keep_until = ALIGN_UP((uint32_t)(uintptr_t)&__heap_end + PAGE_SIZE_4KB, BLOCK_SIZE);
    uint32_t udi_start  = (keep_until >> 22);
    if (udi_start < (USER_MIN >> 22))
        udi_start = (USER_MIN >> 22);
    uint32_t udi_end    = ((USER_MAX - 1) >> 22);
    for (uint32_t di = udi_start; di <= udi_end; di++)
        new_pd[di] = 0;

    uint32_t di = pd_di;
    uint32_t ti = (pd_va >> 12) & 0x3FF;

    uint32_t pde = new_pd[di];
    if (!(pde & PAGE_PRESENT) || (pde & PAGE_PS))
    {
        printf("[PAGING] new_address_space: kernel PT missing or 4MB at di=%u (pde=%08x)\n", di, pde);
        kunmap_phys(0);
        free_phys_page(pd_phys);
        return 0;
    }

    uint32_t pt_phys = pde & 0xFFFFF000u;
    uint32_t *pt = (uint32_t*)kmap_phys(pt_phys, 1);
    pt[ti] = (pd_phys & 0xFFFFF000u) | PAGE_PRESENT | PAGE_RW;

    kunmap_phys(1);
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
    if (!cr3_phys) return;

    uint32_t cur = 0;
    asm volatile("mov %%cr3, %0" : "=r"(cur));
    if (cur == cr3_phys)
    {
        printf("[PAGING] destroy_address_space: refusing to free active CR3\n");
        return;
    }
    free_phys_page(cr3_phys);
}

void paging_free_all_user(void)
{
    uint32_t udi_start = (USER_MIN >> 22);
    uint32_t udi_end   = ((USER_MAX - 1) >> 22);

    uint32_t kpt_start = (uint32_t)kernel_page_tables;
    uint32_t kpt_end   = kpt_start + sizeof(kernel_page_tables);

    for (uint32_t di = udi_start; di <= udi_end; di++)
    {
        uint32_t pde = page_directory[di];
        if (!(pde & PAGE_PRESENT)) continue;

        if (pde & PAGE_PS)
        {
            uint32_t phys_addr = pde & 0xFFC00000u;
            int block = (int)(phys_addr / BLOCK_SIZE);
            clear_block(block);
            page_directory[di] = 0;
            continue;
        }

        uint32_t pt_phys = pde & 0xFFFFF000u;
        uint32_t *pt = (uint32_t*)kmap_phys(pt_phys, 1);

        for (int ti = 0; ti < 1024; ti++)
        {
            uint32_t pte = pt[ti];
            if (!(pte & PAGE_PRESENT)) continue;

            uint32_t pa = pte & 0xFFFFF000u;
            int idx = phys_idx_from_pa(pa);
            phys_ref_dec_idx(idx);
            pt[ti] = 0;
        }

        kunmap_phys(1);
        page_directory[di] = 0;

        if (!(pt_phys >= kpt_start && pt_phys < kpt_end))
        {
            free_phys_page(pt_phys);
        }
    }

    asm volatile("mov %%cr3, %%eax; mov %%eax, %%cr3" ::: "eax", "memory");

    paging_user_heap_reset();
}

void paging_user_heap_reset(void)
{
    uheap_next = UHEAP_BASE;
    uresv_count = 0;
}

void paging_free_all_user_in(uint32_t cr3_phys)
{
    uint32_t old;
    asm volatile("mov %%cr3, %0" : "=r"(old));
    paging_switch_address_space(cr3_phys);

    uint32_t udi_start = (USER_MIN >> 22);
    uint32_t udi_end   = ((USER_MAX - 1) >> 22);

    uint32_t kpt_start = (uint32_t)kernel_page_tables;
    uint32_t kpt_end   = kpt_start + sizeof(kernel_page_tables);

    for (uint32_t di = udi_start; di <= udi_end; di++)
    {
        uint32_t pde = page_directory[di];
        if (!(pde & PAGE_PRESENT)) continue;

        if (pde & PAGE_PS)
        {
            uint32_t phys_addr = pde & 0xFFC00000u;
            int block = (int)(phys_addr / BLOCK_SIZE);
            clear_block(block);
            page_directory[di] = 0;
            continue;
        }

        uint32_t pt_phys = pde & 0xFFFFF000u;
        uint32_t *pt = (uint32_t*)kmap_phys(pt_phys, 1);

        for (int ti = 0; ti < 1024; ti++)
        {
            uint32_t pte = pt[ti];
            if (!(pte & PAGE_PRESENT)) continue;

            uint32_t pa = pte & 0xFFFFF000u;
            int idx = phys_idx_from_pa(pa);
            phys_ref_dec_idx(idx);
            pt[ti] = 0;
        }

        kunmap_phys(1);
        page_directory[di] = 0;

        // Frigör PT om den inte är från statisk pool
        if (!(pt_phys >= kpt_start && pt_phys < kpt_end))
        {
            free_phys_page(pt_phys);
        }
    }

    flush_tlb();

    paging_switch_address_space(old);
}

void paging_pt_pool_commit(void)
{
    pt_bootstrap_next = pt_next;
}
