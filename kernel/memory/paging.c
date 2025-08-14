#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "paging.h"

__attribute__((aligned(4096))) uint32_t page_directory[1024];

__attribute__((aligned(4096))) uint32_t kernel_page_tables[64][PAGE_ENTRIES];

#define PAGE_SIZE_4K PAGE_SIZE_4KB
#define ALIGN_UP(x, a) (((x) + ((a) - 1)) & ~((a) - 1))

#ifndef UHEAP_BASE
#define UHEAP_BASE 0x40000000u
#endif

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

static uint32_t *block_bitmap;
static uint32_t max_blocks; 
static uint32_t phys_page_bitmap[(MAX_PHYS_PAGES + 31) / 32];
static uint32_t uheap_next = UHEAP_BASE;

static int pt_next = 1;

static inline void flush_tlb(void)
{
    asm volatile("mov %%cr3, %%eax; mov %%eax, %%cr3" ::: "eax", "memory");
}

static inline void invlpg(uint32_t va)
{
    asm volatile("invlpg (%0)" :: "r"(va) : "memory");
}

static inline void set_phys_page(int i)
{
    phys_page_bitmap[i / 32] |= (1u << (i % 32));
}

static inline void clear_phys_page(int i)
{
    phys_page_bitmap[i / 32] &= ~(1u << (i % 32));
}

static inline int test_phys_page(int i)
{
    return phys_page_bitmap[i / 32] & (1u << (i % 32));
}

static inline int test_block(int i)
{
    return block_bitmap[i / 32] & (1u << (i % 32));
}

static inline void set_block(int i)
{
    block_bitmap[i / 32] |= (1u << (i % 32));
}

static inline void clear_block(int i)
{
    block_bitmap[i / 32] &= ~(1u << (i % 32));
}

static int find_free_block(void)
{
    for (int i = 0; i < MAX_BLOCKS; i++)
    {
        if (!test_block(i))
        {
            return i;
        }
    }

    return -1;
}

static void alloc_page_table_with_flags(uint32_t dir_index, uint32_t *table, uint32_t flags)
{
    for (int i = 0; i < PAGE_ENTRIES; i++)
    {
        table[i] = 0;
    }

    uint32_t pd_flags = PAGE_PRESENT | PAGE_RW;

    if (flags & PAGE_USER)
    {
        pd_flags |= PAGE_USER;
    }

    page_directory[dir_index] = ((uint32_t)table & 0xFFFFF000u) | pd_flags;
}

static void alloc_page_table(uint32_t dir_index, uint32_t *table)
{
    alloc_page_table_with_flags(dir_index, table, 0);
}

static void init_phys_bitmap(void)
{
    for (int i = 0; i < (int)((MAX_PHYS_PAGES + 31) / 32); i++)
    {
        phys_page_bitmap[i] = 0;
    }

    for (int i = 0; i < (BLOCK_SIZE / PAGE_SIZE_4KB); i++)
    {
        set_phys_page(i);
    }
}

void init_paging(uint32_t ram_mb)
{
    max_blocks = ram_mb / 4;

    if (max_blocks > MAX_BLOCKS)
    {
        max_blocks = MAX_BLOCKS;
    }

    static uint32_t bitmap_storage[(MAX_BLOCKS + 31) / 32];
    block_bitmap = bitmap_storage;

    // Reset page directory and block bitmap
    for (int i = 0; i < 1024; i++)
    {
        page_directory[i] = 0;
    }

    for (int i = 0; i < (int)((max_blocks + 31) / 32); i++)
    {
        block_bitmap[i] = 0;
    }

    init_phys_bitmap();

    alloc_page_table(0, kernel_page_tables[0]);

    for (int i = 0; i < 1024; i++)
    {
        kernel_page_tables[0][i] = (i * 0x1000u) | PAGE_PRESENT | PAGE_RW;
    }

    pt_next = 1;
    set_block(0);  

    // Load CR3 with the address of the page directory
    asm volatile("mov %0, %%cr3" :: "r"(&page_directory));

    // Enable PSE (4MB pages) in CR4
    uint32_t cr4;
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= 0x10;
    asm volatile("mov %0, %%cr4" :: "r"(cr4));

    // Enable paging CR0.PG
    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000u;
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
}

int map_page(uint32_t virt_addr, uint32_t size)
{
    if (size >= BLOCK_SIZE && (virt_addr % BLOCK_SIZE) == 0)
    {
        int blocks = (int)(size / BLOCK_SIZE);

        for (int i = 0; i < blocks; i++)
        {
            int block = find_free_block();

            if (block < 0)
            {
                return -2;
            }

            uint32_t phys_addr = (uint32_t)block * BLOCK_SIZE;
            page_directory[(virt_addr >> 22) + (uint32_t)i] = phys_addr | PAGE_PRESENT | PAGE_RW | PAGE_SIZE;
            set_block(block);
        }
    }
    else
    {
        uint32_t pages = (size + PAGE_SIZE_4KB - 1) / PAGE_SIZE_4KB;

        for (uint32_t i = 0; i < pages; i++)
        {
            uint32_t phys_addr = alloc_phys_page();

            if (!phys_addr)
            {
                return -3;
            }

            map_4kb_page(virt_addr + (i * PAGE_SIZE_4KB), phys_addr);
        }
    }

    flush_tlb();

    return 0;
}

int map_4kb_page_flags(uint32_t virt_addr, uint32_t phys_addr, uint32_t flags)
{
    uint32_t dir_index = (virt_addr >> 22) & 0x3FFu;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t *table;

    if (!(page_directory[dir_index] & PAGE_PRESENT))
    {
        if (pt_next >= (int)(sizeof(kernel_page_tables) / sizeof(kernel_page_tables[0])))
        {
            printf("[PAGING] ERROR: Out of page tables (dir=%u)\n", dir_index);

            return -1;
        }

        table = kernel_page_tables[pt_next++];

        alloc_page_table_with_flags(dir_index, table, flags);
    }
    else
    {
        table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);

        if (flags & PAGE_USER)
        {
            page_directory[dir_index] |= PAGE_USER;
        }
    }

    uint32_t pte = table[table_index];

    uint32_t desired = (phys_addr & 0xFFFFF000u) | (flags & (PAGE_RW | PAGE_USER)) | PAGE_PRESENT;

    if (pte & PAGE_PRESENT)
    {
        uint32_t cur_addr = pte & 0xFFFFF000u;
        uint32_t cur_flags = pte & 0x00000FFFu;

#ifdef DIFF_DEBUG
        if (cur_addr != (phys_addr & 0xFFFFF000u))
        {
            DDBG("[PAGING] WARN: VA 0x%08x already -> PA 0x%08x, requested 0x%08x. Keeping existing PA, upgrading flags.\n", virt_addr, cur_addr, (phys_addr & 0xFFFFF000u));
        }
#endif

        uint32_t new_flags = cur_flags | (desired & 0x00000FFFu);

        if (new_flags != cur_flags)
        {
            table[table_index] = cur_addr | new_flags;

            invlpg(virt_addr);
        }

        return 0;
    }
    else
    {
        table[table_index] = desired;

        return 0;
    }
}

int map_4kb_page(uint32_t virt_addr, uint32_t phys_addr)
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t *table;

    if (!(page_directory[dir_index] & PAGE_PRESENT))
    {
        if (pt_next >= (int)(sizeof(kernel_page_tables) / sizeof(kernel_page_tables[0])))
        {
            return -1;
        }

        table = kernel_page_tables[pt_next++];

        alloc_page_table(dir_index, table);
    }
    else
    {
        table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);
    }

    table[table_index] = (phys_addr & 0xFFFFF000u) | PAGE_PRESENT | PAGE_RW;

    invlpg(virt_addr);

    return 0;
}

void unmap_4kb_page(uint32_t virt_addr)
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;

    if (!(page_directory[dir_index] & PAGE_PRESENT))
    {
        return;
    }

    uint32_t *table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);
    table[table_index] = 0;

    invlpg(virt_addr);
}

void unmap_page(uint32_t virt_addr)
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t entry = page_directory[dir_index];

    if (!(entry & PAGE_PRESENT))
    {
        return;
    }

    if (entry & PAGE_SIZE)
    {
        uint32_t phys_addr = entry & 0xFFC00000u;
        int block = (int)(phys_addr / BLOCK_SIZE);

        free_phys_page(phys_addr);
        clear_block(block);
        page_directory[dir_index] = 0;
    }
    else
    {
        uint32_t *page_table = (uint32_t *)(entry & 0xFFFFF000u);
        uint32_t pte = page_table[table_index];

        if (pte & PAGE_PRESENT)
        {
            free_phys_page(pte & 0xFFFFF000u);
            page_table[table_index] = 0;
        }

        int empty = 1;

        for (int i = 0; i < 1024; i++)
        {
            if (page_table[i] & PAGE_PRESENT)
            {
                empty = 0;

                break;
            }
        }

        if (empty)
        {
            page_directory[dir_index] = 0;
        }
    }

    flush_tlb();
}

int alloc_region(uint32_t virt_start, uint32_t size_mb)
{
    if ((virt_start % BLOCK_SIZE) != 0)
    {
        return -1;
    }

    int blocks = (int)((size_mb + 3) / 4);

    for (int i = 0; i < blocks; i++)
    {
        uint32_t virt_addr = virt_start + (uint32_t)i * BLOCK_SIZE;
        int res = map_page(virt_addr, BLOCK_SIZE);

        if (res != 0)
        {
            for (int j = 0; j < i; j++)
            {
                uint32_t undo_addr = virt_start + (uint32_t)j * BLOCK_SIZE;

                unmap_page(undo_addr);
            }

            return res;
        }
    }

    flush_tlb();

    return 0;
}

int free_region(uint32_t virt_start, uint32_t size_mb)
{
    if ((virt_start % BLOCK_SIZE) != 0)
    {
        return -1;
    }

    int blocks = (int)((size_mb + 3) / 4);

    for (int i = 0; i < blocks; i++)
    {
        uint32_t virt_addr = virt_start + (uint32_t)i * BLOCK_SIZE;

        unmap_page(virt_addr);
    }

    flush_tlb();

    return 0;
}

uint32_t alloc_phys_page(void)
{
    for (int i = 0; i < MAX_PHYS_PAGES; i++)
    {
        if (!test_phys_page(i))
        {
            set_phys_page(i);

            return (uint32_t)i * PAGE_SIZE_4KB;
        }
    }

    return 0;
}

void free_phys_page(uint32_t addr)
{
    int index = (int)(addr / PAGE_SIZE_4KB);

    if (index < MAX_PHYS_PAGES)
    {
        clear_phys_page(index);
    }
}

void paging_set_user(uint32_t addr, uint32_t size)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        if (!(page_directory[dir_index] & PAGE_PRESENT))
        {
            continue;
        }

        if (page_directory[dir_index] & PAGE_SIZE)
        {
            continue;
        }

        uint32_t *table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);

        table[table_index] |= PAGE_USER;
        invlpg(va);
    }

    flush_tlb();
}

void paging_update_flags(uint32_t addr, uint32_t size, uint32_t set_mask, uint32_t clear_mask)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        if (!(page_directory[dir_index] & PAGE_PRESENT))
        {
            continue;
        }

        if (page_directory[dir_index] & PAGE_SIZE)
        {
            continue;
        }

        uint32_t *table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);
        uint32_t pte = table[table_index];

        if (!(pte & PAGE_PRESENT))
        {
            continue;
        }

        pte |= set_mask;
        pte &= ~clear_mask;
        table[table_index] = pte;

        invlpg(va);
    }

    flush_tlb();
}

void* umalloc(size_t size)
{
    if (!size)
    {
        return (void*)0;
    }

    size_t bytes = (size + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1);
    size_t pages = bytes >> 12;

    uint32_t vstart = (uheap_next + (PAGE_SIZE_4KB - 1)) & ~(PAGE_SIZE_4KB - 1);
    uint32_t va = vstart;

    uint32_t phys_list[1024];

    if (pages > (sizeof(phys_list) / sizeof(phys_list[0])))
    {
        return (void*)0;
    }

    for (size_t i = 0; i < pages; i++, va += PAGE_SIZE_4KB)
    {
        uint32_t phys = alloc_phys_page();

        if (!phys)
        {
            for (size_t j = 0; j < i; j++)
            {
                uint32_t v = vstart + (uint32_t)j * PAGE_SIZE_4KB;

                unmap_page(v);
                free_phys_page(phys_list[j]);
            }

            return (void*)0;
        }

        phys_list[i] = phys;

        int r = map_4kb_page_flags(va, phys, PAGE_PRESENT | PAGE_RW | PAGE_USER);

        if (r != 0)
        {
            for (size_t j = 0; j <= i; j++)
            {
                uint32_t v = vstart + (uint32_t)j * PAGE_SIZE_4KB;

                unmap_page(v);
                free_phys_page(phys_list[j]);
            }

            return (void*)0;
        }
    }

    memset((void*)vstart, 0, bytes);

    uheap_next = vstart + (uint32_t)bytes;

    return (void*)vstart;
}

void ufree(void *ptr, size_t size)
{
    if (!ptr || !size)
    {
        return;
    }

    uint32_t vaddr = (uint32_t)ptr;
    size_t bytes = (size + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1);
    size_t pages = bytes / PAGE_SIZE_4KB;

    for (size_t i = 0; i < pages; i++)
    {
        uint32_t va = vaddr + (uint32_t)(i * PAGE_SIZE_4KB);
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        if (!(page_directory[dir_index] & PAGE_PRESENT))
        {
            continue;
        }

        if (page_directory[dir_index] & PAGE_SIZE)
        {
            continue;
        }

        uint32_t *table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);
        uint32_t pte = table[table_index];

        if (!(pte & PAGE_PRESENT))
        {
            continue;
        }

        free_phys_page(pte & 0xFFFFF000u);
        table[table_index] = 0;

        invlpg(va);
    }

    flush_tlb();
}

static void print_pte_line(uint32_t va, uint32_t pde, uint32_t pte)
{
    uint32_t pa = pte & 0xFFFFF000u;
    int P = !!(pte & PAGE_PRESENT);
    int RW = !!(pte & PAGE_RW);
    int US = !!(pte & PAGE_USER);

    printf("[PG] VA=0x%08x PDE=%08x PTE=%08x -> PA=%08x  P=%d RW=%d U=%d\n", va, pde, pte, pa, P, RW, US);
}

void paging_dump_range(uint32_t addr, uint32_t size)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end = (addr + size + PAGE_SIZE_4KB - 1) & ~((uint32_t)PAGE_SIZE_4KB - 1);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t di = va >> 22;
        uint32_t ti = (va >> 12) & 0x3FFu;

        uint32_t pde = page_directory[di];

        if (!(pde & PAGE_PRESENT))
        {
            printf("[PG] VA=0x%08x PDE not present\n", va);

            continue;
        }

        if (pde & PAGE_SIZE)
        {
            printf("[PG] VA=0x%08x uses 4MB page (ignored by user allocator)\n", va);

            continue;
        }

        uint32_t *pt = (uint32_t *)(pde & 0xFFFFF000u);
        uint32_t pte = pt[ti];

        print_pte_line(va, pde, pte);
    }
}

int paging_check_user_range(uint32_t addr, uint32_t size)
{
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end = (addr + size + PAGE_SIZE_4KB - 1) & ~((uint32_t)PAGE_SIZE_4KB - 1);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t di = va >> 22;
        uint32_t ti = (va >> 12) & 0x3FFu;

        uint32_t pde = page_directory[di];

        if (!(pde & PAGE_PRESENT))
        {
            printf("[PG-FAIL] VA=0x%08x PDE not present\n", va);

            return -1;
        }

        if (pde & PAGE_SIZE)
        {
            printf("[PG-FAIL] VA=0x%08x is 4MB page (not user 4KB)\n", va);

            return -1;
        }

        uint32_t *pt = (uint32_t *)(pde & 0xFFFFF000u);
        uint32_t pte = pt[ti];

        if (!(pte & PAGE_PRESENT))
        {
            printf("[PG-FAIL] VA=0x%08x PTE not present\n", va);

            return -1;
        }

        if (!(pte & PAGE_USER))
        {
            printf("[PG-FAIL] VA=0x%08x not USER\n", va);

            return -1;
        }
    }

    return 0;
}

void hexdump_bytes(const void *addr, size_t n)
{
    const uint8_t *p = (const uint8_t *)addr;

    for (size_t i = 0; i < n; i++)
    {
        if ((i & 0x0F) == 0)
        {
            printf("\n  %08x: ", (uint32_t)(uintptr_t)(p + i));
        }

        printf("%02x ", p[i]);
    }

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
        // 4MB page
        uint32_t pa = (pde & 0xFFC00000u) | (lin & 0x003FFFFFu);

        printf("[4MB]  PA=%08x  (flags: RW=%u U=%u)\n", pa, !!(pde & 0x002), !!(pde & 0x004));

        return;
    }

    uint32_t *pt = (uint32_t *)(pde & 0xFFFFF000u);
    uint32_t pte = pt[ti];

    printf("[PTE] idx=%u val=%08x  P=%u RW=%u U=%u\n", ti, pte, !!(pte & 0x001), !!(pte & 0x002), !!(pte & 0x004));

    if (pte & 0x001)
    {
        uint32_t pa = (pte & 0xFFFFF000u) | off;

        printf("[RESOLVED] LA=%08x -> PA=%08x\n", lin, pa);
    }
}

int page_present(uint32_t lin)
{
    uint32_t di = lin >> 22;
    uint32_t ti = (lin >> 12) & 0x3FFu;
    uint32_t pde = page_directory[di];

    if (!(pde & 1))
    {
        return 0;
    }

    if (pde & 0x80)
    {
        return 1;
    }

    uint32_t *pt = (uint32_t *)(pde & 0xFFFFF000u);
    uint32_t pte = pt[ti];

    return !!(pte & 1);
}

void dump_err_bits(uint32_t err)
{
    // Intel order: 
    // Bit0 = P, Bit1 = R/W, Bit2 = U/S, Bit3 = RSV, Bit4 = I/D fetch
    printf("err_code=%08x  [ %s | %s | %s | %s | %s ]\n",
           err,
           (err & 1) ? "P=1 (protection)" : "P=0 (not-present)",
           (err & 2) ? "W=1 (write)" : "W=0 (read)",
           (err & 4) ? "U=1 (user)" : "S=0 (supervisor)",
           (err & 8) ? "RSV=1" : "RSV=0",
           (err & 16) ? "IF=1 (instr)" : "IF=0 (data)");
}

void paging_flush_tlb(void)
{
    flush_tlb();
}

