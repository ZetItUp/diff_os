#include "stdio.h"
#include "stdint.h"
#include "string.h"
#include "paging.h"
#include "system/usercopy.h"

__attribute__((aligned(4096))) uint32_t page_directory[1024];
__attribute__((aligned(4096))) uint32_t kernel_page_tables[64][PAGE_ENTRIES];

#define PAGE_SIZE_4K  PAGE_SIZE_4KB
#define ALIGN_UP(x,a) (((x)+((a)-1)) & ~((a)-1))

#ifndef UHEAP_BASE
#define UHEAP_BASE 0x40000000u
#endif

#ifdef DIFF_DEBUG
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

#ifndef USER_MIN
#define USER_MIN 0x00100000u
#endif

#ifndef USER_MAX
#define USER_MAX 0x7FFF0000u
#endif

extern char __heap_start;
extern char __heap_end;

// Track both 4MB blocks and normal 4KB pages
static uint32_t *block_bitmap;
static uint32_t max_blocks;
static uint32_t phys_page_bitmap[(MAX_PHYS_PAGES + 31) / 32];
static uint32_t uheap_next = UHEAP_BASE;

static int pt_next = 1;
extern volatile int g_in_irq;
static int page_is_present(uint32_t lin);

// Allow peeking user memory inside IRQ
static volatile int g_dbg_allow_irq_userpeek = 0;

void paging_dbg_allow_irq_userpeek(int enable)
{
    // Flip the guard so debug code can read user memory even in IRQ
    g_dbg_allow_irq_userpeek = (enable != 0);
}

static inline int is_user_addr(uint32_t vaddr)
{
    // Quick check: is this address in user space range?
    return (vaddr >= USER_MIN) && (vaddr < USER_MAX);
}

static inline void flush_tlb(void)
{
    // Reload CR3 to flush whole TLB fast
    asm volatile("mov %%cr3, %%eax; mov %%eax, %%cr3" ::: "eax", "memory");
}

static inline void invlpg(uint32_t va)
{
    // Drop one TLB entry for this VA
    asm volatile("invlpg (%0)" :: "r"(va) : "memory");
}

// Mark a 4KB physical page as used
static inline void set_phys_page(int i)
{
    phys_page_bitmap[i / 32] |= (1u << (i % 32));
}

// Mark a 4KB physical page as free
static inline void clear_phys_page(int i)
{
    phys_page_bitmap[i / 32] &= ~(1u << (i % 32));
}

// Check if a 4KB physical page is taken
static inline int test_phys_page(int i)
{
    return phys_page_bitmap[i / 32] & (1u << (i % 32));
}

// Check if a 4MB block is taken
static inline int test_block(int i)
{
    return block_bitmap[i / 32] & (1u << (i % 32));
}

// Mark a 4MB block as used
static inline void set_block(int i)
{
    block_bitmap[i / 32] |= (1u << (i % 32));
}

// Mark a 4MB block as free
static inline void clear_block(int i)
{
    block_bitmap[i / 32] &= ~(1u << (i % 32));
}

static int find_free_block(void)
{
    // Walk all blocks and grab the first free one
    for (int i = 0; i < MAX_BLOCKS; i++)
    {
        if (!test_block(i))
        {
            return i;
        }
    }

    // No 4MB blocks left
    return -1;
}

int page_present(uint32_t lin)
{
    // Thin wrapper so other code can ask the simple question
    return page_is_present(lin);
}

void dump_err_bits(uint32_t err)
{
    // Page codes
    int P = !!(err & (1u << 0));   // Present bit: 1 = protection, 0 = not present
    int W = !!(err & (1u << 1));   // 1 = write, 0 = read
    int U = !!(err & (1u << 2));   // 1 = user, 0 = supervisor
    int R = !!(err & (1u << 3));   // Reserved bit was set
    int I = !!(err & (1u << 4));   // 1 = fetch (if NX/IF used)
    int PK = !!(err & (1u << 5));   // Protection key (if enabled)
    int SS = !!(err & (1u << 6));   // Shadow stack (if enabled)

    printf("[PF] err=0x%08x  P=%d W=%d U=%d RSVD=%d IF=%d PK=%d SS=%d\n",
           err, P, W, U, R, I, PK, SS);

    printf("     cause=%s, access=%s, mode=%s\n",
           P ? "protection-violation" : "non-present",
           W ? "write" : "read",
           U ? "user" : "supervisor");
}

// Check PDE/PTE safely, no faults. 0 = ok, <0 = no PT for this VA
int paging_probe_pde_pte(uint32_t va, uint32_t *out_pde, uint32_t *out_pte)
{
    uint32_t di  = va >> 22;
    uint32_t ti  = (va >> 12) & 0x3FFu;
    uint32_t pde = page_directory[di];

    if (out_pde)
    {
        *out_pde = pde;
    }

    if ((pde & PAGE_PRESENT) == 0)
    {
        if (out_pte)
        {
            *out_pte = 0;
        }

        return -1;
    }

    if (pde & PAGE_SIZE)
    {
        // Make a fake PTE so callers can reuse flag checks
        uint32_t synth_pte = (pde & 0xFFC00000u) | (va & 0x003FF000u);
        synth_pte |= (pde & (PAGE_PRESENT | PAGE_RW | PAGE_USER | PAGE_PCD | PAGE_PWT));

        if (out_pte)
        {
            *out_pte = synth_pte;
        }

        return 0;
    }

    // Normal 4KB page path
    uint32_t *pt  = (uint32_t *)(pde & 0xFFFFF000u);
    uint32_t pte  = pt[ti];

    if (out_pte)
    {
        *out_pte = pte;
    }

    return 0;
}

// Check if page is present
static int page_is_present(uint32_t va)
{
    uint32_t pde, pte;

    if (paging_probe_pde_pte(va, &pde, &pte) != 0)
    {
        return 0;
    }

    if ((pde & PAGE_PRESENT) == 0)
    {
        return 0;
    }

    if ((pte & PAGE_PRESENT) == 0)
    {
        return 0;
    }

    return 1;
}

// Print a tiny hex dump from user space without crashing in IRQ
static void hexdump_user_bytes(uint32_t uaddr, size_t n)
{
    printf("[user bytes @%08x] ", uaddr);

    // Do not poke user memory in IRQ unless we flipped the guard
    if (g_in_irq && !g_dbg_allow_irq_userpeek)
    {
        printf("(skipped: IRQ)\n");

        return;
    }

    // First page must be mapped or we bail early
    if (!page_is_present(uaddr))
    {
        printf("(unmapped)\n");

        return;
    }

    if (g_in_irq && g_dbg_allow_irq_userpeek)
    {
        printf("(IRQ override) ");
    }

    for (size_t i = 0; i < n; i++)
    {
        uint32_t va = uaddr + (uint32_t)i;

        // On page boundary, recheck mapping so we do not fault mid-loop
        if ((va & 0xFFFu) == 0 && !page_is_present(va))
        {
            printf("..");

            break;
        }

        // Best-effort read
        // Still can fault if mapping gets yanked right now.
        uint8_t b = *(volatile uint8_t *)va;
        printf("%02x ", b);
    }

    printf("\n");
}

// Allocate a page table and mirror wanted flags into the PDE
static void alloc_page_table_with_flags(uint32_t dir_index, uint32_t *table, uint32_t flags)
{
    // Clear the new table so we do not leak mappings
    for (int i = 0; i < PAGE_ENTRIES; i++)
    {
        table[i] = 0;
    }

    // Base flags kernel PDE
    uint32_t pd_flags = PAGE_PRESENT | PAGE_RW;

    // Set user/cache flags if needed
    if (flags & PAGE_USER)
    {
        pd_flags |= PAGE_USER;
    }

    if (flags & PAGE_PCD)
    {
        pd_flags |= PAGE_PCD;
    }

    if (flags & PAGE_PWT)
    {
        pd_flags |= PAGE_PWT;
    }

    // Assign table into the directory
    page_directory[dir_index] = ((uint32_t)table & 0xFFFFF000u) | pd_flags;
}

// Same as above, without flags
static void alloc_page_table(uint32_t dir_index, uint32_t *table)
{
    alloc_page_table_with_flags(dir_index, table, 0);
}

// Identity map start to start+size as RW kernel pages
static void identity_map_range(uint32_t start, uint32_t size)
{
    uint32_t end = start + size;

    for (uint32_t va = start; va < end; va += 0x1000u)
    {
        map_4kb_page_flags(va, va, PAGE_PRESENT | PAGE_RW);
    }
}

// Init physical 4KB bitmap and mark area as used
static void init_phys_bitmap(void)
{
    // Clear the whole bitmap
    for (int i = 0; i < (int)((MAX_PHYS_PAGES + 31) / 32); i++)
    {
        phys_page_bitmap[i] = 0;
    }

    // First 4MB is reserved for early kernel/boot stuff
    for (int i = 0; i < (BLOCK_SIZE / PAGE_SIZE_4KB); i++)
    {
        set_phys_page(i);
    }
}

// Turn on paging and set up early identity map
void init_paging(uint32_t ram_mb)
{
    // Cap how many 4MB blocks we can track
    max_blocks = ram_mb / 4;

    if (max_blocks > MAX_BLOCKS)
    {
        max_blocks = MAX_BLOCKS;
    }

    // Storage for the 4MB block bitmap
    static uint32_t bitmap_storage[(MAX_BLOCKS + 31) / 32];
    block_bitmap = bitmap_storage;

    // Wipe the page directory so we start clean
    for (int i = 0; i < 1024; i++)
    {
        page_directory[i] = 0;
    }

    // Clear the block bitmap
    for (int i = 0; i < (int)((max_blocks + 31) / 32); i++)
    {
        block_bitmap[i] = 0;
    }

    init_phys_bitmap();

    // Make sure PD[0] points at a valid table for low memory
    alloc_page_table(0, kernel_page_tables[0]);

    // Identity map past the heap end so BSS/heap are safe
    uint32_t heap_end = (uint32_t)(uintptr_t)&__heap_end;
    uint32_t id_end = ALIGN_UP(heap_end, PAGE_SIZE_4KB);
    uint32_t id_end_plus = id_end + PAGE_SIZE_4KB;

    identity_map_range(0x00000000u, id_end_plus);

    // Mark those physical pages as taken in the 4KB bitmap
    uint32_t pages_reserved = id_end_plus / PAGE_SIZE_4KB;
    uint32_t pages_already = (BLOCK_SIZE / PAGE_SIZE_4KB);

    if (pages_reserved > MAX_PHYS_PAGES)
    {
        pages_reserved = MAX_PHYS_PAGES;
    }

    for (uint32_t i = pages_already; i < pages_reserved; i++)
    {
        set_phys_page((int)i);
    }

    // Also mark full 4MB blocks that overlap that identity range
    int blocks_reserved = (int)((id_end_plus + BLOCK_SIZE - 1) / BLOCK_SIZE);

    if (blocks_reserved > (int)MAX_BLOCKS)
    {
        blocks_reserved = (int)MAX_BLOCKS;
    }

    for (int b = 0; b < blocks_reserved; b++)
    {
        set_block(b);
    }

    // Point CR3 at our page directory
    asm volatile("mov %0, %%cr3" :: "r"(&page_directory));

    // Turn on PSE (4MB pages)
    uint32_t cr4;
    asm volatile("mov %%cr4, %0" : "=r"(cr4));
    cr4 |= 0x10;
    asm volatile("mov %0, %%cr4" :: "r"(cr4));

    // Flip the paging bit
    uint32_t cr0;
    asm volatile("mov %%cr0, %0" : "=r"(cr0));
    cr0 |= 0x80000000u;
    asm volatile("mov %0, %%cr0" :: "r"(cr0));
}

// Map a region
int map_page(uint32_t virt_addr, uint32_t size)
{
    // Use big pages if caller is aligned and size is large enough
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

            page_directory[(virt_addr >> 22) + (uint32_t)i] =
                phys_addr | PAGE_PRESENT | PAGE_RW | PAGE_SIZE;

            set_block(block);
        }
    }
    else
    {
        // Fall back to per-page mapping
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

// Map one 4KB page with flags, also lift PDE bits if needed
int map_4kb_page_flags(uint32_t virt_addr, uint32_t phys_addr, uint32_t flags)
{
    uint32_t dir_index = (virt_addr >> 22) & 0x3FFu;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t *table;

    // If there is no PT yet, grab one of our preallocated tables
    if (!(page_directory[dir_index] & PAGE_PRESENT))
    {
        if (pt_next >= (int)(sizeof(kernel_page_tables) / sizeof(kernel_page_tables[0])))
        {
            printf("[PAGING] ERROR: Out of page tables (dir=%u)\n", dir_index);

            return -1;
        }

        table = kernel_page_tables[pt_next++];

        // Mirror user/cache flags into PDE so PTE bits actually work
        alloc_page_table_with_flags(dir_index, table, flags);
    }
    else
    {
        table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);

        // If caller wants USER/PCD/PWT, make sure PDE also has them
        if (flags & PAGE_USER)
        {
            page_directory[dir_index] |= PAGE_USER;
        }

        if (flags & PAGE_PCD)
        {
            page_directory[dir_index] |= PAGE_PCD;
        }

        if (flags & PAGE_PWT)
        {
            page_directory[dir_index] |= PAGE_PWT;
        }
    }

    // Build the PTE 
    uint32_t pte = table[table_index];
    uint32_t desired = (phys_addr & 0xFFFFF000u)
                     | (flags & (PAGE_RW | PAGE_USER | PAGE_PCD | PAGE_PWT))
                     | PAGE_PRESENT;

    // If entry already present, add missing bits
    if (pte & PAGE_PRESENT)
    {
        uint32_t cur_addr = pte & 0xFFFFF000u;
        uint32_t cur_flags = pte & 0x00000FFFu;
        uint32_t new_flags = cur_flags | (desired & 0x00000FFFu);

        if (new_flags != cur_flags)
        {
            table[table_index] = cur_addr | new_flags;
            invlpg(virt_addr);
        }

        return 0;
    }

    // Fresh mapping
    table[table_index] = desired;

    return 0;
}

// Map one 4KB page as RW
int map_4kb_page(uint32_t virt_addr, uint32_t phys_addr)
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t *table;

    // Allocate a PT
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

    // Write the PTE and drop that one TLB entry
    table[table_index] = (phys_addr & 0xFFFFF000u) | PAGE_PRESENT | PAGE_RW;
    invlpg(virt_addr);

    return 0;
}

// Unmap a single 4KB page (no free of PT here)
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

// Unmap either a 4MB PDE or one 4KB PTE, then flush
void unmap_page(uint32_t virt_addr)
{
    uint32_t dir_index = virt_addr >> 22;
    uint32_t table_index = (virt_addr >> 12) & 0x3FFu;
    uint32_t entry = page_directory[dir_index];

    if (!(entry & PAGE_PRESENT))
    {
        return;
    }

    // Big 4MB mapping path
    if (entry & PAGE_SIZE)
    {
        uint32_t phys_addr = entry & 0xFFC00000u;
        int block = (int)(phys_addr / BLOCK_SIZE);

        clear_block(block);
        page_directory[dir_index] = 0;

        flush_tlb();

        return;
    }

    // Normal 4KB page path
    uint32_t *page_table = (uint32_t *)(entry & 0xFFFFF000u);
    uint32_t pte = page_table[table_index];

    if (pte & PAGE_PRESENT)
    {
        // Free the physical page and clear the slot
        free_phys_page(pte & 0xFFFFF000u);
        page_table[table_index] = 0;
    }

    // If the whole PT is empty now, drop the PDE too
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

    flush_tlb();
}

// Reserve a VA region in 4MB steps
int alloc_region(uint32_t virt_start, uint32_t size_mb)
{
    // Must be 4MB aligned for 4MB PDE chunks
    if ((virt_start % BLOCK_SIZE) != 0)
    {
        return -1;
    }

    int blocks = (int)((size_mb + 3) / 4);

    for (int i = 0; i < blocks; i++)
    {
        // Map one 4MB chunk per loop
        uint32_t virt_addr = virt_start + (uint32_t)i * BLOCK_SIZE;
        int res = map_page(virt_addr, BLOCK_SIZE);

        if (res != 0)
        {
            // Roll back the chunks we just mapped
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

// Release a VA region in 4MB steps
int free_region(uint32_t virt_start, uint32_t size_mb)
{
    // Must be 4MB aligned for 4MB PDE chunks
    if ((virt_start % BLOCK_SIZE) != 0)
    {
        return -1;
    }

    int blocks = (int)((size_mb + 3) / 4);

    for (int i = 0; i < blocks; i++)
    {
        // Drop one 4MB mapping per loop
        uint32_t virt_addr = virt_start + (uint32_t)i * BLOCK_SIZE;
        unmap_page(virt_addr);
    }

    flush_tlb();

    return 0;
}

// Grab one free 4KB physical page (returns phys address or 0)
uint32_t alloc_phys_page(void)
{
    // Linear scan is fine here, bitmap makes it cheap
    for (int i = 0; i < MAX_PHYS_PAGES; i++)
    {
        if (!test_phys_page(i))
        {
            // Mark taken and return base address
            set_phys_page(i);

            return (uint32_t)i * PAGE_SIZE_4KB;
        }
    }

    // No physical pages left
    return 0;
}

// Mark a 4KB physical page as free again
void free_phys_page(uint32_t addr)
{
    // Compute bitmap index and guard bounds
    int index = (int)(addr / PAGE_SIZE_4KB);

    if (index < MAX_PHYS_PAGES)
    {
        clear_phys_page(index);
    }
}

// Set USER bit over a VA range
void paging_set_user(uint32_t addr, uint32_t size)
{
    // Page-align the full range
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        // Skip if PT missing
        if (!(page_directory[dir_index] & PAGE_PRESENT))
        {
            continue;
        }

        // Skip 4MB mappings
        if (page_directory[dir_index] & PAGE_SIZE)
        {
            continue;
        }

        // Flip USER and nuke one TLB entry
        uint32_t *table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);
        table[table_index] |= PAGE_USER;
        invlpg(va);
    }

    flush_tlb();
}

// Update PTE flags over a VA range
void paging_update_flags(uint32_t addr, uint32_t size, uint32_t set_mask, uint32_t clear_mask)
{
    // Page-align the range so we hit clean PTEs
    uint32_t start = addr & ~((uint32_t)PAGE_SIZE_4KB - 1);
    uint32_t end = ALIGN_UP(addr + size, PAGE_SIZE_4KB);

    for (uint32_t va = start; va < end; va += PAGE_SIZE_4KB)
    {
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        // Skip if PT missing
        if (!(page_directory[dir_index] & PAGE_PRESENT))
        {
            continue;
        }

        // Skip 4MB mappings
        if (page_directory[dir_index] & PAGE_SIZE)
        {
            continue;
        }

        uint32_t *table = (uint32_t *)(page_directory[dir_index] & 0xFFFFF000u);
        uint32_t pte = table[table_index];

        // Skip unmapped slots
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

// Malloc a Userspace area. page-aligned, zeroed, grows upward
void* umalloc(size_t size)
{
    if (!size)
    {
        return (void*)0;
    }

    // Round up to full pages
    size_t bytes = (size + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1);
    size_t pages = bytes >> 12;

    // Keep start aligned to page size
    uint32_t vstart = (uheap_next + (PAGE_SIZE_4KB - 1)) & ~(PAGE_SIZE_4KB - 1);
    uint32_t va = vstart;

    // Track physical pages so we can unwind cleanly
    uint32_t phys_list[1024];

    if (pages > (sizeof(phys_list) / sizeof(phys_list[0])))
    {
        return (void*)0;
    }

    for (size_t i = 0; i < pages; i++, va += PAGE_SIZE_4KB)
    {
        // Get one physical page
        uint32_t phys = alloc_phys_page();

        if (!phys)
        {
            // Undo mappings done so far
            for (size_t j = 0; j < i; j++)
            {
                uint32_t v = vstart + (uint32_t)j * PAGE_SIZE_4KB;
                unmap_page(v);
                free_phys_page(phys_list[j]);
            }

            return (void*)0;
        }

        phys_list[i] = phys;

        // Map as USER|RW|P
        if (map_4kb_page_flags(va, phys, PAGE_PRESENT | PAGE_RW | PAGE_USER) != 0)
        {
            // Undo everything on failure
            for (size_t j = 0; j <= i; j++)
            {
                uint32_t v = vstart + (uint32_t)j * PAGE_SIZE_4KB;
                unmap_page(v);
                free_phys_page(phys_list[j]);
            }

            return (void*)0;
        }
    }

    // Pages are mapped USER|RW, zeroing is safe
    memset((void*)vstart, 0, bytes);

    // Bump the simple bump pointer
    uheap_next = vstart + (uint32_t)bytes;

    return (void*)vstart;
}

// Free pages belonging to a user allocation
void ufree(void *ptr, size_t size)
{
    if (!ptr || !size)
    {
        return;
    }

    // Work on page boundaries
    uint32_t vaddr = (uint32_t)ptr;
    size_t bytes = (size + PAGE_SIZE_4KB - 1) & ~(PAGE_SIZE_4KB - 1);
    size_t pages = bytes / PAGE_SIZE_4KB;

    for (size_t i = 0; i < pages; i++)
    {
        uint32_t va = vaddr + (uint32_t)(i * PAGE_SIZE_4KB);
        uint32_t dir_index = va >> 22;
        uint32_t table_index = (va >> 12) & 0x3FFu;

        // Skip if PT missing
        if (!(page_directory[dir_index] & PAGE_PRESENT))
        {
            continue;
        }

        // Skip 4MB mappings
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

        // Return the physical page and clear the slot
        free_phys_page(pte & 0xFFFFF000u);
        table[table_index] = 0;
        invlpg(va);
    }

    flush_tlb();
}

// Print one clear PTE line for quick reading
static void print_pte_line(uint32_t va, uint32_t pde, uint32_t pte)
{
    uint32_t pa = pte & 0xFFFFF000u;
    int P = !!(pte & PAGE_PRESENT);
    int RW = !!(pte & PAGE_RW);
    int US = !!(pte & PAGE_USER);

    printf("[PG] VA=0x%08x PDE=%08x PTE=%08x -> PA=%08x  P=%d RW=%d U=%d\n",
           va, pde, pte, pa, P, RW, US);
}

// Dump mappings for a VA range
void paging_dump_range(uint32_t addr, uint32_t size)
{
    // Page-align range for stable output
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
            printf("[PG] VA=0x%08x uses 4MB page (skipped)\n", va);

            continue;
        }

        uint32_t *pt = (uint32_t *)(pde & 0xFFFFF000u);
        uint32_t pte = pt[ti];
        
        print_pte_line(va, pde, pte);
    }
}

// Validate a user range (present + user-accessible)
int paging_check_user_range(uint32_t addr, uint32_t size)
{
    // Page-align the bounds for a clean walk
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

// Hex-dump 
void hexdump_bytes(const void *addr, size_t n)
{
    uint32_t va = (uint32_t)(uintptr_t)addr;

    if (is_user_addr(va))
    {
        hexdump_user_bytes(va, n);

        return;
    }

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

// Print PDE/PTE
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

    uint32_t *pt = (uint32_t *)(pde & 0xFFFFF000u);
    uint32_t pte = pt[ti];

    printf("[PTE] idx=%u val=%08x  P=%u RW=%u U=%u\n",
           ti, pte, !!(pte & 0x001), !!(pte & 0x002), !!(pte & 0x004));

    if (pte & 0x001)
    {
        uint32_t pa = (pte & 0xFFFFF000u) | off;
        printf("[RESOLVED] LA=%08x -> PA=%08x\n", lin, pa);
    }
}

// Public TLB flush wrapper
void paging_flush_tlb(void)
{
    flush_tlb();
}

