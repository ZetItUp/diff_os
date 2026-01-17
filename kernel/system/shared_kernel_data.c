#include "shared_kernel_data.h"
#include "paging.h"
#include "string.h"
#include "stdio.h"

// Physical page shared by all processes
static uint32_t shared_page_phys = 0;

// Kernel pointer for writing updates
static shared_kernel_data_t *kernel_data_ptr = NULL;

// Kernel VA for the shared page
#define SHARED_PAGE_KERNEL_VA 0xFFBFF000u

void shared_kernel_data_init(void)
{
    shared_page_phys = alloc_phys_page();

    if (!shared_page_phys)
    {
        printf("[SHARED] Failed to allocate physical page\n");

        return;
    }

    // Map into kernel address space for writing
    int result = map_4kb_page_flags(SHARED_PAGE_KERNEL_VA, shared_page_phys,
                                    PAGE_PRESENT | PAGE_RW);

    if (result != 0)
    {
        printf("[SHARED] Failed to map kernel VA\n");
        free_phys_page(shared_page_phys);
        shared_page_phys = 0;

        return;
    }

    kernel_data_ptr = (shared_kernel_data_t *)SHARED_PAGE_KERNEL_VA;

    // Clear and initialize
    memset(kernel_data_ptr, 0, PAGE_SIZE_4KB);
    kernel_data_ptr->timer_frequency = 100;

    printf("[SHARED] Kernel data page ready, phys=%08x\n", shared_page_phys);
}

void shared_kernel_data_update_time(uint64_t milliseconds, uint32_t ticks)
{
    if (kernel_data_ptr)
    {
        kernel_data_ptr->time_ms = milliseconds;
        kernel_data_ptr->tick_count = ticks;
    }
}

int shared_kernel_data_map_to_process(uint32_t cr3_phys)
{
    if (!shared_page_phys)
    {
        return -1;
    }

    // Access target page directory
    uint32_t *target_pd = (uint32_t *)paging_kmap_phys(cr3_phys, 0);

    if (!target_pd)
    {
        return -2;
    }

    uint32_t dir_index = PDE_INDEX(SHARED_KERNEL_DATA_VA);
    uint32_t table_index = PTE_INDEX(SHARED_KERNEL_DATA_VA);
    uint32_t pde = target_pd[dir_index];

    // Create page table if missing
    if (!(pde & PAGE_PRESENT))
    {
        uint32_t pt_phys = alloc_phys_page();

        if (!pt_phys)
        {
            paging_kunmap_phys(0);

            return -3;
        }

        // Zero the new page table
        uint32_t *new_pt = (uint32_t *)paging_kmap_phys(pt_phys, 1);

        if (!new_pt)
        {
            free_phys_page(pt_phys);
            paging_kunmap_phys(0);

            return -4;
        }

        memset(new_pt, 0, PAGE_SIZE_4KB);
        paging_kunmap_phys(1);

        // Install page directory entry
        target_pd[dir_index] = pt_phys | PAGE_PRESENT | PAGE_RW | PAGE_USER;
        pde = target_pd[dir_index];
    }

    // Map the page table
    uint32_t pt_phys = pde & 0xFFFFF000u;
    uint32_t *pt = (uint32_t *)paging_kmap_phys(pt_phys, 1);

    if (!pt)
    {
        paging_kunmap_phys(0);

        return -5;
    }

    // Map shared page as read-only to userspace
    pt[table_index] = shared_page_phys | PAGE_PRESENT | PAGE_USER;

    paging_kunmap_phys(1);
    paging_kunmap_phys(0);

    return 0;
}
