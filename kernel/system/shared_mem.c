#include "system/shared_mem.h"
#include "system/process.h"
#include "system/spinlock.h"
#include "system/scheduler.h"
#include "paging.h"
#include "heap.h"
#include "string.h"

#ifndef SHARED_MEMORY_BASE
#define SHARED_MEMORY_BASE  0x50000000u
#endif

#ifndef SHARED_MEMORY_LIMIT
#define SHARED_MEMORY_LIMIT 0x60000000u   // 64 MB window
#endif

static shared_memory_object_t g_shared_memory[SHARED_MEMORY_MAX_OBJECTS];
static spinlock_t g_shared_memory_lock;
static spinlock_t g_shared_memory_window_lock;
static uintptr_t g_shared_memory_cursor = SHARED_MEMORY_BASE;
static int g_shared_memory_lock_initialized = 0;

static inline uint32_t page_align_up(uint32_t x)
{
    return (x + PAGE_SIZE_4KB - 1u) & ~(PAGE_SIZE_4KB - 1u);
}

// Lookup a shared memory object by handle if it exists
static shared_memory_object_t *shared_memory_get(int handle)
{
    if (handle < 0 || handle >= SHARED_MEMORY_MAX_OBJECTS)
    {
        return NULL;
    }

    if (!g_shared_memory[handle].used)
    {
        return NULL;
    }

    return &g_shared_memory[handle];
}

// Check if a pid is allowed to access the shared memory object
static int shared_memory_pid_allowed(shared_memory_object_t *obj, int pid)
{
    if (pid == obj->owner_pid || obj->allow_all)
    {
        return 1;
    }

    for (int i = 0; i < SHARED_MEMORY_MAX_ALLOWED_PIDS; i++)
    {
        if (obj->allowed_pids[i] == pid)
        {
            return 1;
        }
    }

    return 0;
}

// Add a pid to the allowed list
static int shared_memory_add_allowed(shared_memory_object_t *obj, int pid)
{
    if (pid == obj->owner_pid || obj->allow_all)
    {
        return 0;
    }

    for (int i = 0; i < SHARED_MEMORY_MAX_ALLOWED_PIDS; i++)
    {
        if (obj->allowed_pids[i] == pid)
        {
            // Already allowed
            return 0;
        }
    }

    for (int i = 0; i < SHARED_MEMORY_MAX_ALLOWED_PIDS; i++)
    {
        if (obj->allowed_pids[i] == 0)
        {
            obj->allowed_pids[i] = pid;
            
            return 0;
        }
    }

    return -1;
}

// Allocated memory for mapping
static uintptr_t shared_memory_allocate_window(uint32_t size_bytes)
{
    uint32_t bytes = page_align_up(size_bytes);
    uintptr_t base = g_shared_memory_cursor;

    if (base + bytes > SHARED_MEMORY_LIMIT)
    {
        return 0;
    }

    g_shared_memory_cursor = base + bytes;
    return base;
}

// Lazy init global locks
static inline void shared_memory_lazy_init(void)
{
    if (!g_shared_memory_lock_initialized)
    {
        spinlock_init(&g_shared_memory_lock);
        spinlock_init(&g_shared_memory_window_lock);
        g_shared_memory_lock_initialized = 1;
    }
}

// Map all pages of an object into the current process at a base VA
static int shared_memory_map_into_current(shared_memory_object_t *obj, uintptr_t va_base)
{
    uint32_t flags = PAGE_PRESENT | PAGE_USER | PAGE_RW;

    for (uint32_t i = 0; i < obj->page_count; i++)
    {
        uintptr_t va = va_base + i * PAGE_SIZE_4KB;

        if (paging_ensure_pagetable((uint32_t)va, flags) != 0)
        {
            return -1;
        }

        // Remove any old mapping before inserting
        unmap_4kb_page((uint32_t)va);

        if (map_4kb_page_flags((uint32_t)va, obj->phys_pages[i], flags) != 0)
        {
            return -1;
        }
    }

    paging_flush_tlb();
    return 0;
}

// Create a new shared memory object
int shared_memory_create(uint32_t size_bytes)
{
    if (size_bytes == 0)
    {
        return -1;
    }

    uint32_t bytes = page_align_up(size_bytes);
    if (bytes / PAGE_SIZE_4KB > SHARED_MEMORY_MAX_PAGES_PER_OBJECT)
    {
        return -2;
    }

    uint32_t page_count = bytes / PAGE_SIZE_4KB;

    uint32_t lock_flags;

    shared_memory_lazy_init();

    spin_lock_irqsave(&g_shared_memory_lock, &lock_flags);

    int handle = -1;
    for (int i = 0; i < SHARED_MEMORY_MAX_OBJECTS; i++)
    {
        if (!g_shared_memory[i].used)
        {
            handle = i;
            g_shared_memory[i].used = 1;
            break;
        }
    }

    if (handle < 0)
    {
        spin_unlock_irqrestore(&g_shared_memory_lock, lock_flags);
        return -3;
    }

    shared_memory_object_t *obj = &g_shared_memory[handle];
    memset(obj, 0, sizeof(*obj));
    obj->used = 1;
    obj->id = handle;
    obj->owner_pid = process_pid(process_current());
    obj->size_bytes = bytes;
    obj->page_count = page_count;
    obj->refcount = 1;
    spinlock_init(&obj->lock);

    // Allocate physical pages
    for (uint32_t i = 0; i < page_count; i++)
    {
        uint32_t phys = alloc_phys_page();
        if (!phys)
        {
            // Roll back allocations
            for (uint32_t j = 0; j < i; j++)
            {
                free_phys_page(obj->phys_pages[j]);
            }
            
            obj->used = 0;
            spin_unlock_irqrestore(&g_shared_memory_lock, lock_flags);
            
            return -4;
        }

        obj->phys_pages[i] = phys;
    }

    spin_unlock_irqrestore(&g_shared_memory_lock, lock_flags);
    
    return handle;
}

// Allow another pid to use the shared memory
int shared_memory_grant(int handle, int pid)
{
    shared_memory_lazy_init();

    shared_memory_object_t *obj = shared_memory_get(handle);
    
    if (!obj)
    {
        return -1;
    }

    if (process_pid(process_current()) != obj->owner_pid)
    {
        return -3;
    }

    uint32_t flags;
    spin_lock_irqsave(&obj->lock, &flags);

    if (shared_memory_add_allowed(obj, pid) != 0)
    {
        spin_unlock_irqrestore(&obj->lock, flags);
    
        return -2;
    }

    obj->refcount++;
    spin_unlock_irqrestore(&obj->lock, flags);
    
    return 0;
}

// Map the shared memory into the caller
int shared_memory_map(int handle)
{
    shared_memory_lazy_init();

    shared_memory_object_t *obj = shared_memory_get(handle);
    
    if (!obj)
    {
        return -1;
    }

    int pid = process_pid(process_current());

    uint32_t flags;
    spin_lock_irqsave(&obj->lock, &flags);

    if (!shared_memory_pid_allowed(obj, pid))
    {
        spin_unlock_irqrestore(&obj->lock, flags);
    
        return -2;
    }

    // Find existing mapping for this pid
    for (int i = 0; i < SHARED_MEMORY_MAX_ALLOWED_PIDS; i++)
    {
        if (obj->mappings[i].active && obj->mappings[i].pid == pid)
        {
            uintptr_t va = obj->mappings[i].va;
            spin_unlock_irqrestore(&obj->lock, flags);
    
            return (int)va;
        }
    }

    spin_lock(&g_shared_memory_window_lock);
    uintptr_t va = shared_memory_allocate_window(obj->size_bytes);
    spin_unlock(&g_shared_memory_window_lock);

    if (va == 0)
    {
        spin_unlock_irqrestore(&obj->lock, flags);
    
        return -3;
    }

    if (shared_memory_map_into_current(obj, va) != 0)
    {
        spin_unlock_irqrestore(&obj->lock, flags);
    
        return -4;
    }

    // Record mapping
    for (int i = 0; i < SHARED_MEMORY_MAX_ALLOWED_PIDS; i++)
    {
        if (!obj->mappings[i].active)
        {
            obj->mappings[i].active = 1;
            obj->mappings[i].pid = pid;
            obj->mappings[i].va = va;
            obj->mapping_count++;
    
            break;
        }
    }

    spin_unlock_irqrestore(&obj->lock, flags);
    
    return (int)va;
}

// Unmap the shared memory from the caller
int shared_memory_unmap(int handle)
{
    shared_memory_lazy_init();

    shared_memory_object_t *obj = shared_memory_get(handle);
    
    if (!obj)
    {
        return -1;
    }

    int pid = process_pid(process_current());

    uint32_t flags;
    spin_lock_irqsave(&obj->lock, &flags);

    int found_index = -1;
    uintptr_t va = 0;

    for (int i = 0; i < SHARED_MEMORY_MAX_ALLOWED_PIDS; i++)
    {
        if (obj->mappings[i].active && obj->mappings[i].pid == pid)
        {
            found_index = i;
            va = obj->mappings[i].va;
    
            break;
        }
    }

    if (found_index < 0)
    {
        spin_unlock_irqrestore(&obj->lock, flags);
    
        return -2;
    }

    for (uint32_t i = 0; i < obj->page_count; i++)
    {
        unmap_4kb_page((uint32_t)(va + i * PAGE_SIZE_4KB));
    }
    
    paging_flush_tlb();

    obj->mappings[found_index].active = 0;
    obj->mappings[found_index].pid = 0;
    obj->mappings[found_index].va = 0;
    
    if (obj->mapping_count > 0)
    {
        obj->mapping_count--;
    }

    spin_unlock_irqrestore(&obj->lock, flags);
    
    return 0;
}

// Drop a reference and free when unused
int shared_memory_release(int handle)
{
    shared_memory_lazy_init();

    shared_memory_object_t *obj = shared_memory_get(handle);
    
    if (!obj)
    {
        return -1;
    }

    uint32_t flags;
    spin_lock_irqsave(&obj->lock, &flags);

    if (obj->mapping_count > 0)
    {
        spin_unlock_irqrestore(&obj->lock, flags);
    
        return -2;
    }

    if (obj->refcount > 0)
    {
        obj->refcount--;
    }

    int ref = obj->refcount;

    if (ref > 0)
    {
        spin_unlock_irqrestore(&obj->lock, flags);
    
        return 0;
    }

    // Free physical pages
    for (uint32_t i = 0; i < obj->page_count; i++)
    {
        if (obj->phys_pages[i])
        {
            free_phys_page(obj->phys_pages[i]);
        }
    }

    obj->used = 0;

    spin_unlock_irqrestore(&obj->lock, flags);
    
    return 0;
}

void shared_memory_cleanup_process(int pid)
{
    shared_memory_lazy_init();

    for (int i = 0; i < SHARED_MEMORY_MAX_OBJECTS; i++)
    {
        shared_memory_object_t *obj = &g_shared_memory[i];
        if (!obj->used)
        {
            continue;
        }

        uint32_t flags;
        spin_lock_irqsave(&obj->lock, &flags);

        // Unmap mappings owned by pid
        for (int m = 0; m < SHARED_MEMORY_MAX_ALLOWED_PIDS; m++)
        {
            if (obj->mappings[m].active && obj->mappings[m].pid == pid)
            {
                uintptr_t va = obj->mappings[m].va;
                for (uint32_t p = 0; p < obj->page_count; p++)
                {
                    unmap_4kb_page((uint32_t)(va + p * PAGE_SIZE_4KB));
                }
                paging_flush_tlb();

                obj->mappings[m].active = 0;
                obj->mappings[m].pid = 0;
                obj->mappings[m].va = 0;
                if (obj->mapping_count > 0)
                {
                    obj->mapping_count--;
                }
                if (obj->refcount > 0)
                {
                    obj->refcount--;
                }
            }
        }

        // If owner died or refcount is zero, free the object
        if (obj->owner_pid == pid || obj->refcount <= 0)
        {
            for (uint32_t p = 0; p < obj->page_count; p++)
            {
                if (obj->phys_pages[p])
                {
                    free_phys_page(obj->phys_pages[p]);
                }
            }
            memset(obj, 0, sizeof(*obj));
        }

        spin_unlock_irqrestore(&obj->lock, flags);
    }
}
