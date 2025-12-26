#include "dex/dex.h"
#include "dex/exl.h"
#include "system/process.h"
#include "system/syscall.h"
#include "system/path.h"
#include "diff.h"
#include "string.h"
#include "stdint.h"
#include "stddef.h"
#include "stdio.h"
#include "console.h"
#include "paging.h"
#include "heap.h"
#include "system/usercopy.h"
#include "debug.h"

#define DEX_DBG(...) DDBG_IF(DEBUG_AREA_EXL, __VA_ARGS__)

extern void enter_user_mode(uint32_t entry, uint32_t user_stack_top);
extern FileTable *file_table;

// Paging and process helpers
extern uint32_t paging_new_address_space(void);
extern void paging_switch_address_space(uint32_t cr3);
extern void paging_destroy_address_space(uint32_t cr3);

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

// Check if address is in user range
static inline int is_user_va(uint32_t a)
{
    return (a >= USER_MIN) && (a < USER_MAX);
}

// Safe range check for file sections
static inline int in_range(uint32_t off, uint32_t sz, uint32_t max)
{
    if (sz == 0)
    {
        return 1;
    }
    if (off > max)
    {
        return 0;
    }
    if (max - off < sz)
    {
        return 0;
    }
    return 1;
}

// Check if pointer lies inside an image buffer
static int ptr_in_image(const void *p, const uint8_t *base, uint32_t size)
{
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;

    return (v >= b) && (v < b + size);
}

// Exit stub and user stack
static uint8_t *build_user_exit_stub(uint32_t entry_va)
{
    // Build a deterministic user stub:
    // 1) Set DS/ES/FS/GS = 0x23 (user data)
    // 2) Call entry_va
    // 3) Syscall exit(0) via int 0x66
    // 4) Infinite loop if syscall returns (should not)
    uint8_t *stub = (uint8_t *)umalloc(64);
    if (!stub)
    {
        DEX_DBG("[DEX] Stub alloc failed\n");

        return NULL;
    }

    // Make sure the stub bytes are mapped as present|user|rw
    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    uint8_t *p = stub;

    // mov ax, 0x23
    *p++ = 0x66; *p++ = 0xB8; *p++ = 0x23; *p++ = 0x00;

    // mov ds, ax
    *p++ = 0x8E; *p++ = 0xD8;

    // mov es, ax
    *p++ = 0x8E; *p++ = 0xC0;

    // mov fs, ax
    *p++ = 0x8E; *p++ = 0xE0;

    // mov gs, ax
    *p++ = 0x8E; *p++ = 0xE8;

    // call entry_va (rel32)
    *p++ = 0xE8;
    int32_t rel = (int32_t)entry_va - (int32_t)((uint32_t)p + 4);
    memcpy(p, &rel, 4);
    p += 4;

    // mov eax, 1  ; SYSTEM_EXIT
    *p++ = 0xB8;
    uint32_t sys_exit = SYSTEM_EXIT;
    memcpy(p, &sys_exit, 4);
    p += 4;

    // xor ebx, ebx ; exit code = 0
    *p++ = 0x31; *p++ = 0xDB;

    // int 0x66     ; SYSCALL_VECTOR
    *p++ = 0xCD; *p++ = 0x66;

    // ud2 (should never return)
    *p++ = 0x0F; *p++ = 0x0B;
    // jmp $        ; safety if syscall returns
    *p++ = 0xEB; *p++ = 0xFE;

    // Mark the actual written range as user (covers shorter-than-64 writes)
    paging_set_user((uint32_t)stub, (uint32_t)(p - stub));

    DEX_DBG("[DEX] stub@%p -> call %08x rel=%d\n", stub, entry_va, rel);

    return stub;
}


static uint32_t build_user_stack(
    const char *prog_path,
    int argc_in,
    char *const argv_in[],
    uint32_t *out_base,
    uint32_t *out_size
)
{
    // Place the user stack high in the user address space to avoid collisions
    // with the user heap that grows up from USER_MIN. Use a fixed 512 KB stack
    // mapped explicitly near USER_MAX with a 4 KB guard page above it.
    const uint32_t STK_SZ = 512 * 1024;
    const uint32_t GUARD  = PAGE_SIZE_4KB;
    const uint32_t stack_limit = USER_MAX - GUARD; // leave guard page unmapped
    uint32_t stack_top  = stack_limit;
    uint32_t stack_base = stack_top - STK_SZ;

    if (stack_base < USER_MIN + (1u << 20)) // sanity: keep clear of image/heap
    {
        stack_base = USER_MIN + (1u << 20);
        stack_top  = stack_base + STK_SZ;
        if (stack_top > stack_limit)
        {
            stack_top = stack_limit;
            if (stack_top < stack_base)
            {
                stack_top = stack_base;
            }
        }
    }

    if (out_base)
    {
        *out_base = stack_base;
    }
    if (out_size)
    {
        *out_size = STK_SZ;
    }

    // Reserve the entire stack range so demand faults can grow it.
    paging_reserve_range(stack_base, STK_SZ);

    // Eagerly map the top 32 KB to cover initial frames/argv and avoid faults
    // near the very top of the stack.
    const uint32_t PREFAULT = 32 * 1024;
    uint32_t prefault_base = (stack_top > PREFAULT) ? (stack_top - PREFAULT) : stack_base;
    if (paging_map_user_range(prefault_base, stack_top - prefault_base, 1) != 0)
    {
        DEX_DBG("[DEX] Stack map failed base=%08x sz=%u\n", prefault_base, (unsigned)(stack_top - prefault_base));
        return 0;
    }
    memset((void *)prefault_base, 0, stack_top - prefault_base);

    int argc = (argc_in > 0 && argv_in) ? argc_in : 1;

    uint32_t *argv_ptrs = (uint32_t *)kmalloc(
        sizeof(uint32_t) * (size_t)argc
    );
    if (!argv_ptrs)
    {
        DEX_DBG("[DEX] argv_ptrs alloc failed\n");
        return 0;
    }

    uint32_t sp = stack_top;
    uint32_t base = stack_base;

    for (int i = argc - 1; i >= 0; --i)
    {
        const char *src =
            (argc_in > 0 && argv_in) ? argv_in[i] : (i == 0 ? prog_path : "");

        size_t len = strlen(src) + 1;

        if (sp < base + (uint32_t)len + 64)
        {
            DEX_DBG("[DEX] Stack overflow while building argv\n");
            kfree(argv_ptrs);
            return 0;
        }

        sp -= (uint32_t)len;
        memcpy((void *)sp, src, len);
        argv_ptrs[i] = sp;
    }

    // Linux ELF convention: stack layout from SP is:
    // [SP]    = undefined (fake return address, always 0)
    // [SP+4]  = argc
    // [SP+8]  = argv[0]
    // [SP+12] = argv[1]
    // ...
    // [SP+4*(argc+2)] = NULL (end of argv)
    // [SP+4*(argc+3)] = NULL (end of envp, we have no envp)
    //
    // The fake return address is needed because GCC's main() prologue
    // does "lea 0x4(%esp),%ecx" expecting a return address at ESP
    //
    // CRITICAL: SP must be 16-byte aligned BEFORE we write anything,
    // because GCC's "and $0xfffffff0,%esp" expects to not move more than
    // 12 bytes, and it needs [ECX-4] (where ECX = old ESP + 4) to still
    // be valid after alignment.

    // We need space for: fake_ret + argc + argv[argc] + NULL + envp_NULL
    uint32_t needed = 4 + 4 + (uint32_t)((argc + 1) * sizeof(uint32_t)) + 4;
    if (sp < base + needed)
    {
        kfree(argv_ptrs);
        return 0;
    }
    sp -= needed;

    // Ensure SP ends up 16-byte aligned (pointing to fake return address)
    // This way GCC's alignment won't move ESP more than necessary
    sp &= ~0xFu;

    // Write fake return address (0 = no return)
    *(uint32_t *)sp = 0;

    // Write argc at SP+4
    *(uint32_t *)(sp + 4) = (uint32_t)argc;

    // Write argv[] array starting at SP+8
    for (int i = 0; i < argc; ++i)
    {
        ((uint32_t *)(sp + 8))[i] = argv_ptrs[i];
    }

    // NULL terminator for argv
    ((uint32_t *)(sp + 8))[argc] = 0;

    // NULL terminator for envp (we have no environment variables)
    ((uint32_t *)(sp + 8))[argc + 1] = 0;

    kfree(argv_ptrs);

    DEX_DBG("[DEX] stack built base=%08x top=%08x size=%u\n", base, sp, STK_SZ);
    return sp;
}

// Imports and relocations
static int resolve_imports_user(
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const char *strtab,
    void **out_ptrs,
    uint8_t *image,
    uint32_t image_sz
)
{
    uint32_t cnt = hdr->import_table_count;

    // Import table was already validated against file_size in dex_load().
    // Only sanity-limit the count here.
    if (cnt > 4096)
    {
        DEX_DBG("[DEX] Too many imports (%u)\n", cnt);
        return -1;
    }

    for (uint32_t i = 0; i < cnt; ++i)
    {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;

        void *addr = resolve_exl_symbol(exl, sym);

        if (!addr)
        {
            const exl_t *lib = load_exl(file_table, exl);
            if (!lib)
            {
                DEX_DBG("[DEX] Cannot load EXL %s\n", exl);
                return -2;
            }
            addr = resolve_exl_symbol(exl, sym);
        }

        if (!addr)
        {
            DEX_DBG("[DEX] Unresolved import %s:%s\n", exl, sym);
            return -3;
        }

        // Forbid imports that point inside this image
        if (ptr_in_image(addr, image, image_sz))
        {
            DEX_DBG("[DEX] Import %s:%s resolves inside image %p\n", exl, sym, addr);
            return -4;
        }

        // Force user VA
        if (!is_user_va((uint32_t)addr))
        {
            DEX_DBG("[DEX] Import %s:%s -> kernel VA %p\n", exl, sym, addr);
            return -5;
        }

        out_ptrs[i] = addr;
        DEX_DBG("[IMP] %s:%s -> %p\n", exl, sym, addr);
    }

    return 0;
}

static int relocate_image(
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const dex_reloc_t *rel,
    const char *strtab,
    uint8_t *image,
    uint32_t image_sz
)
{
    void **import_ptrs = NULL;

    DEX_DBG("[DEX-RELOC-DEBUG] imports=%u relocs=%u\n", hdr->import_table_count, hdr->reloc_table_count);

    if (hdr->import_table_count > 4096)
    {
        DEX_DBG("[DEX] Too many imports (%u)\n", hdr->import_table_count);
        return -1;
    }

    if (hdr->import_table_count)
    {
        size_t bytes = (size_t)hdr->import_table_count * sizeof(void *);
        import_ptrs = (void **)kmalloc(bytes);

        if (!import_ptrs)
        {
            DEX_DBG("[DEX] kmalloc import_ptrs=%u failed\n", (unsigned)bytes);

            return -2;
        }

        memset(import_ptrs, 0, bytes);
    }

    // Resolve imports against EXLs
    if (resolve_imports_user(hdr, imp, strtab, import_ptrs, image, image_sz) != 0)
    {
        if (import_ptrs)
        {
            kfree(import_ptrs);
        }

        return -3;
    }

    DEX_DBG("[RELOC] Applying %u relocations\n", hdr->reloc_table_count);

    // Apply relocations
    DEX_DBG("[DEX] Processing %u relocations from reloc table\n", hdr->reloc_table_count);

    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (off > image_sz || image_sz - off < 4)
        {
            DEX_DBG("[DEX] Reloc out of range off=0x%08x image=%u\n", off, image_sz);

            if (import_ptrs)
            {
                kfree(import_ptrs);
            }

            return -4;
        }

        uint8_t *target = image + off;
        uint32_t old = *(uint32_t *)target;

        switch (typ)
        {
            case DEX_ABS32:
            {
                if (idx >= hdr->import_table_count)
                {
                    if (import_ptrs)
                    {
                        kfree(import_ptrs);
                    }

                    return -5;
                }
                *(uint32_t *)target = (uint32_t)import_ptrs[idx];

                DEX_DBG("[REL] ABS32 @%08x %08x -> %08x S=%08x\n",
                     (uint32_t)(uintptr_t)target, old, *(uint32_t *)target, (uint32_t)import_ptrs[idx]);
                break;
            }

            case DEX_PC32:
            {
                if (idx >= hdr->import_table_count)
                {
                    DEX_DBG("[DEX][ERROR] PC32 reloc idx=%u >= import_count=%u at off=0x%08x\n",
                           idx, hdr->import_table_count, off);
                    if (import_ptrs)
                    {
                        kfree(import_ptrs);
                    }

                    return -6;
                }

                uint32_t S = (uint32_t)import_ptrs[idx];
                int32_t disp = (int32_t)S - (int32_t)((uint32_t)(uintptr_t)target + 4);
                *(int32_t *)target = disp;

                // Temporarily log ALL PC32 relocations
                static int pc32_count = 0;
                pc32_count++;

                const char *sym_name = (idx < hdr->import_table_count)
                                           ? (strtab + imp[idx].symbol_name_offset)
                                           : "<bad-idx>";
                const char *lib_name = (idx < hdr->import_table_count)
                                           ? (strtab + imp[idx].exl_name_offset)
                                           : "<bad-idx>";

                // Log putchar/printf or first 100
                int is_putchar = (strcmp(sym_name, "putchar") == 0);
                int is_printf = (strcmp(sym_name, "printf") == 0);
                if (pc32_count <= 100 || is_putchar || is_printf || (off >= hdr->entry_offset && off < hdr->entry_offset + 0x200))
                {
                    DEX_DBG("[DEX][PC32 #%d] off=0x%08x S=%08x P=%08x disp=%08x old=%08x new=%08x sym=%s:%s\n",
                           pc32_count, off, S, (uint32_t)(uintptr_t)target + 4,
                           (uint32_t)disp, old, *(uint32_t *)target, lib_name, sym_name);
                }

                DEX_DBG("[REL] PC32  @%08x P=%08x S=%08x disp=%d old=%08x new=%08x\n",
                     (uint32_t)(uintptr_t)target,
                     (uint32_t)(uintptr_t)target + 4,
                     S, disp, old, *(uint32_t *)target);

                break;
            }

            case DEX_RELATIVE:
            {
                uint32_t val = old + (uint32_t)image;
                // DEBUG: Track specific relocations
                if (off == 0x2AEA)
                {
                    DEX_DBG("[DEX][DEBUG-0x2AEA] D_QuitNetGame reloc: off=0x%08x old=0x%08x base=0x%08x -> val=0x%08x\n",
                           off, old, (uint32_t)image, val);
                    DEX_DBG("[DEX][DEBUG-0x2AEA] target=%p *target_before=0x%08x\n",
                           target, *(uint32_t *)target);
                }
                if (off == 0x4044)
                {
                    DEX_DBG("[DEX][DEBUG-0x4044] G_CheckDemoStatus reloc: off=0x%08x old=0x%08x base=0x%08x -> val=0x%08x\n",
                           off, old, (uint32_t)image, val);
                    DEX_DBG("[DEX][DEBUG-0x4044] target=%p *target_before=0x%08x\n",
                           target, *(uint32_t *)target);
                }
                // Warn if old value is suspiciously large (> 100MB)
                if (old > 100 * 1024 * 1024)
                {
                    DEX_DBG("[DEX][WARN] Large RELATIVE old value: off=0x%08x old=0x%08x base=0x%08x -> val=0x%08x\n",
                           off, old, (uint32_t)image, val);
                }
                // Check if the RESULT looks like x86 code (common function prologues)
                uint8_t byte0 = val & 0xFF;
                uint8_t byte1 = (val >> 8) & 0xFF;
                // 0x55 = push ebp, 0x53 = push ebx, 0x56 = push esi, 0x57 = push edi, 0x83 = sub, 0x8b = mov
                if ((byte0 == 0x55 || byte0 == 0x53 || byte0 == 0x56 || byte0 == 0x57) &&
                    (byte1 == 0x89 || byte1 == 0x8B || byte1 == 0x83 || byte1 == 0x56 || byte1 == 0x53))
                {
                    DEX_DBG("[DEX][WARN] SUSPICIOUS RELOC: off=0x%08x old=0x%08x base=0x%08x -> val=0x%08x (looks like x86 code!)\n",
                           off, old, (uint32_t)image, val);
                }
                if (off >= hdr->entry_offset && off < hdr->entry_offset + 0x200)
                {
                    DEX_DBG("[DEX][REL] off=0x%08x old=0x%08x base=0x%08x -> 0x%08x\n",
                           off, old, (uint32_t)image, val);
                }
                *(uint32_t *)target = val;
                if (off == 0x2AEA)
                {
                    DEX_DBG("[DEX][DEBUG-0x2AEA] *target_after=0x%08x\n", *(uint32_t *)target);
                }
                if (off == 0x4044)
                {
                    DEX_DBG("[DEX][DEBUG-0x4044] *target_after=0x%08x\n", *(uint32_t *)target);
                }

                DEX_DBG("[REL] REL   @%08x %08x -> %08x base=%08x\n",
                     (uint32_t)(uintptr_t)target, old, val, (uint32_t)image);

                break;
            }

            default:
            {
                DEX_DBG("[DEX] Unknown reloc type=%u off=0x%08x old=%08x\n", typ, off, old);

                if (import_ptrs)
                {
                    kfree(import_ptrs);
                }

                return -11;
            }
        }

        DEX_DBG("new=0x%08x\n", *(uint32_t *)target);
    }

    DEX_DBG("[DEX] Applied %u relocations successfully\n", hdr->reloc_table_count);

    if (import_ptrs)
    {
        kfree(import_ptrs);
    }

    // Post check for kernel addresses in ABS32 slots
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t typ = rel[i].type;

        if (typ == DEX_ABS32)
        {
            uint32_t val = *(uint32_t *)(image + off);

            if (!is_user_va(val))
            {
                DEX_DBG("[DEX] Post check ABS32 off=0x%08x -> kernel VA %08x\n", off, val);

                return -12;
            }
        }
    }

    return 0;
}

// Loader API
int dex_load(const void *file_data, size_t file_size, dex_executable_t *out)
{
    const dex_header_t *hdr;
    uint32_t text_sz;
    uint32_t ro_sz;
    uint32_t data_sz;
    uint32_t bss_sz;
    uint32_t entry_off;
    uint32_t max_end;
    uint32_t tmp;
    uint32_t total_sz;
    uint32_t resources_sz;
    uint32_t resources_off;
    uint8_t *image;
    const dex_import_t *imp;
    const dex_reloc_t *rel;
    const char *stab;

    if (!file_data || file_size < sizeof(dex_header_t) || !out)
    {
        return -1;
    }

    hdr = (const dex_header_t *)file_data;

    // Validate magic
    if (hdr->magic != DEX_MAGIC)
    {
        DEX_DBG("[DEX] Invalid DEX file\n");

        return -2;
    }
    if (hdr->version_major != DEX_VERSION_MAJOR || hdr->version_minor != DEX_VERSION_MINOR)
    {
        DEX_DBG("[DEX] Unsupported DEX version %u.%u (want %u.%u)\n",
                hdr->version_major, hdr->version_minor,
                DEX_VERSION_MAJOR, DEX_VERSION_MINOR);

        return -2;
    }

    /* Only mark the source buffer user-accessible if it actually lives in the user window. */
    if (is_user_va((uint32_t)file_data))
    {
        paging_update_flags((uint32_t)file_data,
                        PAGE_ALIGN_UP(file_size),
                        PAGE_PRESENT | PAGE_USER | PAGE_RW,
                        0);
    }

    // Validate section ranges inside file
    if (!in_range(hdr->text_offset,   hdr->text_size,   (uint32_t)file_size) ||
        !in_range(hdr->rodata_offset, hdr->rodata_size, (uint32_t)file_size) ||
        !in_range(hdr->data_offset,   hdr->data_size,   (uint32_t)file_size) ||
        !in_range(hdr->strtab_offset, hdr->strtab_size, (uint32_t)file_size) ||
        (hdr->resources_size &&
         !in_range(hdr->resources_offset, hdr->resources_size, (uint32_t)file_size)))
    {
        DEX_DBG("[DEX] Section offsets or sizes out of file\n");

        return -3;
    }

    // Validate entry inside .text
    if (!in_range(hdr->entry_offset, 1, (uint32_t)file_size) ||
        hdr->entry_offset < hdr->text_offset ||
        hdr->entry_offset >= hdr->text_offset + hdr->text_size)
    {
        DEX_DBG("[DEX] Entry offset out of range off=0x%x\n", (unsigned)hdr->entry_offset);

        return -3;
    }

    // Cache sizes and compute total image span
    text_sz      = hdr->text_size;
    ro_sz        = hdr->rodata_size;
    data_sz      = hdr->data_size;
    bss_sz       = hdr->bss_size;
    entry_off    = hdr->entry_offset;
    resources_sz = hdr->resources_size;
    resources_off = hdr->resources_offset;

    max_end = hdr->data_offset + data_sz + bss_sz;
    tmp = hdr->rodata_offset + ro_sz; if (tmp > max_end) max_end = tmp;
    tmp = hdr->text_offset   + text_sz; if (tmp > max_end) max_end = tmp;
    tmp = resources_off + resources_sz; if (tmp > max_end) max_end = tmp;
    tmp = entry_off + 16u; if (tmp > max_end) max_end = tmp;

    total_sz = PAGE_ALIGN_UP(max_end);

    // Allocate user image
    image = (uint8_t *)umalloc(total_sz);
    if (!image)
    {
        DEX_DBG("[DEX] Unable to allocate %u bytes for program\n", total_sz);

        return -4;
    }

    paging_reserve_range((uintptr_t)image, total_sz);
    // Map as user and ensure fresh view
    paging_set_user((uint32_t)image, total_sz);
    paging_update_flags(
        (uint32_t)image,
        total_sz,
        PAGE_PRESENT | PAGE_USER | PAGE_RW,
        0
    );
    paging_flush_tlb();
    /* Zero-fill full image so padding matches the zeroed layout emitted by the tooling. */
    memset(image, 0, total_sz);

    // Copy sections and clear bss into user image
    if (text_sz)
    {
        if (copy_to_user(image + hdr->text_offset,
                         (const uint8_t *)file_data + hdr->text_offset,
                         text_sz) != 0)
        {
            DEX_DBG("[DEX] Failed to copy .text to user image\n");
            ufree(image, total_sz);
            return -20;
        }
    }

    if (ro_sz)
    {
        if (copy_to_user(image + hdr->rodata_offset,
                         (const uint8_t *)file_data + hdr->rodata_offset,
                         ro_sz) != 0)
        {
            DEX_DBG("[DEX] Failed to copy .rodata to user image\n");
            ufree(image, total_sz);
            return -21;
        }
    }

    if (data_sz)
    {
        if (copy_to_user(image + hdr->data_offset,
                         (const uint8_t *)file_data + hdr->data_offset,
                         data_sz) != 0)
        {
            DEX_DBG("[DEX] Failed to copy .data to user image\n");
            ufree(image, total_sz);
            return -22;
        }
    }

    if (bss_sz)
    {
        // zero-init bss in userland
        memset(image + hdr->data_offset + data_sz, 0, bss_sz);
    }

    // Copy resources blob if present
    if (resources_sz)
    {
        if (copy_to_user(image + resources_off,
                         (const uint8_t *)file_data + resources_off,
                         resources_sz) != 0)
        {
            DEX_DBG("[DEX] Failed to copy resources blob to user image\n");
            ufree(image, total_sz);
            return -23;
        }
    }

    // Validate table windows
    if ((hdr->import_table_count &&
         !in_range(hdr->import_table_offset,
                   hdr->import_table_count * sizeof(dex_import_t),
                   (uint32_t)file_size)) ||
        (hdr->reloc_table_count  &&
         !in_range(hdr->reloc_table_offset,
                   hdr->reloc_table_count * sizeof(dex_reloc_t),
                   (uint32_t)file_size)) ||
        (hdr->strtab_size &&
         !in_range(hdr->strtab_offset,
                   hdr->strtab_size,
                   (uint32_t)file_size)))
    {
        DEX_DBG("[DEX] Table offsets or sizes out of file\n");
        ufree(image, total_sz);

        return -5;
    }

    // Table pointers
    imp  = (const dex_import_t *)((const uint8_t *)file_data + hdr->import_table_offset);
    rel  = (const dex_reloc_t  *)((const uint8_t *)file_data + hdr->reloc_table_offset);
    stab = (const char         *)((const uint8_t *)file_data + hdr->strtab_offset);

    DEX_DBG("=== DEX HEADER DEBUG ===\n");
    DEX_DBG("magic=0x%08x ver=%u.%u\n", hdr->magic, hdr->version_major, hdr->version_minor);
    DEX_DBG("entry_off=0x%08x\n", hdr->entry_offset);
    DEX_DBG(".text off=0x%08x sz=%u\n", hdr->text_offset, hdr->text_size);
    DEX_DBG(".ro   off=0x%08x sz=%u\n", hdr->rodata_offset, hdr->rodata_size);
    DEX_DBG(".data off=0x%08x sz=%u\n", hdr->data_offset, hdr->data_size);
    DEX_DBG(".bss  sz=%u\n", hdr->bss_size);
    DEX_DBG("import off=0x%08x cnt=%u\n", hdr->import_table_offset, hdr->import_table_count);
    DEX_DBG("reloc  off=0x%08x cnt=%u\n", hdr->reloc_table_offset,  hdr->reloc_table_count);
    DEX_DBG("rsrc  off=0x%08x sz=%u\n", hdr->resources_offset, hdr->resources_size);
    DEX_DBG("========================\n");

    // Apply relocations and imports
    if (relocate_image(hdr, imp, rel, stab, image, total_sz) != 0)
    {
        ufree(image, total_sz);

        return -6;
    }

    if (is_user_va((uint32_t)file_data))
    {
        paging_update_flags((uint32_t)file_data,
                        PAGE_ALIGN_UP(file_size),
                        0,
                        PAGE_USER);
    }

    // Make .text read execute
    if (text_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->text_offset),
                            PAGE_ALIGN_UP(text_sz),
                            0,
                            PAGE_RW);
    }

    // Ensure .data and .bss are writable
    if (data_sz || bss_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->data_offset),
                            PAGE_ALIGN_UP(data_sz + bss_sz),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW,
                            0);
    }

    // Reassert user mapping
    paging_set_user((uint32_t)image, total_sz);

    // Fill output
    out->image_base     = image;
    out->header         = (dex_header_t *)file_data;
    out->dex_entry      = (void (*)(void))((uint32_t)image + entry_off);
    out->image_size     = total_sz;
    out->resources_base = resources_sz ? (image + resources_off) : NULL;
    out->resources_size = resources_sz;

    DEX_DBG("[DEX] entry_va=0x%08x text_off=0x%08x text_sz=0x%08x\n",
           (uint32_t)out->dex_entry,
           hdr->text_offset,
           hdr->text_size);

    {
        const uint8_t *ep = (const uint8_t *)out->dex_entry;
        DEX_DBG("[DEX] entry_bytes:");
        for (int i = 0; i < 16; ++i)
        {
            DEX_DBG(" %02x", ep[i]);
        }
        DEX_DBG("\n");
    }

    if (g_debug_mask & DEBUG_AREA_EXL)
    {
        hexdump_bytes((void *)((uint32_t)image + entry_off), 64);
        DEX_DBG("[DEX] entry VA=%08x off=0x%x\n", (uint32_t)image + entry_off, entry_off);
    }

    return 0;
}

// Run DEX inside current process address space
int dex_run(const FileTable *ft, const char *path, int argc, char **argv)
{
    int file_index;
    const FileEntry *fe;
    uint8_t *buffer;
    dex_executable_t dex;
    int rc;
    uint32_t user_sp;
    uint32_t user_stack_base = 0;
    uint32_t user_stack_size = 0;
    uint8_t *stub;

    if (!ft || !path || !path[0])
    {

        return -1;
    }
    // Locate file
    file_index = find_entry_by_path(ft, path);
    if (file_index < 0)
    {
        DEX_DBG("[DEX] ERROR: File not found: %s\n", path);

        return -1;
    }

    fe = &ft->entries[file_index];
    if (!fe_file_size_bytes(fe))
    {
        DEX_DBG("[DEX] ERROR: Empty file: %s\n", path);

        return -2;
    }

    // Read whole file into temporary buffer
    buffer = (uint8_t *)kmalloc(fe_file_size_bytes(fe));

    if (!buffer)
    {
        DEX_DBG("[DEX] ERROR: Unable to allocate %u bytes\n", fe_file_size_bytes(fe));

        return -3;
    }

    if (read_file(ft, path, buffer) < 0)
    {
        DEX_DBG("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);

        return -4;
    }

    // Load image into user space
    rc = dex_load(buffer, fe_file_size_bytes(fe), &dex);
    if (rc != 0)
    {
        kfree(buffer);

        return rc;
    }

    // Build initial user stack
    user_sp = build_user_stack(path, argc, argv, &user_stack_base, &user_stack_size);
    if (!user_sp)
    {
        kfree(buffer);

        return -5;
    }

    // Build small exit stub that calls int 0x66
    stub = build_user_exit_stub((uint32_t)dex.dex_entry);
    if (!stub)
    {
        DEX_DBG("[DEX] ERROR: No stub found\n");
        kfree(buffer);

        return -6;
    }

    // Ensure stub is user present and writable while patching
    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    // Disable single-stepping for now to avoid debug state corruption
    // if (dex.header && dex.header->text_size > 0x10000)
    // {
    //     debug_request_single_step((uint32_t)stub, 512);
    // }

    DEX_DBG("[DEX] run: entry=%08x stub=%08x sp=%08x (no process)\n",
         (uint32_t)dex.dex_entry, (uint32_t)stub, user_sp);

    
    uintptr_t image_end = PAGE_ALIGN_UP((uintptr_t)dex.image_base + dex.image_size);
    const uintptr_t GUARD_GAP = 4 * 1024 * 1024;
    uintptr_t heap_base = image_end + GUARD_GAP;
    uintptr_t heap_size  = 64u << 20;  // 64 MB window

    DEX_DBG("[DEX] image_base=%p size=%u -> heap_base=%p window=%u\n",
           (void *)dex.image_base,
           (unsigned)dex.image_size,
           (void *)heap_base,
           (unsigned)heap_size);

    // Reserve demand-zero window and allocate initial heap
    paging_reserve_range(heap_base, heap_size);
    paging_set_user_heap(heap_base);

    // Commit initial heap pages (8MB)
    uintptr_t initial_heap = 8u << 20;
    if (initial_heap > heap_size) initial_heap = heap_size;
    uintptr_t initial_end = PAGE_ALIGN_UP(heap_base + initial_heap);

    // Pre-allocate some initial heap pages
    for (uintptr_t va = heap_base; va < initial_end && va < heap_base + (1u << 20); va += PAGE_SIZE_4KB)
    {
        uint32_t phys = alloc_phys_page();
        if (phys)
        {
            map_4kb_page_flags(va, phys, PAGE_PRESENT | PAGE_RW | PAGE_USER);
        }
    }

    // Initialize heap fields for the current process
    process_t *p = process_current();
    if (p)
    {
        process_set_user_stack(p, (uintptr_t)user_stack_base, (uintptr_t)user_sp, user_stack_size);

        uintptr_t base = PAGE_ALIGN_UP(heap_base);
        uintptr_t max  = base + heap_size;
        p->heap_base = base;
        p->heap_end  = initial_end;  // Set to initial committed size
        p->heap_max  = max;
        p->heap_alloc_next = base;   // Start allocations from heap base
        DEX_DBG("[DEX] exec: PID=%d heap_base=%p heap_end=%p heap_max=%p\n",
               p->pid, (void *)p->heap_base, (void *)p->heap_end, (void *)p->heap_max);
    }
    
    // Jump to user mode
    enter_user_mode((uint32_t)stub, user_sp);

    // Not reached in normal flow
    kfree(buffer);

    return 0;
}

int dex_spawn_process(const FileTable *ft, const char *path, int argc, char **argv,
                      const char *exec_dir, int set_cwd)
{
    int file_index;
    const FileEntry *fe;
    uint8_t *buffer;
    uint32_t cr3_parent;
    uint32_t cr3_child;
    dex_executable_t dex;
    int load_rc;
    uint32_t user_sp;
    uint32_t user_stack_base = 0;
    uint32_t user_stack_size = 0;
    uint32_t entry_va;
    uint8_t *stub;
    process_t *p;
    int pid;
    if (g_debug_mask & DEBUG_AREA_EXL)
    {
        DEX_DBG("dex_spawn_process heap_dump:\n");
        heap_dump();
    }

    if (!ft || !path || !path[0])
    {
        return -1;
    }

    file_index = find_entry_by_path(ft, path);
    if (file_index < 0)
    {
        DEX_DBG("[DEX] ERROR: File not found: %s\n", path);
        return -2;
    }

    fe = &ft->entries[file_index];
    if (!fe_file_size_bytes(fe))
    {
        DEX_DBG("[DEX] ERROR: Empty file: %s\n", path);
        return -3;
    }

    buffer = (uint8_t *)kmalloc(fe_file_size_bytes(fe));
    if (!buffer)
    {
        DEX_DBG("[DEX] ERROR: Unable to allocate %u bytes\n", fe_file_size_bytes(fe));
        return -4;
    }

    DEX_DBG("Trying to read_file(%p, %s, buffer)\n", (void*)ft, path);
    DEX_DBG("Buffer attempted to allocate: %d bytes\n", fe_file_size_bytes(fe));

    // Read into kernel buffer directly (no PAGE_USER hack)
    if (read_file(ft, path, buffer) < 0)
    {
        DEX_DBG("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);
        return -5;
    }

    cr3_parent = read_cr3_local();
    cr3_child  = paging_new_address_space();
    if (!cr3_child)
    {
        DEX_DBG("[DEX] ERROR: paging_new_address_space failed");
        kfree(buffer);
        return -6;
    }

    paging_switch_address_space(cr3_child);
    /* Invalidera EXL-cache för nuvarande CR3 innan vi river alla user-mappningar */
    exl_invalidate_for_cr3(read_cr3_local());
    paging_free_all_user();
    paging_user_heap_reset();

    load_rc = dex_load(buffer, fe_file_size_bytes(fe), &dex);
    if (load_rc != 0)
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        DEX_DBG("[DEX] ERROR: dex_load rc=%d\n", load_rc);
        return -7;
    }

    user_sp = build_user_stack(path, argc, argv, &user_stack_base, &user_stack_size);
    if (!user_sp || !is_user_va(user_sp))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        DEX_DBG("[DEX] ERROR: bad user_sp=%08x\n", user_sp);
        return -8;
    }

    entry_va = (uint32_t)dex.dex_entry;
    if (!is_user_va(entry_va))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        DEX_DBG("[DEX] ERROR: bad entry_va=%08x\n", entry_va);
        return -9;
    }

    stub = build_user_exit_stub(entry_va);
    if (!stub || !is_user_va((uint32_t)stub))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        DEX_DBG("[DEX] ERROR: stub build failed (%p)\n", stub);
        return -10;
    }

    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    // Disable single-stepping for now to avoid debug state corruption
    // if (dex.header && dex.header->text_size > 0x10000)
    // {
    //     debug_request_single_step((uint32_t)stub, 512);
    // }

    uintptr_t image_end = PAGE_ALIGN_UP((uintptr_t)dex.image_base + dex.image_size);
    const uintptr_t GUARD_GAP = 4 * 1024 * 1024;
    uintptr_t heap_base = image_end + GUARD_GAP;
    uintptr_t heap_size = 64u << 20;

    // Note: heap fields will be set on the process after it's created below
    DEX_DBG("[DEX] image_base=%p size=%u -> heap_base=%p window=%u\n",
           (void *)dex.image_base,
           (unsigned)dex.image_size,
           (void *)heap_base,
           (unsigned)heap_size);
    paging_reserve_range(heap_base, heap_size);
    paging_set_user_heap(heap_base);

    // Commit initial heap pages (8MB) while in child CR3
    uintptr_t initial_heap = 8u << 20;
    if (initial_heap > heap_size) initial_heap = heap_size;
    uintptr_t initial_end = PAGE_ALIGN_UP(heap_base + initial_heap);
    uintptr_t base = PAGE_ALIGN_UP(heap_base);
    uintptr_t max  = base + heap_size;
    paging_reserve_range(heap_base, initial_end - heap_base);

    // Pre-allocate some initial heap pages to avoid immediate demand faults
    for (uintptr_t va = heap_base; va < initial_end && va < heap_base + (1u << 20); va += PAGE_SIZE_4KB)
    {
        uint32_t phys = alloc_phys_page();
        if (phys)
        {
            map_4kb_page_flags(va, phys, PAGE_PRESENT | PAGE_RW | PAGE_USER);
        }
    }

    paging_switch_address_space(cr3_parent);

    // Clear single-step debug state before spawning new process
    debug_clear_single_step();

    p = process_create_user_with_cr3((uint32_t)stub,
                                     user_sp,
                                     cr3_child,
                                     65536,
                                     (uintptr_t)user_stack_base,
                                     (size_t)user_stack_size,
                                     base,
                                     initial_end,
                                     max);
    if (!p)
    {
        paging_switch_address_space(cr3_child);
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        DEX_DBG("[DEX] ERROR: process_create_user_with_as failed");
        return -12;
    }

    pid = process_pid(p);
    DEX_DBG("[DEX] spawn: pid=%d parent_cr3=%08x child_cr3=%08x\n",
         pid, cr3_parent, cr3_child);

    // Initialize heap fields for the new process with initial 8MB committed
    p->heap_base = base;
    p->heap_end  = initial_end;  // Set to initial committed size, not base
    p->heap_max  = max;
    p->heap_alloc_next = base;   // Start allocations from heap base
    paging_adopt_pending_reservations(cr3_child, p);

    DEX_DBG("[DEX] PID=%d heap_base=%p heap_end=%p heap_max=%p\n",
           pid, (void *)p->heap_base, (void *)p->heap_end, (void *)p->heap_max);

    // Stash embedded resources info on the process for later lookup
    p->resources_base = (uintptr_t)dex.resources_base;
    p->resources_size = dex.resources_size;

    // Also keep a kernel copy of the resources (if present) for cross-process queries
    if (dex.header && dex.header->resources_size &&
        dex.header->resources_offset + dex.header->resources_size <= fe_file_size_bytes(fe))
    {
        uint32_t rsz = dex.header->resources_size;
        uint8_t *kres = (uint8_t *)kmalloc(rsz);
        if (kres)
        {
            memcpy(kres, buffer + dex.header->resources_offset, rsz);
            p->resources_kernel = kres;
            p->resources_kernel_size = rsz;
        }
    }

    kfree(buffer);

    if (p)
    {
        const char *launch_dir = (exec_dir && exec_dir[0]) ? exec_dir : "/";
        process_set_exec_root(p, launch_dir);

        if (set_cwd)
        {
            uint32_t dir_id = vfs_root_id();

            if (vfs_resolve_dir(launch_dir, &dir_id) != 0)
            {
                dir_id = vfs_root_id();
                launch_dir = "/";
            }

            process_set_cwd(p, dir_id, launch_dir);
        }
    }
    return pid;
}// Spawn new process and load DEX into child address space
