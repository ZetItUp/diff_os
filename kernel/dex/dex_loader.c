#include "dex/dex.h"
#include "dex/exl.h"
#include "system/process.h"
#include "system/syscall.h"
#include "diff.h"
#include "string.h"
#include "stdint.h"
#include "stddef.h"
#include "stdio.h"
#include "console.h"
#include "paging.h"
#include "heap.h"
#include "system/usercopy.h"

//#define IGNORE_DEBUG

extern void enter_user_mode(uint32_t entry, uint32_t user_stack_top);
extern FileTable *file_table;

// Paging and process helpers
extern uint32_t paging_new_address_space(void);
extern void paging_switch_address_space(uint32_t cr3);
extern void paging_destroy_address_space(uint32_t cr3);

#ifndef PAGE_ALIGN_UP
#define PAGE_ALIGN_UP(x) (((uint32_t)(x) + 0xFFFu) & ~0xFFFu)
#endif

#if defined(DIFF_DEBUG) && !defined(IGNORE_DEBUG)
#define DDBG(...) printf(__VA_ARGS__)
#else
#define DDBG(...) do {} while (0)
#endif

// Check if address is in user range
static inline int is_user_va(uint32_t a)
{
    return (a >= USER_MIN) && (a < USER_MAX);
}

static void commit_initial_heap(uintptr_t base, uintptr_t size, uintptr_t want)
{
    if (want > size)
    {
        want = size;
    }

    system_brk_set((void *)(base + want));
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

static void dex_debug_dump_imports(const dex_header_t *h,
                                   const uint8_t *file_data)
{
    if (!h->import_table_count) { printf("[DEX] no imports\n"); return; }

    const dex_import_t *imp = (const dex_import_t*)(file_data + h->import_table_offset);
    const char *strtab = (const char*)(file_data + h->strtab_offset);

    for (uint32_t i = 0; i < h->import_table_count; ++i) {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;
        printf("[DEX][imp] %u: %s:%s\n", i, exl, sym);
    }
}

// Check if pointer lies inside an image buffer
static int ptr_in_image(const void *p, const uint8_t *base, uint32_t size)
{
    uint32_t v = (uint32_t)p;
    uint32_t b = (uint32_t)base;

    return (v >= b) && (v < b + size);
}

// ==========================
// Exit stub placed in user memory
// Behavior:
//   reads [argc][argv][envp] from current ESP,
//   pushes envp, argv, argc (cdecl),
//   calls entry (rel32),
//   then does SYSTEM_EXIT on return.
// ==========================
static uint8_t *build_user_exit_stub(uint32_t entry_va)
{
    uint8_t tmpl[64];
    uint8_t *p = tmpl;

    // mov ax, 0x23 (user data selector)
    *p++ = 0x66; *p++ = 0xB8; *p++ = 0x23; *p++ = 0x00;
    // mov ds, ax
    *p++ = 0x8E; *p++ = 0xD8;
    // mov es, ax
    *p++ = 0x8E; *p++ = 0xC0;
    // mov fs, ax
    *p++ = 0x8E; *p++ = 0xE0;
    // mov gs, ax
    *p++ = 0x8E; *p++ = 0xE8;

    // Push envp, argv, argc from current ESP frame:
    // Note: After each push, ESP decreases by 4, so the next source stays at +8.
    // push dword [esp+8] ; envp
    *p++ = 0xFF; *p++ = 0x74; *p++ = 0x24; *p++ = 0x08;
    // push dword [esp+8] ; argv
    *p++ = 0xFF; *p++ = 0x74; *p++ = 0x24; *p++ = 0x08;
    // push dword [esp+8] ; argc
    *p++ = 0xFF; *p++ = 0x74; *p++ = 0x24; *p++ = 0x08;

    // call rel32 entry_va (disp patched later)
    *p++ = 0xE8;
    uint8_t *rel32_at = p;
    uint32_t zero = 0;
    memcpy(p, &zero, 4);
    p += 4;

    // mov eax, SYSTEM_EXIT
    *p++ = 0xB8;
    uint32_t sys_exit = SYSTEM_EXIT;
    memcpy(p, &sys_exit, 4);
    p += 4;

    // xor ebx, ebx   ; status = 0
    *p++ = 0x31; *p++ = 0xDB;

    // int 0x66       ; do exit
    *p++ = 0xCD; *p++ = 0x66;

    // ud2 ; jmp $ as safety if we ever continue
    *p++ = 0x0F; *p++ = 0x0B;
    *p++ = 0xEB; *p++ = 0xFE;

    size_t stub_sz = (size_t)(p - tmpl);

    // Allocate user memory RW while building
    uint8_t *stub = (uint8_t *)umalloc(PAGE_ALIGN_UP(stub_sz));
    if (!stub)
    {
        printf("[DEX] Stub alloc failed\n");

        return NULL;
    }

    paging_update_flags((uint32_t)stub, PAGE_ALIGN_UP(stub_sz),
                        PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    // Copy template into user
    if (copy_to_user(stub, tmpl, stub_sz) != 0)
    {
        printf("[DEX] copy stub -> user failed\n");
        ufree(stub, PAGE_ALIGN_UP(stub_sz));

        return NULL;
    }

    // Patch call disp32 in user
    uint32_t rel_off_in_stub = (uint32_t)(rel32_at - tmpl);
    uint32_t P = (uint32_t)stub + rel_off_in_stub;        // Address of disp32 field in user
    uint32_t disp = (int32_t)entry_va - (int32_t)(P + 4); // S - (P+4)

    if (copy_to_user((void *)P, &disp, sizeof(disp)) != 0)
    {
        printf("[DEX] patch rel32 failed\n");
        ufree(stub, PAGE_ALIGN_UP(stub_sz));

        return NULL;
    }

    // Flip to RX (no write) for the stub page(s)
    paging_update_flags((uint32_t)stub, PAGE_ALIGN_UP(stub_sz),
                        PAGE_PRESENT | PAGE_USER, PAGE_RW);

    DDBG("[DEX] stub@%p -> call %08x rel=%d\n", stub, entry_va, (int)disp);

    return stub;
}

// ==========================
// Build initial user stack
// Layout on entry ESP: [argc][argv][envp]
// No dummy return address is pushed here.
// ==========================
static uint32_t build_user_stack(
    const char *prog_path,
    int argc_in,
    char *const argv_in[]
)
{
    const uint32_t STK_SZ  = 64 * 1024;          // User stack size
    const uint32_t GUARD   = PAGE_SIZE;          // One guard page (non-present)
    const uint32_t TOTAL   = STK_SZ + GUARD;     // Total reservation

    uint8_t *stk = (uint8_t *)umalloc(TOTAL);
    if (!stk)
    {
        printf("[DEX] Stack alloc failed %u bytes\n", TOTAL);

        return 0;
    }

    // Reserve and protect: guard page NP, rest P|U|RW during build
    paging_reserve_range((uintptr_t)stk, TOTAL);
    paging_update_flags((uint32_t)stk, GUARD, 0, PAGE_PRESENT | PAGE_USER | PAGE_RW);

    // Synthesize argv
    int argc = argc_in;
    if (argc < 0)
    {
        argc = 0;
    }

    // Prepare an argv list; if caller passed NULL, fabricate one with program name
    const char *fallback[2] = { 0 };
    if (!argv_in || argc == 0)
    {
        fallback[0] = (prog_path && *prog_path) ? prog_path : "program";
        argv_in = (char *const *)fallback;
        argc = 1;
    }

    // Allocate temporary kernel array for argv pointers (to final user VAs)
    uint32_t *argv_ptrs = (uint32_t *)kmalloc(sizeof(uint32_t) * (size_t)argc);
    if (!argv_ptrs)
    {
        printf("[DEX] argv_ptrs alloc failed\n");
        ufree(stk, TOTAL);

        return 0;
    }

    uint32_t base_map = (uint32_t)stk + GUARD;   // First mapped user page
    uint32_t sp       = base_map + STK_SZ;       // Grow down

    // Copy argv strings top-down so we can take their user VAs
    for (int i = argc - 1; i >= 0; i--)
    {
        const char *src = argv_in[i] ? argv_in[i] : "";
        size_t slen = strlen(src) + 1;

        sp -= (uint32_t)slen;

        // Keep stack 16-byte aligned regularly
        sp &= ~0xFu;

        if (copy_to_user((void *)sp, src, slen) != 0)
        {
            printf("[DEX] copy argv[%d] failed\n", i);
            kfree(argv_ptrs);
            ufree(stk, TOTAL);

            return 0;
        }

        argv_ptrs[i] = sp;
    }

    // Build minimal envp: NULL-terminated array of pointers (no variables)
// We intentionally provide an empty environment: envp points to an array that contains only a NULL pointer.
sp &= ~0xFu;

sp -= (uint32_t)sizeof(uint32_t);
uint32_t env_null = 0;
if (copy_to_user((void *)sp, &env_null, sizeof(uint32_t)) != 0)
{
    printf("[DEX] write envp NULL failed\n");
    kfree(argv_ptrs);
    ufree(stk, TOTAL);

    return 0;
}

uint32_t envp_array = sp;

    // Build argv[] array (argc entries + terminating NULL)
    sp &= ~0xFu;

    // One extra NULL sentinel
    sp -= (uint32_t)sizeof(uint32_t);
    uint32_t zero = 0;
    if (copy_to_user((void *)sp, &zero, sizeof(uint32_t)) != 0)
    {
        printf("[DEX] write argv NULL failed\n");
        kfree(argv_ptrs);
        ufree(stk, TOTAL);

        return 0;
    }

    // Write argv pointers in ascending index order (argv[0]..argv[argc-1])
    uint32_t argv_array = sp;
    for (int i = 0; i < argc; i++)
    {
        sp -= (uint32_t)sizeof(uint32_t);
        if (copy_to_user((void *)sp, &argv_ptrs[i], sizeof(uint32_t)) != 0)
        {
            printf("[DEX] write argv[%d] ptr failed\n", i);
            kfree(argv_ptrs);
            ufree(stk, TOTAL);

            return 0;
        }
    }

    // At this point, [esp] should be argc, [esp+4] argv, [esp+8] envp
    sp &= ~0xFu;

    uint32_t frame_words[3];
    frame_words[0] = (uint32_t)argc;
    frame_words[1] = (uint32_t)sp;               // This will become argv after we push it below
    frame_words[2] = envp_array;

    // But we just placed argv elements downward; the current top is the last pointer we wrote.
    // The start of the argv array is at the highest address of that block.
    // We computed argv_array earlier to point at the terminating NULL; adjust:
    // After pushing argc/argv/env below, the stub will load them from [esp], [esp+4], [esp+8].
    // Fix frame_words[1] to the real argv base (start of the pointers array).
    // The pointers we wrote were pushed in a loop, so argv base is (sp + sizeof(uint32_t) * (size_t)0)
    // However we wrote pointers by decreasing sp; argv base should be the lowest address among them.
    // Easiest: track argv base separately. We recorded 'argv_array' before pushing pointers; that location
    // currently holds the terminating NULL. The first real argv pointer is just below it.
    // So the real argv base is (argv_array - argc * 4).
    frame_words[1] = argv_array - (uint32_t)(argc * sizeof(uint32_t));

    sp -= sizeof(frame_words);
    if (copy_to_user((void *)sp, frame_words, sizeof(frame_words)) != 0)
    {
        printf("[DEX] argc/argv/env frame write failed\n");
        kfree(argv_ptrs);
        ufree(stk, TOTAL);

        return 0;
    }

    // Lock final permissions: user stack should be P|U|RW (guard is already NP)
    paging_update_flags(base_map, STK_SZ, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    kfree(argv_ptrs);
    DDBG("[DEX] stack built base=%08x top=%08x size=%u (+guard)\n", base_map, sp, STK_SZ);

    return sp;
}

// ==========================
// Imports + relocations
// ==========================
static int resolve_imports_user(
    const dex_header_t *hdr,
    const dex_import_t *imp,
    const char *strtab,
    void **out_ptrs,
    uint8_t *image,
    uint32_t image_sz
)
{
    if (!hdr || !imp || !strtab || !out_ptrs) return -1;
    if (hdr->import_table_count > 4096) return -1;

    for (uint32_t i = 0; i < hdr->import_table_count; ++i)
    {
        const char *exl = strtab + imp[i].exl_name_offset;
        const char *sym = strtab + imp[i].symbol_name_offset;

        if (!exl || !*exl || !sym || !*sym) {
            printf("[DEX] bad import strings @%u\n", i);
            return -2;
        }

        void *addr = resolve_exl_symbol(exl, sym);
        if (!addr) {
            /* försök lazy-load av EXL, sen slå upp igen */
            const exl_t *mod = load_exl(file_table, exl);
            if (!mod) {
                printf("[DEX] cannot load dependency: %s\n", exl);
                return -3;
            }
            (void)mod;
            addr = resolve_exl_symbol(exl, sym);
        }

        if (!addr) {
            printf("[DEX] unresolved import %s:%s\n", exl, sym);
            return -4;
        }

        /* ska INTE peka in i den egna mappade bilden */
        uintptr_t a = (uintptr_t)addr;
        if (a >= (uintptr_t)image && a < ((uintptr_t)image + image_sz)) {
            printf("[DEX] Import %s:%s resolves inside image (%p)\n", exl, sym, addr);
            return -5;
        }

        /* imports måste vara user-VA enligt din design */
        if (!is_user_addr((uint32_t)a)) {
            printf("[DEX] Import %s:%s -> kernel VA %p\n", exl, sym, addr);
            return -6;
        }

        out_ptrs[i] = addr;
        printf("[DEX][imp] %u: %s:%s -> %p\n", i, exl, sym, addr);
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

    if (hdr->import_table_count > 4096)
    {
        printf("[DEX] Too many imports (%u)\n", hdr->import_table_count);
        return -1;
    }

    if (hdr->import_table_count)
    {
        size_t bytes = (size_t)hdr->import_table_count * sizeof(void *);
        import_ptrs = (void **)kmalloc(bytes);

        if (!import_ptrs)
        {
            printf("[DEX] kmalloc import_ptrs=%u failed\n", (unsigned)bytes);
            return -2;
        }

        memset(import_ptrs, 0, bytes);
    }

    // Resolve imports against EXLs
    if (resolve_imports_user(hdr, imp, strtab, import_ptrs, image, image_sz) != 0)
    {
        if (import_ptrs) kfree(import_ptrs);
        return -3;
    }

    DDBG("[RELOC] Applying %u relocations\n", hdr->reloc_table_count);

    // Apply relocations
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t idx = rel[i].symbol_index;
        uint32_t typ = rel[i].type;

        if (off > image_sz || image_sz - off < 4)
        {
            printf("[DEX] Reloc out of range off=0x%08x image=%u\n", off, image_sz);
            if (import_ptrs) kfree(import_ptrs);
            return -4;
        }

        uint8_t *target = image + off;
        uint32_t old = 0;
        if (copy_from_user(&old, target, 4) != 0)
        {
            if (import_ptrs) kfree(import_ptrs);
            return -4;
        }

        switch (typ)
        {
            case DEX_ABS32:
            {
                if (idx >= hdr->import_table_count)
                {
                    if (import_ptrs) kfree(import_ptrs);
                    return -5;
                }
                uint32_t W = (uint32_t)import_ptrs[idx];
                if (copy_to_user(target, &W, 4) != 0)
                {
                    if (import_ptrs) kfree(import_ptrs);
                    return -5;
                }

                DDBG("[REL] ABS32 @%08x %08x -> %08x\n",
                     (uint32_t)(uintptr_t)target, old, W);
                break;
            }

            case DEX_PC32:
            {
                if (idx >= hdr->import_table_count)
                {
                    if (import_ptrs) kfree(import_ptrs);
                    return -6;
                }

                uint32_t S = (uint32_t)import_ptrs[idx];
                int32_t disp = (int32_t)S - (int32_t)((uint32_t)(uintptr_t)target + 4);
                if (copy_to_user(target, &disp, 4) != 0)
                {
                    if (import_ptrs) kfree(import_ptrs);
                    return -6;
                }

                DDBG("[REL] PC32  @%08x P=%08x S=%08x disp=%d old=%08x\n",
                     (uint32_t)(uintptr_t)target,
                     (uint32_t)(uintptr_t)target + 4,
                     S, disp, old);

                break;
            }

            case DEX_RELATIVE:
            {
                uint32_t val = old + (uint32_t)image;
                if (copy_to_user(target, &val, 4) != 0)
                {
                    if (import_ptrs) kfree(import_ptrs);
                    return -7;
                }

                DDBG("[REL] REL   @%08x %08x -> %08x base=%08x\n",
                     (uint32_t)(uintptr_t)target, old, val, (uint32_t)image);

                break;
            }

            default:
            {
                printf("[DEX] Unknown reloc type=%u off=0x%08x old=%08x\n", typ, off, old);
                if (import_ptrs) kfree(import_ptrs);
                return -11;
            }
        }
    }

    if (import_ptrs)
    {
        kfree(import_ptrs);
    }

    // Post: ABS32 får inte peka på kernel
    for (uint32_t i = 0; i < hdr->reloc_table_count; ++i)
    {
        uint32_t off = rel[i].reloc_offset;
        uint32_t typ = rel[i].type;

        if (typ == DEX_ABS32)
        {
            uint32_t val = 0;
            if (copy_from_user(&val, image + off, 4) != 0)
            {
                return -12;
            }

            if (!is_user_va(val))
            {
                printf("[DEX] Post check ABS32 off=0x%08x -> kernel VA %08x\n", off, val);
                return -12;
            }
        }
    }

    // Safety: leta kvarvarande "CALL -4" (E8 FC FF FF FF) i .text
    if (hdr->text_size)
    {
        size_t scan = hdr->text_size;
        const uint8_t *utext = image + hdr->text_offset;

        // kopiera till kernel-buffert för skanningen
        uint8_t *tmp = (uint8_t *)kmalloc(scan ? scan : 1);
        if (!tmp) return -13;

        if (copy_from_user(tmp, utext, scan) != 0)
        {
            kfree(tmp);
            return -13;
        }

        for (size_t i = 0; i + 5 <= scan; ++i)
        {
            if (tmp[i] == 0xE8 &&
                tmp[i+1] == 0xFC && tmp[i+2] == 0xFF &&
                tmp[i+3] == 0xFF && tmp[i+4] == 0xFF)
            {
                printf("[DEX] FATAL: unresolved CALL -4 at .text+%p (VA=%08x)\n",
                       i, (uint32_t)(uintptr_t)(utext + i));
                kfree(tmp);
                return -14;
            }
        }

        kfree(tmp);
    }

    return 0;
}

// ==========================
// Loader API
// ==========================
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
        printf("[DEX] Invalid DEX file\n");
        return -2;
    }

    // Validate section ranges inside file
    if (!in_range(hdr->text_offset,   hdr->text_size,   (uint32_t)file_size) ||
        !in_range(hdr->rodata_offset, hdr->rodata_size, (uint32_t)file_size) ||
        !in_range(hdr->data_offset,   hdr->data_size,   (uint32_t)file_size) ||
        !in_range(hdr->strtab_offset, hdr->strtab_size, (uint32_t)file_size))
    {
        printf("[DEX] Section offsets or sizes out of file\n");
        return -3;
    }

    uint32_t entry_offset = hdr->entry_offset;
    // Validate/fix entry inside .text
    if (entry_offset == 0)
    {
        // Fallback: starta vid .text-början om entry saknas
        printf("[DEX][WARN] entry==0 -> using .text start 0x%08x\n", (unsigned)hdr->text_offset);
        entry_offset = hdr->text_offset;
    }

    if (entry_offset < hdr->text_offset ||
        entry_offset >= hdr->text_offset + hdr->text_size)
    {
        printf("[DEX] Entry offset out of range off=0x%x\n", (unsigned)entry_offset);
        return -3;
    }

    // Cache sizes and compute total image span
    text_sz   = hdr->text_size;
    ro_sz     = hdr->rodata_size;
    data_sz   = hdr->data_size;
    bss_sz    = hdr->bss_size;
    entry_off = entry_offset;

    max_end = hdr->data_offset + data_sz + bss_sz;
    tmp = hdr->rodata_offset + ro_sz;   if (tmp > max_end) max_end = tmp;
    tmp = hdr->text_offset   + text_sz; if (tmp > max_end) max_end = tmp;
    tmp = entry_off + 16u;              if (tmp > max_end) max_end = tmp;

    total_sz = PAGE_ALIGN_UP(max_end);

    // Allocate user image
    image = (uint8_t *)umalloc(total_sz);
    if (!image)
    {
        printf("[DEX] Unable to allocate %u bytes for program\n", total_sz);
        return -4;
    }

    paging_reserve_range((uintptr_t)image, total_sz);
    // Map as user and ensure fresh view
    paging_set_user((uint32_t)image, total_sz);
    paging_update_flags((uint32_t)image, total_sz,
                        PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    paging_flush_tlb();

    // Copy sections and clear bss into user image
    if (text_sz)
    {
        if (copy_to_user(image + hdr->text_offset,
                         (const uint8_t *)file_data + hdr->text_offset,
                         text_sz) != 0)
        {
            printf("[DEX] Failed to copy .text to user image\n");
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
            printf("[DEX] Failed to copy .rodata to user image\n");
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
            printf("[DEX] Failed to copy .data to user image\n");
            ufree(image, total_sz);
            return -22;
        }
    }

    if (bss_sz)
    {
        if (zero_user(image + hdr->data_offset + data_sz, bss_sz) != 0)
        {
            printf("[DEX] Failed to zero .bss in user image\n");
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
        printf("[DEX] Table offsets or sizes out of file\n");
        ufree(image, total_sz);
        return -5;
    }

    // Table pointers (i fil-bufferten, kernel)
    imp  = (const dex_import_t *)((const uint8_t *)file_data + hdr->import_table_offset);
    rel  = (const dex_reloc_t  *)((const uint8_t *)file_data + hdr->reloc_table_offset);
    stab = (const char         *)((const uint8_t *)file_data + hdr->strtab_offset);

#ifdef DIFF_DEBUG
    DDBG("=== DEX HEADER DEBUG ===\n");
    DDBG("magic=0x%08x ver=%u.%u\n", hdr->magic, hdr->version_major, hdr->version_minor);
    DDBG("entry_off=0x%08x\n", hdr->entry_offset);
    DDBG(".text off=0x%08x sz=%u\n", hdr->text_offset, hdr->text_size);
    DDBG(".ro   off=0x%08x sz=%u\n", hdr->rodata_offset, hdr->rodata_size);
    DDBG(".data off=0x%08x sz=%u\n", hdr->data_offset, hdr->data_size);
    DDBG(".bss  sz=%u\n", hdr->bss_size);
    DDBG("import off=0x%08x cnt=%u\n", hdr->import_table_offset, hdr->import_table_count);
    DDBG("reloc  off=0x%08x cnt=%u\n", hdr->reloc_table_offset,  hdr->reloc_table_count);
    DDBG("========================\n");
#endif

    // Apply relocations and imports
    if (relocate_image(hdr, imp, rel, stab, image, total_sz) != 0)
    {
        ufree(image, total_sz);
        return -6;
    }

    // Gör .text RX (ta bort RW)
    if (text_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->text_offset),
                            PAGE_ALIGN_UP(text_sz),
                            0, PAGE_RW);
    }

    // .data + .bss ska vara RW|user|present
    if (data_sz || bss_sz)
    {
        paging_update_flags((uint32_t)(image + hdr->data_offset),
                            PAGE_ALIGN_UP(data_sz + bss_sz),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW,
                            0);
    }

    dex_debug_dump_imports(hdr, file_data);

    // Reassert user mapping
    paging_set_user((uint32_t)image, total_sz);

    // Fill output
    out->image_base = image;
    out->header     = (dex_header_t *)0; // header i fil-buffert, inte persistent – lämna NULL
    out->dex_entry  = (void (*)(void))((uint32_t)image + entry_off);
    out->image_size = total_sz;

#ifdef DIFF_DEBUG
    hexdump_bytes((void *)((uint32_t)image + entry_off), 64);
    DDBG("[DEX] entry VA=%08x off=0x%x\n", (uint32_t)image + entry_off, entry_off);
#endif

    return 0;
}

// ==========================
// Run DEX inside current process address space
// ==========================
int dex_run(const FileTable *ft, const char *path, int argc, char **argv)
{
    int file_index;
    const FileEntry *fe;
    uint8_t *buffer;
    dex_executable_t dex;
    int rc;
    uint32_t user_sp;
    uint8_t *stub;

    if (!ft || !path || !path[0])
    {
        return -1;
    }
    // Locate file
    file_index = find_entry_by_path(ft, path);
    if (file_index < 0)
    {
        printf("[DEX] ERROR: File not found: %s\n", path);
        return -1;
    }

    fe = &ft->entries[file_index];
    if (!fe->file_size_bytes)
    {
        printf("[DEX] ERROR: Empty file: %s\n", path);
        return -2;
    }

    // Read whole file into temporary kernel buffer
    buffer = (uint8_t *)kmalloc(fe->file_size_bytes);
    if (!buffer)
    {
        printf("[DEX] ERROR: Unable to allocate %u bytes\n", fe->file_size_bytes);
        return -3;
    }

    if (read_file(ft, path, buffer) < 0)
    {
        printf("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);
        return -4;
    }

    // Load image into user space
    rc = dex_load(buffer, fe->file_size_bytes, &dex);
    if (rc != 0)
    {
        kfree(buffer);
        return rc;
    }

    // Build initial user stack (med guard page)
    user_sp = build_user_stack(path, argc, argv);
    if (!user_sp)
    {
        kfree(buffer);
        return -5;
    }

    // Build exit stub
    stub = build_user_exit_stub((uint32_t)dex.dex_entry);
    if (!stub)
    {
        printf("[DEX] ERROR: No stub built\n");
        kfree(buffer);
        return -6;
    }

    // Gör stub RW under ev. patchning (redan klar, men ok)
    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    DDBG("[DEX] run: entry=%08x stub=%08x sp=%08x (no process)\n",
         (uint32_t)dex.dex_entry, (uint32_t)stub, user_sp);

    // Init heap-fönster ovanför stub
    uintptr_t heap_base = (((uintptr_t)stub + 0xFFFu) & ~0xFFFu);  // Page-align above stub
    uintptr_t heap_size  = 64u << 20;                              // 64 MB window

    system_brk_init_window(heap_base, heap_size);
    paging_reserve_range(heap_base, heap_size);
    commit_initial_heap(heap_base, heap_size, 8u << 20);

    // Jump to user mode
    enter_user_mode((uint32_t)stub, user_sp);

    // Not reached in normal flow
    kfree(buffer);
    return 0;
}

// ==========================
// Spawn new process and load DEX into child address space
// ==========================
int dex_spawn_process(const FileTable *ft, const char *path, int argc, char **argv)
{
    int file_index;
    const FileEntry *fe;
    uint8_t *buffer;
    uint32_t cr3_parent;
    uint32_t cr3_child;
    dex_executable_t dex;
    int load_rc;
    uint32_t user_sp;
    uint32_t entry_va;
    uint8_t *stub;
    process_t *p;
    int pid;

#ifdef DIFF_DEBUG
    printf("dex_spawn_process heap_dump:\n");
    heap_dump();
#endif

    if (!ft || !path || !path[0])
    {
        return -1;
    }

    file_index = find_entry_by_path(ft, path);
    if (file_index < 0)
    {
        printf("[DEX] ERROR: File not found: %s\n", path);
        return -2;
    }

    fe = &ft->entries[file_index];
    if (!fe->file_size_bytes)
    {
        printf("[DEX] ERROR: Empty file: %s\n", path);
        return -3;
    }

    buffer = (uint8_t *)kmalloc(fe->file_size_bytes);
    if (!buffer)
    {
        printf("[DEX] ERROR: Unable to allocate %u bytes\n", fe->file_size_bytes);
        return -4;
    }

#ifdef DIFF_DEBUG
    printf("Trying to read_file(%p, %s, buffer)\n", ft, path);
    printf("Buffer attempted to allocate: %d bytes\n", fe->file_size_bytes);
#endif

    // Read into kernel buffer directly
    if (read_file(ft, path, buffer) < 0)
    {
        printf("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(buffer);
        return -5;
    }

    cr3_parent = read_cr3_local();
    cr3_child  = paging_new_address_space();
    if (!cr3_child)
    {
        printf("[DEX] ERROR: paging_new_address_space failed");
        kfree(buffer);
        return -6;
    }

    paging_switch_address_space(cr3_child);

    /* Invalidera EXL-cache för nuvarande CR3 innan vi river alla user-mappningar */
    exl_invalidate_for_cr3(read_cr3_local());

    paging_free_all_user();
    paging_user_heap_reset();

    load_rc = dex_load(buffer, fe->file_size_bytes, &dex);
    if (load_rc != 0)
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: dex_load rc=%d\n", load_rc);
        return -7;
    }

    user_sp = build_user_stack(path, argc, argv);
    if (!user_sp || !is_user_va(user_sp))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: bad user_sp=%08x\n", user_sp);
        return -8;
    }

    entry_va = (uint32_t)dex.dex_entry;
    if (!is_user_va(entry_va))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: bad entry_va=%08x\n", entry_va);
        return -9;
    }

    stub = build_user_exit_stub(entry_va);
    if (!stub || !is_user_va((uint32_t)stub))
    {
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: stub build failed (%p)\n", stub);
        return -10;
    }

    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    uintptr_t heap_base = (((uintptr_t)stub + 0xFFFu) & ~0xFFFu);
    uintptr_t heap_size = 64u << 20;

    system_brk_init_window(heap_base, heap_size);
    paging_reserve_range(heap_base, heap_size);
    commit_initial_heap(heap_base, heap_size, 8u << 20);

    paging_switch_address_space(cr3_parent);

    p = process_create_user_with_cr3((uint32_t)stub, user_sp, cr3_child, 16384);
    if (!p)
    {
        paging_switch_address_space(cr3_child);
        paging_switch_address_space(cr3_parent);
        paging_destroy_address_space(cr3_child);
        kfree(buffer);
        printf("[DEX] ERROR: process_create_user_with_as failed");
        return -12;
    }

    pid = process_pid(p);
    DDBG("[DEX] spawn: pid=%d parent_cr3=%08x child_cr3=%08x\n",
         pid, cr3_parent, cr3_child);

    kfree(buffer);
    return pid;
}


