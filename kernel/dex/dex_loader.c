#include "dex/dex.h"
#include "dex/exl.h"
#include "system/process.h"
#include "system/syscall.h"
#include "system/path.h"
#include "system/profiler.h"
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
#include "shared_kernel_data.h"

#define DEX_DBG(...) DDBG_IF(DEBUG_AREA_EXL, __VA_ARGS__)
#define DEX_REL_DEBUG 0

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
static inline int is_user_va(uint32_t address)
{
    return (address >= USER_MIN) && (address < USER_MAX);
}

static void dex_assign_process_resources(process_t *process,
                                         const dex_executable_t *loaded,
                                         const FileEntry *file_entry,
                                         const uint8_t *file_buffer,
                                         const char *exec_path)
{
    if (!process)
    {
        return;
    }

    if (process->resources_kernel)
    {
        kfree(process->resources_kernel);
        process->resources_kernel = NULL;
        process->resources_kernel_size = 0;
    }

    if (!loaded || !loaded->header || !file_entry || !file_buffer)
    {
        process_assign_name_from_resources(process, exec_path);
        return;
    }

    uint32_t file_size = fe_file_size_bytes(file_entry);
    uint32_t resource_size = loaded->header->resources_size;
    uint32_t resource_offset = loaded->header->resources_offset;

    if (resource_size && resource_offset + resource_size <= file_size)
    {
        uint8_t *resource_copy = (uint8_t *)kmalloc(resource_size);

        if (resource_copy)
        {
            memcpy(resource_copy,
                   file_buffer + resource_offset,
                   resource_size);
            process->resources_kernel = resource_copy;
            process->resources_kernel_size = resource_size;
        }
    }

    process_assign_name_from_resources(process, exec_path);
}

// Safe range check for file sections
static inline int in_range(uint32_t offset, uint32_t size, uint32_t maximum)
{
    if (size == 0)
    {
        return 1;
    }

    if (offset > maximum)
    {
        return 0;
    }

    if (maximum - offset < size)
    {
        return 0;
    }

    return 1;
}

// Check if pointer lies inside an image buffer
static int ptr_in_image(const void *pointer, const uint8_t *base, uint32_t size)
{
    uint32_t pointer_value = (uint32_t)pointer;
    uint32_t base_value = (uint32_t)base;

    return (pointer_value >= base_value) && (pointer_value < base_value + size);
}

// Exit stub and user stack
static uint8_t *build_user_exit_stub(uint32_t entry_address)
{
    // Build a deterministic user stub
    // - Set DS ES FS GS to 0x23
    // - Call entry_address
    // - Syscall exit 0 with int 0x66
    // - Loop if syscall returns
    uint8_t *stub = (uint8_t *)umalloc(64);

    if (!stub)
    {
        DEX_DBG("[DEX] Stub alloc failed\n");

        return NULL;
    }

    // Make sure the stub bytes are mapped as present user rw
    paging_update_flags((uint32_t)stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    uint8_t *write_pointer = stub;

    // mov ax, 0x23
    *write_pointer++ = 0x66; *write_pointer++ = 0xB8; *write_pointer++ = 0x23; *write_pointer++ = 0x00;

    // mov ds, ax
    *write_pointer++ = 0x8E; *write_pointer++ = 0xD8;

    // mov es, ax
    *write_pointer++ = 0x8E; *write_pointer++ = 0xC0;

    // mov fs, ax
    *write_pointer++ = 0x8E; *write_pointer++ = 0xE0;

    // mov gs, ax
    *write_pointer++ = 0x8E; *write_pointer++ = 0xE8;

    // call entry_address (rel32)
    *write_pointer++ = 0xE8;
    int32_t relative_offset = (int32_t)entry_address - (int32_t)((uint32_t)write_pointer + 4);
    memcpy(write_pointer, &relative_offset, 4);
    write_pointer += 4;

    // mov eax, 1  ; SYSTEM_EXIT
    *write_pointer++ = 0xB8;
    uint32_t system_exit_number = SYSTEM_EXIT;
    memcpy(write_pointer, &system_exit_number, 4);
    write_pointer += 4;

    // xor ebx, ebx ; exit code = 0
    *write_pointer++ = 0x31; *write_pointer++ = 0xDB;

    // int 0x66     ; SYSCALL_VECTOR
    *write_pointer++ = 0xCD; *write_pointer++ = 0x66;

    // ud2 (should never return)
    *write_pointer++ = 0x0F; *write_pointer++ = 0x0B;
    // jmp $        ; safety if syscall returns
    *write_pointer++ = 0xEB; *write_pointer++ = 0xFE;

    // Mark the actual written range as user
    paging_set_user((uint32_t)stub, (uint32_t)(write_pointer - stub));

    DEX_DBG("[DEX] stub@%p -> call %08x rel=%d\n", stub, entry_address, relative_offset);

    return stub;
}

static uint32_t build_user_stack(
    const char *program_path,
    int argument_count_in,
    char *const argument_values_in[],
    uint32_t *out_base_address,
    uint32_t *out_stack_size
)
{
    // Place the user stack high to avoid collisions
    // The user heap grows up from USER_MIN
    // Use a fixed 1 MB stack with a 4 KB guard page
    const uint32_t STACK_SIZE = 1024 * 1024;
    const uint32_t GUARD_SIZE = PAGE_SIZE_4KB;
    const uint32_t stack_limit = USER_MAX - GUARD_SIZE; // leave guard page unmapped
    uint32_t stack_top = stack_limit;
    uint32_t stack_base = stack_top - STACK_SIZE;

    // Keep clear of image and heap
    if (stack_base < USER_MIN + (1u << 20))
    {
        stack_base = USER_MIN + (1u << 20);
        stack_top = stack_base + STACK_SIZE;

        if (stack_top > stack_limit)
        {
            stack_top = stack_limit;

            if (stack_top < stack_base)
            {
                stack_top = stack_base;
            }
        }
    }

    if (out_base_address)
    {
        *out_base_address = stack_base;
    }

    if (out_stack_size)
    {
        *out_stack_size = STACK_SIZE;
    }

    // Reserve the entire stack range so demand faults can grow it
    paging_reserve_range(stack_base, STACK_SIZE);

    // Map the full stack range so argv strings are always accessible
    if (paging_map_user_range(stack_base, stack_top - stack_base, 1) != 0)
    {
        DEX_DBG("[DEX] Stack map failed base=%08x sz=%u\n", stack_base, (unsigned)(stack_top - stack_base));

        return 0;
    }

    memset((void *)stack_base, 0, stack_top - stack_base);

    int argument_count = (argument_count_in > 0 && argument_values_in) ? argument_count_in : 1;

    uint32_t *argument_pointers = (uint32_t *)kmalloc(sizeof(uint32_t) * (size_t)argument_count);

    if (!argument_pointers)
    {
        DEX_DBG("[DEX] argv_ptrs alloc failed\n");

        return 0;
    }

    uint32_t stack_pointer = stack_top;
    uint32_t base_address = stack_base;

    for (int argument_index = argument_count - 1; argument_index >= 0; --argument_index)
    {
        const char *source_string = (argument_count_in > 0 && argument_values_in)
                ? argument_values_in[argument_index]
                : (argument_index == 0 ? program_path : "");

        size_t length = strlen(source_string) + 1;

        if (stack_pointer < base_address + (uint32_t)length + 64)
        {
            DEX_DBG("[DEX] Stack overflow while building argv\n");
            kfree(argument_pointers);

            return 0;
        }

        stack_pointer -= (uint32_t)length;
        memcpy((void *)stack_pointer, source_string, length);
        argument_pointers[argument_index] = stack_pointer;
    }

    // Stack layout from stack_pointer (callee expects a call frame)
    // [SP] is argc
    // [SP+4] is argv pointer
    // [SP+8] is envp pointer
    // argv array follows (argc pointers + NULL)
    // envp array follows (NULL)
    // The stub does a call, so the return address is pushed above this frame
    // The stack pointer must stay 16 byte aligned

    // We need space for argc, argv ptr, envp ptr, argv array, envp NULL
    uint32_t needed_bytes = 12 + (uint32_t)((argument_count + 1) * sizeof(uint32_t)) + 4;
    if (stack_pointer < base_address + needed_bytes)
    {
        kfree(argument_pointers);

        return 0;
    }

    stack_pointer -= needed_bytes;

    // Ensure SP ends up 16 byte aligned
    stack_pointer &= ~0xF;

    uint32_t argv_ptr = stack_pointer + 12;
    uint32_t envp_ptr = argv_ptr + (uint32_t)((argument_count + 1) * sizeof(uint32_t));

    // Write argc, argv pointer, envp pointer
    *(uint32_t *)stack_pointer = (uint32_t)argument_count;
    *(uint32_t *)(stack_pointer + 4) = argv_ptr;
    *(uint32_t *)(stack_pointer + 8) = envp_ptr;

    // Write argv array
    for (int argument_index = 0; argument_index < argument_count; ++argument_index)
    {
        ((uint32_t *)argv_ptr)[argument_index] = argument_pointers[argument_index];
    }

    // Null terminator for argv
    ((uint32_t *)argv_ptr)[argument_count] = 0;

    // Null terminator for envp
    *(uint32_t *)envp_ptr = 0;

    kfree(argument_pointers);

    DEX_DBG("[DEX] stack built base=%08x top=%08x size=%u\n", base_address, stack_pointer, STACK_SIZE);
    DEX_DBG("[DEX] argc=%d argv_ptr=%08x envp_ptr=%08x\n", argument_count, argv_ptr, envp_ptr);
    DEX_DBG("[DEX] stack[0] (argc)=%u stack[4] (argv)=%08x stack[8] (envp)=%08x\n",
            *(uint32_t *)stack_pointer,
            *(uint32_t *)(stack_pointer + 4),
            *(uint32_t *)(stack_pointer + 8));
    for (int i = 0; i < argument_count && i < 4; ++i)
    {
        DEX_DBG("[DEX] argv[%d]=%08x -> \"%s\"\n", i, ((uint32_t *)argv_ptr)[i], (const char *)((uint32_t *)argv_ptr)[i]);
    }

    return stack_pointer;
}

// Imports and relocations
static int resolve_imports_user(
    const dex_header_t *header,
    const dex_import_t *imports,
    const char *string_table,
    void **output_pointers,
    uint8_t *image,
    uint32_t image_size
)
{
    uint32_t import_count = header->import_table_count;

    // Import table is already validated in dex_load
    // Only sanity check the count here
    if (import_count > 4096)
    {
        DEX_DBG("[DEX] Too many imports (%u)\n", import_count);
        
        return -1;
    }

    for (uint32_t index = 0; index < import_count; ++index)
    {
        const char *library_name = string_table + imports[index].exl_name_offset;
        const char *symbol_name = string_table + imports[index].symbol_name_offset;

        void *address = resolve_exl_symbol(library_name, symbol_name);

        if (!address)
        {
            const exl_t *library = load_exl(file_table, library_name);

            if (!library)
            {
                DEX_DBG("[DEX] Cannot load EXL %s\n", library_name);
                
                return -2;
            }

            address = resolve_exl_symbol(library_name, symbol_name);
        }

        if (!address)
        {
            DEX_DBG("[DEX] Unresolved import %s:%s\n", library_name, symbol_name);
            
            return -3;
        }

        // Forbid imports that point inside this image
        if (ptr_in_image(address, image, image_size))
        {
            DEX_DBG("[DEX] Import %s:%s resolves inside image %p\n", library_name, symbol_name, address);
            
            return -4;
        }

        // Force user VA
        if (!is_user_va((uint32_t)address))
        {
            DEX_DBG("[DEX] Import %s:%s -> kernel VA %p\n", library_name, symbol_name, address);
            
            return -5;
        }

        output_pointers[index] = address;
        DEX_DBG("[IMP] %s:%s -> %p\n", library_name, symbol_name, address);
    }

    return 0;
}

static int relocate_image(
    const dex_header_t *header,
    const dex_import_t *imports,
    const dex_reloc_t *relocations,
    const char *string_table,
    uint8_t *image,
    uint32_t image_size
)
{
    void **import_pointers = NULL;

    DEX_DBG("[DEX-RELOC-DEBUG] imports=%u relocs=%u\n", header->import_table_count, header->reloc_table_count);

    if (header->import_table_count > 4096)
    {
        DEX_DBG("[DEX] Too many imports (%u)\n", header->import_table_count);
        
        return -1;
    }

    if (header->import_table_count)
    {
        size_t bytes = (size_t)header->import_table_count * sizeof(void *);
        import_pointers = (void **)kmalloc(bytes);

        if (!import_pointers)
        {
            DEX_DBG("[DEX] kmalloc import_ptrs=%u failed\n", (unsigned)bytes);

            return -2;
        }

        memset(import_pointers, 0, bytes);
    }

    // Resolve imports against EXLs
    if (resolve_imports_user(header, imports, string_table, import_pointers, image, image_size) != 0)
    {
        if (import_pointers)
        {
            kfree(import_pointers);
        }

        return -3;
    }

    DEX_DBG("[RELOC] Applying %u relocations\n", header->reloc_table_count);

    // Apply relocations
    DEX_DBG("[DEX] Processing %u relocations from reloc table\n", header->reloc_table_count);

    for (uint32_t index = 0; index < header->reloc_table_count; ++index)
    {
        uint32_t offset = relocations[index].reloc_offset;
        uint32_t symbol_index = relocations[index].symbol_index;
        uint32_t reloc_type = relocations[index].type;

        if (offset > image_size || image_size - offset < 4)
        {
            DEX_DBG("[DEX] Reloc out of range off=0x%08x image=%u\n", offset, image_size);

            if (import_pointers)
            {
                kfree(import_pointers);
            }

            return -4;
        }

        uint8_t *target = image + offset;
        uint32_t old_value = *(uint32_t *)target;

        switch (reloc_type)
        {
            case DEX_ABS32:
            {
                if (symbol_index >= header->import_table_count)
                {
                    if (import_pointers)
                    {
                        kfree(import_pointers);
                    }

                    return -5;
                }

                *(uint32_t *)target = (uint32_t)import_pointers[symbol_index];

#if DEX_REL_DEBUG
                DEX_DBG("[REL] ABS32 @%08x %08x -> %08x S=%08x\n",
                     (uint32_t)(uintptr_t)target, old_value, *(uint32_t *)target,
                     (uint32_t)import_pointers[symbol_index]);
#endif

        
                break;
            }

            case DEX_PC32:
            {
                if (symbol_index >= header->import_table_count)
                {
                    DEX_DBG("[DEX][ERROR] PC32 reloc idx=%u >= import_count=%u at off=0x%08x\n",
                           symbol_index, header->import_table_count, offset);

                    if (import_pointers)
                    {
                        kfree(import_pointers);
                    }

                    return -6;
                }

                uint32_t symbol_address = (uint32_t)import_pointers[symbol_index];
                int32_t displacement = (int32_t)symbol_address - (int32_t)((uint32_t)(uintptr_t)target + 4);
                *(int32_t *)target = displacement;

                // Temporarily log all PC32 relocations
                static int pc32_count = 0;
                pc32_count++;

                const char *symbol_name = (symbol_index < header->import_table_count) ? 
                    (string_table + imports[symbol_index].symbol_name_offset) : "<bad-idx>";
                const char *library_name = (symbol_index < header->import_table_count) ? 
                    (string_table + imports[symbol_index].exl_name_offset) : "<bad-idx>";

                // Log putchar printf or first 100
                int is_putchar = (strcmp(symbol_name, "putchar") == 0);
                int is_printf = (strcmp(symbol_name, "printf") == 0);

                if (pc32_count <= 100 || is_putchar || is_printf ||
                    (offset >= header->entry_offset && offset < header->entry_offset + 0x200))
                {
                    DEX_DBG("[DEX][PC32 #%d] off=0x%08x S=%08x P=%08x disp=%08x old=%08x new=%08x sym=%s:%s\n",
                           pc32_count, offset, symbol_address, (uint32_t)(uintptr_t)target + 4,
                           (uint32_t)displacement, old_value, *(uint32_t *)target,
                           library_name, symbol_name);
                }

#if DEX_REL_DEBUG
                DEX_DBG("[REL] PC32  @%08x P=%08x S=%08x disp=%d old=%08x new=%08x\n",
                     (uint32_t)(uintptr_t)target,
                     (uint32_t)(uintptr_t)target + 4,
                     symbol_address, displacement, old_value, *(uint32_t *)target);
#endif

                break;
            }

            case DEX_RELATIVE:
            {
                uint32_t value = old_value + (uint32_t)image;

                // Debug track specific relocations
                if (offset == 0x2AEA)
                {
                    DEX_DBG("[DEX][DEBUG-0x2AEA] D_QuitNetGame reloc: off=0x%08x old=0x%08x base=0x%08x -> val=0x%08x\n",
                           offset, old_value, (uint32_t)image, value);
                    DEX_DBG("[DEX][DEBUG-0x2AEA] target=%p *target_before=0x%08x\n", target, *(uint32_t *)target);
                }

                if (offset == 0x4044)
                {
                    DEX_DBG("[DEX][DEBUG-0x4044] G_CheckDemoStatus reloc: off=0x%08x old=0x%08x base=0x%08x -> val=0x%08x\n", offset, old_value, (uint32_t)image, value);
                    DEX_DBG("[DEX][DEBUG-0x4044] target=%p *target_before=0x%08x\n", target, *(uint32_t *)target);
                }

                // Warn if old value seems too large
                if (old_value > 100 * 1024 * 1024)
                {
                    DEX_DBG("[DEX][WARN] Large RELATIVE old value: off=0x%08x old=0x%08x base=0x%08x -> val=0x%08x\n", offset, old_value, (uint32_t)image, value);
                }

                // Check if the result looks like x86 code
                uint8_t first_byte = value & 0xFF;
                uint8_t second_byte = (value >> 8) & 0xFF;

                if ((first_byte == 0x55 || first_byte == 0x53 || first_byte == 0x56 || first_byte == 0x57) &&
                    (second_byte == 0x89 || second_byte == 0x8B || second_byte == 0x83 ||
                     second_byte == 0x56 || second_byte == 0x53))
                {
                    DEX_DBG("[DEX][WARN] SUSPICIOUS RELOC: off=0x%08x old=0x%08x base=0x%08x -> val=0x%08x (looks like x86 code!)\n", offset, old_value, (uint32_t)image, value);
                }

                if (offset >= header->entry_offset && offset < header->entry_offset + 0x200)
                {
#if DEX_REL_DEBUG
                    DEX_DBG("[DEX][REL] off=0x%08x old=0x%08x base=0x%08x -> 0x%08x\n", offset, old_value, (uint32_t)image, value);
#endif
                }

                *(uint32_t *)target = value;

                if (offset == 0x2AEA)
                {
                    DEX_DBG("[DEX][DEBUG-0x2AEA] *target_after=0x%08x\n", *(uint32_t *)target);
                }

                if (offset == 0x4044)
                {
                    DEX_DBG("[DEX][DEBUG-0x4044] *target_after=0x%08x\n", *(uint32_t *)target);
                }

#if DEX_REL_DEBUG
                DEX_DBG("[REL] REL   @%08x %08x -> %08x base=%08x\n", (uint32_t)(uintptr_t)target, old_value, value, (uint32_t)image);
#endif

                break;
            }

            default:
            {
                DEX_DBG("[DEX] Unknown reloc type=%u off=0x%08x old=%08x\n", reloc_type, offset, old_value);

                if (import_pointers)
                {
                    kfree(import_pointers);
                }

                return -11;
            }
        }

        #if DEX_REL_DEBUG
        DEX_DBG("new=0x%08x\n", *(uint32_t *)target);
        #endif
    }

    DEX_DBG("[DEX] Applied %u relocations successfully\n", header->reloc_table_count);

    if (import_pointers)
    {
        kfree(import_pointers);
    }

    // Post check for kernel addresses in ABS32 slots
    for (uint32_t index = 0; index < header->reloc_table_count; ++index)
    {
        uint32_t offset = relocations[index].reloc_offset;
        uint32_t reloc_type = relocations[index].type;

        if (reloc_type == DEX_ABS32)
        {
            uint32_t value = *(uint32_t *)(image + offset);

            if (!is_user_va(value))
            {
                DEX_DBG("[DEX] Post check ABS32 off=0x%08x -> kernel VA %08x\n", offset, value);

                return -12;
            }
        }
    }

    return 0;
}

// Loader API
int dex_load(const void *file_data, size_t file_size, dex_executable_t *out_executable)
{
    const dex_header_t *header;
    uint32_t text_size;
    uint32_t rodata_size;
    uint32_t data_size;
    uint32_t bss_size;
    uint32_t entry_offset;
    uint32_t max_end_offset;
    uint32_t temp_end_offset;
    uint32_t total_size;
    uint32_t resources_size;
    uint32_t resources_offset;
    uint8_t *image;
    const dex_import_t *imports;
    const dex_reloc_t *relocations;
    const char *string_table;

    if (!file_data || file_size < sizeof(dex_header_t) || !out_executable)
    {
        return -1;
    }

    header = (const dex_header_t *)file_data;

    // Validate magic
    if (header->magic != DEX_MAGIC)
    {
        DEX_DBG("[DEX] Invalid DEX file\n");

        return -2;
    }

    if (header->version_major != DEX_VERSION_MAJOR || header->version_minor != DEX_VERSION_MINOR)
    {
        DEX_DBG("[DEX] Unsupported DEX version %u.%u (want %u.%u)\n",
                header->version_major, header->version_minor,
                DEX_VERSION_MAJOR, DEX_VERSION_MINOR);

        return -2;
    }

    if (is_user_va((uint32_t)file_data))
    {
        paging_update_flags((uint32_t)file_data, PAGE_ALIGN_UP(file_size), PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    }

    // Validate section ranges inside file
    if (!in_range(header->text_offset, header->text_size, (uint32_t)file_size) ||
        !in_range(header->rodata_offset, header->rodata_size, (uint32_t)file_size) ||
        !in_range(header->data_offset, header->data_size, (uint32_t)file_size) ||
        !in_range(header->strtab_offset, header->strtab_size, (uint32_t)file_size) ||
        (header->resources_size && 
         !in_range(header->resources_offset, header->resources_size, (uint32_t)file_size)))
    {
        DEX_DBG("[DEX] Section offsets or sizes out of file\n");

        return -3;
    }

    // Validate entry inside text
    if (!in_range(header->entry_offset, 1, (uint32_t)file_size) ||
        header->entry_offset < header->text_offset ||
        header->entry_offset >= header->text_offset + header->text_size)
    {
        DEX_DBG("[DEX] Entry offset out of range off=0x%x\n", (unsigned)header->entry_offset);

        return -3;
    }

    // Cache sizes and compute total image span
    text_size = header->text_size;
    rodata_size = header->rodata_size;
    data_size = header->data_size;
    bss_size = header->bss_size;
    entry_offset = header->entry_offset;
    resources_size = header->resources_size;
    resources_offset = header->resources_offset;

    max_end_offset = header->data_offset + data_size + bss_size;
    temp_end_offset = header->rodata_offset + rodata_size;

    if (temp_end_offset > max_end_offset)
    {
        max_end_offset = temp_end_offset;
    }

    temp_end_offset = header->text_offset + text_size;

    if (temp_end_offset > max_end_offset)
    {
        max_end_offset = temp_end_offset;
    }

    temp_end_offset = resources_offset + resources_size;

    if (temp_end_offset > max_end_offset)
    {
        max_end_offset = temp_end_offset;
    }

    temp_end_offset = entry_offset + 16u;

    if (temp_end_offset > max_end_offset)
    {
        max_end_offset = temp_end_offset;
    }

    total_size = PAGE_ALIGN_UP(max_end_offset);

    // Allocate user image
    image = (uint8_t *)umalloc(total_size);

    if (!image)
    {
        DEX_DBG("[DEX] Unable to allocate %u bytes for program\n", total_size);

        return -4;
    }

    paging_reserve_range((uintptr_t)image, total_size);
    
    // Map as user and ensure fresh view
    paging_set_user((uint32_t)image, total_size);
    paging_update_flags((uint32_t)image, total_size, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    paging_flush_tlb();

    // Zero fill full image so padding matches the tool output
    memset(image, 0, total_size);

    // Copy sections and clear bss into user image
    if (text_size)
    {
        if (copy_to_user(image + header->text_offset, (const uint8_t *)file_data + header->text_offset, text_size) != 0)
        {
            DEX_DBG("[DEX] Failed to copy .text to user image\n");
            ufree(image, total_size);

            return -20;
        }
    }

    if (rodata_size)
    {
        if (copy_to_user(image + header->rodata_offset,
                         (const uint8_t *)file_data + header->rodata_offset,
                         rodata_size) != 0)
        {
            DEX_DBG("[DEX] Failed to copy .rodata to user image\n");
            ufree(image, total_size);
            
            return -21;
        }
    }

    if (data_size)
    {
        if (copy_to_user(image + header->data_offset,
                         (const uint8_t *)file_data + header->data_offset,
                         data_size) != 0)
        {
            DEX_DBG("[DEX] Failed to copy .data to user image\n");
            ufree(image, total_size);
            
            return -22;
        }
    }

    if (bss_size)
    {
        // Zero fill bss in userland
        memset(image + header->data_offset + data_size, 0, bss_size);
    }

    // Copy resources blob if present
    if (resources_size)
    {
        if (copy_to_user(image + resources_offset,
                         (const uint8_t *)file_data + resources_offset,
                         resources_size) != 0)
        {
            DEX_DBG("[DEX] Failed to copy resources blob to user image\n");
            ufree(image, total_size);
            
            return -23;
        }
    }

    // Validate table windows
    if ((header->import_table_count &&
         !in_range(header->import_table_offset, header->import_table_count * sizeof(dex_import_t), (uint32_t)file_size)) ||
        (header->reloc_table_count  &&
         !in_range(header->reloc_table_offset, header->reloc_table_count * sizeof(dex_reloc_t), (uint32_t)file_size)) ||
        (header->strtab_size &&
         !in_range(header->strtab_offset, header->strtab_size, (uint32_t)file_size)))
    {
        DEX_DBG("[DEX] Table offsets or sizes out of file\n");
        ufree(image, total_size);

        return -5;
    }

    // Table pointers
    imports = (const dex_import_t *)((const uint8_t *)file_data + header->import_table_offset);
    relocations = (const dex_reloc_t *)((const uint8_t *)file_data + header->reloc_table_offset);
    string_table = (const char *)((const uint8_t *)file_data + header->strtab_offset);

    DEX_DBG("=== DEX HEADER DEBUG ===\n");
    DEX_DBG("magic=0x%08x ver=%u.%u\n", header->magic, header->version_major, header->version_minor);
    DEX_DBG("entry_off=0x%08x\n", header->entry_offset);
    DEX_DBG(".text off=0x%08x sz=%u\n", header->text_offset, header->text_size);
    DEX_DBG(".ro   off=0x%08x sz=%u\n", header->rodata_offset, header->rodata_size);
    DEX_DBG(".data off=0x%08x sz=%u\n", header->data_offset, header->data_size);
    DEX_DBG(".bss  sz=%u\n", header->bss_size);
    DEX_DBG("import off=0x%08x cnt=%u\n", header->import_table_offset, header->import_table_count);
    DEX_DBG("reloc  off=0x%08x cnt=%u\n", header->reloc_table_offset, header->reloc_table_count);
    DEX_DBG("rsrc  off=0x%08x sz=%u\n", header->resources_offset, header->resources_size);
    DEX_DBG("========================\n");

    // Apply relocations and imports
    if (relocate_image(header, imports, relocations, string_table, image, total_size) != 0)
    {
        ufree(image, total_size);

        return -6;
    }

    if (is_user_va((uint32_t)file_data))
    {
        paging_update_flags((uint32_t)file_data, PAGE_ALIGN_UP(file_size), 0, PAGE_USER);
    }

    // Make text read execute
    if (text_size)
    {
        paging_update_flags((uint32_t)(image + header->text_offset), PAGE_ALIGN_UP(text_size), 0,PAGE_RW);
    }

    // Ensure data and bss are writable
    if (data_size || bss_size)
    {
        paging_update_flags((uint32_t)(image + header->data_offset),
                            PAGE_ALIGN_UP(data_size + bss_size),
                            PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);
    }

    // Reassert user mapping
    paging_set_user((uint32_t)image, total_size);

    // Fill output
    out_executable->image_base = image;
    out_executable->header = (dex_header_t *)file_data;
    out_executable->dex_entry = (void (*)(void))((uint32_t)image + entry_offset);
    out_executable->image_size = total_size;
    out_executable->resources_base = resources_size ? (image + resources_offset) : NULL;
    out_executable->resources_size = resources_size;

    DEX_DBG("[DEX] entry_va=0x%08x text_off=0x%08x text_sz=0x%08x\n",
           (uint32_t)out_executable->dex_entry,
           header->text_offset,
           header->text_size);

    {
        const uint8_t *entry_bytes = (const uint8_t *)out_executable->dex_entry;
        DEX_DBG("[DEX] entry_bytes:");

        for (int byte_index = 0; byte_index < 16; ++byte_index)
        {
            DEX_DBG(" %02x", entry_bytes[byte_index]);
        }

        DEX_DBG("\n");
    }

    if (g_debug_mask & DEBUG_AREA_EXL)
    {
        hexdump_bytes((void *)((uint32_t)image + entry_offset), 64);
        DEX_DBG("[DEX] entry VA=%08x off=0x%x\n", (uint32_t)image + entry_offset, entry_offset);
    }

    return 0;
}

// Run DEX inside current process address space
int dex_run(const FileTable *file_table_ref, const char *path, int argument_count, char **argument_values)
{
    int file_index;
    const FileEntry *file_entry;
    uint8_t *file_buffer;
    dex_executable_t loaded_executable;
    int return_code;
    uint32_t user_stack_pointer;
    uint32_t user_stack_base_address = 0;
    uint32_t user_stack_size = 0;
    uint8_t *exit_stub;
    char **kargv = NULL;
    int owns_kargv = 0;

    if (!file_table_ref || !path || !path[0])
    {
        return -1;
    }

    if (argument_count > 0 && argument_values && is_user_va((uint32_t)argument_values))
    {
        if (copy_user_argv(argument_count, argument_values, &kargv) != 0)
        {

            return -1;
        }

        argument_values = kargv;
        owns_kargv = 1;
    }

    // Locate file
    file_index = find_entry_by_path(file_table_ref, path);

    if (file_index < 0)
    {
        DEX_DBG("[DEX] ERROR: File not found: %s\n", path);

        return -1;
    }

    file_entry = &file_table_ref->entries[file_index];

    if (!fe_file_size_bytes(file_entry))
    {
        DEX_DBG("[DEX] ERROR: Empty file: %s\n", path);

        return -2;
    }

    // Read whole file into temporary buffer
    file_buffer = (uint8_t *)kmalloc(fe_file_size_bytes(file_entry));

    if (!file_buffer)
    {
        DEX_DBG("[DEX] ERROR: Unable to allocate %u bytes\n", fe_file_size_bytes(file_entry));

        return -3;
    }

    if (read_file(file_table_ref, path, file_buffer) < 0)
    {
        DEX_DBG("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(file_buffer);

        if (owns_kargv)
        {
            free_kargv(kargv);
        }


        return -4;
    }

    // Load image into user space
    return_code = dex_load(file_buffer, fe_file_size_bytes(file_entry), &loaded_executable);

    if (return_code != 0)
    {
        kfree(file_buffer);

        if (owns_kargv)
        {
            free_kargv(kargv);
        }


        return return_code;
    }

    // Build initial user stack
    user_stack_pointer = build_user_stack(path, argument_count, argument_values, &user_stack_base_address, &user_stack_size);

    if (!user_stack_pointer)
    {
        kfree(file_buffer);

        if (owns_kargv)
        {
            free_kargv(kargv);
        }


        return -5;
    }

    // Build small exit stub that calls int 0x66
    exit_stub = build_user_exit_stub((uint32_t)loaded_executable.dex_entry);

    if (!exit_stub)
    {
        DEX_DBG("[DEX] ERROR: No stub found\n");
        kfree(file_buffer);

        if (owns_kargv)
        {
            free_kargv(kargv);
        }


        return -6;
    }

    if (owns_kargv)
    {
        free_kargv(kargv);
    }

    // Ensure stub is user present and writable while patching
    paging_update_flags((uint32_t)exit_stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    DEX_DBG("[DEX] run: entry=%08x stub=%08x sp=%08x (no process)\n", (uint32_t)loaded_executable.dex_entry, (uint32_t)exit_stub, user_stack_pointer);

    uintptr_t image_end = PAGE_ALIGN_UP((uintptr_t)loaded_executable.image_base + loaded_executable.image_size);
    const uintptr_t GUARD_GAP = 4 * 1024 * 1024;
    uintptr_t heap_base = image_end + GUARD_GAP;
    uintptr_t heap_size = 64u << 20; // 64 MB window

    DEX_DBG("[DEX] image_base=%p size=%u -> heap_base=%p window=%u\n",
           (void *)loaded_executable.image_base,
           (unsigned)loaded_executable.image_size,
           (void *)heap_base,
           (unsigned)heap_size);

    // Reserve demand-zero window and allocate initial heap
    paging_reserve_range(heap_base, heap_size);
    paging_set_user_heap(heap_base);

    // Commit initial heap pages
    uintptr_t initial_heap = 8u << 20;

    if (initial_heap > heap_size)
    {
        initial_heap = heap_size;
    }

    uintptr_t initial_end = PAGE_ALIGN_UP(heap_base + initial_heap);

    // Pre-allocate some initial heap pages
    for (uintptr_t virtual_address = heap_base;
         virtual_address < initial_end && virtual_address < heap_base + (1u << 20);
         virtual_address += PAGE_SIZE_4KB)
    {
        uint32_t physical_address = alloc_phys_page();

        if (physical_address)
        {
            map_4kb_page_flags(virtual_address, physical_address, PAGE_PRESENT | PAGE_RW | PAGE_USER);
        }
    }

    // Initialize heap fields for the current process
    process_t *process = process_current();

    if (process)
    {
        process_set_user_stack(process, (uintptr_t)user_stack_base_address,
                               (uintptr_t)user_stack_pointer, user_stack_size);

        uintptr_t heap_base_aligned = PAGE_ALIGN_UP(heap_base);
        uintptr_t heap_max_address = heap_base_aligned + heap_size;
        process->heap_base = heap_base_aligned;
        process->heap_end = initial_end;
        process->heap_max = heap_max_address;
        process->heap_alloc_next = heap_base_aligned;
        DEX_DBG("[DEX] exec: PID=%d heap_base=%p heap_end=%p heap_max=%p\n",
               process->pid, (void *)process->heap_base, (void *)process->heap_end,
               (void *)process->heap_max);
    }

    if (process)
    {
        dex_assign_process_resources(process, &loaded_executable, file_entry, file_buffer, path);
    }

    // Load symbols for profiler
    profiler_load_symbols(file_buffer, fe_file_size_bytes(file_entry),
                          (uint32_t)loaded_executable.image_base, NULL);

    // Jump to user mode
    enter_user_mode((uint32_t)exit_stub, user_stack_pointer);

    // Not reached in normal flow
    kfree(file_buffer);

    return 0;
}

int dex_spawn_process(const FileTable *file_table_ref, const char *path,
                      int argument_count, char **argument_values,
                      const char *exec_dir, int set_cwd)
{
    int file_index;
    const FileEntry *file_entry;
    uint8_t *file_buffer;
    uint32_t parent_cr3;
    uint32_t child_cr3;
    dex_executable_t loaded_executable;
    int load_return_code;
    uint32_t user_stack_pointer;
    uint32_t user_stack_base_address = 0;
    uint32_t user_stack_size = 0;
    uint32_t entry_address;
    uint8_t *exit_stub;
    process_t *process;
    int process_id;

    if (g_debug_mask & DEBUG_AREA_EXL)
    {
        DEX_DBG("dex_spawn_process heap_dump:\n");
        heap_dump();
    }

    if (!file_table_ref || !path || !path[0])
    {
        return -1;
    }

    file_index = find_entry_by_path(file_table_ref, path);

    if (file_index < 0)
    {
        DEX_DBG("[DEX] ERROR: File not found: %s\n", path);
        
        return -2;
    }

    file_entry = &file_table_ref->entries[file_index];

    if (!fe_file_size_bytes(file_entry))
    {
        DEX_DBG("[DEX] ERROR: Empty file: %s\n", path);
        
        return -3;
    }

    file_buffer = (uint8_t *)kmalloc(fe_file_size_bytes(file_entry));

    if (!file_buffer)
    {
        DEX_DBG("[DEX] ERROR: Unable to allocate %u bytes\n", fe_file_size_bytes(file_entry));
        
        return -4;
    }

    DEX_DBG("Trying to read_file(%p, %s, buffer)\n", (void*)file_table_ref, path);
    DEX_DBG("Buffer attempted to allocate: %d bytes\n", fe_file_size_bytes(file_entry));

    // Read into kernel buffer directly
    if (read_file(file_table_ref, path, file_buffer) < 0)
    {
        DEX_DBG("[DEX] ERROR: Failed to read file: %s\n", path);
        kfree(file_buffer);
        
        return -5;
    }

    parent_cr3 = read_cr3_local();
    child_cr3 = paging_new_address_space();

    if (!child_cr3)
    {
        DEX_DBG("[DEX] ERROR: paging_new_address_space failed");
        kfree(file_buffer);
        
        return -6;
    }

    paging_switch_address_space(child_cr3);
    
    // Clear EXL cache for this CR3 before removing user mappings
    exl_invalidate_for_cr3(read_cr3_local());
    
    paging_free_all_user();
    paging_user_heap_reset();

    load_return_code = dex_load(file_buffer, fe_file_size_bytes(file_entry), &loaded_executable);

    if (load_return_code != 0)
    {
        paging_switch_address_space(parent_cr3);
        paging_destroy_address_space(child_cr3);
        kfree(file_buffer);
        DEX_DBG("[DEX] ERROR: dex_load rc=%d\n", load_return_code);
    
        return -7;
    }

    user_stack_pointer = build_user_stack(path, argument_count, argument_values, &user_stack_base_address, &user_stack_size);

    if (!user_stack_pointer || !is_user_va(user_stack_pointer))
    {
        paging_switch_address_space(parent_cr3);
        paging_destroy_address_space(child_cr3);
        kfree(file_buffer);
        DEX_DBG("[DEX] ERROR: bad user_sp=%08x\n", user_stack_pointer);
        
        return -8;
    }

    entry_address = (uint32_t)loaded_executable.dex_entry;

    if (!is_user_va(entry_address))
    {
        paging_switch_address_space(parent_cr3);
        paging_destroy_address_space(child_cr3);
        kfree(file_buffer);
        DEX_DBG("[DEX] ERROR: bad entry_va=%08x\n", entry_address);
        
        return -9;
    }

    exit_stub = build_user_exit_stub(entry_address);

    if (!exit_stub || !is_user_va((uint32_t)exit_stub))
    {
        paging_switch_address_space(parent_cr3);
        paging_destroy_address_space(child_cr3);
        kfree(file_buffer);
        DEX_DBG("[DEX] ERROR: stub build failed (%p)\n", exit_stub);
        
        return -10;
    }

    paging_update_flags((uint32_t)exit_stub, 64, PAGE_PRESENT | PAGE_USER | PAGE_RW, 0);

    uintptr_t image_end = PAGE_ALIGN_UP((uintptr_t)loaded_executable.image_base + loaded_executable.image_size);
    const uintptr_t GUARD_GAP = 4 * 1024 * 1024;
    uintptr_t heap_base = image_end + GUARD_GAP;
    uintptr_t heap_size = 64u << 20;

    // Note: heap fields will be set on the process after it's created below
    DEX_DBG("[DEX] image_base=%p size=%u -> heap_base=%p window=%u\n",
           (void *)loaded_executable.image_base,
           (unsigned)loaded_executable.image_size,
           (void *)heap_base,
           (unsigned)heap_size);
    paging_reserve_range(heap_base, heap_size);
    paging_set_user_heap(heap_base);

    // Commit initial heap pages while in child CR3
    uintptr_t initial_heap = 8u << 20;

    if (initial_heap > heap_size)
    {
        initial_heap = heap_size;
    }

    uintptr_t initial_end = PAGE_ALIGN_UP(heap_base + initial_heap);
    uintptr_t heap_base_aligned = PAGE_ALIGN_UP(heap_base);
    uintptr_t heap_max_address = heap_base_aligned + heap_size;
    paging_reserve_range(heap_base, initial_end - heap_base);

    // Pre-allocate some initial heap pages to avoid immediate demand faults
    for (uintptr_t virtual_address = heap_base;
         virtual_address < initial_end && virtual_address < heap_base + (1u << 20);
         virtual_address += PAGE_SIZE_4KB)
    {
        uint32_t physical_address = alloc_phys_page();

        if (physical_address)
        {
            map_4kb_page_flags(virtual_address, physical_address, PAGE_PRESENT | PAGE_RW | PAGE_USER);
        }
    }

    paging_switch_address_space(parent_cr3);

    // Clear single-step debug state before spawning new process
    debug_clear_single_step();

    process = process_create_user_with_cr3((uint32_t)exit_stub,
                                           user_stack_pointer,
                                           child_cr3,
                                           65536,
                                           (uintptr_t)user_stack_base_address,
                                           (size_t)user_stack_size,
                                           heap_base_aligned,
                                           initial_end,
                                           heap_max_address);

    if (!process)
    {
        paging_switch_address_space(child_cr3);
        paging_switch_address_space(parent_cr3);
        paging_destroy_address_space(child_cr3);
        kfree(file_buffer);
        DEX_DBG("[DEX] ERROR: process_create_user_with_as failed");
        
        return -12;
    }

    process_id = process_pid(process);
    DEX_DBG("[DEX] spawn: pid=%d parent_cr3=%08x child_cr3=%08x\n", process_id, parent_cr3, child_cr3);

    // Initialize heap fields for the new process
    process->heap_base = heap_base_aligned;
    process->heap_end = initial_end;
    process->heap_max = heap_max_address;
    process->heap_alloc_next = heap_base_aligned;
    paging_adopt_pending_reservations(child_cr3, process);

    // Map shared kernel data page so userspace can read time without syscall
    if (shared_kernel_data_map_to_process(child_cr3) != 0)
    {
        DEX_DBG("[DEX] Warning: failed to map shared kernel data\n");
    }

    DEX_DBG("[DEX] PID=%d heap_base=%p heap_end=%p heap_max=%p\n",
           process_id, (void *)process->heap_base, (void *)process->heap_end, (void *)process->heap_max);

    // Stash embedded resources info on the process for later lookup
    process->resources_base = (uintptr_t)loaded_executable.resources_base;
    process->resources_size = loaded_executable.resources_size;

    // Keep a kernel copy of the resources for cross process queries
    dex_assign_process_resources(process, &loaded_executable, file_entry, file_buffer, path);

    // Load symbols for profiler
    profiler_load_symbols(file_buffer, fe_file_size_bytes(file_entry),
                          (uint32_t)loaded_executable.image_base, NULL);

    kfree(file_buffer);

    if (process)
    {
        const char *launch_dir = (exec_dir && exec_dir[0]) ? exec_dir : "/";
        process_set_exec_root(process, launch_dir);

        if (set_cwd)
        {
            uint32_t dir_id = vfs_root_id();

            if (vfs_resolve_dir(launch_dir, &dir_id) != 0)
            {
                dir_id = vfs_root_id();
                launch_dir = "/";
            }

            process_set_cwd(process, dir_id, launch_dir);
        }
    }

    return process_id;
}
