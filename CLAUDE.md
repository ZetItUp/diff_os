# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Overview

DiffOS is a custom x86 operating system built from scratch with its own bootloader, filesystem, executable format, and driver system. This is a learning project exploring OS development fundamentals.

Key features:
- 2-stage bootloader written in x86 assembly
- Custom filesystem called "Diff" with superblock, file tables, and sector bitmaps
- Custom executable format **DEX** (DiffOS Executable) for programs
- Custom library format **EXL** (Executable Library) for shared code
- Driver file format (**DDF**) with module loader
- Basic syscall interface for userspace programs
- Threading and process management with scheduler
- Memory management with paging and heap allocation

## Build System

### Requirements
- **i386-elf-gcc** cross-compiler (32-bit x86 target)
- **i386-elf-ld**, **i386-elf-objcopy**, **i386-elf-ar** from binutils
- **nasm** assembler
- **python3** for build tools
- **qemu-system-i386** for testing

### Common Commands

```bash
# Full build and run in QEMU
make clean && make run

# Build everything (kernel, tools, drivers, programs)
make all

# Build only specific components
make tools          # Build Python/C utilities in tools/
make drivers        # Build .ddf drivers
make diffc          # Build DiffC standard library (diffc.exl)
make progs          # Build userspace programs to .dex format

# Clean builds
make clean          # Clean kernel and tools
make allclean       # Clean kernel, tools, programs, and DiffC

# Debug with GDB
make debug          # Starts QEMU with -s -S and launches GDB
```

### Debug Mode
Set `DEBUG=1` (default) to enable `-DDIFF_DEBUG` for verbose kernel logging:
```bash
make DEBUG=1 run
```

Logs are written to:
- `serial.log` - Serial port output
- `debugcon.log` - Debug console output (port 0xe9)
- `qemu.log` - QEMU trace logs

## Architecture

### Boot Process
1. **boot/boot.asm** - Stage 1: 512-byte MBR bootloader, loads Stage 2
2. **boot/boot_stage2.asm** - Stage 2: Sets up protected mode, loads kernel.bin
3. **kernel/kernel.c** - Kernel entry point, initializes subsystems

### Filesystem (Diff)
- Implementation: `kernel/fs/diff.c`, header: `kernel/includes/diff.h`
- On-disk structure: Superblock + File table + Sector/file bitmaps
- File entries contain: entry_id, parent_id, type (file/dir), filename, start_sector, sector_count, size
- Syscalls: open, close, read, seek, stat, fstat (no write support yet)
- Directory operations: opendir, readdir, closedir
- File descriptors stored in per-process handle table

### Executable Format (DEX)
- Header: `kernel/includes/dex/dex.h`
- Loader: `kernel/dex/dex_loader.c`
- Magic: `0x58454400` ("DEX\0")
- Sections: .text, .rodata, .data, .bss
- Import table: references to EXL symbols (external functions/data)
- Relocation table: fixups for absolute/relative addresses
- Symbol table: exported symbols from this executable
- Entry point offset from image base

DEX files are loaded into userspace with:
- Image base typically around 0x400000
- Stack at ~0x7FFEF000 (4MB size + 256KB guard)
- Parameters struct (dex_params_t) passed at stack top with argc/argv/envp

### Library Format (EXL)
- Header: `kernel/includes/dex/exl.h`
- Loader: `kernel/dex/exl_loader.c`
- EXL files are DEX executables that export symbols
- Loaded per-CR3 (per process address space) and cached
- Symbol resolution is "relaxed": ignores leading `_` and stdcall `@N` suffixes
- Standard library: **DiffC** (`DiffC/` directory) compiled to `diffc.exl`

### DiffC Standard Library
- Build: `make diffc` or within DiffC directory
- Source: `DiffC/source/*.c`
- Headers: `DiffC/include/`
- Output: `diffc.exl` installed to `image/system/exls/`
- Provides: malloc, free, printf, string functions, getline, file I/O wrappers
- Built with `-ffreestanding -fno-builtin` (no libc)

### Userspace Programs
- Source: `programs/*/` (each subdirectory is a program)
- Build: `make progs` (builds all programs to .dex format)
- Programs reference symbols in `diffc.exl` for standard library functions
- Entry point: `int main(int argc, char **argv)`
- Default shell: **dterm** (`programs/dterm/dterm.c`)

### Drivers (DDF format)
- Source: `drivers/*/`
- Module loader: `kernel/drivers/module_loader.c`
- Drivers have init/cleanup hooks called by the kernel

### Tools
Python tools in `tools/`:
- **elf2dex.py** - Convert ELF to DEX executable format
- **elf2exl.py** - Convert ELF to EXL library format
- **elf2dex_common.py** - Shared conversion logic
- **mkdiffos** (C) - Creates bootable Diff filesystem image
- **fsreader** (C) - Reads Diff filesystem images
- **dex_verify.py**, **verify_ddf.py** - Format validators
- **lsexl.py** - List symbols in EXL files

### Memory Management
- Paging: `kernel/memory/paging.c` - Page directory/table management, user/kernel separation
- Heap: `kernel/memory/heap.c` - Kernel heap allocator (kmalloc/kfree)
- User copy: `kernel/memory/usercopy.c` - Safe copy between kernel and userspace
- Demand paging: Page faults trigger on-demand stack/heap allocation

### Process/Thread Model
- Processes: `kernel/system/process.c`, header: `kernel/includes/system/process.h`
- Threads: `kernel/system/threads.c`, header: `kernel/includes/system/threads.h`
- Scheduler: `kernel/system/scheduler.c` - Preemptive round-robin scheduling
- Each process has its own CR3 (page directory)
- Processes can spawn child processes via `SYSTEM_PROCESS_SPAWN` syscall
- Parent can wait for child with `SYSTEM_WAIT_PID`

### Syscall Interface
- Header: `kernel/includes/system/syscall.h`
- Implementation: `kernel/system/syscall.c`, `syscall_file.c`, `syscall_dir.c`
- Entry: `system_call_stub` in `kernel/arch/x86_64/cpu/usermode.asm`
- Syscall numbers defined as `SYSTEM_*` enums (e.g., SYSTEM_PUTCHAR, SYSTEM_FILE_OPEN)
- Arguments passed via registers, dispatched in `system_call_dispatch()`

Common syscalls:
- 0: EXIT - Terminate process
- 1: PUTCHAR - Print character
- 8-12: FILE operations (open, close, seek, read, write)
- 13: EXEC_DEX - Execute a DEX file
- 14-16: DIR operations (opendir, readdir, closedir)
- 19-22: THREAD operations (yield, sleep, get_id)
- 23-24: PROCESS operations (spawn, wait_pid)
- 29: BREAK - Set program break (for sbrk/malloc)

### Interrupt Handling
- IDT: `kernel/arch/x86_64/cpu/idt.c`
- IRQ: `kernel/arch/x86_64/cpu/irq.c`
- ISR stubs: `kernel/arch/x86_64/cpu/isr_stub.asm`
- PIC: `kernel/arch/x86_64/cpu/pic.c` - 8259 PIC configuration
- Timer: `kernel/arch/x86_64/cpu/timer.c` - PIT for scheduling ticks

### Console/Terminal
- Console: `kernel/console.c` - Text mode output with scrolling, color support
- VBE text: `kernel/library/graphics/vbe_text.c` - VESA text rendering
- Serial: `kernel/serial.c` - Serial port for debug output

### Driver Interfaces
- Headers: `kernel/interfaces/intf_*.c`
- Provides abstraction for: kernel, keyboard, memory, VBE, console
- Drivers can call kernel functions via these interfaces

## Development Workflow

### Adding a New Syscall
1. Add enum constant to `kernel/includes/system/syscall.h`
2. Implement handler function in `kernel/system/syscall*.c`
3. Add case to `system_call_dispatch()` in `syscall.c`
4. Add wrapper function to DiffC library if needed (`DiffC/source/syscall.c`)

### Creating a New Program
1. Create directory under `programs/your_program/`
2. Add `main.c` or `your_program.c` with `int main(int argc, char **argv)`
3. Include DiffC headers: `#include <stdio.h>`, `#include <syscall.h>`, etc.
4. Build with `make progs` - automatically converts to .dex
5. Program installed to `image/programs/your_program/your_program.dex`

### Adding Kernel Features
1. Modify kernel source in `kernel/`
2. If adding new files, update KERNEL_SRC in root Makefile
3. Rebuild with `make clean && make`
4. Test with `make run`

### Debugging Programs
- Use `printf()` in userspace (goes to console)
- Check `serial.log` for kernel debug messages (if DEBUG=1)
- Use `make debug` to attach GDB to QEMU (see `1kernel.gdb` for script)

## Important Technical Details

### Path Resolution
- Paths are absolute from root: `/system/kernel.bin`, `/programs/ls/ls.dex`
- `resolve_exec_path()` in `syscall.c` searches:
  1. Exact path if contains '/'
  2. `/programs/<name>/<name>.dex`
  3. Current directory `./<name>.dex`

### Symbol Linking
- EXL symbols matched with relaxed comparison: `_foo` matches `foo`, `bar@4` matches `bar`
- Import resolution happens at DEX load time
- Relocations applied to fix up references to imported/local symbols
- If symbol not found, load fails with error message

### Address Space Layout
- Kernel: High memory (mapped in all processes)
- User image: ~0x400000 - varies by program size
- User heap: Grows up from end of .bss via `brk()` syscall
- User stack: ~0x7FFEF000, grows down (4MB max)
- Kmap window: 0xD0000000+ (kernel temporary mappings)

### Concurrency
- Spinlocks used for critical sections (file_table, sector_bitmap, etc.)
- IRQ-safe spinlocks (`spinlock_irqsave/restore`) for structures accessed in interrupts
- Preemptive multitasking on timer interrupt
- Context switches save/restore all registers via TSS and stack

### Filesystem Limitations
- Read-only for user programs (no create/write/delete yet)
- Max 256 files (MAX_FILES)
- Max 64 open file handles per system (FILESYSTEM_MAX_OPEN)
- 512-byte sectors
- No subdirectory creation support yet

## Testing

Run the OS in QEMU:
```bash
make run
```

Available commands in dterm shell:
- `cd <path>` - Change directory
- `ver` - Show version
- `help` - Show help
- `exit` - Exit shell (system halts)

Available programs:
- `ls` - List directory contents
- `hello` - Print "Hello World!"

## Notes

- This is an x86 32-bit protected mode OS (not x86_64 despite some directory names)
- No floating point support in kernel
- No dynamic memory allocation in drivers yet
- Interrupts must be disabled when holding spinlocks
- User pointers validated before kernel access to prevent crashes
