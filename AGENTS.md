# Agent Guidelines for DiffOS

## Build Commands
- **Full build**: `make all` (builds kernel, tools, drivers)
- **Run OS**: `make run` (QEMU emulator)
- **Debug build**: `make DEBUG=1 run` (with debug symbols)
- **Debug with GDB**: `make debug`
- **Clean**: `make clean`
- **DiffC library**: `make diffc`
- **Programs**: `make progs`
- **Games**: `make -C games/`
- **Tools**: `make -C tools/`
- **Drivers**: `make -C drivers/`

## Test Commands
- **Run single test**: No dedicated test framework; use `make DEBUG=1 run` for debug builds
- **Debug output**: Enable DIFF_DEBUG macro for verbose logging

## Code Style Guidelines

### Language & Compiler
- **Language**: C (GNU99 standard)
- **Compiler**: i386-elf-gcc cross-compiler
- **Flags**: -Wall -Wextra -O2 -g -ffreestanding -nostdlib

### Naming Conventions
- **Functions**: snake_case (e.g., `collapse_slashes`, `ascii_tolower`)
- **Variables**: snake_case (e.g., `system_info`, `background`)
- **Types**: Use stdint.h types (uint32_t, int32_t, etc.)
- **Macros**: UPPER_SNAKE_CASE (e.g., DIFF_DEBUG)

### Formatting
- **Indentation**: 4 spaces (inconsistent in codebase, prefer 4 spaces)
- **Braces**: K&R style (opening brace on same line)
- **Line length**: No strict limit, keep reasonable
- **Includes**: Local headers with quotes `"header.h"`, system with angle brackets `<stdint.h>`

### Error Handling
- Return error codes from functions
- Use errno for system-level errors
- Check pointers before use
- Debug builds use DIFF_DEBUG macro for logging

### Imports & Dependencies
- Kernel includes: Relative paths from kernel/includes/
- DiffC library: Available for programs and games
- No external dependencies except cross-compiler toolchain

### Architecture Notes
- 32-bit x86 OS with custom executable formats (DEX, EXL)
- Freestanding environment (no standard library)
- Custom filesystem, drivers, and syscall interface