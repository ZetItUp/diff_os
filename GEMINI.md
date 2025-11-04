# Different OS

## Project Overview

This project is a custom-built operating system named "Different OS". It features a 2-stage bootloader, its own filesystem, a custom driver file format (DDF), and custom executable formats (DEX and EXL). The OS has a kernel that supports paging, a heap, processes, threads, and system calls. It also includes a shell called `dterm`.

The project is built using a cross-compiler for i386-elf-gcc and NASM. The build process is managed by a `Makefile`.

## Building and Running

### Requirements

*   Cross-compiler for GCC i386
*   Python3
*   Binutils
*   QEMU

### Instructions

1.  **Configure Makefile:** Open the `Makefile` in the root directory and ensure the paths and programs point to your builds.
2.  **Build and Run:**
    ```bash
    make clean && make run
    ```
    This will build the entire OS, create a disk image, and run it in QEMU.

### Debugging

To run the OS in debug mode with GDB:

```bash
make debug
```

## Development Conventions

*   The kernel is written in C and assembly.
*   The build system is based on `make`.
*   The OS has its own executable formats (DEX and EXL) and tools to create them from ELF files.
*   Drivers are in a custom format (DDF).

## Shell (dterm)

The OS includes a shell called `dterm`. It supports the following built-in commands:

*   `cd`: Change current directory.
*   `help`: List built-in commands.
*   `echo`: Print its arguments.
*   `ver`: Show shell version.
*   `exit`: Exit the shell.

External commands are located in `/system/commands.map` and are executed as DEX files.
