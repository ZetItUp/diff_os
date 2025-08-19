# Different OS
A different OS

<img width="1020" height="825" alt="Skärmbild 2025-08-19 041200" src="https://github.com/user-attachments/assets/f864566f-7b5e-4cce-a483-32de4b6aa67c" />



The goal for this was to load a kernel from a bootloader. However i kept building on it.
Features for now:
* 2 Stage Bootloader 
* It's own filesystem
* Custom tool to create a filesystem image
* It's own driver file format
* Module loader to load drivers
* Custom tools to create drivers
* It's own Executable format, DEX
* It's own Executable Linking format, EXL
* Custom tools to create the files from ELF to DEX and/or EXL
* Supports some basic syscalls

## Shell
* Shell is called dterm
* Commands cd, ver, help, exit

## Software
* ls     - list directory
* hello  - prints Hello World!

This is my first serious attempt at making my own OS.
The ways i've done some stuff in it may seem weird, but im learning.

## Build Instructions
### Requirements
* Cross-compiler for GCC i386
* Python3
* Binutils
* QEMU

### Preperations
Open the Makefile in the root folder and make sure the paths and programs points to your builds.
If everything is configured correctly, you should just need to do
* make clean && make run

and it will boot up.
