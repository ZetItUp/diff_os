# Different OS
A different OS

<img width="719" height="455" alt="Skärmbild 2025-08-09 185901" src="https://github.com/user-attachments/assets/2f6836a8-35c3-4905-ac47-54de5e44dbdf" />

The goal for this was to load a kernel from a bootloader. However i kept building on it.
Features for now:
* 2 Stage Bootloader 
* It's own filesystem
* Custom tool to create a filesystem image
* It's own driver file format
* Module loader to load drivers
* Custom tools to create drivers
* It's own Executable format, DEX
* It's own Executable Linking forma, EXL
* Custom tools to create the files from ELF to DEX and/or EXL

This is my first serious attempt at making my own OS.
The ways i've done some stuff in it may seem weird, but im learning.

## Build Instructions
### Requirements
* Cross-compiler for GCC i386
* Python3
* Binutils
* QEMU 6 or 7, not newer

### Preperations
Open the Makefile in the root folder and make sure the paths and programs points to your builds.
If everything is configured correctly, you should just need to do
* make clean && make run

and it will boot up.
