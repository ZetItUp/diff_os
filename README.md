# Different OS
A different OS

The goal for this was to load a kernel from a bootloader. However i kept building on it.
Features for now:
* 2 Stage Bootloader 
* It's own filesystem
* It's own driver file format
* Module loader to load drivers
* Custom tools to create drivers

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
