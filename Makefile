# Outputdir
BUILD = build

LD = i386-elf-ld
#LD = x86_64-elf-ld
LDARGS = -n -T linker.ld -o 
CC = i386-elf-gcc
#CC = x86_64-elf-gcc
CFLAGS = -m32 -ffreestanding -nostdlib -O2 -Wall -Wextra -std=gnu99 -g
#OBJCPY = x86_64-elf-objcopy
OBJCPY = i386-elf-objcopy
OBJCPYARGS = -O binary 

ASMFLAGS = -f elf32 -g -F dwarf

# Source paths
BOOT = boot/boot.asm
PMODE = kernel/arch/x86_64/cpu/pmode.asm

INCLUDES = -I kernel/includes

# Källfiler uppdelat per kategori
KERNEL_SRC      = kernel/kernel.c \
					kernel/console.c \
					kernel/io.c

FS_SRC          = kernel/fs/diff.c
LIBRARY_SRC     = kernel/library/string.c
MEMORY_SRC      = kernel/memory/paging.c

KERNEL_OBJ      = $(patsubst kernel/%.c, build/obj/%.o, $(KERNEL_SRC)) \
                  $(patsubst kernel/fs/%.c, build/obj/fs_%.o, $(FS_SRC)) \
                  $(patsubst kernel/library/%.c, build/obj/library_%.o, $(LIBRARY_SRC)) \
                  $(patsubst kernel/memory/%.c, build/obj/memory_%.o, $(MEMORY_SRC))

all: $(BUILD)/os-img.bin

# Bygg bootloader (16-bit, raw)
$(BUILD)/boot.bin: $(BOOT) $(BUILD)/kernel.bin
	mkdir -p $(BUILD)
	nasm -f bin $< -o $@

	KERNEL_SIZE=$$(stat -c %s $(BUILD)/kernel.bin); \
	KERNEL_SECTORS=$$(( ($$KERNEL_SIZE + 511) / 512 )); \
	printf "%02x%02x" $$(( $$KERNEL_SECTORS & 0xFF )) $$(( ($$KERNEL_SECTORS >> 8) & 0xFF )) | \
	xxd -r -p | dd of=$@ bs=1 seek=508 count=2 conv=notrunc

# Bygg pmode (raw)
$(BUILD)/pmode.bin: $(PMODE)
	mkdir -p $(BUILD)
	nasm -f bin $< -o $@

build/obj/%.o: kernel/%.c
	mkdir -p $(BUILD)/obj
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/obj/fs_%.o: kernel/fs/%.c
	mkdir -p $(BUILD)/obj
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/obj/library_%.o: kernel/library/%.c
	mkdir -p $(BUILD)/obj
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

build/obj/memory_%.o: kernel/memory/%.c
	mkdir -p $(BUILD)/obj
	$(CC) $(CFLAGS) $(INCLUDES) -c $< -o $@

# Länka ihop kernel.elf (med 64-bit entrypoint, egen linker-script)
$(BUILD)/kernel.elf: $(KERNEL_OBJ)
	$(LD) $(LDARGS) $@ $(KERNEL_OBJ)

# Extrahera binär kernel
$(BUILD)/kernel.bin: $(BUILD)/kernel.elf
	$(OBJCPY) $(OBJCPYARGS) $< $@

build/kernel.size: $(BUILD)/kernel.bin
	mkdir -p $(BUILD)
	printf "%04x" $$(( ( $(shell stat -c %s $(BUILD)/kernel.bin ) + 511 ) / 512 )) | xxd -r -p > $@

build/boot_size.bin: $(BUILD)/boot.bin build/kernel.size
	cp $(BUILD)/boot.bin $@
	dd if=$(BUILD)/kernel.size of=$@ bs=1 seek=508 conv=notrunc

# Slå ihop allting till en bootbar image
$(BUILD)/os-img.bin: $(BUILD)/boot_size.bin $(BUILD)/pmode.bin $(BUILD)/kernel.bin
	dd if=/dev/zero of=$@ bs=512 count=4096
	dd if=$(BUILD)/boot.bin of=$@ conv=notrunc
	dd if=$(BUILD)/pmode.bin of=$@ bs=512 seek=1 conv=notrunc
	dd if=$(BUILD)/kernel.bin of=$@ bs=512 seek=2048 conv=notrunc

# Kör i QEMU
run: $(BUILD)/os-img.bin
	qemu-system-i386 -monitor stdio -drive format=raw,file=$(BUILD)/os-img.bin

debug: $(BUILD)/os-img.bin
	qemu-system-i386 -monitor stdio -drive format=raw,file=$(BUILD)/os-img.bin -s -S &
	gdb -x 1kernel.gdb

clean:
	rm -rf $(BUILD)

.PHONY: all clean run
