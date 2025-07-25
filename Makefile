# Toolchain Configuration
CC = i386-elf-gcc
LD = i386-elf-ld
OBJCOPY = i386-elf-objcopy
NASM = nasm

# Build Directories
BUILD = build
OBJ = $(BUILD)/obj

# Compiler/Linker Flags
CFLAGS = -m32 -ffreestanding -nostdlib -nostartfiles -O2 -Wall -Wextra -std=gnu99 -g -I kernel/includes
LDFLAGS = -n -T linker.ld
OBJCOPYFLAGS = -O binary
NASMFLAGS = -f bin

# Source Files
BOOT_SRC = boot/boot.asm

ASM_SRC = \
	kernel/arch/x86_64/cpu/isr_stub.asm

KERNEL_SRC = \
	kernel/arch/x86_64/cpu/idt.c \
	kernel/arch/x86_64/cpu/irq.c \
	kernel/arch/x86_64/cpu/io.c \
	kernel/arch/x86_64/cpu/pic.c \
	kernel/arch/x86_64/cpu/timer.c \
	kernel/kernel.c \
    kernel/console.c \
    kernel/fs/diff.c \
    kernel/library/string.c \
    kernel/memory/paging.c \

ASM_OBJ = $(addprefix $(OBJ)/,$(notdir $(ASM_SRC:.asm=.o)))
KERNEL_OBJ = $(addprefix $(OBJ)/,$(notdir $(KERNEL_SRC:.c=.o)))

# Targets
TARGET = $(BUILD)/os-img.bin

.PHONY: all clean run debug

all: $(TARGET)

# Main OS image
$(TARGET): $(BUILD)/boot.bin $(BUILD)/kernel.bin
	@echo "[IMG] Creating OS image"
	@dd if=/dev/zero of=$@ bs=512 count=4096 2>/dev/null
	@dd if=$(BUILD)/boot.bin of=$@ conv=notrunc 2>/dev/null
	@dd if=$(BUILD)/kernel.bin of=$@ bs=512 seek=2048 conv=notrunc 2>/dev/null
	@echo "[IMG] OS image created: $@"

# Bootloader
$(BUILD)/boot.bin: $(BOOT_SRC) $(BUILD)/kernel_sizes.inc
	@mkdir -p $(BUILD)
	@echo "[ASM] Building bootloader"
	@$(NASM) $(NASMFLAGS) $< -o $@
	@echo "[ASM] Bootloader built: $@"

# Kernel ELF
$(BUILD)/kernel.elf: $(KERNEL_OBJ) $(ASM_OBJ) linker.ld
	@echo "[LD] Linking kernel"
	@$(LD) $(LDFLAGS) -o $@ $(KERNEL_OBJ) $(ASM_OBJ)
	@echo "[LD] Kernel linked: $@"


$(BUILD)/kernel_sizes.inc: $(BUILD)/kernel.bin
	@mkdir -p $(BUILD)
	@echo "KERNEL_SIZE equ $$(stat -c %s $(BUILD)/kernel.bin)" > $@
	@echo "KERNEL_SECTORS equ $$(expr \( $$(stat -c %s $(BUILD)/kernel.bin) + 511 \) / 512)" >> $@
	@echo "KERNEL_MOVSDS equ $$(expr \( $$(stat -c %s $(BUILD)/kernel.bin) + 3 \) / 4)" >> $@


# Kernel binary
$(BUILD)/kernel.bin: $(BUILD)/kernel.elf
	@echo "[OBJCOPY] Creating kernel binary"
	@$(OBJCOPY) $(OBJCOPYFLAGS) $< $@
	@echo "[OBJCOPY] Kernel binary created: $@"

# ASM source compilation
$(OBJ)/%.o: kernel/arch/x86_64/cpu/%.asm
	@mkdir -p $(OBJ)
	@echo "[ASM] Compiling $<"
	@nasm -f elf32 $< -o $@

# C source compilation
$(OBJ)/%.o: kernel/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/fs/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/library/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/memory/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/arch/x86_64/cpu/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Run in QEMU
run: $(TARGET)
	@echo "[QEMU] Starting OS"
	@qemu-system-i386 -monitor stdio -hda $(TARGET) -no-reboot

# Debug in QEMU with GDB
debug: $(TARGET)
	@echo "[QEMU] Starting in debug mode"
	@qemu-system-i386 -monitor stdio -drive format=raw,file=$(TARGET) -s -S &
	@echo "[GDB] Starting debugger"
	@gdb -x 1kernel.gdb

# Clean build
clean:
	@echo "[CLEAN] Removing build files"
	@rm -rf $(BUILD)
