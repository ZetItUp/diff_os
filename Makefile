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

# mkdiffos tool
MKDIFFOS = $(BUILD)/mkdiffos
TOOLS_DIR = tools

IMAGE = $(TARGET)

# Source Files
BOOT_STAGE1 = boot/boot.asm
BOOT_STAGE2 = boot/boot_stage2.asm

ASM_SRC = \
	kernel/arch/x86_64/cpu/isr_stub.asm

KERNEL_SRC = \
    kernel/library/string.c \
	kernel/library/printf.c \
	kernel/arch/x86_64/cpu/idt.c \
	kernel/arch/x86_64/cpu/irq.c \
	kernel/arch/x86_64/cpu/io.c \
	kernel/arch/x86_64/cpu/pic.c \
	kernel/arch/x86_64/cpu/timer.c \
	kernel/drivers/driver.c \
	kernel/drivers/keyboard.c \
	kernel/kernel.c \
    kernel/console.c \
    kernel/fs/diff.c \
    kernel/memory/paging.c \
	kernel/memory/heap.c

ASM_OBJ = $(addprefix $(OBJ)/,$(notdir $(ASM_SRC:.asm=.o)))
KERNEL_OBJ = $(addprefix $(OBJ)/,$(notdir $(KERNEL_SRC:.c=.o)))

# Targets
TARGET = $(BUILD)/diffos.img

.PHONY: all clean run debug tools

all: tools $(TARGET)

tools:
	@echo "[TOOLS] Making tools..."
	@$(MAKE) -C $(TOOLS_DIR) all --no-print-directory

# Main OS image
$(TARGET): tools $(BUILD)/boot.bin $(BUILD)/boot_stage2.bin $(BUILD)/kernel.bin
	@echo "[IMG] Creating OS image"
	$(MKDIFFOS) $(TARGET) 64 $(BUILD)/boot.bin $(BUILD)/boot_stage2.bin $(BUILD)/kernel.bin
	@echo "[IMG] OS image created: $@"

# Bootloader Stages
$(BUILD)/boot.bin: $(BOOT_STAGE1)
	@mkdir -p $(BUILD)
	@echo "[ASM] Building Stage 1 bootloader"
	@$(NASM) $(NASMFLAGS) $< -o $@
	@echo "[ASM] Bootloader Stage 1 built: $@"

$(BUILD)/boot_stage2.bin: $(BOOT_STAGE2) $(BUILD)/kernel_sizes.inc
	@mkdir -p $(BUILD)
	@echo "[ASM] Building Stage 2 loader"
	@$(NASM) $(NASMFLAGS) $< -o $@
	@echo "[ASM] Stage 2 loader built: $@"

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

$(OBJ)/%.o: kernel/drivers/%.c
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
	@VBoxManage convertfromraw --format VDI build/diffos.img build/diffos.vdi
	@qemu-system-i386 -monitor stdio -m 64M -machine pc -drive id=disk,file=build/diffos.img,if=ide,format=raw -device i8042

# Debug in QEMU with GDB
debug: $(TARGET)
	@echo "[QEMU] Starting in debug mode"
	@qemu-system-i386 -monitor stdio -m 64M -drive format=raw,file=$(TARGET) -s -S &
	@echo "[GDB] Starting debugger"
	@gdb -x 1kernel.gdb

# Clean build
clean:
	@echo "[CLEAN] Removing build files"
	@echo "[CLEAN] Removing tools build files"
	@$(MAKE) -C $(TOOLS_DIR) clean --no-print-directory
	@rm -rf $(BUILD)
