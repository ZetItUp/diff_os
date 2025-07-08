# Filepaths
BOOT = boot/boot.asm
PMODE = kernel/arch/x86_64/cpu/pmode.asm
KERNEL_SRC = kernel
FS_SRC = $(KERNEL_SRC)/fs
ARCH_SRC = $(KERNEL_SRC)/arch/x86_64

# Binary outdata
BUILD_DIR = build
BOOT_BIN = $(BUILD_DIR)/boot.bin
PMODE_BIN = $(BUILD_DIR)/pmode.bin
PMODE_OBJ = $(BUILD_DIR)/pmode.o
OS_IMG = $(BUILD_DIR)/os-img.bin

NASM = nasm
NASM_BOOT_FLAGS = -f bin -I kernel/arch/x86_64/cpu
NASM_PMODE_FLAGS = -f elf64 -I kernel/arch/x86_64/cpu

LIBRARY_OBJS = $(BUILD_DIR)/library/string.o
KERNEL_OBJS = $(BUILD_DIR)/start.o 			\
			  	$(BUILD_DIR)/kernel.o 		\
			  	$(BUILD_DIR)/diff_fs.o 		\
			  	$(LIBRARY_OBJS)
ALL_OBJS = $(PMODE_OBJ) $(KERNEL_OBJS)

CC = x86_64-elf-gcc
CFLAGS = -ffreestanding -O2 -Wall -Wextra -std=gnu99 -Ikernel/includes
LD = x86_64-elf-ld
LD_FLAGS = -T linker.ld

OBJCOPY = x86_64-elf-objcopy
OBJCOPY_FLAGS = -O binary

all: $(OS_IMG)

# Build boot.bin
$(BOOT_BIN): $(BOOT)
	@mkdir -p $(BUILD_DIR)
	$(NASM) $(NASM_FLAGS) $< -o $@

$(BOOT_BIN): $(BOOT)
	@mkdir -p $(BUILD_DIR)
	$(NASM) $(NASM_BOOT_FLAGS) $< -o $@

$(BUILD_DIR)/start.o: $(ARCH_SRC)/cpu/start.asm
	@mkdir -p $(dir $@)
	$(NASM) $(NASM_PMODE_FLAGS) $< -o $@

# Build pmode.bin
$(PMODE_OBJ): $(PMODE)
	@mkdir -p $(BUILD_DIR)
	$(NASM) $(NASM_PMODE_FLAGS) $< -o $@

$(PMODE_BIN): $(PMODE_OBJ)
	$(OBJCOPY) $(OBJCOPY_FLAGS) $< $@

$(BUILD_DIR)/%.o: $(KERNEL_SRC)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/library/%.o: $(KERNEL_SRC)/library/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/diff_fs.o: $(FS_SRC)/diff.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/kernel.elf: $(KERNEL_OBJS)
	$(LD) $(LDFLAGS) -o $@ $^

$(BUILD_DIR)/kernel.bin: $(BUILD_DIR)/kernel.elf $(LIBRARY_OBJS)
	$(OBJCOPY) $(OBJCOPY_FLAGS) $< $@

# Build image file
$(OS_IMG): $(BOOT_BIN) $(PMODE_BIN) $(BUILD_DIR)/kernel.bin
	cat $^ > $@

# Run QEMU
run: all
	qemu-system-i386 -fda $(OS_IMG)

clean:
	rm -rf $(BUILD_DIR)
