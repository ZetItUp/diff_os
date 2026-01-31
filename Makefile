# Toolchain Configuration
CC = i386-elf-gcc
LD = i386-elf-ld
OBJCOPY = i386-elf-objcopy
NASM = nasm

# QEMU Configuration
QEMU = qemu-system-i386

# QEMU runtime config:
# - Default uses a GUI display (if available).
# - Use `HEADLESS=1 make run` for serial-only output.
QEMU_DISPLAY ?= default,show-cursor=off
QEMU_MONITOR ?= stdio
QEMU_SERIAL  ?= file:serial.log
QEMU_EXTRA   ?=
QEMU_MEM     ?= 128M
QEMU_VGAMEM  ?= 64

ifeq ($(HEADLESS),1)
QEMU_MONITOR = none
QEMU_SERIAL  = mon:stdio
QEMU_EXTRA   = -nographic
endif

# Build Directories
BUILD = build
OBJ = $(BUILD)/obj

# Compiler/Linker Flags
CFLAGS = -m32 -g -ffreestanding -nostdlib -nostartfiles -O2 -Wall -Wextra -std=gnu99 -g -I kernel/includes
LDFLAGS = -n -T linker.ld
OBJCOPYFLAGS = -O binary
NASMFLAGS = -f bin

# mkdiffos tool
MKDIFFOS = $(BUILD)/mkdiffos
TOOLS_DIR = tools
DRIVERS_DIR = drivers
EXLS_DIR = exls
EXL_SUBDIRS := $(patsubst %/,%,$(dir $(wildcard $(EXLS_DIR)/*/Makefile)))

DEBUG ?=0
ifeq ($(DEBUG),1)
CFLAGS += -DDIFF_DEBUG
endif

.PRECIOUS: %.o %.elf %.bin %.patched

# Source Files
BOOT_STAGE1 = boot/boot.asm
BOOT_STAGE2 = boot/boot_stage2.asm

ASM_SRC = \
	boot/multiboot.asm \
	kernel/arch/x86_64/cpu/isr_stub.asm \
	kernel/arch/x86_64/cpu/usermode.asm \
	kernel/arch/x86_64/cpu/context_switch.asm

KERNEL_SRC = \
    kernel/library/string.c \
	kernel/library/printf.c \
	kernel/library/graphics/vbe_text.c \
	kernel/arch/x86_64/cpu/idt.c \
	kernel/arch/x86_64/cpu/irq.c \
	kernel/arch/x86_64/cpu/io.c \
	kernel/arch/x86_64/cpu/pic.c \
	kernel/arch/x86_64/cpu/apic.c \
	kernel/arch/x86_64/cpu/timer.c \
	kernel/arch/x86_64/cpu/tss.c \
	kernel/arch/x86_64/cpu/cpu.c \
	kernel/drivers/ata.c \
	kernel/drivers/config.c \
	kernel/drivers/ipv4_config.c \
	kernel/drivers/device.c \
	kernel/drivers/module_loader.c \
	kernel/network/network_interface.c \
	kernel/network/network_communicator.c \
	kernel/network/packet.c \
	kernel/network/arp_service.c \
	kernel/network/socket.c \
	kernel/system/system.c \
	kernel/system/syscall.c \
	kernel/system/syscall_dir.c \
	kernel/system/syscall_file.c \
	kernel/system/debug.c \
	kernel/system/path.c \
	kernel/system/threads.c \
	kernel/system/process.c \
	kernel/system/scheduler.c \
	kernel/system/irqsw.c \
	kernel/system/spinlock.c \
	kernel/system/callstack.c \
	kernel/system/messaging.c \
	kernel/system/shared_mem.c \
	kernel/system/shared_kernel_data.c \
	kernel/system/signal.c \
	kernel/system/pci.c \
	kernel/system/profiler/profiler.c \
	kernel/dex/dex_loader.c \
	kernel/dex/exl_loader.c \
	kernel/kernel.c \
	kernel/drivers/device_registry.c \
	kernel/serial.c \
    kernel/console.c \
    kernel/fs/diff.c \
	kernel/memory/paging.c \
	kernel/memory/heap.c \
	kernel/memory/usercopy.c

# Interfaces
KERNEL_SRC += \
	kernel/interfaces/intf_kernel.c \
	kernel/interfaces/intf_keyboard.c \
	kernel/interfaces/intf_mouse.c \
	kernel/interfaces/intf_memory.c \
	kernel/interfaces/intf_vbe.c \
	kernel/interfaces/intf_pci.c \
	kernel/interfaces/intf_console.c \
	kernel/interfaces/intf_tty.c

ASM_OBJ = $(addprefix $(OBJ)/,$(notdir $(ASM_SRC:.asm=.o)))
KERNEL_OBJ = $(addprefix $(OBJ)/,$(notdir $(KERNEL_SRC:.c=.o)))

# Targets
TARGET_RAW = $(BUILD)/diffos.img
TARGET_VMDK = $(BUILD)/diffos.vmdk
IMG_SIZE_MB ?= 48

.PHONY: all clean run games debug tools drivers exls exls-clean progs allclean vmdk vdi graphics quake

# Default target: build VMDK
all: $(TARGET_VMDK)

tools:
	@echo "[TOOLS] Making tools..."
	@$(MAKE) -C $(TOOLS_DIR) all --no-print-directory

drivers:
	@echo "[DRIVERS] Creating Drivers..."
	@$(MAKE) -C $(DRIVERS_DIR) all --no-print-directory

graphics:
	@$(MAKE) -C graphics --no-print-directory

# Raw disk image with GRUB bootloader and Diff filesystem
$(TARGET_RAW): tools exls graphics $(BUILD)/kernel.elf $(BUILD)/kernel.bin
	@echo "[IMG] Creating OS disk image with GRUB"
	@cp $(BUILD)/kernel.bin image/system/kernel.bin
	@chmod +x $(TOOLS_DIR)/mkgrubdisk.sh
	@$(TOOLS_DIR)/mkgrubdisk.sh $(TARGET_RAW) $(IMG_SIZE_MB) $(BUILD)/kernel.elf
	@$(MKDIFFOS) $(TARGET_RAW) $(IMG_SIZE_MB) $(BUILD)/kernel.bin
	@echo "[IMG] Raw disk image created: $@"

# VMDK format (works with QEMU, VirtualBox, VMware)
$(TARGET_VMDK): $(TARGET_RAW)
	@echo "[VMDK] Creating VMDK disk image"
	@rm -f $@
	@qemu-img convert -f raw -O vmdk $(TARGET_RAW) $@
	@echo "[VMDK] Disk image created: $@"

# VirtualBox VDI format
$(BUILD)/diffos.vdi: $(TARGET_RAW)
	@echo "[VDI] Creating VirtualBox disk image"
	@rm -f $@
	@VBoxManage convertfromraw --format VDI $(TARGET_RAW) $@ 2>/dev/null || \
		qemu-img convert -f raw -O vdi $(TARGET_RAW) $@
	@echo "[VDI] VirtualBox image created: $@"

vmdk: $(TARGET_VMDK)
vdi: $(BUILD)/diffos.vdi

# Bootloader Stages
$(BUILD)/boot.bin: $(BOOT_STAGE1)
	@mkdir -p $(BUILD)
	@echo "[ASM] Building Stage 1 bootloader"
	@$(NASM) $(NASMFLAGS) $< -o $@

$(BUILD)/boot_stage2.bin: $(BOOT_STAGE2) $(BUILD)/kernel_sizes.inc
	@mkdir -p $(BUILD)
	@echo "[ASM] Building Stage 2 loader"
	@$(NASM) $(NASMFLAGS) $< -o $@

# Kernel ELF
$(BUILD)/kernel.elf: $(KERNEL_OBJ) $(ASM_OBJ) linker.ld
	@echo "[LD] Linking kernel"
	$(LD) $(LDFLAGS) -o $@ $(KERNEL_OBJ) $(ASM_OBJ)

$(BUILD)/kernel_sizes.inc: $(BUILD)/kernel.bin
	@mkdir -p $(BUILD)
	@echo "KERNEL_SIZE equ $$(stat -c %s $(BUILD)/kernel.bin)" > $@
	@echo "KERNEL_SECTORS equ $$(expr \( $$(stat -c %s $(BUILD)/kernel.bin) + 511 \) / 512)" >> $@
	@echo "KERNEL_MOVSDS equ $$(expr \( $$(stat -c %s $(BUILD)/kernel.bin) + 3 \) / 4)" >> $@

# Kernel binary
$(BUILD)/kernel.bin: $(BUILD)/kernel.elf
	@echo "[OBJCOPY] Creating kernel binary"
	@$(OBJCOPY) $(OBJCOPYFLAGS) $< $@

# ASM source compilation
$(OBJ)/%.o: boot/%.asm
	@mkdir -p $(OBJ)
	@echo "[ASM] Compiling $<"
	@nasm -f elf32 $< -o $@

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

$(OBJ)/%.o: kernel/dex/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/library/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/library/graphics/%.c
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

$(OBJ)/%.o: kernel/system/syscall/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/system/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/system/profiler/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/interfaces/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/network/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

$(OBJ)/%.o: kernel/arch/x86_64/cpu/%.c
	@mkdir -p $(OBJ)
	@echo "[CC] Compiling $<"
	@$(CC) $(CFLAGS) -c $< -o $@

# Run in QEMU (boots from disk image)
run:
	@$(MAKE) clean --no-print-directory
	@$(MAKE) drivers --no-print-directory
	@$(MAKE) $(TARGET_VMDK) --no-print-directory
	@echo "[QEMU] Starting OS from disk"
	$(QEMU) \
		$(if $(HEADLESS),,$(if $(QEMU_DISPLAY),-display $(QEMU_DISPLAY),)) \
		-monitor $(QEMU_MONITOR) \
		-m $(QEMU_MEM) \
		-device VGA,vgamem_mb=$(QEMU_VGAMEM) \
		-serial $(QEMU_SERIAL) \
		-no-reboot -no-shutdown \
		-d guest_errors -D qemu.log \
		-drive file=$(TARGET_VMDK),format=vmdk \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		$(QEMU_EXTRA) \
		-chardev file,id=dbg,path=debugcon.log \
		-device isa-debugcon,iobase=0xe9,chardev=dbg

# Debug in QEMU with GDB
debug: tools drivers $(TARGET_VMDK)
	@echo "[QEMU] Starting in debug mode"
	@$(QEMU) -display default,show-cursor=off -monitor stdio -m $(QEMU_MEM) -device VGA,vgamem_mb=$(QEMU_VGAMEM) \
		-drive file=$(TARGET_VMDK),format=vmdk \
		-netdev user,id=net0 -device rtl8139,netdev=net0 -s -S &
	@echo "[GDB] Starting debugger"
	@gdb -x 1kernel.gdb

exls:
	@dirs="$(EXL_SUBDIRS)"; \
	if [ -z "$$dirs" ]; then \
		echo "[EXLS] No libraries to build"; \
	else \
		for d in $$dirs; do \
			name=$$(basename $$d); \
			echo "[EXLS] Building $$name"; \
			$(MAKE) -C $$d --no-print-directory || exit $$?; \
		done; \
	fi

exls-clean:
	@dirs="$(EXL_SUBDIRS)"; \
	if [ -z "$$dirs" ]; then \
		echo "[EXLS] No libraries to clean"; \
	else \
		for d in $$dirs; do \
			name=$$(basename $$d); \
			echo "[EXLS] Cleaning $$name"; \
			$(MAKE) -C $$d clean --no-print-directory || exit $$?; \
		done; \
	fi

progs:
	@echo "[Programs] Compiling all programs"
	@$(MAKE) -C programs/

games:
	@echo "[Games] Compiling all games"
	@$(MAKE) -C games/doom clean
	@$(MAKE) -C games/doom

quake:
	@echo "[Games] Compiling quake"
	@$(MAKE) -C games/quake/WinQuake clean
	@$(MAKE) -C games/quake/WinQuake

allclean: clean
	@echo "[CLEAN] Cleaning everything!"
	@$(MAKE) exls-clean --no-print-directory
	@$(MAKE) -C programs/ clean --no-print-directory

# Clean build
clean:
	@echo "[CLEAN] Removing build files"
	@$(MAKE) -C $(TOOLS_DIR) clean --no-print-directory
	@$(MAKE) -C $(DRIVERS_DIR) clean --no-print-directory
	@$(MAKE) -C graphics clean --no-print-directory
	@rm -rf $(BUILD)
