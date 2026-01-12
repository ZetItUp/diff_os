# Toolchain Configuration
CC = i386-elf-gcc
LD = i386-elf-ld
OBJCOPY = i386-elf-objcopy
NASM = nasm

# QEMU Configuration
# Choose which QEMU to use (comment/uncomment):
QEMU = qemu-system-i386

# QEMU runtime config:
# - Default uses a GUI display (if available).
# - Use `HEADLESS=1 make run` / `HEADLESS=1 make run-cd` for serial-only output.
QEMU_DISPLAY ?= default,show-cursor=off
QEMU_MONITOR ?= stdio
QEMU_SERIAL  ?= file:serial.log
QEMU_EXTRA   ?=

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
MKISOFS = mkisofs
TOOLS_DIR = tools
DRIVERS_DIR = drivers
IMAGE = $(TARGET)
EXLS_DIR = exls
EXL_SUBDIRS := $(patsubst %/,%,$(dir $(wildcard $(EXLS_DIR)/*/Makefile)))

DEBUG ?=0
ifeq ($(DEBUG),1)
CFLAGS += -DDIFF_DEBUG
endif

.PRECIOUS: %.o %.elf %.bin %.patched

# Source Files - Normal HDD boot
BOOT_STAGE1 = boot/boot.asm
BOOT_STAGE2 = boot/boot_stage2.asm

# Source Files - CD-ROM boot
BOOT_CD_STAGE1 = boot/boot_cd.asm
BOOT_CD_STAGE2 = boot/boot_stage2_cd.asm

ASM_SRC = \
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
	kernel/system/messaging.c \
	kernel/system/shared_mem.c \
	kernel/system/signal.c \
	kernel/system/pci.c \
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

PROGRAMS_LIST = dterm \
				hello \
				ls \
				ttest \
				ptest \
				brktest

# Helpers
KERNEL_SRC += \

ASM_OBJ = $(addprefix $(OBJ)/,$(notdir $(ASM_SRC:.asm=.o)))
KERNEL_OBJ = $(addprefix $(OBJ)/,$(notdir $(KERNEL_SRC:.c=.o)))

# Targets
TARGET = $(BUILD)/diffos.img
ISO = $(BUILD)/diffos.iso
CD_ISO = $(BUILD)/diffos_cd.iso

.PHONY: all clean run games debug tools drivers exls exls-clean progs allclean iso vdi vmdk graphics cd run-cd

all: tools drivers $(ISO)

tools:
	@echo "[TOOLS] Making tools..."
	@$(MAKE) -C $(TOOLS_DIR) all --no-print-directory

drivers:
	@echo "[DRIVERS] Creating Drivers...i"
	@$(MAKE) -C $(DRIVERS_DIR) all --no-print-directory

graphics:
	@$(MAKE) -C graphics --no-print-directory

# Main OS image
$(TARGET): tools exls graphics $(BUILD)/boot.bin $(BUILD)/boot_stage2.bin $(BUILD)/kernel.bin
	@echo "[IMG] Creating OS image"
	@cp $(BUILD)/kernel.bin image/system/kernel.bin
	@$(MKDIFFOS) $(TARGET) 64 $(BUILD)/boot.bin $(BUILD)/boot_stage2.bin $(BUILD)/kernel.bin
	@echo "[IMG] OS image created: $@"

# VirtualBox VDI format
$(BUILD)/diffos.vdi: $(TARGET)
	@echo "[VDI] Creating VirtualBox disk image"
	@rm -f $@
	@VBoxManage convertfromraw --format VDI $(TARGET) $@ 2>/dev/null || \
		qemu-img convert -f raw -O vdi $(TARGET) $@
	@echo "[VDI] VirtualBox image created: $@"

# VMware VMDK format
$(BUILD)/diffos.vmdk: $(TARGET)
	@echo "[VMDK] Creating VMware disk image"
	@rm -f $@
	@qemu-img convert -f raw -O vmdk $(TARGET) $@
	@echo "[VMDK] VMware image created: $@"

# Hybrid ISO (boots as CD-ROM or raw disk via USB/direct)
$(ISO): $(TARGET)
	@echo "[ISO] Creating hybrid ISO"
	@cp $(TARGET) $@
	@# Rename to .iso - the raw image already has a valid MBR and can boot directly
	@echo "[ISO] Hybrid image created: $@"
	@echo "[ISO] Use with: -cdrom (CD boot) or -hda (disk boot)"

iso: $(ISO)
vdi: $(BUILD)/diffos.vdi
vmdk: $(BUILD)/diffos.vmdk

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

# CD-ROM Bootloader Stages
$(BUILD)/boot_cd_stage1.bin: $(BOOT_CD_STAGE1) $(BUILD)/boot_stage2_cd.bin
	@mkdir -p $(BUILD)
	@echo "[ASM] Building CD Stage 1 bootloader"
	@stage2_sectors=$$(expr \( $$(stat -c %s $(BUILD)/boot_stage2_cd.bin) + 2047 \) / 2048); \
	$(NASM) $(NASMFLAGS) -D STAGE2_SECTORS=$$stage2_sectors $< -o $@
	@echo "[ASM] CD Bootloader Stage 1 built: $@"

$(BUILD)/boot_stage2_cd.bin: $(BOOT_CD_STAGE2)
	@mkdir -p $(BUILD)
	@echo "[ASM] Building CD Stage 2 loader"
	@$(NASM) $(NASMFLAGS) $< -o $@
	@echo "[ASM] CD Stage 2 loader built: $@"

$(BUILD)/boot_cd.bin: $(BUILD)/boot_cd_stage1.bin $(BUILD)/boot_stage2_cd.bin
	@echo "[CD] Packing El Torito boot image (stage1 + stage2)"
	@dd if=$(BUILD)/boot_cd_stage1.bin of=$(BUILD)/boot_cd_stage1.padded.bin bs=2048 conv=sync status=none
	@dd if=$(BUILD)/boot_stage2_cd.bin of=$(BUILD)/boot_stage2_cd.padded.bin bs=2048 conv=sync status=none
	@cat $(BUILD)/boot_cd_stage1.padded.bin $(BUILD)/boot_stage2_cd.padded.bin > $@
	@echo "[CD] Boot image built: $@"

# Kernel ELF
$(BUILD)/kernel.elf: $(KERNEL_OBJ) $(ASM_OBJ) linker.ld
	@echo "[LD] Linking kernel"
	$(LD) $(LDFLAGS) -o $@ $(KERNEL_OBJ) $(ASM_OBJ) # 2>/dev/null
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


# Run in QEMU (using hard disk boot - more reliable than CD-ROM)
run: tools drivers $(TARGET)
	@echo "[QEMU] Starting OS"
	$(QEMU) \
		$(if $(HEADLESS),,$(if $(QEMU_DISPLAY),-display $(QEMU_DISPLAY),)) \
		-monitor $(QEMU_MONITOR) \
		-m 64M \
		-serial $(QEMU_SERIAL) \
		-no-reboot -no-shutdown \
		-d guest_errors,trace:ioport_* -D qemu.log \
		-boot c \
		-hda $(TARGET) \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		$(QEMU_EXTRA) \
		-chardev file,id=dbg,path=/home/zet/os/debugcon.log \
		-device isa-debugcon,iobase=0xe9,chardev=dbg

# Debug in QEMU with GDB
debug: tools drivers $(TARGET)
	@echo "[QEMU] Starting in debug mode"
	@$(QEMU) -display default,show-cursor=off -monitor stdio -m 64M -vga std -boot c -hda $(TARGET) -netdev user,id=net0 -device rtl8139,netdev=net0 -s -S &
	@echo "[GDB] Starting debugger"
	@gdb -x 1kernel.gdb

# CD-ROM ISO image (El Torito bootable)
$(CD_ISO): tools exls graphics $(BUILD)/boot_cd.bin $(BUILD)/boot_stage2_cd.bin $(BUILD)/kernel.bin $(TARGET)
	@echo "[CD] Creating bootable CD-ROM ISO"
	@mkdir -p $(BUILD)/cdroot/boot
	@cp $(BUILD)/boot_cd.bin $(BUILD)/cdroot/boot/
	@cp $(BUILD)/boot_stage2_cd.bin $(BUILD)/cdroot/boot/
	@cp $(TARGET) $(BUILD)/cdroot/diffos.img
	@$(MKISOFS) -o $@ \
		-b boot/boot_cd.bin \
		-no-emul-boot \
		-boot-load-size 12 \
		-boot-info-table \
		-V "DIFFOS" \
		-publisher "DiffOS" \
		-quiet \
		$(BUILD)/cdroot
	@rm -rf $(BUILD)/cdroot
	@echo "[CD] Bootable CD-ROM ISO created: $@"

# Build CD target
cd: $(CD_ISO)

# Run CD-ROM in QEMU
run-cd: $(CD_ISO)
	@echo "[QEMU] Starting OS from CD-ROM"
	$(QEMU) \
		$(if $(HEADLESS),,$(if $(QEMU_DISPLAY),-display $(QEMU_DISPLAY),)) \
		-monitor $(QEMU_MONITOR) \
		-m 64M \
		-serial $(QEMU_SERIAL) \
		-no-reboot -no-shutdown \
		-d guest_errors,trace:ioport_* -D qemu.log \
		-boot d \
		-cdrom $(CD_ISO) \
		-netdev user,id=net0 \
		-device rtl8139,netdev=net0 \
		$(QEMU_EXTRA) \
		-chardev file,id=dbg,path=/home/zet/os/debugcon.log \
		-device isa-debugcon,iobase=0xe9,chardev=dbg

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

allclean: clean
	@echo "[CLEAN] Cleaning everything!"
	@$(MAKE) exls-clean --no-print-directory
	@$(MAKE) -C programs/ clean --no-print-directory

# Clean build
clean:
	@echo "[CLEAN] Removing build files"
	@echo "[CLEAN] Removing tools build files"
	@$(MAKE) -C $(TOOLS_DIR) clean --no-print-directory
	@$(MAKE) -C $(DRIVERS_DIR) clean --no-print-directory
	@$(MAKE) -C graphics clean --no-print-directory
	@rm -rf $(BUILD)
