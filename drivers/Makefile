# Config
CC = i386-elf-gcc
LD = i386-elf-ld
OBJCOPY = i386-elf-objcopy
PYTHON = python3

DRIVERS_PATH = .
IMAGE_DRIVERS_PATH = ../image/system/drivers
TOOLS_DIR = ../tools

CFLAGS = -g -Wall -Wextra -Wunused-parameter -ffreestanding -fno-stack-protector -nodefaultlibs -nostdlib \
		 -ffunction-sections -fdata-sections -fno-common -fno-PIC -fno-pic -fno-pie -fno-plt \
		 -fno-asynchronous-unwind-tables -fno-unwind-tables \
          -fno-exceptions -fno-jump-tables -fno-ipa-cp-clone \
          -fno-optimize-sibling-calls -fno-omit-frame-pointer \
          -fno-builtin -I ../kernel/includes -c

LDFLAGS = -T driver.ld --gc-sections --emit-relocs -nostdlib -no-pie \
  --undefined=ddf_driver_init \
  --undefined=ddf_driver_exit \
  --undefined=ddf_driver_irq \
  --undefined=ddf_irq_number \
  -static
  ##\
#  ../build/obj/string.o

# Source files
ALL_DRIVER_CS := $(wildcard $(DRIVERS_PATH)/*.c)

BUILD_DRIVER_HELPER ?= 0

ifeq ($(BUILD_DRIVER_HELPER),0)
    DRIVER_HELPER := $(DRIVERS_PATH)/driver.c
    DRIVERS_CS := $(filter-out $(DRIVER_HELPER),$(ALL_DRIVER_CS))
else
    DRIVERS_CS := $(ALL_DRIVER_CS)
endif

DRIVERS_OBJ := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%.o,$(DRIVERS_CS))
DRIVERS_NOSYM_ELF := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%_nosym.ddf.elf,$(DRIVERS_CS))
DRIVERS_NM := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%_nosym.nm.txt,$(DRIVERS_CS))
DRIVERS_SYMBOLS_C := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%_symbols.c,$(DRIVERS_CS))
DRIVERS_SYMBOLS_OBJ := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%_symbols.o,$(DRIVERS_CS))
DRIVERS_ELF := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%.ddf.elf,$(DRIVERS_CS))
DRIVERS_BIN := $(patsubst $(DRIVERS_PATH)/%.c,$(IMAGE_DRIVERS_PATH)/%.ddf,$(DRIVERS_CS))

.PRECIOUS: %.o %.elf %.bin %.elf.bin %.txt %.ddf.elf %.c
.PHONY: all clean drivers

all: drivers
	bash $(TOOLS_DIR)/ddf_patcher.sh obj ../image/system/drivers
	@echo "[DRIVERS] Build complete"

drivers: $(DRIVERS_BIN)
	@echo "[DRIVERS] All drivers built"

# Directory creation
$(DRIVERS_PATH)/obj:
	@mkdir -p $(DRIVERS_PATH)/obj

$(IMAGE_DRIVERS_PATH):
	@mkdir -p $(IMAGE_DRIVERS_PATH)

# Driver Compilation
.SECONDARY:
$(DRIVERS_PATH)/obj/%.o: $(DRIVERS_PATH)/%.c | $(DRIVERS_PATH)/obj
	@echo "[DRIVERS CC] Compiling $<"
	@$(CC) $(CFLAGS) $< -o $@

$(DRIVERS_PATH)/obj/driver.o: $(DRIVERS_PATH)/obj
	@echo "[DRIVERS CC] Compiling $<"
	@$(CC) $(CFLAGS) $< -o $@

.SECONDARY:
$(DRIVERS_PATH)/obj/%_nosym.ddf.elf: $(DRIVERS_PATH)/obj/%.o | $(DRIVERS_PATH)/obj
	@echo "[DRIVERS LD] Linking ELF without symbols $*"
	@$(LD) $(LDFLAGS) -o $@ $^

# Generate nm output from ELF
.SECONDARY:
$(DRIVERS_PATH)/obj/%_nosym.nm.txt: $(DRIVERS_PATH)/obj/%_nosym.ddf.elf
	@echo "[DRIVERS] Generating nm output for $<"
	@nm -n $< > $@

# Generate symbol table C from nm output
$(DRIVERS_PATH)/obj/%_symbols.c: $(DRIVERS_PATH)/obj/%_nosym.nm.txt | $(DRIVERS_PATH)/obj
	@echo "[DRIVERS] Generating symbol table C for $*"
	@$(PYTHON) $(TOOLS_DIR)/gen_ddf_symbol_table.py $< $@

# Compile symbol table C to object
.SECONDARY:
$(DRIVERS_PATH)/obj/%_symbols.o: $(DRIVERS_PATH)/obj/%_symbols.c
	@echo "[DRIVERS CC] Compiling symbol table $<"
	@$(CC) $(CFLAGS) $< -o $@

# Link final ELF
.SECONDARY:
$(DRIVERS_PATH)/obj/%.ddf.elf: $(DRIVERS_PATH)/obj/%.o $(DRIVERS_PATH)/obj/%_symbols.o | $(DRIVERS_PATH)/obj
	@echo "[DRIVERS LD] Linking final ELF $*"
	@$(LD) $(LDFLAGS) -o $@ $^

.SECONDARY:
$(IMAGE_DRIVERS_PATH)/%.ddf: $(DRIVERS_PATH)/obj/%.ddf.elf | $(IMAGE_DRIVERS_PATH)
	@echo "[DRIVERS] Creating DDF driver $*"
	@$(PYTHON) $(TOOLS_DIR)/patch_ddf.py $< $@

# Clean
clean:
	@echo "[DRIVERS] Cleaning build files"
	@rm -rf $(DRIVERS_PATH)/obj
	@rm -rf $(IMAGE_DRIVERS_PATH)/*.ddf

