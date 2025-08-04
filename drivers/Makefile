# --- Config ---
CC = i386-elf-gcc
LD = i386-elf-ld
OBJCOPY = i386-elf-objcopy
PYTHON = python3

DRIVERS_PATH = .
IMAGE_DRIVERS_PATH = ../image/system/drivers
TOOLS_DIR = ../tools

CFLAGS = -ffreestanding -I ../kernel/includes -c
LDFLAGS = -T driver.ld --gc-sections --undefined=ddf_driver_init --undefined=ddf_driver_exit --undefined=ddf_driver_irq -o 

# --- Files ---
DRIVERS_SOURCE := $(wildcard $(DRIVERS_PATH)/*.c)

DRIVERS_OBJ := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%.o,$(DRIVERS_SOURCE))
DRIVERS_NOSYM_ELF := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%_nosym.ddf.elf,$(DRIVERS_SOURCE))
DRIVERS_NM := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%_nosym.nm.txt,$(DRIVERS_SOURCE))
DRIVERS_SYMBOLS_C := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%_symbols.c,$(DRIVERS_SOURCE))
DRIVERS_SYMBOLS_OBJ := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%_symbols.o,$(DRIVERS_SOURCE))
DRIVERS_ELF := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%.ddf.elf,$(DRIVERS_SOURCE))
DRIVERS_PATCHED_ELF := $(patsubst $(DRIVERS_PATH)/%.c,$(DRIVERS_PATH)/obj/%.ddf.patched.elf,$(DRIVERS_SOURCE))
DRIVERS_BIN := $(patsubst $(DRIVERS_PATH)/%.c,$(IMAGE_DRIVERS_PATH)/%.ddf,$(DRIVERS_SOURCE))

$(info DRIVERS_SOURCE is $(DRIVERS_SOURCE))
$(info DRIVERS_PATH is $(DRIVERS_PATH))

# --- Rules ---
.PRECIOUS: %.o %.elf %.bin %.elf.bin %.txt %.ddf.elf %.c %.ddf.patched.elf
.PHONY: all clean drivers

all: drivers
	bash $(TOOLS_DIR)/ddf_patcher.sh
	@echo "[DRIVERS] Build complete"

drivers: $(DRIVERS_BIN)
	@echo "[DRIVERS] All drivers built"

# Create needed directories
$(DRIVERS_PATH)/obj:
	mkdir -p $(DRIVERS_PATH)/obj

$(IMAGE_DRIVERS_PATH):
	mkdir -p $(IMAGE_DRIVERS_PATH)

# Compile driver source to object
.SECONDARY:
$(DRIVERS_PATH)/obj/%.o: $(DRIVERS_PATH)/%.c | $(DRIVERS_PATH)/obj
	@echo "[DRIVERS CC] Compiling $<"
	$(CC) $(CFLAGS) $< -o $@

# Link intermediate ELF WITHOUT symbol table (för nm)
.SECONDARY:
$(DRIVERS_PATH)/obj/%_nosym.ddf.elf: $(DRIVERS_PATH)/obj/%.o | $(DRIVERS_PATH)/obj
	@echo "[DRIVERS LD] Linking intermediate ELF (no symbols) $*"
	$(LD) $(LDFLAGS) $@ $<

# Generate nm output from intermediate ELF
.SECONDARY:
$(DRIVERS_PATH)/obj/%_nosym.nm.txt: $(DRIVERS_PATH)/obj/%_nosym.ddf.elf
	@echo "[DRIVERS] Generating nm output for $<"
	nm -n $< > $@

# Generate symbol table C from nm output
$(DRIVERS_PATH)/obj/%_symbols.c: $(DRIVERS_PATH)/obj/%_nosym.nm.txt | $(DRIVERS_PATH)/obj
	@echo "[DRIVERS] Generating symbol table C for $*"
	$(PYTHON) $(TOOLS_DIR)/gen_ddf_symbol_table.py $< $@

# Compile symbol table C to object
.SECONDARY:
$(DRIVERS_PATH)/obj/%_symbols.o: $(DRIVERS_PATH)/obj/%_symbols.c
	@echo "[DRIVERS CC] Compiling symbol table $<"
	$(CC) $(CFLAGS) $< -o $@

# Link final ELF with driver object and symbol table object
.SECONDARY:
$(DRIVERS_PATH)/obj/%.ddf.elf: $(DRIVERS_PATH)/obj/%.o $(DRIVERS_PATH)/obj/%_symbols.o | $(DRIVERS_PATH)/obj
	@echo "[DRIVERS LD] Linking final ELF $*"
	$(LD) $(LDFLAGS) $@ $^

# Patch DDF header offsets in final ELF
.SECONDARY:
$(DRIVERS_PATH)/obj/%.ddf.patched.elf: $(DRIVERS_PATH)/obj/%.ddf.elf
	@echo "[DRIVERS] Patching DDF header offsets for $*"
	@INIT=$$(nm -n $< | grep ' ddf_driver_init$$' | awk '{print $$1}' | head -n1); \
	EXIT=$$(nm -n $< | grep ' ddf_driver_exit$$' | awk '{print $$1}' | head -n1); \
	IRQ=$$(nm -n $< | grep ' ddf_driver_irq$$' | awk '{print $$1}' | head -n1); \
	SYMTAB=$$(nm -n $< | grep ' ddf_symbol_table$$' | awk '{print $$1}' | head -n1); \
	cp $< $@; \
	$(PYTHON) $(TOOLS_DIR)/patch_ddf.py $@ $$INIT $$EXIT $$IRQ $$SYMTAB; \
	echo "[DRIVERS] DDF header patched for $*"

# Convert patched ELF to raw binary driver
$(IMAGE_DRIVERS_PATH)/%.ddf: $(DRIVERS_PATH)/obj/%.ddf.patched.elf | $(IMAGE_DRIVERS_PATH)
	@echo "[DRIVERS] Creating binary driver $*"
	$(OBJCOPY) -O binary $< $@

# Clean build artifacts
clean:
	@echo "[DRIVERS] Cleaning build files"
	rm -rf $(DRIVERS_PATH)/obj
	rm -rf $(IMAGE_DRIVERS_PATH)/*.ddf

