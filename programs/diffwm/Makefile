CC        := i386-elf-gcc
PYTHON    := python3

CFLAGS    := -ffreestanding -nostdlib -O0 -m32 -fno-pic -no-pie \
             -I../../exls/DiffC/include -I../../exls/DiffWM/includes \
             -I../../exls/DiffFonts/include -I../../exls/DiffTGA/include \
             -Wall -Wextra -fno-pic

ELFDUMP   := ../../tools/elfdump
ELF2DEX   := ../../tools/elf2dex.py
GEN_IMPORTS := ../../tools/gen_imports.py

OUT_ROOT  := ../../image/programs
LIBMAP    := ../libmap.json
DEFAULT_EXL := diffc.exl

# All source files in this directory
SRCS      := diffwm.c event.c theme.c titlebar.c
OBJS      := $(SRCS:%.c=build/%.o)
TARGET    := diffwm
HEADERS   := ../../exls/DiffWM/includes/diffwm/protocol.h
LOCAL_HEADERS := wm_internal.h event.h theme.h settings.h titlebar.h

.PHONY: all clean

all: $(OUT_ROOT)/$(TARGET)/$(TARGET).dex

build/%.o: %.c $(HEADERS) $(LOCAL_HEADERS)
	@mkdir -p build
	$(CC) $(CFLAGS) -c $< -o $@

# Link all objects into a single ELF
build/$(TARGET).elf: $(OBJS)
	$(CC) $(CFLAGS) -r -o $@ $(OBJS)

$(OUT_ROOT)/$(TARGET)/$(TARGET).dex: build/$(TARGET).elf $(LIBMAP)
	@mkdir -p $(OUT_ROOT)/$(TARGET)
	$(PYTHON) $(GEN_IMPORTS) build/$(TARGET).elf build $(LIBMAP) $(DEFAULT_EXL)
	$(ELFDUMP) build/$(TARGET).elf build/dump.txt
	$(PYTHON) $(ELF2DEX) build/dump.txt build/$(TARGET).elf \
		$(OUT_ROOT)/$(TARGET)/$(TARGET).dex --default-exl $(DEFAULT_EXL) \
		--imports-map build/imports_map.txt --verbose
	@cp -f *.bin $(OUT_ROOT)/$(TARGET)/ 2>/dev/null || true
	@echo "[OUT]  $(OUT_ROOT)/$(TARGET)/$(TARGET).dex"

clean:
	rm -rf build
	rm -f $(OUT_ROOT)/$(TARGET)/$(TARGET).dex
