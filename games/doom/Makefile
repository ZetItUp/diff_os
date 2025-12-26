CC        ?= i386-elf-gcc
LD        ?= ld
PYTHON    ?= python3

TOOLS       := ../../tools
ELFDUMP     := $(TOOLS)/elfdump
ELF2DEX     := $(TOOLS)/elf2dex.py
GEN_IMPORTS := $(TOOLS)/gen_imports.py
LIBMAP      := ../libmap.json

OUT_ROOT  := ../../image/games
OUT_DIR   := $(OUT_ROOT)/doom
OUT       := $(OUT_DIR)/doom.dex

BUILDDIR  := build
OBJDIR    := $(BUILDDIR)/obj

DG_WIDTH  ?= 640
DG_HEIGHT ?= 400

CFLAGS := -ffreestanding -nostdlib -O2 -m32 -fno-pic -fno-plt -std=gnu11 \
		  -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-ssse3 \
          -mno-sse4.1 -mno-sse4.2 -mno-avx -mno-avx2 -mno-fma \
		  -fno-asynchronous-unwind-tables -fno-unwind-tables \
          -Wall -Wextra \
          -I../../exls/DiffC/include -I../../exls/DiffWM/includes -I../../exls/DiffFonts/include -I../../exls/DiffTGA/include -I. \
          -DDG_WIDTH=$(DG_WIDTH) -DDG_HEIGHT=$(DG_HEIGHT) \
		  -march=i386 -mtune=i386 -fno-builtin -fno-stack-protector

LDFLAGS := -melf_i386 -nostdlib -no-pie

SRCS := $(wildcard *.c)
OBJS := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))

SUPEROBJ := $(BUILDDIR)/doom.o

.PHONY: all clean
all: $(OUT)

$(OBJDIR)/%.o: %.c | $(OBJDIR) $(OUT_DIR)
	@echo "[CC] $<"
	$(CC) $(CFLAGS) -c $< -o $@

$(SUPEROBJ): $(OBJS) | $(BUILDDIR)
	@echo "[LD -r] $@"
	$(LD) -m elf_i386 -r --emit-relocs -o $@ $(OBJS)

$(BUILDDIR)/imports.stamp: $(SUPEROBJ)
	@echo "[GEN] imports"
	$(PYTHON) $(GEN_IMPORTS) $(SUPEROBJ) $(BUILDDIR) $(LIBMAP) diffc diffwm
	@touch $@

$(BUILDDIR)/dump.txt: $(SUPEROBJ)
	@echo "[ELFDUMP] $<"
	$(ELFDUMP) $(SUPEROBJ) $(BUILDDIR)/dump.txt

$(OUT): $(SUPEROBJ) $(BUILDDIR)/imports.stamp $(BUILDDIR)/dump.txt | $(OUT_DIR)
	@echo "[DEX] $@"
	$(PYTHON) $(ELF2DEX) $(BUILDDIR)/dump.txt $(SUPEROBJ) $(OUT) \
		--default-exl diffc.exl --imports-map $(BUILDDIR)/imports_map.txt --verbose
	@echo "[OUT]  $(OUT)"

$(OBJDIR):
	@mkdir -p $(OBJDIR)

$(BUILDDIR):
	@mkdir -p $(BUILDDIR)

$(OUT_DIR):
	@mkdir -p $(OUT_DIR)

clean:
	@echo "[CLEAN] Cleaning up doom"
	@rm -rf $(BUILDDIR)
	@rm -f  $(OUT)
