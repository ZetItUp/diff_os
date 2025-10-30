CC        ?= i386-elf-gcc
LD        ?= ld
PYTHON    ?= python3

TOOLS       := ../../tools
ELFDUMP     := $(TOOLS)/elfdump
ELF2DEX     := $(TOOLS)/elf2dex.py
GEN_IMPORTS := $(TOOLS)/gen_imports.py
EXTRACT_TEXT:= $(TOOLS)/text_extract.py

OUT_ROOT  := ../../image/games
OUT_DIR   := $(OUT_ROOT)/doom
OUT       := $(OUT_DIR)/doom.dex

# Byggkataloger
BUILDDIR  := build
OBJDIR    := $(BUILDDIR)/obj

# Per-projekt libmap skrivs i build/
LIBMAP    := $(BUILDDIR)/libmap.json

DG_WIDTH  ?= 640
DG_HEIGHT ?= 400

CFLAGS := -ffreestanding -nostdlib -O2 -m32 -fno-pic -no-pie \
		  -mno-mmx -mno-sse -mno-sse2 -mno-sse3 -mno-ssse3 \
          -mno-sse4.1 -mno-sse4.2 -mno-avx -mno-avx2 -mno-fma \
		  -fno-asynchronous-unwind-tables -fno-unwind-tables \
          -Wall -Wextra \
          -I../../DiffC/include -I. \
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
	$(LD) -m elf_i386 -r -o $@ $(OBJS)

# Dumpa ELF (frivilligt – kvar för diagnos)
$(BUILDDIR)/dump.txt: $(SUPEROBJ) | $(BUILDDIR)
	@echo "[ELFDUMP] $<"
	$(ELFDUMP) $(SUPEROBJ) $@

# NYTT: extrahera rå .text så gen_imports ALLTID har något att skanna
$(BUILDDIR)/text.bin: $(SUPEROBJ) | $(BUILDDIR)
	@echo "[TEXT]  $@"
	$(PYTHON) $(EXTRACT_TEXT) $(SUPEROBJ) $@

# Generera imports + libmap i build/
# Viktigt: bero på text.bin (så gen_imports kan läsa build/text.bin)
$(BUILDDIR)/imports.stamp: $(SUPEROBJ) $(BUILDDIR)/text.bin | $(BUILDDIR)
	@echo "[GEN] imports"
	# 5:e argumentet 'exit' = fallback-symbol för alla okända PC32-nycklar
	$(PYTHON) $(GEN_IMPORTS) $(SUPEROBJ) $(BUILDDIR) $(LIBMAP) diffc exit
	@touch $@

# Bygg DEX, mata in libmap så PC32-hoppen kan lösas
$(OUT): $(SUPEROBJ) $(BUILDDIR)/imports.stamp $(BUILDDIR)/dump.txt | $(OUT_DIR)
	@echo "[DEX] $@"
	$(PYTHON) $(ELF2DEX) $(BUILDDIR)/dump.txt $(SUPEROBJ) $(OUT) \
		--default-exl diffc.exl --verbose \
		--entry main --map-undef 3=__stack_chk_fail \
		--pc32-libmap $(LIBMAP)
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

