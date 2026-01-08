# DiffHardware - Hardware/Device enumeration library (diffhardware.exl)

CC        := i386-elf-gcc
LD        := i386-elf-ld
PYTHON    := python3
ELF2DEX   := ../DiffC/elf2dexlib.py
GEN_IMPORTS := ../../tools/gen_imports.py
LIBMAP    := ../../programs/libmap.json

CFLAGS    := -ffreestanding -nostdlib -Wall -Wextra -O2 -Iinclude/ -I../DiffC/include
SRCDIR    := source
OBJDIR    := build
EXLDIR    := exls
IMAGE_EXL := ../../image/system/exls

LIBNAME   := diffhardware.exl
VERBOSE   = 1
IMPORT_EXL ?= diffc.exl

rwildcard = $(foreach d,$(wildcard $(1)/*),$(call rwildcard,$(d),$(2))) $(wildcard $(1)/$(2))
SRCS      := $(call rwildcard,$(SRCDIR),*.c)
OBJS      := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean exldir image_exl

all: $(EXLDIR)/$(LIBNAME) image_exl

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/libdiffhardware.elf: $(OBJS)
	$(LD) -r -o $@ $^

$(OBJDIR)/imports.stamp: $(OBJDIR)/libdiffhardware.elf
	@echo "[GEN] imports for DiffHardware"
	$(PYTHON) $(GEN_IMPORTS) $(OBJDIR)/libdiffhardware.elf $(OBJDIR) $(LIBMAP) diffc
	@touch $@

exldir:
	@mkdir -p $(EXLDIR)

$(EXLDIR)/$(LIBNAME): $(OBJDIR)/libdiffhardware.elf $(OBJDIR)/imports.stamp exldir $(ELF2DEX)
	@rm -f $@
	$(PYTHON) $(ELF2DEX) $< $@ $(LIBNAME) \
		$(if $(IMPORT_EXL),--import-exl $(IMPORT_EXL)) \
		--imports-map $(OBJDIR)/imports_map.txt \
		$(if $(VERBOSE),--verbose)

image_exl: $(EXLDIR)/$(LIBNAME)
	@mkdir -p $(IMAGE_EXL)
	cp $< $(IMAGE_EXL)/

clean:
	rm -rf $(OBJDIR) $(EXLDIR) $(IMAGE_EXL)/$(LIBNAME)
