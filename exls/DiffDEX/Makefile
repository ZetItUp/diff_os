# DiffDEX - DEX utilities for userland (diffdex.exl)

CC        := i386-elf-gcc
LD        := i386-elf-ld
PYTHON    := python3
ELF2DEX   := ../DiffC/elf2dexlib.py

CFLAGS    := -ffreestanding -nostdlib -Wall -Wextra -O2 -Iinclude/ -I../DiffC/include -I../../kernel/includes
SRCDIR    := source
OBJDIR    := build
EXLDIR    := exls
IMAGE_EXL := ../../image/system/exls

LIBNAME   := diffdex.exl
VERBOSE   = 1
IMPORT_EXL ?= diffc.exl

DEX_HEADER_SRC := ../../kernel/includes/dex/dex.h
DEX_HEADER_DST := include/dex/dex.h

rwildcard = $(foreach d,$(wildcard $(1)/*),$(call rwildcard,$(d),$(2))) $(wildcard $(1)/$(2))
SRCS      := $(call rwildcard,$(SRCDIR),*.c)
OBJS      := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean exldir image_exl copy_dex_header

all: $(EXLDIR)/$(LIBNAME) image_exl

copy_dex_header: $(DEX_HEADER_DST)

$(DEX_HEADER_DST): $(DEX_HEADER_SRC)
	@mkdir -p $(dir $@)
	@cp $< $@

$(OBJDIR)/%.o: $(SRCDIR)/%.c $(DEX_HEADER_DST)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/libdiffdex.elf: $(OBJS)
	$(LD) -r -o $@ $^

exldir:
	@mkdir -p $(EXLDIR)

$(EXLDIR)/$(LIBNAME): $(OBJDIR)/libdiffdex.elf exldir $(ELF2DEX) copy_dex_header
	@rm -f $@
	$(PYTHON) $(ELF2DEX) $< $@ $(LIBNAME) \
		$(if $(IMPORT_EXL),--import-exl $(IMPORT_EXL)) \
		$(if $(VERBOSE),--verbose)

image_exl: $(EXLDIR)/$(LIBNAME)
	@mkdir -p $(IMAGE_EXL)
	cp $< $(IMAGE_EXL)/

clean:
	rm -rf $(OBJDIR) $(EXLDIR) $(IMAGE_EXL)/$(LIBNAME) $(DEX_HEADER_DST)
