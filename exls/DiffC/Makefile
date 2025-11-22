# DiffC - Minimal libc for Different OS (EN FIL: diffc.exl)

CC        := i386-elf-gcc
LD        := i386-elf-ld
PYTHON    := python3
ELF2DEX   := elf2dexlib.py

CFLAGS    := -ffreestanding -nostdlib -Wall -Wextra -O0 -Iinclude/
SRCDIR    := source
OBJDIR    := build
EXLDIR    := exls
IMAGE_EXL := ../../image/system/exls

LIBNAME   := diffc.exl
VERBOSE   = 1
IMPORT_EXL ?=

# --- Rekursiv wildcard för alla .c under source/
rwildcard = $(foreach d,$(wildcard $(1)/*),$(call rwildcard,$(d),$(2))) $(wildcard $(1)/$(2))
SRCS      := $(call rwildcard,$(SRCDIR),*.c)

OBJS      := $(SRCS:$(SRCDIR)/%.c=$(OBJDIR)/%.o)

.PHONY: all clean exldir image_exl

all: $(EXLDIR)/$(LIBNAME) image_exl

print:
	@echo SRCS=$(SRCS)
	@echo OBJS=$(OBJS)

# Byggregel som funkar för undermappar
$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/libdiffc.elf: $(OBJS)
	$(LD) -r -o $@ $^

exldir:
	@mkdir -p $(EXLDIR)

# Bygg EXL från ELF
$(EXLDIR)/$(LIBNAME): $(OBJDIR)/libdiffc.elf exldir $(ELF2DEX)
	@rm -f $@
	$(PYTHON) $(ELF2DEX) $< $@ $(LIBNAME) $(if $(IMPORT_EXL),--import-exl $(IMPORT_EXL)) $(if $(VERBOSE),--verbose)

image_exl: $(EXLDIR)/$(LIBNAME)
	@mkdir -p $(IMAGE_EXL)
	cp $< $(IMAGE_EXL)/

clean:
	rm -rf $(OBJDIR) $(EXLDIR) $(IMAGE_EXL)/$(LIBNAME)

