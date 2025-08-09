# DiffC - Minimal libc for Different OS (EN FIL: diffc.exl)

CC        := i386-elf-gcc
LD        := i386-elf-ld
PYTHON    := python3
# elf2dexlib.py ska ligga där Makefile kan hitta den (t.ex. i den här katalogen)
ELF2DEX   := elf2dexlib.py

CFLAGS    := -ffreestanding -nostdlib -Wall -Wextra -O2 -Iinclude/
SRCDIR    := source
OBJDIR    := build
EXLDIR    := exls
IMAGE_EXL := ../image/system/exls

# Namnet som ska skrivas in i EXL (matcha hur loadern refererar till biblioteket)
LIBNAME   := diffc.exl

# Sätt VERBOSE=1 om du vill se debug från elf2dexlib.py
VERBOSE   ?= 1
# Om detta bibliotek ska importera symboler från ett annat EXL, sätt t.ex.
# IMPORT_EXL=diffc.exl (oftast tomt för diffc själv)
IMPORT_EXL ?=

SRCS      := $(wildcard $(SRCDIR)/*.c)
OBJS      := $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SRCS))

.PHONY: all clean exldir image_exl

all: $(EXLDIR)/$(LIBNAME) image_exl

$(OBJDIR)/%.o: $(SRCDIR)/%.c
	@mkdir -p $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR)/libdiffc.elf: $(OBJS)
	$(LD) -r -o $@ $^

exldir:
	@mkdir -p $(EXLDIR)

# Bygg EXL från ELF med nya elf2dexlib.py
# Beroende på skriptet så att ändringar triggar rebuild
$(EXLDIR)/$(LIBNAME): $(OBJDIR)/libdiffc.elf exldir $(ELF2DEX)
	@rm -f $@
	$(PYTHON) $(ELF2DEX) $< $@ $(LIBNAME) $(if $(IMPORT_EXL),--import-exl $(IMPORT_EXL)) $(if $(VERBOSE),--verbose)

image_exl: $(EXLDIR)/$(LIBNAME)
	@mkdir -p $(IMAGE_EXL)
	cp $< $(IMAGE_EXL)/

clean:
	rm -rf $(OBJDIR) $(EXLDIR) $(IMAGE_EXL)/$(LIBNAME)

