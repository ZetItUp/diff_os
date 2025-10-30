# DiffC - bygger diffc.exl och loggar elf2exl-output till build_diffc.txt

SHELL        := /bin/sh
.ONESHELL:
.SHELLFLAGS  := -eu -o pipefail -c
.SILENT:

# Loggfil (i samma katalog som denna Makefile)
LOGFILE      := $(CURDIR)/build_diffc.txt

# Verktyg
CC           := i386-elf-gcc
LD           := i386-elf-ld
AR           := i386-elf-ar
PYTHON       := python3
ELF2EXL      := ../tools/elf2exl.py

# Namn och sökvägar
LIBNAME      := diffc.exl
SRCDIR       := source
INCDIR       := include
OBJDIR       := build
EXLDIR       := exls
IMAGE_EXL    := ../image/system/exls

# Flaggor (freestanding lib, inga libc-beroenden)
CFLAGS       := -ffreestanding -fno-builtin -Wall -Wextra -O2 -I$(INCDIR)
LDFLAGS      := -r

# Hitta källor rekursivt
SRCS         := $(shell find $(SRCDIR) -type f -name '*.c')
OBJS         := $(patsubst %.c,$(OBJDIR)/%.o,$(SRCS))
ELF_OUT      := $(OBJDIR)/libdiffc.elf
EXL_OUT      := $(EXLDIR)/$(LIBNAME)

.PHONY: all clean install exldir loginit

all: loginit $(EXL_OUT)
	@mkdir -p "$(IMAGE_EXL)"
	cp "$(EXL_OUT)" "$(IMAGE_EXL)/"

# Truncar loggfilen i början av bygget
loginit:
	@echo -n > "$(LOGFILE)"

# EXL-katalog
exldir:
	@mkdir -p "$(EXLDIR)"

# Byggobjekt
$(OBJDIR)/%.o: %.c
	@mkdir -p "$(dir $@)"
	$(CC) $(CFLAGS) -c "$<" -o "$@"

# Länka ihop till en sammanslagen ELF (relokatbar)
$(ELF_OUT): $(OBJS)
	@mkdir -p "$(dir $@)"
	$(LD) $(LDFLAGS) -o "$@" $(OBJS)

# Konvertera ELF -> EXL och logga all output till build_diffc.txt
# Stöd för valfri SYM2EXL: make SYM2EXL=libmap.json
$(EXL_OUT): $(ELF_OUT) exldir $(ELF2EXL)
	@rm -f "$@"
ifneq ($(strip $(SYM2EXL)),)
	$(PYTHON) "$(ELF2EXL)" "$<" -o "$@" --default-exl "$(LIBNAME)" --sym2exl "$(SYM2EXL)" 2>&1 | tee -a "$(LOGFILE)"
else
	$(PYTHON) "$(ELF2EXL)" "$<" -o "$@" --default-exl "$(LIBNAME)" 2>&1 | tee -a "$(LOGFILE)"
endif
	@echo "EXL klar: $(LIBNAME)"

clean:
	@rm -rf "$(OBJDIR)" "$(EXLDIR)"
	@rm -f "$(IMAGE_EXL)/$(LIBNAME)" 2>/dev/null || true

