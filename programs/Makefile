# Quiet top-level builder: C -> .o -> ld -r -> .dex
SHELL        := /bin/sh
.ONESHELL:
.SHELLFLAGS  := -eu -o pipefail -c
.SILENT:

# Toolchain
CC           := i386-elf-gcc
LD           := i386-elf-ld
PYTHON       := python3
ELF2DEX      := ../tools/elf2dex.py

# Loggfil (i samma katalog som denna Makefile)
LOGFILE      := $(CURDIR)/build_progs.txt

# OBS: ingen --gc-sections, ingen -s/strip
CFLAGS       := -ffreestanding -nostdlib -Wall -Wextra -O2 -I../DiffC/include/
LDFLAGS      := -r

# Kataloger och output
BUILDDIR     := build
DEXDIR       := dex
IMAGEDIR     := ../image/programs

# Default EXL att länka mot (måste finnas i image/system/exls/)
DEFAULT_EXL  := diffc.exl

# Valfri symbolkarta för EXL (lämna tom om du inte har en)
# Ex: make SYM2EXL=../tools/libmap.json
SYM2EXL      :=

# Programkataloger (alla underkataloger utom "common" om du har en sådan)
PROGDIRS     := $(filter-out common,$(patsubst %/,%,$(wildcard */)))

# Minimal ELF-storlek (bytes) för att varna om något ser trasigt ut
MIN_ELF_SIZE := 256

.PHONY: all progs clean

all: progs

progs:
	@echo "[Programs] Compiling all programs"
	@echo -n > "$(LOGFILE)"
	@for dir in $(PROGDIRS); do \
		if [ -f "$$dir/Makefile" ]; then \
			$(MAKE) -C "$$dir" -s; \
			if [ -f "$$dir/$(DEXDIR)/$$dir.dex" ]; then \
				install -D -m 0644 "$$dir/$(DEXDIR)/$$dir.dex" "$(IMAGEDIR)/$$dir/$$dir.dex"; \
				echo "$$dir: OK (sub-make)"; \
			else \
				echo "$$dir: inget .dex hittades (sub-make)"; \
			fi; \
		else \
			src=""; \
			if   [ -f "$$dir/main.c" ]; then src="$$dir/main.c"; \
			elif [ -f "$$dir/$$dir.c" ];  then src="$$dir/$$dir.c";  fi; \
			if [ -z "$$src" ]; then \
				echo "$$dir: hoppar över (saknar $$dir/main.c eller $$dir/$$dir.c)"; \
				continue; \
			fi; \
			mkdir -p "$(BUILDDIR)/$$dir" "$(DEXDIR)" "$(IMAGEDIR)/$$dir"; \
			$(CC) $(CFLAGS) -c "$$src" -o "$(BUILDDIR)/$$dir/$$(basename "$$src" .c).o"; \
			$(LD) $(LDFLAGS) -o "$(BUILDDIR)/$$dir/prog.elf" "$(BUILDDIR)/$$dir/$$(basename "$$src" .c).o"; \
			if ! nm -n "$(BUILDDIR)/$$dir/prog.elf" | grep -E ' main$$|_start$$' >/dev/null; then \
				echo "$$dir: ERROR: saknar main/_start i prog.elf" >&2; exit 1; \
			fi; \
			sz=$$(stat -c %s "$(BUILDDIR)/$$dir/prog.elf"); \
			[ $$sz -lt $(MIN_ELF_SIZE) ] && echo "$$dir: warn: prog.elf liten ($$sz B)" || true; \
			if [ -n "$(SYM2EXL)" ] && [ -f "$(SYM2EXL)" ]; then \
				( \
					$(PYTHON) "$(ELF2DEX)" "$(BUILDDIR)/$$dir/prog.elf" -o "$(DEXDIR)/$$dir.dex" \
						--default-exl "$(DEFAULT_EXL)" --sym2exl "$(SYM2EXL)"; \
				) 2>&1 | tee -a "$(LOGFILE)"; \
			else \
				( \
					$(PYTHON) "$(ELF2DEX)" "$(BUILDDIR)/$$dir/prog.elf" -o "$(DEXDIR)/$$dir.dex" \
						--default-exl "$(DEFAULT_EXL)"; \
				) 2>&1 | tee -a "$(LOGFILE)"; \
			fi; \
			install -m 0644 "$(DEXDIR)/$$dir.dex" "$(IMAGEDIR)/$$dir/$$dir.dex"; \
			echo "$$dir: OK"; \
		fi; \
	done

clean:
	@rm -rf "$(BUILDDIR)" "$(DEXDIR)"
	@for d in $(PROGDIRS); do rm -f "$(IMAGEDIR)/$$d/$$d.dex"; done

