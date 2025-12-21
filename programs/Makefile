CC        := i386-elf-gcc
PYTHON    := python3

CFLAGS    := -ffreestanding -nostdlib -O0 -m32 -fno-pic -no-pie \
             -I../exls/DiffC/include -I../exls/DiffWM/includes -I../exls/DiffFonts/include \
             -I../exls/DiffTGA/include -I../exls/DiffRuntime/include \
             -Wall -Wextra -fno-pic

ELFDUMP   := ../tools/elfdump
ELF2DEX   := ../tools/elf2dex.py
GEN_IMPORTS := ../tools/gen_imports.py

OUT_ROOT  := ../image/programs

# Excluded directories (templates, etc.)
EXCLUDED_DIRS := window_template

# All program directories where <dir>/<dir>.c exists
ALL_PROGRAMS := $(filter-out $(EXCLUDED_DIRS),$(foreach d,$(patsubst %/,%,$(wildcard */)),$(if $(wildcard $d/$d.c),$d)))

# Programs with their own Makefile (multi-file builds)
CUSTOM_PROGRAMS := $(foreach d,$(ALL_PROGRAMS),$(if $(wildcard $d/Makefile),$d))

# Programs without Makefile (single-file builds)
SIMPLE_PROGRAMS := $(filter-out $(CUSTOM_PROGRAMS),$(ALL_PROGRAMS))

LIBMAP   := libmap.json
DEFAULT_EXL := diffc.exl

.PHONY: all $(ALL_PROGRAMS) clean list

all: $(ALL_PROGRAMS)

# Programs with their own Makefile - delegate to their Makefile
$(CUSTOM_PROGRAMS):
	@echo "[BUILD] $@ (custom Makefile)"
	$(MAKE) -C $@

# Simple single-file programs
$(SIMPLE_PROGRAMS):
	@echo "[BUILD] $@"
	@mkdir -p $@/build
	@mkdir -p $(OUT_ROOT)/$@

	$(CC) $(CFLAGS) -c $@/$@.c -o $@/build/$@.o

	$(PYTHON) $(GEN_IMPORTS) $@/build/$@.o $@/build $(LIBMAP) $(DEFAULT_EXL)

	$(ELFDUMP) $@/build/$@.o $@/build/dump.txt

	$(PYTHON) $(ELF2DEX) $@/build/dump.txt $@/build/$@.o \
		$(OUT_ROOT)/$@/$@.dex --default-exl $(DEFAULT_EXL) \
		--imports-map $@/build/imports_map.txt --verbose

	@cp -f $@/*.bin $(OUT_ROOT)/$@/ 2>/dev/null || true

	@echo "[OUT]  $(OUT_ROOT)/$@/$@.dex"
	@echo "[INFO] artifacts: $@/build/dump.txt, undefined.txt, imports_map.txt, libs.txt"

list:
	@echo "All programs: $(ALL_PROGRAMS)"
	@echo "Custom builds: $(CUSTOM_PROGRAMS)"
	@echo "Simple builds: $(SIMPLE_PROGRAMS)"

clean:
	@for dir in $(SIMPLE_PROGRAMS); do \
		rm -rf $$dir/build; \
		rm -f $(OUT_ROOT)/$$dir/$$dir.dex; \
	done
	@for dir in $(CUSTOM_PROGRAMS); do \
		$(MAKE) -C $$dir clean; \
	done
