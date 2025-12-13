CC        := i386-elf-gcc
PYTHON    := python3

CFLAGS    := -ffreestanding -nostdlib -O0 -m32 -fno-pic -no-pie \
             -I../exls/DiffC/include -I../exls/DiffWM/includes -I../exls/DiffFonts/include \
             -I../exls/DiffTGA/include \
             -Wall -Wextra -fno-pic

ELFDUMP   := ../tools/elfdump
ELF2DEX   := ../tools/elf2dex.py
GEN_IMPORTS := ../tools/gen_imports.py

OUT_ROOT  := ../image/programs

# Only build directories where <dir>/<dir>.c exists (ignores helper files like theme.c)
PROGRAMS := $(foreach d,$(patsubst %/,%,$(wildcard */)),$(if $(wildcard $d/$d.c),$d))

LIBMAP   := libmap.json
DEFAULT_EXL := diffc.exl

.PHONY: all $(PROGRAMS) clean list

all: $(PROGRAMS)

$(PROGRAMS):
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
	@echo $(PROGRAMS)

clean:
	@for dir in $(PROGRAMS); do \
		rm -rf $$dir/build; \
		rm -f $(OUT_ROOT)/$$dir/$$dir.dex; \
	done
