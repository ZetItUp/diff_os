CC        := i386-elf-gcc
PYTHON    := python3

CFLAGS    := -ffreestanding -nostdlib -O0 -m32 -fno-pic -no-pie -I../DiffC/include -Wall -Wextra -fno-pic

ELFDUMP   := ../tools/elfdump
ELF2DEX   := ../tools/elf2dex.py
GEN_IMPORTS := ../tools/gen_imports.py

OUT_ROOT  := ../image/programs

PROGRAMS := $(basename $(notdir $(wildcard */*.c)))

LIBMAP   := libmap.json

.PHONY: all $(PROGRAMS) clean list

all: $(PROGRAMS)

$(PROGRAMS):
	@echo "[BUILD] $@"
	@mkdir -p $@/build
	@mkdir -p $(OUT_ROOT)/$@

	$(CC) $(CFLAGS) -c $@/$@.c -o $@/build/$@.o

	$(PYTHON) $(GEN_IMPORTS) $@/build/$@.o $@/build $(LIBMAP) diffc

	$(ELFDUMP) $@/build/$@.o $@/build/dump.txt

	$(PYTHON) $(ELF2DEX) $@/build/dump.txt $@/build/$@.o $(OUT_ROOT)/$@/$@.dex --default-exl diffc.exl --verbose

	@echo "[OUT]  $(OUT_ROOT)/$@/$@.dex"
	@echo "[INFO] artifacts: $@/build/dump.txt, undefined.txt, imports_map.txt, libs.txt"

list:
	@echo $(PROGRAMS)

clean:
	@for dir in $(PROGRAMS); do \
		rm -rf $$dir/build; \
		rm -f $(OUT_ROOT)/$$dir/$$dir.dex; \
	done

