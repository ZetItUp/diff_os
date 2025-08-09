# Självständig build av user-program till DEX + import-info

CC        := i386-elf-gcc
PYTHON    := python3

CFLAGS    := -ffreestanding -nostdlib -O0 -m32 -fno-pic -no-pie -I../DiffC/include -Wall -Wextra -fno-pic

# Verktyg
ELFDUMP   := ../tools/elfdump
ELF2DEX   := ../tools/elf2dex.py
GEN_IMPORTS := ../tools/gen_imports.py

# Var program hamnar
OUT_ROOT  := ../image/programs

# Program = varje mapp som har en <name>/<name>.c
PROGRAMS := $(basename $(notdir $(wildcard */*.c)))

# (Valfri) symbol->lib / lib->symbols karta
LIBMAP   := libmap.json

.PHONY: all $(PROGRAMS) clean list

all: $(PROGRAMS)

# Ex: make hello  ==> hello/hello.c -> hello/build/hello.o -> dump.txt -> hello.dex
$(PROGRAMS):
	@echo "[BUILD] $@"
	@mkdir -p $@/build
	@mkdir -p $(OUT_ROOT)/$@

	$(CC) $(CFLAGS) -c $@/$@.c -o $@/build/$@.o

	# Steg 1: Generera undefined/imports/libs
	$(PYTHON) $(GEN_IMPORTS) $@/build/$@.o $@/build $(LIBMAP) diffc

	# Steg 2: Dumpa ELF-info (utan tredjepartsverktyg)
	$(ELFDUMP) $@/build/$@.o $@/build/dump.txt

	# Steg 3: Bygg DEX från dumpfilen
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

