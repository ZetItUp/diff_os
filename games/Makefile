CC          ?= i386-elf-gcc
PYTHON      ?= python3

CFLAGS := -ffreestanding -nostdlib -O0 -m32 -fno-pic -no-pie \
          -I../DiffC/include -Wall -Wextra

ELFDUMP     := ../tools/elfdump
ELF2DEX     := ../tools/elf2dex.py
GEN_IMPORTS := ../tools/gen_imports.py

OUT_ROOT    := ../image/games

PROGRAMS := $(basename $(notdir $(wildcard */*.c)))

LIBMAP     := libmap.json
DEFAULT_EXL:= diffc.exl

.PHONY: all clean list

all: $(PROGRAMS)

%:
	@echo "[BUILD] $@"
	@if [ -f "$@/Makefile" ]; then \
		echo "[DELEGATE] make -C $@"; \
		$(MAKE) -C $@; \
	elif [ -f "$@/$@.c" ]; then \
		mkdir -p $@/build; \
		mkdir -p $(OUT_ROOT)/$@; \
		$(CC) $(CFLAGS) -c $@/$@.c -o $@/build/$@.o; \
		$(PYTHON) $(GEN_IMPORTS) $@/build/$@.o $@/build $(LIBMAP) diffc; \
		$(ELFDUMP) $@/build/$@.o $@/build/dump.txt; \
		$(PYTHON) $(ELF2DEX) $@/build/dump.txt $@/build/$@.o $(OUT_ROOT)/$@/$@.dex \
			--default-exl $(DEFAULT_EXL) --verbose; \
		echo "[OUT]  $(OUT_ROOT)/$@/$@.dex"; \
		echo "[INFO] artifacts: $@/build/dump.txt, undefined.txt, imports_map.txt, libs.txt"; \
	else \
		echo "[ERROR] Hittar varken $@/Makefile eller $@/$@.c"; \
		exit 1; \
	fi

list:
	@echo $(PROGRAMS)

clean:
	@for dir in $(PROGRAMS); do \
		rm -rf $$dir/build; \
		rm -f $(OUT_ROOT)/$$dir/$$dir.dex; \
	done

