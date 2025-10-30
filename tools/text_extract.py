#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# extract_text.py <in.o> <out.bin>
# Läser ett ELF32 little-endian objekt och dumpar .text-sektionen som rå bytes.

import sys, struct
from pathlib import Path

ELF_HDR_FMT = "<16sHHIIIIIHHHHHH"   # ELF32
SHDR_FMT    = "<IIIIIIIIII"         # Elf32_Shdr

def die(msg):
    print(f"[extract_text] ERROR: {msg}", file=sys.stderr)
    sys.exit(1)

def read_at(f, off, size):
    f.seek(off)
    b = f.read(size)
    if len(b) != size:
        die(f"short read at {off} (wanted {size}, got {len(b)})")
    return b

def main():
    if len(sys.argv) != 3:
        print("usage: extract_text.py <in.o> <out.bin>", file=sys.stderr)
        sys.exit(2)

    src = Path(sys.argv[1])
    dst = Path(sys.argv[2])

    with open(src, "rb") as f:
        ehdr = read_at(f, 0, struct.calcsize(ELF_HDR_FMT))
        (e_ident, e_type, e_machine, e_version, e_entry, e_phoff, e_shoff,
         e_flags, e_ehsize, e_phentsize, e_phnum, e_shentsize, e_shnum,
         e_shstrndx) = struct.unpack(ELF_HDR_FMT, ehdr)

        if e_ident[:4] != b"\x7fELF":
            die("not an ELF file")
        if e_ident[4] != 1:  # EI_CLASS = 1 => 32-bit
            die("not ELF32")
        if e_ident[5] != 1:  # EI_DATA = 1 => little-endian
            die("not little-endian")
        if e_shoff == 0 or e_shnum == 0:
            die("no section headers")

        # Läs sektionstabellen
        sh_size = e_shentsize * e_shnum
        sht = read_at(f, e_shoff, sh_size)

        # Läs shstrtab först
        if not (0 <= e_shstrndx < e_shnum):
            die("bad e_shstrndx")
        shstr_off = e_shoff + e_shentsize * e_shstrndx
        shstr = struct.unpack(SHDR_FMT, read_at(f, shstr_off, e_shentsize))
        shstrtab_off = shstr[4]  # sh_offset
        shstrtab_size = shstr[5] # sh_size
        shstrtab = read_at(f, shstrtab_off, shstrtab_size)

        def get_name(off):
            if off >= len(shstrtab): return b""
            end = shstrtab.find(b"\x00", off)
            if end == -1: end = len(shstrtab)
            return shstrtab[off:end]

        # Hitta .text
        text_off = None
        text_size = None

        for i in range(e_shnum):
            sh_off = e_shoff + i * e_shentsize
            sh = struct.unpack(SHDR_FMT, read_at(f, sh_off, e_shentsize))
            sh_name, sh_type, sh_flags, sh_addr, sh_offset, sh_size, sh_link, sh_info, sh_addralign, sh_entsize = sh
            name = get_name(sh_name)
            if name == b".text":
                text_off = sh_offset
                text_size = sh_size
                break

        if text_off is None or text_size is None:
            die("no .text section found")

        code = read_at(f, text_off, text_size)

    dst.parent.mkdir(parents=True, exist_ok=True)
    with open(dst, "wb") as g:
        g.write(code)

    print(f"[extract_text] wrote {len(code)} bytes -> {dst}")

if __name__ == "__main__":
    main()

