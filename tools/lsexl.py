#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import sys
import struct
import argparse

DEX_MAGIC = 0x58454400  # "DEX\0"
HDR_SIZE = 0x100

# Header offsets (u32, little-endian)
OFF_ENTRY_OFF = 0x0C
OFF_TEXT_OFF = 0x10
OFF_TEXT_LEN = 0x14
OFF_RO_OFF = 0x18
OFF_RO_LEN = 0x1C
OFF_DATA_OFF = 0x20
OFF_DATA_LEN = 0x24
OFF_BSS_LEN = 0x28
OFF_IMPORT_OFF = 0x2C
OFF_IMPORT_CNT = 0x30
OFF_RELOC_OFF = 0x34
OFF_RELOC_CNT = 0x38
OFF_SYMTAB_OFF = 0x3C
OFF_SYMTAB_CNT = 0x40
OFF_STRTAB_OFF = 0x44
OFF_STRTAB_LEN = 0x48


def u32(buf, off):
    value = struct.unpack_from("<I", buf, off)[0]

    return value


def read_hdr(f):
    hdr = f.read(HDR_SIZE)

    if len(hdr) != HDR_SIZE:
        raise ValueError("file is shorter than header (0x100)")

    if u32(hdr, 0x00) != DEX_MAGIC:
        raise ValueError("not a DEX/EXL file (bad magic)")

    return hdr


def read_block(f, off, length):
    if off == 0 or length == 0:

        return b""

    f.seek(off)

    return f.read(length)


def cstr_at(buf, off):
    if off >= len(buf):

        return ""

    end = buf.find(b"\x00", off)

    if end < 0:
        end = len(buf)

    s = buf[off:end].decode("utf-8", errors="replace")

    return s


def list_imports(f, hdr, strtab):
    imp_off = u32(hdr, OFF_IMPORT_OFF)
    imp_cnt = u32(hdr, OFF_IMPORT_CNT)

    print(f"imports: {imp_cnt} (table @ 0x{imp_off:08x}, strtab @ 0x{u32(hdr, OFF_STRTAB_OFF):08x})")
    print("idx exl_name          symbol              type   (exl_off sym_off)")
    print("--- ----------------- ------------------- ------ ---------------------")

    if imp_off == 0 or imp_cnt == 0:

        return

    f.seek(imp_off)

    for i in range(imp_cnt):
        raw = f.read(16)

        if len(raw) != 16:
            print(f"!! truncated import table at entry {i}", file=sys.stderr)
            break

        exl_off, sym_off, typ, _ = struct.unpack("<IIII", raw)
        exl_nm = cstr_at(strtab, exl_off)
        sym_nm = cstr_at(strtab, sym_off)
        kind = "func" if typ == 0 else "obj"

        print(f"{i:3d} {exl_nm:<17} {sym_nm:<19} {kind:<6} (0x{exl_off:06x} 0x{sym_off:06x})")


def list_exports(f, hdr, strtab):
    sym_off = u32(hdr, OFF_SYMTAB_OFF)
    sym_cnt = u32(hdr, OFF_SYMTAB_CNT)

    if sym_off == 0 or sym_cnt == 0:
        print("\nexports: 0")

        return

    print(f"\nexports: {sym_cnt} (table @ 0x{sym_off:08x})")
    print("idx name                 value       type")
    print("--- -------------------- ----------  ----")

    f.seek(sym_off)

    for i in range(sym_cnt):
        raw = f.read(12)

        if len(raw) != 12:
            print(f"!! truncated symbol table at entry {i}", file=sys.stderr)
            break

        name_off, val_off, typ = struct.unpack("<III", raw)
        name = cstr_at(strtab, name_off)
        t = "func" if typ == 0 else "obj"

        print(f"{i:3d} {name:<20} 0x{val_off:08x} {t}")


def main():
    ap = argparse.ArgumentParser(description="List imports and exports in an EXL/DEX file")
    ap.add_argument("path", help="path to .exl/.dex file")
    args = ap.parse_args()

    with open(args.path, "rb") as f:
        hdr = read_hdr(f)

        strtab_off = u32(hdr, OFF_STRTAB_OFF)
        strtab_len = u32(hdr, OFF_STRTAB_LEN)
        strtab = read_block(f, strtab_off, strtab_len)

        list_imports(f, hdr, strtab)
        list_exports(f, hdr, strtab)


if __name__ == "__main__":
    try:
        main()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

