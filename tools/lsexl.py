#!/usr/bin/env python3
import sys
import struct
import argparse
from collections import defaultdict

DEX_MAGIC = 0x58454400  # "DEX\0"
HDR_SIZE = 0x100

# Header offsets
OFF_MAGIC = 0x00
OFF_VERSION_MAJ = 0x04
OFF_VERSION_MIN = 0x08
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


def show_header(hdr, filename):
    """Display EXL/DEX header information"""
    magic = u32(hdr, OFF_MAGIC)
    ver_maj = u32(hdr, OFF_VERSION_MAJ)
    ver_min = u32(hdr, OFF_VERSION_MIN)

    print(f"=== EXL/DEX File: {filename} ===")
    print(f"Magic:     0x{magic:08x} {'(DEX)' if magic == DEX_MAGIC else '(INVALID!)'}")
    print(f"Version:   {ver_maj}.{ver_min}")
    print(f"Entry:     0x{u32(hdr, OFF_ENTRY_OFF):08x}")
    print()

    # Section information
    print("Sections:")
    text_off = u32(hdr, OFF_TEXT_OFF)
    text_len = u32(hdr, OFF_TEXT_LEN)
    ro_off = u32(hdr, OFF_RO_OFF)
    ro_len = u32(hdr, OFF_RO_LEN)
    data_off = u32(hdr, OFF_DATA_OFF)
    data_len = u32(hdr, OFF_DATA_LEN)
    bss_len = u32(hdr, OFF_BSS_LEN)

    print(f"  .text   offset=0x{text_off:08x} size={text_len:6d} (0x{text_len:05x})")
    print(f"  .rodata offset=0x{ro_off:08x} size={ro_len:6d} (0x{ro_len:05x})")
    print(f"  .data   offset=0x{data_off:08x} size={data_len:6d} (0x{data_len:05x})")
    print(f"  .bss    (runtime)         size={bss_len:6d} (0x{bss_len:05x})")
    print()

    # Tables
    imp_off = u32(hdr, OFF_IMPORT_OFF)
    imp_cnt = u32(hdr, OFF_IMPORT_CNT)
    rel_off = u32(hdr, OFF_RELOC_OFF)
    rel_cnt = u32(hdr, OFF_RELOC_CNT)
    sym_off = u32(hdr, OFF_SYMTAB_OFF)
    sym_cnt = u32(hdr, OFF_SYMTAB_CNT)
    str_off = u32(hdr, OFF_STRTAB_OFF)
    str_len = u32(hdr, OFF_STRTAB_LEN)

    print("Tables:")
    print(f"  imports    offset=0x{imp_off:08x} count={imp_cnt:4d}")
    print(f"  relocs     offset=0x{rel_off:08x} count={rel_cnt:4d}")
    print(f"  symbols    offset=0x{sym_off:08x} count={sym_cnt:4d}")
    print(f"  strtab     offset=0x{str_off:08x} size={str_len:6d}")
    print()


def list_imports(f, hdr, strtab):
    imp_off = u32(hdr, OFF_IMPORT_OFF)
    imp_cnt = u32(hdr, OFF_IMPORT_CNT)

    print(f"Imports: {imp_cnt}")

    if imp_off == 0 or imp_cnt == 0:
        print("  (none)")
        print()
        return

    # Read all imports
    f.seek(imp_off)
    imports = []
    for i in range(imp_cnt):
        raw = f.read(16)
        if len(raw) != 16:
            print(f"!! truncated import table at entry {i}", file=sys.stderr)
            break

        exl_off, sym_off, typ, _ = struct.unpack("<IIII", raw)
        exl_nm = cstr_at(strtab, exl_off)
        sym_nm = cstr_at(strtab, sym_off)
        kind = "func" if typ == 0 else "obj"

        imports.append({
            'idx': i,
            'exl': exl_nm,
            'symbol': sym_nm,
            'type': kind,
            'exl_off': exl_off,
            'sym_off': sym_off
        })

    # Group by library
    by_lib = defaultdict(list)
    for imp in imports:
        by_lib[imp['exl']].append(imp)

    # Display grouped by library
    for lib_name in sorted(by_lib.keys()):
        lib_imports = by_lib[lib_name]
        print(f"\n  From {lib_name} ({len(lib_imports)} symbols):")
        for imp in lib_imports:
            print(f"    [{imp['idx']:3d}] {imp['symbol']:<25} ({imp['type']})")

    print()


def list_exports(f, hdr, strtab):
    sym_off = u32(hdr, OFF_SYMTAB_OFF)
    sym_cnt = u32(hdr, OFF_SYMTAB_CNT)

    print(f"Exports: {sym_cnt}")

    if sym_off == 0 or sym_cnt == 0:
        print("  (none)")
        print()
        return

    f.seek(sym_off)

    funcs = []
    objs = []

    for i in range(sym_cnt):
        raw = f.read(12)

        if len(raw) != 12:
            print(f"!! truncated symbol table at entry {i}", file=sys.stderr)
            break

        name_off, val_off, typ = struct.unpack("<III", raw)
        name = cstr_at(strtab, name_off) 

        if typ == 0:
            funcs.append((i, name, val_off))
        else:
            objs.append((i, name, val_off))

    if funcs:
        print(f"\n  Functions ({len(funcs)}):")
        for idx, name, val in funcs:
            print(f"    [{idx:3d}] {name:<30} @ 0x{val:08x}")

    if objs:
        print(f"\n  Objects ({len(objs)}):")
        for idx, name, val in objs:
            print(f"    [{idx:3d}] {name:<30} @ 0x{val:08x}")

    print()


def list_relocations(f, hdr):
    """Show relocation information"""
    rel_off = u32(hdr, OFF_RELOC_OFF)
    rel_cnt = u32(hdr, OFF_RELOC_CNT)

    print(f"Relocations: {rel_cnt}")

    if rel_off == 0 or rel_cnt == 0:
        print("  (none)")
        print()
        
        return

    f.seek(rel_off)

    type_names = 
    {
        0: "ABS32",
        2: "PC32",
        8: "DEX_RELATIVE"
    }

    by_type = defaultdict(int)

    for i in range(min(rel_cnt, 20)):  # Show first 20
        raw = f.read(16)  # dex_reloc_t is 16 bytes (offset, symbol_idx, type, reserved)
        
        if len(raw) != 16:
            break

        offset, symbol_idx, reloc_type, reserved = struct.unpack("<IIII", raw)
        type_name = type_names.get(reloc_type, f"UNKNOWN({reloc_type})")
        by_type[type_name] += 1

        if i < 10:  # Show first 10 in detail
            print(f"  [{i:3d}] offset=0x{offset:08x} sym_idx={symbol_idx:3d} type={type_name}")

    if rel_cnt > 10:
        print(f"  ... ({rel_cnt - 10} more relocations)")

    print(f"\nRelocation summary:")
    
    for rtype, count in sorted(by_type.items()):
        print(f"  {rtype}: {count}")

    print()


def main():
    ap = argparse.ArgumentParser(description="Inspect EXL/DEX file structure")
    ap.add_argument("path", help="path to .exl/.dex file")
    ap.add_argument("--relocs", "-r", action="store_true", help="show relocation details")
    args = ap.parse_args()

    import os
    filename = os.path.basename(args.path)

    with open(args.path, "rb") as f:
        hdr = read_hdr(f)

        strtab_off = u32(hdr, OFF_STRTAB_OFF)
        strtab_len = u32(hdr, OFF_STRTAB_LEN)
        strtab = read_block(f, strtab_off, strtab_len)

        show_header(hdr, filename)
        list_imports(f, hdr, strtab)
        list_exports(f, hdr, strtab)

        if args.relocs:
            list_relocations(f, hdr)


if __name__ == "__main__":
    try:
        main()

    except Exception as e:
        print(f"ERROR: {e}", file=sys.stderr)
        sys.exit(1)

