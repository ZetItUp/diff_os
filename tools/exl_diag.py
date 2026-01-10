#!/usr/bin/env python3
"""
exl_diag.py - Dump and sanity-check a DEX/EXL file.

Usage:
    exl_diag.py <file.exl>

Prints header fields, validates table/section ranges, and lists imports,
relocations, symbols, and strtab excerpts to help debug broken EXLs.
"""

import sys
import struct
from pathlib import Path

DEX_MAGIC = 0x58454400
HDR_SIZE = 0x100

DEX_ABS32 = 0
DEX_PC32 = 2
DEX_RELATIVE = 8

def u32_le(b, off):
    return struct.unpack_from("<I", b, off)[0]

def range_ok(off, sz, max_len):
    if sz == 0:
        return True
    if off > max_len:
        return False
    return (max_len - off) >= sz

def dump_header(hdr):
    print("=== HEADER ===")
    print(f"magic=0x{hdr['magic']:08x} ver={hdr['ver_major']}.{hdr['ver_minor']}")
    print(f"entry_off=0x{hdr['entry_off']:08x}")
    print(f".text  off=0x{hdr['text_off']:08x} sz={hdr['text_sz']}")
    print(f".ro    off=0x{hdr['ro_off']:08x} sz={hdr['ro_sz']}")
    print(f".data  off=0x{hdr['data_off']:08x} sz={hdr['data_sz']}")
    print(f".bss   sz={hdr['bss_sz']}")
    print(f"imports off=0x{hdr['import_off']:08x} cnt={hdr['import_cnt']}")
    print(f"relocs  off=0x{hdr['reloc_off']:08x} cnt={hdr['reloc_cnt']}")
    print(f"symtab  off=0x{hdr['sym_off']:08x} cnt={hdr['sym_cnt']}")
    print(f"strtab  off=0x{hdr['str_off']:08x} sz={hdr['str_sz']}")

def parse_header(blob):
    if len(blob) < HDR_SIZE:
        raise ValueError("file too small for header")
    magic = u32_le(blob, 0)
    if magic != DEX_MAGIC:
        raise ValueError(f"bad magic 0x{magic:08x}")
    return {
        "magic": magic,
        "ver_major": u32_le(blob, 4),
        "ver_minor": u32_le(blob, 8),
        "entry_off": u32_le(blob, 0x0C),
        "text_off": u32_le(blob, 0x10),
        "text_sz": u32_le(blob, 0x14),
        "ro_off": u32_le(blob, 0x18),
        "ro_sz": u32_le(blob, 0x1C),
        "data_off": u32_le(blob, 0x20),
        "data_sz": u32_le(blob, 0x24),
        "bss_sz": u32_le(blob, 0x28),
        "import_off": u32_le(blob, 0x2C),
        "import_cnt": u32_le(blob, 0x30),
        "reloc_off": u32_le(blob, 0x34),
        "reloc_cnt": u32_le(blob, 0x38),
        "sym_off": u32_le(blob, 0x3C),
        "sym_cnt": u32_le(blob, 0x40),
        "str_off": u32_le(blob, 0x44),
        "str_sz": u32_le(blob, 0x48),
    }

def read_imports(blob, hdr, strtab):
    imports = []

    if hdr["import_cnt"] == 0 or hdr["import_off"] == 0:

    return imports
    
    base = hdr["import_off"]
    
    for i in range(hdr["import_cnt"]):
        off = base + i * 16
        exl_off = u32_le(blob, off + 0)
        sym_off = u32_le(blob, off + 4)
        typ = u32_le(blob, off + 8)
        exl = strtab[exl_off:].split(b"\x00", 1)[0].decode("utf-8", "ignore") if exl_off < len(strtab) else f"<bad:{exl_off}>"
        sym = strtab[sym_off:].split(b"\x00", 1)[0].decode("utf-8", "ignore") if sym_off < len(strtab) else f"<bad:{sym_off}>"
        imports.append((i, exl, sym, typ))
    
    return imports

def read_relocs(blob, hdr):
    relocs = []
    
    if hdr["reloc_cnt"] == 0 or hdr["reloc_off"] == 0:
        return relocs
    
    base = hdr["reloc_off"]
    
    for i in range(hdr["reloc_cnt"]):
        off = base + i * 16
        r_off = u32_le(blob, off + 0)
        symidx = u32_le(blob, off + 4)
        typ = u32_le(blob, off + 8)
        relocs.append((i, r_off, symidx, typ))
    
    return relocs

def read_symbols(blob, hdr, strtab):
    syms = []
    
    if hdr["sym_cnt"] == 0 or hdr["sym_off"] == 0:
        return syms
    
    base = hdr["sym_off"]
    
    for i in range(hdr["sym_cnt"]):
        off = base + i * 12
        name_off = u32_le(blob, off + 0)
        val_off = u32_le(blob, off + 4)
        typ = u32_le(blob, off + 8)
        name = strtab[name_off:].split(b"\x00", 1)[0].decode("utf-8", "ignore") if name_off < len(strtab) else f"<bad:{name_off}>"
        syms.append((i, name, val_off, typ))
    
    return syms

def main():
    if len(sys.argv) < 2:
        print(__doc__.strip())
        sys.exit(1)

    path = Path(sys.argv[1])
    data = path.read_bytes()
    hdr = parse_header(data)
    dump_header(hdr)

    # Range checks
    ok = True
    if not range_ok(hdr["text_off"], hdr["text_sz"], len(data)):
        print("ERR: text range OOB")
        ok = False
    if not range_ok(hdr["ro_off"], hdr["ro_sz"], len(data)):
        print("ERR: ro range OOB")
        ok = False
    if not range_ok(hdr["data_off"], hdr["data_sz"], len(data)):
        print("ERR: data range OOB")
        ok = False
    if hdr["import_cnt"] and not range_ok(hdr["import_off"], hdr["import_cnt"] * 16, len(data)):
        print("ERR: import table OOB")
        ok = False
    if hdr["reloc_cnt"] and not range_ok(hdr["reloc_off"], hdr["reloc_cnt"] * 16, len(data)):
        print("ERR: reloc table OOB")
        ok = False
    if hdr["sym_cnt"] and not range_ok(hdr["sym_off"], hdr["sym_cnt"] * 12, len(data)):
        print("ERR: symtab OOB")
        ok = False
    if hdr["str_sz"] and not range_ok(hdr["str_off"], hdr["str_sz"], len(data)):
        print("ERR: strtab OOB")
        ok = False
    if not ok:
        return

    strtab = data[hdr["str_off"]:hdr["str_off"] + hdr["str_sz"]] if hdr["str_sz"] else b""

    imports = read_imports(data, hdr, strtab)
    relocs = read_relocs(data, hdr)
    syms = read_symbols(data, hdr, strtab)

    print("\n=== IMPORTS ===")
    if not imports:
        print("(none)")
    else:
        for idx, exl, sym, typ in imports:
            tname = "func" if typ == 0 else "obj"
            print(f"[{idx:3d}] {exl}:{sym} type={tname}")

    print("\n=== RELOCS ===")
    if not relocs:
        print("(none)")
    else:
        for idx, off, si, typ in relocs:
            tname = {DEX_ABS32: "ABS32", DEX_PC32: "PC32", DEX_RELATIVE: "REL"}.get(typ, f"?{typ}")
            print(f"[{idx:3d}] off=0x{off:08x} symidx={si} type={tname}")

    print("\n=== SYMBOLS ===")
    if not syms:
        print("(none)")
    else:
        for idx, name, val, typ in syms:
            tname = "func" if typ == 0 else "obj"
            print(f"[{idx:3d}] {name:<20} val_off=0x{val:08x} type={tname}")

    print("\n=== STRINGS (first 10) ===")
    if not strtab:
        print("(none)")
    else:
        strs = strtab.split(b"\x00")
        shown = 0
        off = 0
        for s in strs:
            if s or off == 0:  # include empty at offset 0
                txt = s.decode("utf-8", "ignore")
                print(f"@0x{off:08x}: {txt}")
                shown += 1
                if shown >= 10:
                    break
            off += len(s) + 1

if __name__ == "__main__":
    main()
