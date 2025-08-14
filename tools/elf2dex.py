#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import struct
import sys

# DEX constants
DEX_MAGIC = 0x58454400  # "DEX\0"
DEX_MAJ = 1
DEX_MIN = 0

DEX_ABS32 = 0
DEX_PC32 = 2
DEX_REL = 8

# ELF i386 relocation types
R_386_NONE = 0
R_386_32 = 1
R_386_PC32 = 2
R_386_PLT32 = 4

FILE_ALIGN = 1
HDR_SIZE = 0x100
MAX_IMP = 256


def align_up(x, a):

    return (x + (a - 1)) & ~(a - 1)


def _to_int(s, base=0):
    s = s.strip().rstrip(",")

    if s.startswith(("0x", "0X")):

        return int(s, 16)

    return int(s or "0", base or 10)


def parse_dump(path):
    sections = {}   # idx -> {name, off, size, info}
    symbols = []    # [{name, value, shndx}]
    relocs = []     # [{relsec, offset, type, symidx, symname, target_secidx}]

    with open(path, "r", encoding="utf-8") as f:

        for raw in f:
            line = raw.strip()

            if not line:
                continue

            if line.startswith("SECTION "):
                kv = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
                idx = _to_int(kv.get("idx", "0"))
                sections[idx] = {
                    "idx": idx,
                    "name": kv.get("name", ""),
                    "off": _to_int(kv.get("off", "0"), 16),
                    "size": _to_int(kv.get("size", "0"), 16),
                    "info": _to_int(kv.get("info", "0")),
                }

            elif line.startswith("SYMBOL "):
                kv = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
                symbols.append({
                    "name": kv.get("name", ""),
                    "value": _to_int(kv.get("value", "0"), 16),
                    "shndx": _to_int(kv.get("shndx", "-1")),
                })

            elif line.startswith("RELOC "):
                kv = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
                try:
                    symidx = int(kv.get("symidx", "-1"))
                except ValueError:
                    symidx = -1
                t = kv.get("type", "0")
                if t.startswith("R_386_PC32"):
                    et = R_386_PC32
                elif t.startswith("R_386_PLT32"):
                    et = R_386_PLT32
                elif t.startswith("R_386_32"):
                    et = R_386_32
                else:
                    try:
                        et = _to_int(t)
                    except Exception:
                        et = -1
                relocs.append({
                    "relsec": _to_int(kv.get("secidx", "0")),
                    "offset": _to_int(kv.get("offset", "0"), 16),
                    "type": et,
                    "symidx": symidx,
                    "symname": kv.get("symname", ""),
                })

    # Map relocation section -> target section via SECTION.info
    for r in relocs:
        r["target_secidx"] = sections.get(r["relsec"], {}).get("info", 0)

    return sections, symbols, relocs


def read_bytes(path, off, size):
    if size == 0:

        return b""

    with open(path, "rb") as f:
        f.seek(off)

        return f.read(size)


class StrTab:
    def __init__(self):
        self.buf = bytearray(b"\x00")
        self.map = {}

    def add(self, s: str) -> int:
        if s in self.map:

            return self.map[s]

        off = len(self.buf)
        self.buf.extend(s.encode() + b"\x00")
        self.map[s] = off

        return off

    def bytes(self) -> bytes:

        return bytes(self.buf)


def build_dex(dumpfile, elffile, outfile, default_exl, verbose):
    sections, symbols, relocs = parse_dump(dumpfile)

    # Collect section bytes
    text = ro = dat = b""
    bss_size = 0
    text_secidx = None

    for s in sections.values():
        if s["name"] == ".text":
            text = read_bytes(elffile, s["off"], s["size"])
            text_secidx = s["idx"]

        elif s["name"] == ".rodata":
            ro = read_bytes(elffile, s["off"], s["size"])

        elif s["name"] == ".data":
            dat = read_bytes(elffile, s["off"], s["size"])

        elif s["name"] == ".bss":
            bss_size = s["size"]

    # In-file layout
    text_off = 0x100
    ro_off = align_up(text_off + len(text), FILE_ALIGN)
    data_off = align_up(ro_off + len(ro), FILE_ALIGN)

    text_buf = bytearray(text)
    ro_buf = bytearray(ro)
    dat_buf = bytearray(dat)

    def base_for_secidx(secidx):
        name = sections.get(secidx, {}).get("name", "")

        if name == ".text":

            return text_off, text_buf

        if name == ".rodata":

            return ro_off, ro_buf

        if name == ".data":

            return data_off, dat_buf

        if name == ".bss":

            return data_off + len(dat_buf), None

        return None, None

    strtab = StrTab()

    if default_exl:
        strtab.add(default_exl)

    # Unique imports (functions and objects)
    imports = []        # list of tuples: (exl_off, sym_off, type, 0)
    import_keys = set()

    def ensure_import(symname: str, is_func=True):
        exlname = default_exl or "diffc.exl"
        key = (exlname, symname, 0 if is_func else 1)

        if key in import_keys:
            e = strtab.add(exlname)
            s = strtab.add(symname)

            for i, (E, S, t, _) in enumerate(imports):
                if E == e and S == s and t == (0 if is_func else 1):

                    return i

        e_off = strtab.add(exlname)
        s_off = strtab.add(symname)
        t = 0 if is_func else 1
        imports.append((e_off, s_off, t, 0))
        import_keys.add(key)

        return len(imports) - 1

    # Pre-pass: only undefined symbols that are actually referenced
    used_undef = set()

    for r in relocs:
        si = r["symidx"]
        if 0 <= si < len(symbols) and symbols[si]["shndx"] == 0 and symbols[si]["name"]:
            used_undef.add(symbols[si]["name"])

    for name in sorted(used_undef):
        ensure_import(name, True)

    if len(imports) > MAX_IMP:
        print(f"[FATAL] too many imports: {len(imports)} > {MAX_IMP}")
        sys.exit(1)

    # DEX relocation table
    reloc_table = []  # (img_off, sym_or_idx, dex_type, 0)

    for r in relocs:
        tgt_base, tgt_buf = base_for_secidx(r["target_secidx"])

        if tgt_buf is None:
            if verbose:
                print(f"[SKIP] reloc target secidx={r['target_secidx']} unsupported")
            continue

        raw_off = r["offset"]

        if raw_off + 4 > len(tgt_buf):
            if verbose:
                print(f"[SKIP] reloc off OOR: 0x{raw_off:x}")
            continue

        img_off = tgt_base + raw_off
        etype = r["type"]
        si = r["symidx"]
        sym = symbols[si] if 0 <= si < len(symbols) else None
        name = (r["symname"] or (sym["name"] if sym else ""))
        sect_name = sections.get(r["target_secidx"], {}).get("name", "")

        if etype in (R_386_PC32, R_386_PLT32):
            idx = ensure_import(name or f"@{si}", True)
            reloc_table.append((img_off, idx, DEX_PC32, 0))

            if verbose:
                print(f"[PC32] site_off=0x{img_off:08x} target='{name}' -> DEX_PC32 (idx={idx})")

            continue

        if etype == R_386_32:
            A = struct.unpack_from("<I", tgt_buf, raw_off)[0]

            if sym and sym["shndx"] != 0:
                # Local symbol -> make it image-relative (REL)
                src_base, _ = base_for_secidx(sym["shndx"])

                if src_base is None:
                    if verbose:
                        print(f"[SKIP] ABS32 rel to unknown shndx={sym['shndx']}")
                    continue

                init = (src_base + sym["value"] + A) & 0xffffffff
                struct.pack_into("<I", tgt_buf, raw_off, init)
                reloc_table.append((img_off, 0, DEX_REL, 0))

                if verbose:
                    print(
                        f"[ABS32 rel] sect={sect_name} site_off=0x{img_off:08x} "
                        f"A=0x{A:08x} S=0x{sym['value']:08x} -> old=0x{init:08x} DEX_REL"
                    )

                if verbose and sect_name == ".text" and init < 0x2000:
                    print(f"[WARN] RELATIVE in .text old=0x{init:x} looks small (ok if really within .text)")

            elif sym and sym["shndx"] == 0:
                # External -> ABS32 import
                idx = ensure_import(name or f"@{si}", False)
                reloc_table.append((img_off, idx, DEX_ABS32, 0))

                if verbose:
                    print(
                        f"[ABS32 ext] sect={sect_name} site_off=0x{img_off:08x} "
                        f"A=0x{A:08x} sym='{name}' -> DEX_ABS32 (idx={idx})"
                    )

            else:
                # No symbol -> treat as data_off + A (still REL)
                init = (data_off + A) & 0xffffffff
                struct.pack_into("<I", tgt_buf, raw_off, init)
                reloc_table.append((img_off, 0, DEX_REL, 0))

                if verbose:
                    print(
                        f"[ABS32 no-sym] sect={sect_name} site_off=0x{img_off:08x} "
                        f"A=0x{A:08x} -> old=data_off+A=0x{init:08x} DEX_REL"
                    )

            continue

        if verbose:
            print(f"[WARN] Unknown ELF reloc type {etype} at off=0x{raw_off:08x}")

    # Choose entry symbol (main, then _dex_entry, then _start)
    entry_off = text_off

    if text_secidx is not None:

        for cand in ("main", "_dex_entry", "_start"):
            found = next((s for s in symbols if s["name"] == cand and s["shndx"] == text_secidx), None)

            if found:
                entry_off = text_off + (found["value"] or 0)

                if verbose:
                    print(f"[ENTRY] symbol='{cand}' at .text+0x{found['value']:x} -> entry_off=0x{entry_off:08x}")

                break

    if verbose and entry_off == text_off:
        print(f"[ENTRY] fallback: start of .text -> 0x{entry_off:08x}")

    # Final bytes
    text = bytes(text_buf)
    ro = bytes(ro_buf)
    dat = bytes(dat_buf)

    # Table offsets (aligned after data)
    cur = align_up(data_off + len(dat), FILE_ALIGN)
    import_off = cur
    cur += 16 * len(imports)
    reloc_off = cur
    cur += 16 * len(reloc_table)
    symtab_off = cur
    cur += 0
    strtab_b = strtab.bytes()
    strtab_off = cur
    cur += len(strtab_b)

    # Header
    hdr = bytearray(HDR_SIZE)

    def w32(o, v):
        struct.pack_into("<I", hdr, o, v & 0xFFFFFFFF)

    w32(0x00, DEX_MAGIC)
    w32(0x04, DEX_MAJ)
    w32(0x08, DEX_MIN)
    w32(0x0C, entry_off)
    w32(0x10, text_off)
    w32(0x14, len(text))
    w32(0x18, ro_off)
    w32(0x1C, len(ro))
    w32(0x20, data_off)
    w32(0x24, len(dat))
    w32(0x28, bss_size)
    w32(0x2C, import_off)
    w32(0x30, len(imports))
    w32(0x34, reloc_off)
    w32(0x38, len(reloc_table))
    w32(0x3C, symtab_off)
    w32(0x40, 0)
    w32(0x44, strtab_off)
    w32(0x48, len(strtab_b))

    # Pad file to an absolute offset
    def pad_to(f, ofs):
        curpos = f.tell()

        if curpos > ofs:
            raise RuntimeError(f"layout error: cur=0x{curpos:x} > want=0x{ofs:x}")

        if curpos < ofs:
            f.write(b"\x00" * (ofs - curpos))

    # Write file
    with open(outfile, "wb") as f:
        # Header + sections (already padded to ro_off/data_off)
        f.write(hdr)
        f.write(text)
        pad_to(f, ro_off)
        f.write(ro)
        pad_to(f, data_off)
        f.write(dat)

        # Import table
        pad_to(f, import_off)

        for (e_off, s_off, t, z) in imports:
            f.write(struct.pack("<IIII", e_off, s_off, t, z))

        # Relocation table
        pad_to(f, reloc_off)

        for (off, symi, t, z) in reloc_table:
            f.write(struct.pack("<IIII", off, symi, t, z))

        # String table
        pad_to(f, strtab_off)
        f.write(strtab_b)

    if verbose:
        print("=== DEX HEADER VALUES ===")
        print(f"magic          = 0x{DEX_MAGIC:08x}")
        print(f"text_off       = 0x{text_off:08x} ({len(text)})")
        print(f"rodata_off     = 0x{ro_off:08x} ({len(ro)})")
        print(f"data_off       = 0x{data_off:08x} ({len(dat)})")
        print(f"bss_size       = 0x{bss_size:08x} ({bss_size})")
        print(f"import_off     = 0x{import_off:08x} (cnt={len(imports)})")
        print(f"reloc_off      = 0x{reloc_off:08x} (cnt={len(reloc_table)})")
        print(f"strtab_off     = 0x{strtab_off:08x} (sz={len(strtab_b)})")
        print(f"entry_offset   = 0x{entry_off:08x}")
        print("Imports:")

        inv = {v: k for (k, v) in strtab.map.items()}

        for i, (e_off, s_off, t, _) in enumerate(imports):
            print(f"[{i}] exl='{inv.get(e_off, '?')}' off=0x{e_off:x}  sym='{inv.get(s_off, '?')}' off=0x{s_off:x}  type={t}")

        print("Relocations (DEX):")

        for (off, symi, t, _) in reloc_table:
            symtxt = ""
            if t in (DEX_ABS32, DEX_PC32) and 0 <= symi < len(imports):
                so = imports[symi][1]
                symtxt = inv.get(so, "")
            print(f"off=0x{off:08x} type={t} sym='{symtxt}'")


def main():
    ap = argparse.ArgumentParser(description="Convert elfdump output to a DEX file (i386).")
    ap.add_argument("dumpfile", help="elfdump text output")
    ap.add_argument("elffile", help="source ELF file to read section bytes from")
    ap.add_argument("outfile", help="output .dex file")
    ap.add_argument("--default-exl", default="diffc.exl", help="EXL name to bind imports to (default: diffc.exl)")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    build_dex(args.dumpfile, args.elffile, args.outfile, args.default_exl, args.verbose)


if __name__ == "__main__":
    main()

