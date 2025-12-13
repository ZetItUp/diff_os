#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import os
import struct
import sys

DEX_MAGIC = 0x58454400
DEX_MAJ = 1
DEX_MIN = 0
DEX_RS_MAGIC = 0x53525845  # 'DEXRS' truncated to 4 bytes (EXRS little-endian)

DEX_ABS32 = 0
DEX_PC32 = 2
DEX_REL = 8

R_386_NONE = 0
R_386_32 = 1
R_386_PC32 = 2
R_386_GOT32 = 3
R_386_PLT32 = 4
R_386_RELATIVE = 8
R_386_GOTOFF = 9
R_386_GOTPC = 10
R_386_GOT32X = 43

STB_LOCAL = 0
STB_GLOBAL = 1
STB_WEAK = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC = 2
STT_SECTION = 3
STT_FILE = 4
STT_TLS = 6

FILE_ALIGN = 4
HDR_SIZE = 0x100
MAX_IMP = 4096


def align_up(x, a):
    return (x + (a - 1)) & ~(a - 1)


def _to_int(s, base=0):
    s = (s or "0").strip().rstrip(",")
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    return int(s, base or 10)


def parse_dump(path):
    sections = {}
    symbols = []
    relocs = []
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
                    "addr": _to_int(kv.get("addr", "0"), 16),
                    "info": _to_int(kv.get("info", "0")),
                }
            elif line.startswith("SYMBOL "):
                kv = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
                sval = kv.get("value") or kv.get("value_off") or kv.get("addr")
                symbols.append({
                    "name": kv.get("name", ""),
                    "value": _to_int(sval, 16),
                    "shndx": _to_int(kv.get("shndx", "-1")),
                    "bind": _to_int(kv.get("bind", "0")),
                    "type": _to_int(kv.get("type", "0")),
                    "size": _to_int(kv.get("size", "0"), 16),
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
                elif t.startswith("R_386_GOT32X"):
                    et = R_386_GOT32X
                elif t.startswith("R_386_RELATIVE"):
                    et = R_386_RELATIVE
                elif t.startswith("R_386_GOT32"):
                    et = R_386_GOT32
                elif t.startswith("R_386_GOTOFF"):
                    et = R_386_GOTOFF
                elif t.startswith("R_386_GOTPC"):
                    et = R_386_GOTPC
                elif t.startswith("R_386_32"):
                    et = R_386_32
                else:
                    try:
                        et = _to_int(t)
                    except Exception:
                        et = R_386_NONE
                relocs.append({
                    "relsec": _to_int(kv.get("secidx", "0")),
                    "offset": _to_int(kv.get("offset", "0"), 16),
                    "type": et,
                    "symidx": symidx,
                    "symname": kv.get("symname", ""),
                })

    for r in relocs:
        r["target_secidx"] = sections.get(r["relsec"], {}).get("info", 0)

    got32x = sum(1 for r in relocs if r["type"] == R_386_GOT32X)
    putchar = sum(1 for r in relocs if r.get("symname") == "putchar")
    print(f"[DUMP-DEBUG] Total relocs={len(relocs)}, GOT32X={got32x}, putchar={putchar}")
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

    def add(self, s):
        if s in self.map:
            return self.map[s]
        off = len(self.buf)
        self.buf.extend(s.encode("utf-8") + b"\x00")
        self.map[s] = off
        return off

    def bytes(self):
        return bytes(self.buf)


TEXT_PREFIXES = (".text", ".init", ".fini", ".plt", ".gnu.linkonce.t", ".stub")
RO_PREFIXES = (".rodata", ".gnu.linkonce.r", ".eh_frame", ".gcc_except_table", ".note", ".comment", ".interp")
DATA_PREFIXES = (".data", ".sdata", ".data.rel", ".data.rel.ro", ".data.rel.ro.local",
                 ".got", ".got.plt", ".got2", ".bss.rel.ro", ".ctors", ".dtors", ".jcr",
                 ".init_array", ".fini_array", ".tm_clone_table", ".dynamic", ".idata")
BSS_PREFIXES = (".bss", ".sbss", ".tbss")


def classify_section(name):
    for p in TEXT_PREFIXES:
        if name == p or name.startswith(p + "."):
            return "text"
    for p in RO_PREFIXES:
        if name == p or name.startswith(p + "."):
            return "ro"
    for p in DATA_PREFIXES:
        if name == p or name.startswith(p + "."):
            return "data"
    for p in BSS_PREFIXES:
        if name == p or name.startswith(p + "."):
            return "bss"
    return None


def scrub_vex_nops_at_entry(text_buf, text_off, entry_off, verbose=False):
    rel = entry_off - text_off
    if rel < 0 or rel >= len(text_buf):
        return
    i = 0
    limit = min(len(text_buf) - rel, 32)
    changed = False
    while i + 2 < limit:
        b0 = text_buf[rel + i]
        if b0 == 0xC5 and (i + 2) < limit and text_buf[rel + i + 2] == 0x90:
            text_buf[rel + i:rel + i + 3] = b"\x90\x90\x90"
            i += 3
            changed = True
            continue
        if b0 == 0xC4 and (i + 3) < limit and text_buf[rel + i + 3] == 0x90:
            text_buf[rel + i:rel + i + 4] = b"\x90\x90\x90\x90"
            i += 4
            changed = True
            continue
        break
    if changed and verbose:
        print(f"[PATCH] Replaced VEX NOPs with classic NOPs at entry (offset 0x{entry_off:08x})")


def load_import_map(path):
    if not path:
        return {}
    mapping = {}
    try:
        with open(path, "r", encoding="utf-8") as f:
            for raw in f:
                line = raw.strip()
                if not line or "->" not in line:
                    continue
                sym, exl = line.split("->", 1)
                sym = sym.strip()
                exl = exl.strip()
                if sym:
                    mapping[sym] = exl if exl.endswith(".exl") else f"{exl}.exl"
    except FileNotFoundError:
        pass
    return mapping


def resolve_program_dir(elffile):
    elf_dir = os.path.abspath(os.path.dirname(elffile))
    base_dir = elf_dir
    if os.path.basename(elf_dir) == "build":
        base_dir = os.path.abspath(os.path.join(elf_dir, os.pardir))
    candidates = [base_dir, elf_dir]
    for d in candidates:
        name = os.path.basename(d)
        candidate = os.path.join(d, f"{name}.rs")
        if os.path.isfile(candidate):
            return d, name, candidate
    return base_dir, os.path.basename(base_dir), None


def build_dex(dumpfile, elffile, outfile, default_exl, import_map_path=None, forced_entry=None, verbose=False):
    sections, symbols, relocs = parse_dump(dumpfile)

    # Build resource blob (rs) for this program
    repo_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    program_dir, program_name, rs_path = resolve_program_dir(elffile)
    fallback_rs = os.path.join(repo_root, "programs", "default.rs")
    if rs_path is None:
        rs_path = fallback_rs
    sys.path.append(os.path.dirname(__file__))
    import rsbuild  # noqa: F401
    from rsbuild import parse_rs, build_blob, debug_dump

    with open(rs_path, "r", encoding="utf-8") as f:
        rs_lines = f.readlines()
    rs_entries = parse_rs(rs_lines, program_name)
    rs_blob, rs_strtab_off, rs_strtab_sz, rs_data_off = build_blob(rs_entries)
    # Persist the blob alongside the program for visibility/debugging.
    rs_out_path = os.path.join(program_dir, f"{program_name}.rsbin")
    try:
        with open(rs_out_path, "wb") as rfo:
            rfo.write(rs_blob)
    except OSError as e:
        print(f"[RSBUILD] Warning: failed to write {rs_out_path}: {e}")
    debug_dump(rs_entries, rs_blob, rs_out_path, rs_strtab_off, rs_strtab_sz, rs_data_off)

    sec_list = sorted(sections.values(), key=lambda s: s["off"])
    text_buf = bytearray()
    ro_buf = bytearray()
    dat_buf = bytearray()
    bss_total = 0
    secinfo = {}

    for s in sec_list:
        name = s["name"]
        g = classify_section(name)
        if g is None:
            continue
        off = s["off"]
        size = s["size"]
        idx = s["idx"]
        if g == "text":
            rel = len(text_buf)
            text_buf.extend(read_bytes(elffile, off, size))
            secinfo[idx] = {"group": "text", "rel": rel, "size": size}
        elif g == "ro":
            rel = len(ro_buf)
            ro_buf.extend(read_bytes(elffile, off, size))
            secinfo[idx] = {"group": "ro", "rel": rel, "size": size}
        elif g == "data":
            rel = len(dat_buf)
            dat_buf.extend(read_bytes(elffile, off, size))
            secinfo[idx] = {"group": "data", "rel": rel, "size": size}
        elif g == "bss":
            secinfo[idx] = {"group": "bss", "rel": bss_total, "size": size}
            bss_total += size

    text_off = 0x100
    ro_off = align_up(text_off + len(text_buf), FILE_ALIGN)
    data_off = align_up(ro_off + len(ro_buf), FILE_ALIGN)
    bss_off = data_off + len(dat_buf)

    def base_for_secidx(secidx):
        inf = secinfo.get(secidx)
        if not inf:
            return None, None, 0
        g, rel = inf["group"], inf["rel"]
        if g == "text":
            return text_off + rel, text_buf, rel
        if g == "ro":
            return ro_off + rel, ro_buf, rel
        if g == "data":
            return data_off + rel, dat_buf, rel
        if g == "bss":
            return bss_off + rel, None, 0
        return None, None, 0

    strtab = StrTab()
    import_map = load_import_map(import_map_path)
    default_exl = default_exl or "diffc.exl"
    if not default_exl.endswith(".exl"):
        default_exl += ".exl"
    strtab.add(default_exl)

    imports = []
    import_keys = set()

    def ensure_import(symname, exlname, is_func=True):
        libname = exlname or default_exl
        if not libname.endswith(".exl"):
            libname += ".exl"
        key = (libname, symname, 0 if is_func else 1)
        if key in import_keys:
            e = strtab.add(libname)
            s = strtab.add(symname)
            for i, (E, S, t, _) in enumerate(imports):
                if E == e and S == s and t == (0 if is_func else 1):
                    return i
        e_off = strtab.add(libname)
        s_off = strtab.add(symname)
        t = 0 if is_func else 1
        imports.append((e_off, s_off, t, 0))
        import_keys.add(key)
        return len(imports) - 1

    used_undef = set()
    for r in relocs:
        si = r["symidx"]
        if 0 <= si < len(symbols):
            sym = symbols[si]
            if sym["shndx"] == 0 and sym["name"]:
                used_undef.add(sym["name"])
    for name in sorted(used_undef):
        ensure_import(name, import_map.get(name, default_exl), True)

    if len(imports) > MAX_IMP:
        print(f"[FATAL] too many imports: {len(imports)} > {MAX_IMP}")
        sys.exit(1)

    dex_symbols = []
    exported = set()

    def add_symbol(name, value_off, is_func):
        if not name or name in exported:
            return
        name_off = strtab.add(name)
        dex_symbols.append((name_off, value_off & 0xFFFFFFFF, 0 if is_func else 1))
        exported.add(name)

    for sym in symbols:
        name = sym.get("name", "")
        shndx = sym.get("shndx", -1)
        if not name or shndx not in secinfo:
            continue
        bind = sym.get("bind", STB_LOCAL)
        if bind not in (STB_GLOBAL, STB_WEAK):
            continue
        stype = sym.get("type", STT_NOTYPE)
        if stype in (STT_SECTION, STT_FILE, STT_TLS):
            continue
        base, _, _ = base_for_secidx(shndx)
        if base is None:
            continue
        sec_group = secinfo[shndx]["group"]
        is_func = (stype == STT_FUNC) or (stype == STT_NOTYPE and sec_group == "text")
        value_off = (base + sym["value"]) & 0xFFFFFFFF
        add_symbol(name, value_off, is_func)

    reloc_table = []
    processed_offsets = {}
    skipped = []
    got32x_processed = 0
    pc32_processed = 0

    for r in relocs:
        tgt_base, tgt_buf, buf_offset = base_for_secidx(r["target_secidx"])
        if tgt_base is None or tgt_buf is None:
            skipped.append((r["type"], r.get("symname", ""), r["offset"], "target unsupported"))
            continue

        # raw_off is the offset within the ELF section
        raw_off = r["offset"]

        if raw_off + 4 > len(tgt_buf):
            skipped.append((r["type"], r.get("symname", ""), r["offset"], "offset OOR"))
            continue

        # img_off is the file offset in the DEX where this relocation applies
        # tgt_base = (text_off/ro_off/data_off) + buf_offset (where section starts in DEX)
        # raw_off = offset within the ELF section
        # So img_off = tgt_base + raw_off
        img_off = tgt_base + raw_off

        if img_off in processed_offsets:
            prev_type, prev_name = processed_offsets[img_off]
            skipped.append((r["type"], r.get("symname", ""), r["offset"], f"dup ({prev_type}:{prev_name})"))
            continue
        processed_offsets[img_off] = (r["type"], r.get("symname", ""))

        etype = r["type"]
        si = r["symidx"]
        sym = symbols[si] if 0 <= si < len(symbols) else None
        name = r.get("symname") or (sym.get("name") if sym else "")

        # Calculate buffer position for accessing bytes
        # buf_pos = where in the merged buffer (text_buf/ro_buf/dat_buf) we need to read/write
        buf_pos = buf_offset + raw_off

        if etype in (R_386_PC32, R_386_PLT32):
            pc32_processed += 1
            if sym and sym.get("shndx", 0) != 0:
                S_base, _, _ = base_for_secidx(sym["shndx"])
                if S_base is None:
                    skipped.append((etype, name, r["offset"], "unknown shndx"))
                    continue
                S = (S_base + sym["value"]) & 0xFFFFFFFF
                P = (img_off + 4) & 0xFFFFFFFF
                disp = (S - P) & 0xFFFFFFFF
                struct.pack_into("<I", tgt_buf, buf_pos, disp)
            else:
                idx = ensure_import(name or f"@{si}", import_map.get(name, default_exl), True)
                reloc_table.append((img_off, idx, DEX_PC32, 0))
            continue

        if etype == R_386_RELATIVE:
            reloc_table.append((img_off, 0, DEX_REL, 0))
            continue

        if etype in (R_386_GOT32, R_386_GOTOFF, R_386_GOTPC):
            etype = R_386_GOT32X

        if etype not in (R_386_32, R_386_GOT32X):
            skipped.append((etype, name, r["offset"], "unhandled"))
            continue

        if sym and sym.get("shndx", 0) != 0:
            if etype == R_386_GOT32X:
                patched = False
                if buf_pos >= 2:
                    opcode = tgt_buf[buf_pos-2:buf_pos]
                    if opcode in (b"\xff\x15", b"\xff\x25"):
                        src_base, _, _ = base_for_secidx(sym["shndx"])
                        if src_base is None:
                            skipped.append((etype, name, r["offset"], "unknown shndx"))
                            continue
                        target = (src_base + sym["value"]) & 0xFFFFFFFF
                        tgt_buf[buf_pos-2] = 0xe8 if opcode == b"\xff\x15" else 0xe9
                        new_img_off = img_off - 1
                        P = (new_img_off + 4) & 0xFFFFFFFF
                        disp = (target - P) & 0xFFFFFFFF
                        struct.pack_into("<I", tgt_buf, buf_pos - 1, disp)
                        if buf_pos + 3 < len(tgt_buf):
                            tgt_buf[buf_pos + 3] = 0x90
                        patched = True
                        got32x_processed += 1
                        continue
                    else:
                        op = tgt_buf[buf_pos-2]
                        modrm = tgt_buf[buf_pos-1]
                        if op == 0x8B and (modrm & 0xC7) == 0x05:
                            reg = (modrm >> 3) & 0x7
                            src_base, _, _ = base_for_secidx(sym["shndx"])
                            if src_base is None:
                                skipped.append((etype, name, r["offset"], "unknown shndx"))
                                continue
                            if buf_pos + 3 >= len(tgt_buf):
                                skipped.append((etype, name, r["offset"], "short mov"))
                                continue
                            init = (src_base + sym["value"]) & 0xFFFFFFFF
                            new_op = 0xB8 + reg
                            struct.pack_into("<B", tgt_buf, buf_pos-2, new_op)
                            struct.pack_into("<I", tgt_buf, buf_pos-1, init)
                            if buf_pos + 3 < len(tgt_buf):
                                tgt_buf[buf_pos+3] = 0x90
                            new_img_off = img_off - 1
                            reloc_table.append((new_img_off, 0, DEX_REL, 0))
                            patched = True
                            got32x_processed += 1
                            continue
                        if op == 0xFF and (modrm & 0x38) == 0x30 and (modrm & 0xC7) == 0x05:
                            # push dword ptr [disp32] -> push imm32
                            src_base, _, _ = base_for_secidx(sym["shndx"])
                            if src_base is None:
                                skipped.append((etype, name, r["offset"], "unknown shndx"))
                                continue
                            init = (src_base + sym["value"]) & 0xFFFFFFFF
                            tgt_buf[buf_pos-2] = 0x68  # push imm32
                            struct.pack_into("<I", tgt_buf, buf_pos-1, init)
                            if buf_pos + 3 < len(tgt_buf):
                                tgt_buf[buf_pos+3] = 0x90
                            reloc_table.append((img_off - 1, 0, DEX_REL, 0))
                            patched = True
                            got32x_processed += 1
                            continue

            src_base, _, _ = base_for_secidx(sym["shndx"])
            if src_base is None:
                skipped.append((etype, name, r["offset"], "unknown shndx"))
                continue
            if etype == R_386_GOT32X:
                init = (src_base + sym["value"]) & 0xFFFFFFFF
            else:
                A = struct.unpack_from("<I", tgt_buf, buf_pos)[0]
                init = (src_base + sym["value"] + A) & 0xFFFFFFFF
            struct.pack_into("<I", tgt_buf, buf_pos, init & 0xFFFFFFFF)
            reloc_table.append((img_off, 0, DEX_REL, 0))
            if etype == R_386_GOT32X:
                got32x_processed += 1
            continue

        # Symbol undefined or none.
        if etype == R_386_GOT32X:
            opcode = tgt_buf[buf_pos-2:buf_pos] if buf_pos >= 2 else b""
            idx = ensure_import(name or f"@{si}", import_map.get(name, default_exl), True)
            if opcode in (b"\xff\x15", b"\xff\x25"):
                tgt_buf[buf_pos-2] = 0xe8 if opcode == b"\xff\x15" else 0xe9
                struct.pack_into("<I", tgt_buf, buf_pos - 1, 0)
                if buf_pos + 3 < len(tgt_buf):
                    tgt_buf[buf_pos + 3] = 0x90
                reloc_table.append((img_off - 1, idx, DEX_PC32, 0))
            else:
                struct.pack_into("<I", tgt_buf, buf_pos, 0)
                reloc_table.append((img_off, idx, DEX_ABS32, 0))
            got32x_processed += 1
            continue

        # Plain ABS32 without symbol -> assume data reference.
        A = struct.unpack_from("<I", tgt_buf, buf_pos)[0]
        init = (data_off + A) & 0xFFFFFFFF
        struct.pack_into("<I", tgt_buf, buf_pos, init)
        reloc_table.append((img_off, 0, DEX_REL, 0))

    print(f"PC32/PLT32 relocations processed: {pc32_processed}")
    print(f"GOT32X relocations processed: {got32x_processed}")
    if skipped:
        print(f"Relocations skipped: {len(skipped)}")
        for t, name, off, reason in skipped[:20]:
            print(f"  type={t} sym='{name}' off=0x{off:x} -> {reason}")

    entry_off = text_off

    def entry_for_symbol(sym):
        base, _, _ = base_for_secidx(sym["shndx"])
        if base is None:
            return None
        return base + sym["value"]

    picked = None
    if forced_entry:
        matches = [s for s in symbols if s["name"] == forced_entry and s["shndx"] in secinfo]
        if matches:
            eo = entry_for_symbol(matches[0])
            if eo is not None:
                entry_off = eo
                picked = forced_entry
    if picked is None:
        for cand in ("main", "_dex_entry", "_start"):
            matches = [s for s in symbols if s["name"] == cand and s["shndx"] in secinfo]
            if matches:
                eo = entry_for_symbol(matches[0])
                if eo is not None:
                    entry_off = eo
                    picked = cand
                    break
    if verbose:
        print(f"[ENTRY] picked={picked or 'fallback'} entry_off=0x{entry_off:08x}")

    scrub_vex_nops_at_entry(text_buf, text_off, entry_off, verbose)

    text = bytearray(text_buf)
    ro = bytearray(ro_buf)
    dat = bytearray(dat_buf)
    bss_size = bss_total

    cur = align_up(data_off + len(dat), FILE_ALIGN)
    import_off = cur
    cur += 16 * len(imports)
    reloc_off = cur
    cur += 16 * len(reloc_table)
    symtab_off = cur
    cur += 12 * len(dex_symbols)
    strtab_b = strtab.bytes()
    strtab_off = cur
    cur += len(strtab_b)
    resources_off = align_up(cur, FILE_ALIGN)
    resources_size = len(rs_blob)
    cur = resources_off + resources_size

    hdr = bytearray(HDR_SIZE)

    def w32(off, val):
        struct.pack_into("<I", hdr, off, val & 0xFFFFFFFF)

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
    w32(0x40, len(dex_symbols))
    w32(0x44, strtab_off)
    w32(0x48, len(strtab_b))
    w32(0x4C, resources_off)
    w32(0x50, resources_size)

    def pad_to(f, ofs):
        curpos = f.tell()
        if curpos > ofs:
            raise RuntimeError(f"layout error: cur=0x{curpos:x} > want=0x{ofs:x}")
        if curpos < ofs:
            f.write(b"\x00" * (ofs - curpos))

    with open(outfile, "wb") as f:
        f.write(hdr)
        f.write(text)
        pad_to(f, ro_off)
        f.write(ro)
        pad_to(f, data_off)
        f.write(dat)
        pad_to(f, import_off)
        for e_off, s_off, t, z in imports:
            f.write(struct.pack("<IIII", e_off, s_off, t, z))
        pad_to(f, reloc_off)
        for off, symi, t, z in reloc_table:
            f.write(struct.pack("<IIII", off, symi, t, z))
        pad_to(f, symtab_off)
        for name_off, value_off, stype in dex_symbols:
            f.write(struct.pack("<III", name_off, value_off, stype))
        pad_to(f, strtab_off)
        f.write(strtab_b)
        if resources_size:
            pad_to(f, resources_off)
            f.write(rs_blob)

    if verbose:
        print("=== DEX HEADER VALUES ===")
        print(f"text_off       = 0x{text_off:08x} ({len(text)})")
        print(f"rodata_off     = 0x{ro_off:08x} ({len(ro)})")
        print(f"data_off       = 0x{data_off:08x} ({len(dat)})")
        print(f"bss_size       = 0x{bss_size:08x} ({bss_size})")
        print(f"import_off     = 0x{import_off:08x} (cnt={len(imports)})")
        print(f"reloc_off      = 0x{reloc_off:08x} (cnt={len(reloc_table)})")
        print(f"symtab_off     = 0x{symtab_off:08x} (cnt={len(dex_symbols)})")
        print(f"strtab_off     = 0x{strtab_off:08x} (sz={len(strtab_b)})")
        print(f"resources_off  = 0x{resources_off:08x} (sz={resources_size})")
        if resources_size:
            print(f"resources_magic= 0x{DEX_RS_MAGIC:08x} entries={len(rs_entries)} rsbin_out={rs_out_path}")
            print(f"rs_strtab_off  = {rs_strtab_off} rs_strtab_sz={rs_strtab_sz} rs_data_off={rs_data_off}")
        print(f"entry_offset   = 0x{entry_off:08x}")


def main():
    ap = argparse.ArgumentParser(description="Convert elfdump output to a DEX file (i386).")
    ap.add_argument("dumpfile", help="elfdump text output")
    ap.add_argument("elffile", help="source ELF file")
    ap.add_argument("outfile", help="output .dex file")
    ap.add_argument("--default-exl", default="diffc.exl",
                    help="EXL name to bind unresolved imports to (default: diffc.exl)")
    ap.add_argument("--imports-map", default=None,
                    help="Optional imports_map.txt produced by gen_imports.py for per-symbol EXL mapping")
    ap.add_argument("--entry", dest="entry", default=None, help="force entry symbol")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    build_dex(args.dumpfile, args.elffile, args.outfile, args.default_exl,
              import_map_path=args.imports_map, forced_entry=args.entry, verbose=args.verbose)


if __name__ == "__main__":
    main()
