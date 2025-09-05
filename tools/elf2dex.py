#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import argparse
import struct
import sys

# -------------------------
# DEX constants / formats
# -------------------------
DEX_MAGIC = 0x58454400  # "DEX\0"
DEX_MAJ = 1
DEX_MIN = 0

# DEX relocation types
DEX_ABS32 = 0
DEX_PC32  = 2
DEX_REL   = 8

# ELF i386 relocation types
R_386_NONE  = 0
R_386_32    = 1
R_386_PC32  = 2
R_386_PLT32 = 4

FILE_ALIGN = 1
HDR_SIZE   = 0x100
MAX_IMP    = 4096  # match kernel limit

# -------------------------
# Helpers
# -------------------------
def align_up(x, a):
    return (x + (a - 1)) & ~(a - 1)

def _to_int(s, base=0):
    s = (s or "0").strip().rstrip(",")
    if s.startswith(("0x", "0X")):
        return int(s, 16)
    return int(s, base or 10)

def parse_dump(path):
    """
    Parser för en text-dump som innehåller rader som:
      SECTION idx=... name=... off=0x... size=0x... info=...
      SYMBOL  name=... value=0x...|value_off=0x... shndx=...
      RELOC   secidx=... offset=0x... type=R_386_* symidx=... symname=...
    Stödjer både 'value=' och 'value_off=' (din elfdump använder ofta det senare).
    """
    sections = {}   # idx -> {name, off, size, info}
    symbols  = []   # [{name, value, shndx}]
    relocs   = []   # [{relsec, offset, type, symidx, symname, target_secidx}]
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
                    "off": _to_int(kv.get("off", "0")),
                    "size": _to_int(kv.get("size", "0")),
                    "info": _to_int(kv.get("info", "0")),
                }

            elif line.startswith("SYMBOL "):
                kv = dict(tok.split("=", 1) for tok in line.split()[1:] if "=" in tok)
                sval = kv.get("value") or kv.get("value_off") or kv.get("addr")
                symbols.append({
                    "name": kv.get("name", ""),
                    "value": _to_int(sval),
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
                    "offset": _to_int(kv.get("offset", "0")),
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

# -------------------------
# Patch: sanitize VEX-NOPs at entry for i386
# -------------------------
def scrub_vex_nops_at_entry(text_buf, text_off, entry_off, verbose=False):
    """
    Ersätt VEX-kodade NOPs (C5??90 / C4????90) precis vid entry med klassiska 0x90,
    så i386 inte tolkar dem som LES och råkar läsa omappat minne.
    """
    rel = entry_off - text_off
    if rel < 0 or rel >= len(text_buf):
        return False

    i = 0
    changed = False
    limit = min(len(text_buf) - rel, 32)  # liten fönster vid entry
    while i + 2 < limit:
        b0 = text_buf[rel + i]
        # 3-byte VEX: C5 ?? 90
        if b0 == 0xC5 and (i + 2) < limit and text_buf[rel + i + 2] == 0x90:
            text_buf[rel + i + 0] = 0x90
            text_buf[rel + i + 1] = 0x90
            text_buf[rel + i + 2] = 0x90
            i += 3
            changed = True
            continue
        # 4-byte VEX: C4 ?? ?? 90
        if b0 == 0xC4 and (i + 3) < limit and text_buf[rel + i + 3] == 0x90:
            text_buf[rel + i + 0] = 0x90
            text_buf[rel + i + 1] = 0x90
            text_buf[rel + i + 2] = 0x90
            text_buf[rel + i + 3] = 0x90
            i += 4
            changed = True
            continue
        break
    if verbose and changed:
        print(f"[PATCH] Replaced VEX NOPs with classic NOPs at entry (offset 0x{entry_off:08x})")
    return changed

# -------------------------
# Section classification
# -------------------------
TEXT_PREFIXES = (
    ".text", ".init", ".fini", ".plt",
    ".gnu.linkonce.t", ".stub"
)
RO_PREFIXES = (
    ".rodata", ".gnu.linkonce.r",
    ".eh_frame", ".gcc_except_table",
    ".note", ".comment", ".interp"
)
DATA_PREFIXES = (
    ".data", ".sdata",
    ".data.rel", ".data.rel.ro", ".data.rel.ro.local",
    ".got", ".got.plt", ".got2",
    ".bss.rel.ro",
    ".ctors", ".dtors", ".jcr",
    ".init_array", ".fini_array",
    ".tm_clone_table",
    ".dynamic", ".idata"
)
BSS_PREFIXES = (
    ".bss", ".sbss", ".tbss"
)

def classify_section(name: str):
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
    # default: ignorera (debug, symtab, etc.)
    return None

# -------------------------
# Diagnostik: hitta E8/E9 med disp=-4 (saknade PC32-relocs)
# -------------------------
def scan_missing_pc32_calls(text_buf, text_off, verbose=False):
    """
    Letar i .text efter E8/E9 (CALL/JMP rel32) med disp == 0xFFFFFFFC (=-4),
    vilket tyder på att elfdumpen tappat en PC32/PLT32-reloc.
    """
    if not verbose or not text_buf:
        return 0
    hits = 0
    i = 0
    n = len(text_buf)
    while i + 4 < n:
        op = text_buf[i]
        if op in (0xE8, 0xE9):  # CALL rel32 / JMP rel32
            disp = struct.unpack_from("<i", text_buf, i + 1)[0]
            if disp == -4:
                print(f"[WARN] Potential missing PC32/PLT32 at .text+0x{i:06x} (E8/E9 disp=-4)")
                hits += 1
            i += 5
        else:
            i += 1
    return hits

# -------------------------
# Core converter
# -------------------------
def build_dex(dumpfile, elffile, outfile, default_exl, forced_entry=None, verbose=False, map_undef=None):
    sections, symbols, relocs = parse_dump(dumpfile)

    # --- Tillämpa --map-undef: idx=name för undefined symboler ---
    # map_undef kan vara lista av strängar, varje sträng kan innehålla flera "idx=name" separerade med kommatecken
    map_idx = {}
    map_undef = map_undef or []
    for spec in map_undef:
        parts = [p.strip() for p in spec.split(",") if p.strip()]
        for p in parts:
            if "=" not in p:
                continue
            i_str, name = p.split("=", 1)
            try:
                i = int(i_str, 0)
            except ValueError:
                continue
            name = name.strip()
            if name:
                map_idx[i] = name

    # Applicera på symboltabellen (undefined == shndx==0)
    if map_idx:
        for i, sym in enumerate(symbols):
            if sym.get("shndx", -1) == 0:
                if i in map_idx:
                    sym["name"] = map_idx[i]

    # Sortera sektioner i filordning för stabil packning
    sec_list = sorted(sections.values(), key=lambda s: s["off"])

    # Buffertar per kategori och karta secidx -> group offset
    text_buf = bytearray()
    ro_buf   = bytearray()
    dat_buf  = bytearray()
    bss_total = 0

    # secidx -> {"group": g, "rel": offset_inside_group, "size": sz}
    secinfo = {}

    # Första pass: kopiera bytes & registrera offsetar
    for s in sec_list:
        name, off, size, idx = s["name"], s["off"], s["size"], s["idx"]
        g = classify_section(name)
        if g is None:
            continue
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

    # Layout i DEX
    text_off = HDR_SIZE
    ro_off   = align_up(text_off + len(text_buf), FILE_ALIGN)
    data_off = align_up(ro_off   + len(ro_buf),   FILE_ALIGN)

    # Hjälpare: kartlägg (secidx) -> (img_base, buf_ref)
    def base_for_secidx(secidx):
        inf = secinfo.get(secidx)
        if not inf:
            return None, None
        g, rel = inf["group"], inf["rel"]
        if g == "text":
            return text_off + rel, text_buf
        if g == "ro":
            return ro_off + rel, ro_buf
        if g == "data":
            return data_off + rel, dat_buf
        if g == "bss":
            # BSS ligger direkt efter data i minnet
            return data_off + len(dat_buf) + rel, None
        return None, None

    # Stringtabell / imports
    strtab = StrTab()
    if not default_exl:
        default_exl = "diffc.exl"
    strtab.add(default_exl)

    imports = []        # (exl_off, sym_off, type, 0)
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

    # Pre-pass: undefined symbols som faktiskt används i reloc-tabellen
    used_undef = set()
    for r in relocs:
        si = r["symidx"]
        if 0 <= si < len(symbols) and symbols[si]["shndx"] == 0:
            nm = symbols[si]["name"]
            if nm:
                used_undef.add(nm)
            else:
                # Om namnlös undefined och map_undef gav inget namn -> skapa syntetiskt
                used_undef.add(f"@{si}")
    for name in sorted(used_undef):
        ensure_import(name, True)

    if len(imports) > MAX_IMP:
        print(f"[FATAL] too many imports: {len(imports)} > {MAX_IMP}")
        sys.exit(1)

    # DEX relocation table: (img_off, sym_or_idx, dex_type, 0)
    reloc_table = []

    # Konvertera ELF relocs -> DEX relocs / patch immediates
    for r in relocs:
        tgt_base, tgt_buf = base_for_secidx(r["target_secidx"])
        if tgt_base is None or tgt_buf is None:
            # Kan få relocs som riktar mot BSS; själva site måste ligga i text/ro/data.
            if verbose:
                print(f"[SKIP] reloc target secidx={r['target_secidx']} unsupported (no buffer)")
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
            # Lokal symbol -> lös disp direkt
            if sym and sym["shndx"] != 0:
                A = struct.unpack_from("<I", tgt_buf, raw_off)[0]
                S_base, _ = base_for_secidx(sym["shndx"])
                if S_base is None:
                    if verbose:
                        print(f"[SKIP] PC32 to unknown shndx={sym['shndx']}")
                    continue
                S = (S_base + sym["value"]) & 0xffffffff
                P = (img_off + 4) & 0xffffffff
                disp = (S + A - P) & 0xffffffff
                struct.pack_into("<I", tgt_buf, raw_off, disp)
                if verbose:
                    print(f"[PC32 local] sect={sect_name} site=0x{img_off:08x} "
                          f"S=0x{S:08x} A=0x{A:08x} P=0x{P:08x} -> disp=0x{disp:08x}")
            else:
                # Extern symbol -> DEX_PC32 + import
                idx = ensure_import(name or f"@{si}", True)
                reloc_table.append((img_off, idx, DEX_PC32, 0))
                if verbose:
                    print(f"[PC32 ext] site_off=0x{img_off:08x} target='{name}' -> DEX_PC32 (idx={idx})")
            continue

        if etype == R_386_32:
            A = struct.unpack_from("<I", tgt_buf, raw_off)[0]
            if sym and sym["shndx"] != 0:
                # Lokal absolut -> gör bildrelativ och markera DEX_REL
                src_base, _ = base_for_secidx(sym["shndx"])
                if src_base is None:
                    if verbose:
                        print(f"[SKIP] ABS32 rel to unknown shndx={sym['shndx']}")
                    continue
                init = (src_base + sym["value"] + A) & 0xffffffff
                struct.pack_into("<I", tgt_buf, raw_off, init)
                reloc_table.append((img_off, 0, DEX_REL, 0))
                if verbose:
                    print(f"[ABS32 rel] sect={sect_name} site_off=0x{img_off:08x} "
                          f"A=0x{A:08x} S=0x{sym['value']:08x} -> old=0x{init:08x} DEX_REL")
            elif sym and sym["shndx"] == 0:
                # Extern -> DEX_ABS32 + import
                idx = ensure_import(name or f"@{si}", False)
                reloc_table.append((img_off, idx, DEX_ABS32, 0))
                if verbose:
                    print(f"[ABS32 ext] sect={sect_name} site_off=0x{img_off:08x} "
                          f"A=0x{A:08x} sym='{name}' -> DEX_ABS32 (idx={idx})")
            else:
                # Ingen symbol: behåll värdet men markera DEX_REL om det pekar in i bilden.
                guess = (A & 0xffffffff)
                def _in_file_sections(file_off):
                    return ((text_off <= file_off < text_off + len(text_buf)) or
                            (ro_off   <= file_off < ro_off   + len(ro_buf)) or
                            (data_off <= file_off < data_off + len(dat_buf)))
                if _in_file_sections(guess):
                    reloc_table.append((img_off, 0, DEX_REL, 0))
                    if verbose:
                        print(f"[ABS32 no-sym] sect={sect_name} site_off=0x{img_off:08x} "
                              f"A=0x{A:08x} (looks like in-image) -> DEX_REL")
                else:
                    init = (data_off + A) & 0xffffffff
                    struct.pack_into("<I", tgt_buf, raw_off, init)
                    reloc_table.append((img_off, 0, DEX_REL, 0))
                    if verbose:
                        print(f"[ABS32 no-sym] sect={sect_name} site_off=0x{img_off:08x} "
                              f"A=0x{A:08x} -> old=data_off+A=0x{init:08x} DEX_REL")
            continue

        if verbose:
            print(f"[WARN] Unknown ELF reloc type {etype} at off=0x{raw_off:08x}")

    # -------------------------
    # Entry: use DEX bases (not ELF offsets)
    # -------------------------
    def entry_for_symbol(sym):
        base, _ = base_for_secidx(sym["shndx"])
        return None if base is None else (base + (sym["value"] or 0))

    entry_off = text_off  # fallback
    picked = None

    if forced_entry:
        cands = [s for s in symbols if s["name"] == forced_entry and s["shndx"] in sections]
        if cands:
            eo = entry_for_symbol(cands[0])
            if eo is not None:
                entry_off = eo
                picked = forced_entry

    if picked is None:
        for cand in ("main", "_dex_entry", "_start"):
            cands = [s for s in symbols if s["name"] == cand and s["shndx"] in sections]
            if cands:
                eo = entry_for_symbol(cands[0])
                if eo is not None:
                    entry_off = eo
                    picked = cand
                    break

    if verbose:
        print(f"[ENTRY] picked={picked or 'fallback'} entry_off=0x{entry_off:08x}")

    # Patcha bort VEX-NOPs vid entry (för i386)
    scrub_vex_nops_at_entry(text_buf, text_off, entry_off, verbose)

    # Extra diagnos: leta E8/E9 disp=-4 (saknade relocs)
    scan_missing_pc32_calls(text_buf, text_off, verbose)

    # Final bytes
    text = bytes(text_buf)
    ro   = bytes(ro_buf)
    dat  = bytes(dat_buf)
    bss_size = bss_total

    # --- EXTRA PASS: svep .text/.rodata/.data efter råa in-bildspekare utan reloc ---
    def _dex_end_span():
        max_end = entry_off + 16
        max_end = max(max_end, text_off + len(text))
        max_end = max(max_end, ro_off   + len(ro))
        max_end = max(max_end, data_off + len(dat))
        return align_up(max_end, FILE_ALIGN)

    def _in_file_sections(file_off):
        return ((text_off <= file_off < text_off + len(text)) or
                (ro_off   <= file_off < ro_off   + len(ro)) or
                (data_off <= file_off < data_off + len(dat)))

    existing_sites = set([img_off for (img_off, _, _, _) in reloc_table])
    added_ptrs = 0
    end_span = _dex_end_span()
    mins = [x for x in [text_off if len(text) else None,
                        ro_off   if len(ro)   else None,
                        data_off if len(dat)  else None] if x is not None]
    min_ptr = min(mins) if mins else 0

    for (sec_name, base_off, buf) in ((".text*", text_off, text),
                                      (".rodata*", ro_off, ro),
                                      (".data*", data_off, dat)):
        rng = max(0, len(buf) - 3)
        off = 0
        while off < rng:
            img_off = base_off + off
            if img_off not in existing_sites:
                word = struct.unpack_from("<I", buf, off)[0]
                if (word >= min_ptr) and (word < end_span) and _in_file_sections(word):
                    reloc_table.append((img_off, 0, DEX_REL, 0))
                    existing_sites.add(img_off)
                    added_ptrs += 1
                    if verbose:
                        print(f"[SWEEP {sec_name}] add DEX_REL at +0x{img_off:08x} for word=0x{word:08x}")
            off += 4

    if verbose:
        print(f"[SWEEP] total added pointer relocs: {added_ptrs}")

    # Tabell-offsets (efter data)
    cur = align_up(data_off + len(dat), FILE_ALIGN)
    import_off = cur; cur += 16 * len(imports)
    reloc_off  = cur; cur += 16 * len(reloc_table)
    symtab_off = cur; cur += 0  # inga symboler skrivs ut
    strtab_b   = StrTab.bytes(strtab)
    strtab_off = cur; cur += len(strtab_b)

    # Header
    hdr = bytearray(HDR_SIZE)
    def w32(o, v): struct.pack_into("<I", hdr, o, v & 0xFFFFFFFF)
    w32(0x00, DEX_MAGIC)
    w32(0x04, DEX_MAJ)
    w32(0x08, DEX_MIN)
    w32(0x0C, entry_off)
    w32(0x10, text_off); w32(0x14, len(text))
    w32(0x18, ro_off);   w32(0x1C, len(ro))
    w32(0x20, data_off); w32(0x24, len(dat))
    w32(0x28, bss_size)
    w32(0x2C, import_off); w32(0x30, len(imports))
    w32(0x34, reloc_off);  w32(0x38, len(reloc_table))
    w32(0x3C, symtab_off); w32(0x40, 0)
    w32(0x44, strtab_off); w32(0x48, len(strtab_b))

    def pad_to(f, ofs):
        curpos = f.tell()
        if curpos > ofs:
            raise RuntimeError(f"layout error: cur=0x{curpos:x} > want=0x{ofs:x}")
        if curpos < ofs:
            f.write(b"\x00" * (ofs - curpos))

    with open(outfile, "wb") as f:
        f.write(hdr)
        f.write(text)
        pad_to(f, ro_off);   f.write(ro)
        pad_to(f, data_off); f.write(dat)
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

# -------------------------
# CLI
# -------------------------
def main():
    ap = argparse.ArgumentParser(description="Convert elfdump output to a DEX file (i386).")
    ap.add_argument("dumpfile", help="elfdump text output")
    ap.add_argument("elffile", help="source ELF file to read section bytes from")
    ap.add_argument("outfile", help="output .dex file")
    ap.add_argument("--default-exl", default="diffc.exl",
                    help="EXL name to bind unresolved imports to (default: diffc.exl)")
    ap.add_argument("--entry", dest="entry", default=None,
                    help="force entry-symbol (ex. --entry main)")
    ap.add_argument("--map-undef", action="append", default=[],
                    help="Map undefined symidx to name, e.g. --map-undef 3=__stack_chk_fail or '3=__stack_chk_fail,5=__aeabi_idiv'")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    build_dex(args.dumpfile,
              args.elffile,
              args.outfile,
              args.default_exl,
              args.entry,
              args.verbose,
              map_undef=args.map_undef)

if __name__ == "__main__":
    main()

