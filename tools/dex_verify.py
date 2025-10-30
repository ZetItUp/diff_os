#!/usr/bin/env python3
# -*- coding: utf-8 -*-
#
# dex_verify.py — Verifier and pretty-printer for Different OS DEX images
#
# Matches the layout produced by elf2dex_common.py:
# - Header has 27 uint32 fields (no 'flags', but reserved[8] at the end).
# - Tables:
#     dex_import_t:  exl_name_off, symbol_name_off, import_type, reserved
#     dex_reloc_t:   file_off, sym_name_off, type, reserved
#     dex_symbol_t:  name_off, value_off, type
# - String table referenced by offsets in the above tables.
#
# Prints a readable report to stdout (and optionally to a file with -o).
#
# Exit codes:
#   0 = OK
#   1 = I/O error
#   2 = Validation error / malformed DEX
#

import argparse
import io
import struct
import sys
from typing import Tuple, List, Optional, Dict, DefaultDict
from collections import defaultdict

DEX_MAGIC = 0x58454400  # "DEX\0"
DEX_VER_MAJOR = 1
DEX_VER_MINOR = 0

# Relocation type names (match the builder)
DEX_ABS32 = 0
DEX_PC32 = 2
DEX_RELATIVE = 8

RELTYPE_NAME = {
    DEX_ABS32: "ABS32",
    DEX_PC32: "PC32",
    DEX_RELATIVE: "RELATIVE",
}

# dex_params_t magic in .ro (DPAR)
DEX_PARAMS_MAGIC = 0x44504152  # "DPAR"


def read_u32(buf: bytes, off: int) -> int:
    return struct.unpack_from("<I", buf, off)[0]


def read_header(buf: bytes) -> Tuple[List[int], bytes]:
    """
    Read 27 x uint32 header from the start of the file.
    Returns (fields_list, header_bytes).
    """
    need = 27 * 4
    if len(buf) < need:
        raise ValueError("File too small for DEX header (need 108 bytes).")
    fields = list(struct.unpack_from("<" + "I" * 27, buf, 0))
    return fields, buf[:need]


def fmt_hex(x: int, width: int = 8) -> str:
    return f"0x{x:0{width}x}"


def get_cstr(strtab: bytes, off: int) -> str:
    if off == 0:
        return ""
    if off < 0 or off >= len(strtab):
        return f"<bad-str:{off}>"
    end = strtab.find(b"\x00", off)
    if end == -1:
        end = len(strtab)
    try:
        return strtab[off:end].decode("utf-8", "replace")
    except Exception:
        return "<decoding-error>"


def safe_slice(buf: bytes, off: int, sz: int) -> bytes:
    if off < 0 or sz < 0 or off + sz > len(buf):
        raise ValueError(f"Out-of-range slice off={off} sz={sz} (file size {len(buf)})")
    return buf[off:off + sz]


def validate_range(file_len: int, off: int, sz: int, allow_zero_off: bool = False, label: str = "") -> Optional[str]:
    if sz < 0:
        return f"{label} size negative"
    if off == 0:
        if sz == 0:
            return None
        if not allow_zero_off:
            return f"{label} has size={sz} but off=0"
    if off < 0 or off + sz > file_len:
        return f"{label} out of file bounds (off={off}, sz={sz}, file={file_len})"
    return None



# ---------- Debug helpers ----------
def hexdump(buf: bytes, start: int, length: int, base_off: int = 0) -> str:
    end = min(len(buf), start + length)
    out_lines = []
    for o in range(start, end, 16):
        chunk = buf[o:o+16]
        hexs = " ".join(f"{b:02x}" for b in chunk)
        asc  = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        out_lines.append(f"{base_off+o:08x}  {hexs:<47}  |{asc}|")
    return "\n".join(out_lines)

def region_of(off: int, text_off: int, text_sz: int, ro_off: int, ro_sz: int,
              data_off: int, data_sz: int, rel_off: int, rel_cnt: int,
              sym_off: int, sym_cnt: int, str_off: int, str_sz: int,
              imp_off: int, imp_cnt: int) -> str:
    def within(off, base, sz): return base <= off < base + sz
    if within(off, 0, 27*4): return "header"
    if within(off, text_off, text_sz): return ".text"
    if within(off, ro_off, ro_sz): return ".ro"
    if within(off, data_off, data_sz): return ".data"
    if imp_cnt > 0 and within(off, imp_off, imp_cnt*16): return "imports"
    if within(off, rel_off, rel_cnt*16): return "relocs"
    if within(off, sym_off, sym_cnt*12): return "symbols"
    if str_sz > 0 and within(off, str_off, str_sz): return "strtab"
    return "gap"

def bucket_counts(lst):
    from collections import Counter
    c = Counter(lst)
    return ", ".join(f"{k}:{v}" for k,v in sorted(c.items(), key=lambda x: (str(x[0]))))

def clamp(n, lo, hi): 
    return max(lo, min(hi, n))
def parse_and_dump(fp: io.TextIOBase, data: bytes, path: str, debug: bool = False, entry_bytes: int = 64) -> int:
    try:
        fields, _hdr = read_header(data)
    except Exception as e:
        fp.write(f"[ERROR] {e}\n")
        return 2

    (
        magic,
        ver_major,
        ver_minor,
        entry_off,
        text_off, text_sz,
        ro_off, ro_sz,
        data_off, data_sz,
        bss_sz,
        imp_off, imp_cnt,
        rel_off, rel_cnt,
        sym_off, sym_cnt,
        str_off, str_sz,
        r0, r1, r2, r3, r4, r5, r6, r7,
) = fields

    if debug:
        fp.write("[DEBUG][HEADER RAW]\n")
        names = [
            "magic","ver_major","ver_minor","entry_off",
            "text_off","text_sz","ro_off","ro_sz",
            "data_off","data_sz","bss_sz",
            "imp_off","imp_cnt","rel_off","rel_cnt",
            "sym_off","sym_cnt","str_off","str_sz",
            "reserved0","reserved1","reserved2","reserved3","reserved4","reserved5","reserved6","reserved7"
        ]
        for idx, (n, v) in enumerate(zip(names, fields)):
            fp.write(f"  [{idx:02d}] {n:<10}= {fmt_hex(v)} ({v})\n")
        fp.write("\n")

    # ---- Header checks ----
    errors: List[str] = []
    if magic != DEX_MAGIC:
        errors.append(f"Bad magic: got {fmt_hex(magic)}, expected {fmt_hex(DEX_MAGIC)}")
    if ver_major != DEX_VER_MAJOR or ver_minor != DEX_VER_MINOR:
        errors.append(f"Unexpected version: {ver_major}.{ver_minor} (expected {DEX_VER_MAJOR}.{DEX_VER_MINOR})")

    file_len = len(data)

    # Validate section ranges
    for (off, sz, lbl) in [
        (text_off, text_sz, ".text"),
        (ro_off, ro_sz, ".ro"),
        (data_off, data_sz, ".data"),
    ]:
        msg = validate_range(file_len, off, sz, allow_zero_off=False, label=lbl)
        if msg:
            errors.append(msg)

    # strtab
    msg = validate_range(file_len, str_off, str_sz, allow_zero_off=True, label="strtab")
    if msg:
        errors.append(msg)

    # symbols table: 12 bytes per entry
    if sym_cnt < 0:
        errors.append("symbols count negative")
    sym_sz_total = sym_cnt * 12
    msg = validate_range(file_len, sym_off, sym_sz_total, allow_zero_off=True, label="symbols")
    if msg:
        errors.append(msg)

    # relocations table: 16 bytes per entry
    if rel_cnt < 0:
        errors.append("relocs count negative")
    rel_sz_total = rel_cnt * 16
    msg = validate_range(file_len, rel_off, rel_sz_total, allow_zero_off=True, label="relocs")
    if msg:
        errors.append(msg)

    # imports table (DEX only): 16 bytes per entry
    if imp_cnt < 0:
        errors.append("imports count negative")
    imp_sz_total = imp_cnt * 16
    if imp_cnt == 0:
        if imp_off != 0:
            msg = validate_range(file_len, imp_off, 0, allow_zero_off=True, label="imports")
            if msg:
                errors.append(msg)
    else:
        msg = validate_range(file_len, imp_off, imp_sz_total, allow_zero_off=False, label="imports")
        if msg:
            errors.append(msg)

    # entry should be inside .text
    if not (text_off <= entry_off < text_off + text_sz):
        errors.append(f"entry_off {fmt_hex(entry_off)} not inside .text range [{fmt_hex(text_off)}..{fmt_hex(text_off + text_sz)})")

    # ---- Print header ----
    fp.write(f"File: {path}\n")
    fp.write("=== HEADER ===\n")
    fp.write(f"magic        = {fmt_hex(magic)}\n")
    fp.write(f"version      = {ver_major}.{ver_minor}\n")
    fp.write(f"entry_off    = {fmt_hex(entry_off)}\n")
    fp.write(f".text        = off {fmt_hex(text_off)} size {fmt_hex(text_sz)}  -> [{fmt_hex(text_off)}..{fmt_hex(text_off + text_sz)})\n")
    fp.write(f".ro          = off {fmt_hex(ro_off)} size {fmt_hex(ro_sz)}  -> [{fmt_hex(ro_off)}..{fmt_hex(ro_off + ro_sz)})\n")
    fp.write(f".data        = off {fmt_hex(data_off)} size {fmt_hex(data_sz)}  -> [{fmt_hex(data_off)}..{fmt_hex(data_off + data_sz)})\n")
    fp.write(f".bss         = size {fmt_hex(bss_sz)}\n")
    fp.write(f"imports      = off {fmt_hex(imp_off)} count {imp_cnt}\n")
    fp.write(f"relocs       = off {fmt_hex(rel_off)} count {rel_cnt}\n")
    fp.write(f"symbols      = off {fmt_hex(sym_off)} count {sym_cnt}\n")
    fp.write(f"strtab       = off {fmt_hex(str_off)} size {fmt_hex(str_sz)}\n")
    fp.write(f"reserved[0..7] = {[fmt_hex(x) for x in (r0,r1,r2,r3,r4,r5,r6,r7)]}\n")
    fp.write("================\n\n")

    if errors:
        for e in errors:
            fp.write(f"[ERROR] {e}\n")
        # Keep dumping if possible, but return non-zero at the end
        ret_code = 2
    else:
        ret_code = 0

    # Load string table (may be empty)
    strtab = b""
    if str_sz > 0:
        strtab = safe_slice(data, str_off, str_sz)

    # ---- Dump sections summary ----
    fp.write("=== SECTIONS SUMMARY ===\n")
    fp.write(f".text bytes: {text_sz}  .ro bytes: {ro_sz}  .data bytes: {data_sz}  .bss bytes: {bss_sz}\n")
    total_image = max(
        text_off + text_sz,
        ro_off + ro_sz,
        data_off + data_sz,
        str_off + str_sz,
        rel_off + rel_sz_total,
        imp_off + imp_sz_total,
        sym_off + sym_sz_total,
        108,
    )
    fp.write(f"Image used bytes (to last table end): {total_image} of file size {len(data)}\n")
    fp.write("=========================\n\n")

    # ---- Try to dump dex_params_t ('DPAR') from .ro ----
    if ro_sz > 0:
        ro_bytes = safe_slice(data, ro_off, ro_sz)
        dump_dpar(fp, ro_bytes, ro_off)

    # We'll collect references to strtab offsets as we parse:
    # refs[offset] -> list of "imp[i].exl", "imp[i].sym", "rel[i].sym", "sym[i].name"
    refs: DefaultDict[int, List[str]] = defaultdict(list)

    # ---- Imports ----
    if imp_cnt > 0:
        fp.write("\n[IMPORTS]\n")
        try:
            imp_bytes = safe_slice(data, imp_off, imp_sz_total)
            for i in range(imp_cnt):
                off = i * 16
                (exl_noff, sym_noff, imp_type, _res) = struct.unpack_from("<IIII", imp_bytes, off)
                exl_name = get_cstr(strtab, exl_noff)
                sym_name = get_cstr(strtab, sym_noff)
                if exl_noff:
                    refs[exl_noff].append(f"imp[{i}].exl")
                if sym_noff:
                    refs[sym_noff].append(f"imp[{i}].sym")
                fp.write(f"  [{i}] exl='{exl_name}' sym='{sym_name}' type={imp_type}\n")
                if debug:
                    fp.write(f"      exl_noff={fmt_hex(exl_noff)} sym_noff={fmt_hex(sym_noff)} entry_off={fmt_hex(imp_off + off)}\n")
        except Exception as e:
            fp.write(f"[ERROR] imports parse failed: {e}\n")
            ret_code = 2
    else:
        fp.write("\n[IMPORTS]\n  (none)\n")
    if debug:
        try:
            if imp_cnt>0:
                imp_types = []
                imp_bytes = safe_slice(data, imp_off, imp_sz_total)
                for i in range(imp_cnt):
                    off = i*16
                    (_exl,_sym,t,_r)=struct.unpack_from("<IIII", imp_bytes, off)
                    imp_types.append(t)
                fp.write("[DEBUG][IMPORTS] types histogram: " + bucket_counts(imp_types) + "\n\n")
        except Exception as e:
            fp.write(f"[DEBUG][IMPORTS] histogram failed: {e}\n\n")


    # ---- Relocations ----
    fp.write("\n[RELOCATIONS]\n")
    if rel_cnt > 0:
        try:
            rel_bytes = safe_slice(data, rel_off, rel_sz_total)
            for i in range(rel_cnt):
                o = i * 16
                (r_off, sym_noff, r_type, _res) = struct.unpack_from("<IIII", rel_bytes, o)
                r_name = RELTYPE_NAME.get(r_type, f"TYPE_{r_type}")
                if sym_noff:
                    refs[sym_noff].append(f"rel[{i}].sym")
                sname = get_cstr(strtab, sym_noff) if sym_noff != 0 else ""
                sdisp = (sname if sname else "<none>")
                fp.write(f"  [{i}] off={fmt_hex(r_off)} type={r_name} sym={sdisp}\n")
                if debug:
                    reg = region_of(r_off, text_off, text_sz, ro_off, ro_sz, data_off, data_sz, rel_off, rel_cnt, sym_off, sym_cnt, str_off, str_sz, imp_off, imp_cnt)
                    try:
                        site = safe_slice(data, r_off, 4)
                        fp.write(f"      region={reg} bytes=[{site.hex()}]\n")
                    except Exception as _e:
                        fp.write(f"      region={reg} bytes=<out-of-range>\n")

        except Exception as e:
            fp.write(f"[ERROR] relocations parse failed: {e}\n")
            ret_code = 2
    else:
        fp.write("  (none)\n")

    if debug and sym_cnt>0:
        try:
            sym_bytes = safe_slice(data, sym_off, sym_sz_total)
            by_val: Dict[int, List[str]] = {}
            for i in range(sym_cnt):
                o = i*12
                (name_off_u32, val_off_u32, typ_u32) = struct.unpack_from("<III", sym_bytes, o)
                nm = get_cstr(strtab, name_off_u32)
                by_val.setdefault(val_off_u32, []).append(nm if nm else "<anon>")
            fp.write("\n[DEBUG][SYMBOLS] symbols sharing same value_off:\n")
            for val, names in sorted(by_val.items(), key=lambda kv: kv[0]):
                if len(names) > 1:
                    fp.write(f"  value_off={fmt_hex(val)} -> {names}\n")
            # Specific check for entry group ordering
            if entry_off in by_val:
                group = by_val[entry_off]
                fp.write(f"[DEBUG][ENTRY GROUP] entry_off={fmt_hex(entry_off)} group={group}\n")
        except Exception as e:
            fp.write(f"[DEBUG][SYMBOLS] grouping failed: {e}\n")


    if debug and rel_cnt>0:
        try:
            # Histogram by type and region
            rel_bytes = safe_slice(data, rel_off, rel_sz_total)
            types = []
            regs  = []
            for i in range(rel_cnt):
                o = i*16
                (r_off, sym_noff, r_type, _res) = struct.unpack_from("<IIII", rel_bytes, o)
                types.append(r_type)
                regs.append(region_of(r_off, text_off, text_sz, ro_off, ro_sz, data_off, data_sz, rel_off, rel_cnt, sym_off, sym_cnt, str_off, str_sz, imp_off, imp_cnt))
            fp.write("\n[DEBUG][RELOCS] type histogram: " + bucket_counts(types) + "\n")
            fp.write("[DEBUG][RELOCS] region histogram: " + bucket_counts(regs) + "\n\n")
        except Exception as e:
            fp.write(f"[DEBUG][RELOCS] histogram failed: {e}\n\n")


    # ---- Symbols ----
    fp.write("\n[SYMBOLS]\n")
    if sym_cnt > 0:
        try:
            sym_bytes = safe_slice(data, sym_off, sym_sz_total)
            for i in range(sym_cnt):
                o = i * 12
                (name_off_u32, val_off_u32, typ_u32) = struct.unpack_from("<III", sym_bytes, o)
                if name_off_u32:
                    refs[name_off_u32].append(f"sym[{i}].name")
                nm = get_cstr(strtab, name_off_u32)
                typ_s = "func" if typ_u32 == 0 else ("data" if typ_u32 == 1 else f"type_{typ_u32}")
                fp.write(f"  [{i}] name='{nm}' value_off={fmt_hex(val_off_u32)} type={typ_s}\n")
                if debug:
                    fp.write(f"      name_off={fmt_hex(name_off_u32)} sym_off={fmt_hex(sym_off + o)}\n")
        except Exception as e:
            fp.write(f"[ERROR] symbols parse failed: {e}\n")
            ret_code = 2
    else:
        fp.write("  (none)\n")

    if debug and sym_cnt>0:
        try:
            sym_bytes = safe_slice(data, sym_off, sym_sz_total)
            by_val: Dict[int, List[str]] = {}
            for i in range(sym_cnt):
                o = i*12
                (name_off_u32, val_off_u32, typ_u32) = struct.unpack_from("<III", sym_bytes, o)
                nm = get_cstr(strtab, name_off_u32)
                by_val.setdefault(val_off_u32, []).append(nm if nm else "<anon>")
            fp.write("\n[DEBUG][SYMBOLS] symbols sharing same value_off:\n")
            for val, names in sorted(by_val.items(), key=lambda kv: kv[0]):
                if len(names) > 1:
                    fp.write(f"  value_off={fmt_hex(val)} -> {names}\n")
            # Specific check for entry group ordering
            if entry_off in by_val:
                group = by_val[entry_off]
                fp.write(f"[DEBUG][ENTRY GROUP] entry_off={fmt_hex(entry_off)} group={group}\n")
        except Exception as e:
            fp.write(f"[DEBUG][SYMBOLS] grouping failed: {e}\n")


    if debug and rel_cnt>0:
        try:
            # Histogram by type and region
            rel_bytes = safe_slice(data, rel_off, rel_sz_total)
            types = []
            regs  = []
            for i in range(rel_cnt):
                o = i*16
                (r_off, sym_noff, r_type, _res) = struct.unpack_from("<IIII", rel_bytes, o)
                types.append(r_type)
                regs.append(region_of(r_off, text_off, text_sz, ro_off, ro_sz, data_off, data_sz, rel_off, rel_cnt, sym_off, sym_cnt, str_off, str_sz, imp_off, imp_cnt))
            fp.write("\n[DEBUG][RELOCS] type histogram: " + bucket_counts(types) + "\n")
            fp.write("[DEBUG][RELOCS] region histogram: " + bucket_counts(regs) + "\n\n")
        except Exception as e:
            fp.write(f"[DEBUG][RELOCS] histogram failed: {e}\n\n")


    # ---- Entry symbol hint ----
    fp.write("\n[ENTRY]\n")
    if debug:
        try:
            # Dump entry bytes (clamped)
            win = clamp(entry_bytes, 16, 256)
            fp.write(f"  entry bytes (first {win}):\n")
            fp.write(hexdump(data, entry_off, win, 0) + "\n")
        except Exception as e:
            fp.write(f"  [DEBUG] could not dump entry bytes: {e}\n")
    entry_sym = find_entry_symbol(data, sym_off, sym_cnt, strtab, entry_off)
    if entry_sym:
        fp.write(f"  entry_off {fmt_hex(entry_off)} -> symbol '{entry_sym}'\n")
    else:
        fp.write(f"  entry_off {fmt_hex(entry_off)} (no matching symbol value_off)\n")

    # ---- STRTAB DUMP (alla strängar + referenser) ----
    fp.write("\n[STRTAB]\n")
    if debug and str_sz>0:
        # check unreferenced strings
        all_refs = set(refs.keys())
        used_marks = ["imp", "rel", "sym"]
        # Build a set of all offsets inside table (start of entries)
        starts = set()
        i2 = 0
        while i2 < len(strtab):
            starts.add(i2)
            end2 = strtab.find(b"\x00", i2)
            if end2 == -1:
                end2 = len(strtab)
            i2 = end2 + 1
        unref = [off for off in starts if off not in all_refs]
        if unref:
            fp.write(f"[DEBUG][STRTAB] unreferenced entries: {len(unref)}\n")
        else:
            fp.write("[DEBUG][STRTAB] all strings referenced by some table.\n")
    if str_sz == 0:
        fp.write("  (none)\n")
    else:
        dump_strtab(fp, strtab, str_off, refs)

    return ret_code


def dump_dpar(fp: io.TextIOBase, ro_bytes: bytes, ro_file_off: int) -> None:
    """
    Scan .ro for dex_params_t by looking for 'DPAR' (DEX_PARAMS_MAGIC).
    This mirrors the builder's light dump.
    """
    found = False
    min_len = 52
    for i in range(0, max(0, len(ro_bytes) - min_len + 1)):
        try:
            magic = read_u32(ro_bytes, i)
        except struct.error:
            break
        if magic == DEX_PARAMS_MAGIC:
            try:
                ver_major, ver_minor = struct.unpack_from("<HH", ro_bytes, i + 4)
                flags = read_u32(ro_bytes, i + 8)
                argc, argv, envc, envp = struct.unpack_from("<IIII", ro_bytes, i + 12)
                cmdline, cwd = struct.unpack_from("<II", ro_bytes, i + 28)
                image_base, image_size, stack_top, stack_limit = struct.unpack_from("<IIII", ro_bytes, i + 36)
                fp.write("=== DEX PARAMS (DPAR) ===\n")
                fp.write(f"  file_off = {fmt_hex(ro_file_off + i)}\n")
                fp.write(f"  ver={ver_major}.{ver_minor} flags={fmt_hex(flags)}\n")
                fp.write(f"  argc={argc} argv={fmt_hex(argv)} envc={envc} envp={fmt_hex(envp)}\n")
                fp.write(f"  cmdline={fmt_hex(cmdline)} cwd={fmt_hex(cwd)}\n")
                fp.write(f"  image_base={fmt_hex(image_base)} image_size={fmt_hex(image_size)} "
                         f"stack_top={fmt_hex(stack_top)} stack_limit={fmt_hex(stack_limit)}\n")
                for label, off in (("cmdline", cmdline), ("cwd", cwd)):
                    if 0 <= off < len(ro_bytes):
                        s0 = cstr_from(ro_bytes, off)
                        fp.write(f"  {label}: {s0}\n")
                fp.write("=========================\n")
                found = True
                break
            except Exception:
                pass
    if not found:
        fp.write("=== DEX PARAMS (DPAR) ===\n")
        fp.write("  (none found in .ro)\n")
        fp.write("=========================\n")


def cstr_from(buf: bytes, off: int) -> str:
    if off < 0 or off >= len(buf):
        return "<bad-str>"
    end = buf.find(b"\x00", off)
    if end == -1:
        end = len(buf)
    try:
        return buf[off:end].decode("utf-8", "replace")
    except Exception:
        return "<decoding-error>"


def dump_strtab(fp: io.TextIOBase, strtab: bytes, base_file_off: int, refs: Dict[int, List[str]]) -> None:
    """
    Dump every null-terminated string in the string table, with file offsets and reference info.
    """
    i = 0
    idx = 0
    total = 0
    entries: List[Tuple[int, int, str]] = []  # (off_in_tab, length, text)

    # Linear scan: each entry ends at next NUL. Includes the empty "" at offset 0.
    while i < len(strtab):
        end = strtab.find(b"\x00", i)
        if end == -1:
            end = len(strtab)
        length = end - i
        try:
            text = strtab[i:end].decode("utf-8", "replace")
        except Exception:
            text = "<decoding-error>"
        entries.append((i, length, text))
        total += 1
        i = end + 1  # skip NUL
        idx += 1

    fp.write(f"count={total}, size={len(strtab)} bytes (file range [{fmt_hex(base_file_off)}..{fmt_hex(base_file_off + len(strtab))}))\n")

    # Pretty print each entry with references summary
    for n, (off_in_tab, length, text) in enumerate(entries):
        file_off = base_file_off + off_in_tab
        ref_list = refs.get(off_in_tab, [])
        if ref_list:
            # Summarize by category for compactness
            cats: DefaultDict[str, int] = defaultdict(int)
            for r in ref_list:
                if r.startswith("imp"):
                    cats["imp"] += 1
                elif r.startswith("rel"):
                    cats["rel"] += 1
                elif r.startswith("sym"):
                    cats["sym"] += 1
                else:
                    cats["other"] += 1
            cat_str = ", ".join(f"{k}:{v}" for k, v in sorted(cats.items()))
            fp.write(f"  [{n}] off={fmt_hex(file_off)} (str_off={fmt_hex(off_in_tab)}) len={length} refs=({cat_str})  \"{text}\"\n")
        else:
            fp.write(f"  [{n}] off={fmt_hex(file_off)} (str_off={fmt_hex(off_in_tab)}) len={length}  \"{text}\"\n")


def find_entry_symbol(data: bytes, sym_off: int, sym_cnt: int, strtab: bytes, entry_off: int) -> Optional[str]:
    if sym_cnt <= 0 or sym_off <= 0:
        return None
    try:
        sym_bytes = data[sym_off:sym_off + sym_cnt * 12]
        for i in range(sym_cnt):
            o = i * 12
            (name_off_u32, val_off_u32, _typ_u32) = struct.unpack_from("<III", sym_bytes, o)
            if val_off_u32 == entry_off:
                return get_cstr(strtab, name_off_u32)
    except Exception:
        return None
    return None


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(description="DEX verifier/inspector (Different OS).")
    ap.add_argument("dex_path", help="Path to .dex (or exl-like) file")
    ap.add_argument("-d", "--debug", action="store_true", help="Print very verbose debug output")
    ap.add_argument("--entry-bytes", type=int, default=64, help="How many bytes of entry to dump (16..256)")
    ap.add_argument("-o", "--output", help="Write the printed report to this file (in addition to stdout)")
    args = ap.parse_args(argv[1:])

    try:
        with open(args.dex_path, "rb") as f:
            data = f.read()
    except OSError as e:
        sys.stderr.write(f"[I/O ERROR] {e}\n")
        return 1

    buf = io.StringIO()
    ret = parse_and_dump(buf, data, args.dex_path, debug=args.debug, entry_bytes=args.entry_bytes)
    text = buf.getvalue()

    # Always print to stdout
    sys.stdout.write(text)

    # Optionally write to file
    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as outf:
                outf.write(text)
        except OSError as e:
            sys.stderr.write(f"[I/O ERROR] could not write output file: {e}\n")
            # keep original ret

    return ret


if __name__ == "__main__":
    sys.exit(main(sys.argv))


