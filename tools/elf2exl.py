#!/usr/bin/env python3

import argparse
import struct
import sys
from pathlib import Path

# DEX / EXL constants
DEX_MAGIC     = 0x58454400  # "DEX\0"
DEX_VER_MAJ   = 1
DEX_VER_MIN   = 0
HDR_SIZE      = 0x100
FILE_ALIGN    = 0x1000

# DEX reloc types
DEX_ABS32     = 0
DEX_PC32      = 2
DEX_RELATIVE  = 8

# ELF constants
ELF_MAGIC     = b"\x7fELF"
ELFCLASS32    = 1
ELFDATA2LSB   = 1
EM_386        = 3

SHT_NULL      = 0
SHT_PROGBITS  = 1
SHT_SYMTAB    = 2
SHT_STRTAB    = 3
SHT_RELA      = 4
SHT_NOBITS    = 8
SHT_REL       = 9
SHT_DYNSYM    = 11

# sh_flags
SHF_WRITE     = 0x1
SHF_ALLOC     = 0x2
SHF_EXECINSTR = 0x4

STB_LOCAL     = 0
STB_GLOBAL    = 1
STB_WEAK      = 2

STT_NOTYPE    = 0
STT_OBJECT    = 1
STT_FUNC      = 2
STT_SECTION   = 3
STT_FILE      = 4
STT_TLS       = 6

SHN_UNDEF     = 0

# i386 reloc
R_386_NONE     = 0
R_386_32       = 1
R_386_PC32     = 2
R_386_GOT32    = 3
R_386_PLT32    = 4
R_386_COPY     = 5
R_386_GLOB_DAT = 6
R_386_JMP_SLOT = 7
R_386_RELATIVE = 8
R_386_GOTOFF   = 9
R_386_GOTPC    = 10

U32_MAX = (1 << 32) - 1


def fail(msg: str) -> None:
    print(f"ERROR: {msg}", file=sys.stderr)
    sys.exit(1)


def info(verbose: bool, msg: str) -> None:
    if verbose:
        print(msg)


def align_up(x: int, a: int) -> int:
    return (x + (a - 1)) & ~(a - 1)


def u32(v: int, what: str) -> int:
    if v < 0 or v > U32_MAX:
        fail(f"{what}: outside 32-bit range (0x{v:016x})")

    return v


def read_at(b: bytes, off: int, size: int, what: str) -> bytes:
    end = off + size

    if off < 0 or size < 0 or end > len(b):
        fail(f"{what}: out-of-bounds (off=0x{off:x} size=0x{size:x} file=0x{len(b):x})")

    return b[off:end]


def le16(b: bytes, off: int) -> int:
    return struct.unpack_from("<H", b, off)[0]


def le32(b: bytes, off: int) -> int:
    return struct.unpack_from("<I", b, off)[0]


def load_import_map(path: str) -> dict:
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

                if not sym:
                    continue

                if not exl.endswith(".exl"):
                    exl = f"{exl}.exl"

                mapping[sym] = exl
    except FileNotFoundError:
        pass

    return mapping


class ELF:
    def __init__(self, data: bytes, verbose: bool) -> None:
        self.data = data
        self.verbose = verbose
        self.ei_class = 0
        self.ei_data = 0
        self.e_type = 0
        self.e_machine = 0
        self.e_version = 0
        self.e_entry = 0
        self.e_phoff = 0
        self.e_shoff = 0
        self.e_flags = 0
        self.e_ehsize = 0
        self.e_phentsize = 0
        self.e_phnum = 0
        self.e_shentsize = 0
        self.e_shnum = 0
        self.e_shstrndx = 0

        self.sections = []
        self.shstrtab = b""
        self.symtabs = []
        self.dynsyms = []

        self._parse()

    def _parse(self) -> None:
        b = self.data

        if len(b) < 52:
            fail("ELF too small")

        if b[0:4] != ELF_MAGIC:
            fail("ELF magic wrong")

        self.ei_class = b[4]
        self.ei_data  = b[5]

        if self.ei_class != ELFCLASS32:
            fail("Only ELF32 is supported")

        if self.ei_data != ELFDATA2LSB:
            fail("Only little-endian is supported")

        self.e_type      = le16(b, 16)
        self.e_machine   = le16(b, 18)
        self.e_version   = le32(b, 20)
        self.e_entry     = le32(b, 24)
        self.e_phoff     = le32(b, 28)
        self.e_shoff     = le32(b, 32)
        self.e_flags     = le32(b, 36)
        self.e_ehsize    = le16(b, 40)
        self.e_phentsize = le16(b, 42)
        self.e_phnum     = le16(b, 44)
        self.e_shentsize = le16(b, 46)
        self.e_shnum     = le16(b, 48)
        self.e_shstrndx  = le16(b, 50)

        if self.e_machine != EM_386:
            fail("Only EM_386 is supported")

        if self.e_version != 1:
            fail("Unknown ELF version")

        if self.e_shoff == 0 or self.e_shnum == 0:
            fail("ELF missing section table")

        if self.e_shentsize != 40:
            fail("Section header size unexpected (expected 40 for ELF32)")

        self.sections = []

        for i in range(self.e_shnum):
            off = self.e_shoff + i * self.e_shentsize
            sh_name = le32(b, off + 0)
            sh_type = le32(b, off + 4)
            sh_flags = le32(b, off + 8)
            sh_addr = le32(b, off + 12)
            sh_offset = le32(b, off + 16)
            sh_size = le32(b, off + 20)
            sh_link = le32(b, off + 24)
            sh_info = le32(b, off + 28)
            sh_addralign = le32(b, off + 32)
            sh_entsize = le32(b, off + 36)

            self.sections.append({
                "idx": i, "name_off": sh_name, "type": sh_type, "flags": sh_flags,
                "addr": sh_addr, "off": sh_offset, "size": sh_size,
                "link": sh_link, "info": sh_info, "align": sh_addralign, "entsize": sh_entsize
            })

        if self.e_shstrndx >= len(self.sections):
            fail("shstrndx out of range")

        shstr = self.sections[self.e_shstrndx]

        if shstr["type"] != SHT_STRTAB:
            fail("shstrtab is not STRTAB")

        self.shstrtab = read_at(b, shstr["off"], shstr["size"], ".shstrtab")

        for s in self.sections:
            s["name"] = self._read_cstr(self.shstrtab, s["name_off"])

        info(self.verbose, "--- ELF Sections ---")

        if self.verbose:
            for s in self.sections:
                print(f"[{s['idx']:2d}] {s['name']:<20} type={s['type']:2d} off=0x{s['off']:06x} size=0x{s['size']:06x} link={s['link']} info={s['info']} align={s['align']} entsz={s['entsize']}")

            print("----------------------")

        for s in self.sections:
            if s["type"] in (SHT_SYMTAB, SHT_DYNSYM):
                sym = self._parse_symtab(s)

                if s["type"] == SHT_SYMTAB:
                    self.symtabs.append(sym)
                else:
                    self.dynsyms.append(sym)

        # If no symbols at all, allow but get 0 exports
        # We still support relocs via raw addends

    def _read_cstr(self, blob: bytes, off: int) -> str:
        if off < 0 or off >= len(blob):
            return ""

        end = blob.find(b"\x00", off)

        if end < 0:
            end = len(blob)

        try:
            return blob[off:end].decode("utf-8", errors="strict")
        except UnicodeDecodeError:
            return blob[off:end].decode("latin1", errors="ignore")

    def _parse_symtab(self, sec: dict) -> dict:
        b = self.data
        entsz = sec["entsize"] or 16

        if entsz != 16:
            fail(f"Symbol entry size unexpected: {entsz}")

        count = 0 if sec["size"] == 0 else sec["size"] // entsz
        strsec_idx = sec["link"]

        if strsec_idx >= len(self.sections):
            fail("symtab strtab link out of range")

        strsec = self.sections[strsec_idx]

        if strsec["type"] != SHT_STRTAB:
            fail("symtab does not link to STRTAB")

        strtab = read_at(b, strsec["off"], strsec["size"], "sym strtab")
        symbols = []

        for i in range(count):
            off = sec["off"] + i * entsz
            st_name  = le32(b, off + 0)
            st_value = le32(b, off + 4)
            st_size  = le32(b, off + 8)
            st_info  = b[off + 12]
            st_other = b[off + 13]
            st_shndx = le16(b, off + 14)
            bind = st_info >> 4
            typ  = st_info & 0x0f
            name = self._read_cstr(strtab, st_name)

            symbols.append({
                "idx": i, "name": name, "bind": bind, "type": typ,
                "shndx": st_shndx, "value": st_value, "size": st_size, "other": st_other
            })

        info(self.verbose, f"[symtab] {sec['name']}: {len(symbols)} symbols")

        return {"sec_index": sec["idx"], "symbols": symbols, "strtab": strtab}

    def get_bytes(self, sec: dict) -> bytes:
        if not sec:
            return b""

        if sec["type"] == SHT_NOBITS:
            return b"\x00" * sec["size"]

        return read_at(self.data, sec["off"], sec["size"], f"section {sec['name']}")


def build_exl(input_path: Path, output_path: Path, libname: str,
              default_exl: str, imports_map: str, verbose: bool) -> None:
    raw = input_path.read_bytes()
    elf = ELF(raw, verbose)

    # Group sections by type in ELF order
    text_secs = []
    ro_secs   = []
    data_secs = []
    bss_sec   = None

    for s in elf.sections:
        if s["type"] == SHT_PROGBITS and (s["flags"] & SHF_ALLOC) and (s["flags"] & SHF_EXECINSTR):
            text_secs.append(s)
        elif s["type"] == SHT_PROGBITS and (s["flags"] & SHF_ALLOC) and not (s["flags"] & SHF_WRITE) and not (s["flags"] & SHF_EXECINSTR):
            ro_secs.append(s)
        elif s["type"] == SHT_PROGBITS and (s["flags"] & SHF_ALLOC) and (s["flags"] & SHF_WRITE):
            data_secs.append(s)
        elif s["type"] == SHT_NOBITS and s["name"] == ".bss":
            bss_sec = s

    if not text_secs:
        fail("No TEXT sections (ALLOC+EXEC) found")

    # Pack segments
    def pack_segment(secs):
        blob = bytearray()
        mapping = {}
        cur = 0

        for s in secs:
            align = s["align"] if s["align"] > 0 else 1

            if align & (align - 1) != 0:
                # Bump up to nearest power of 2
                pow2 = 1

                while pow2 < align:
                    pow2 <<= 1

                align = pow2

            new_cur = align_up(cur, align)
            pad = new_cur - cur

            if pad:
                blob.extend(b"\x00" * pad)

            cur = new_cur
            mapping[s["idx"]] = cur
            data = elf.get_bytes(s)
            blob.extend(data)
            cur += len(data)

        return blob, mapping

    text_blob, text_relmap = pack_segment(text_secs)
    ro_blob,   ro_relmap   = pack_segment(ro_secs)
    data_blob, data_relmap = pack_segment(data_secs)

    bss_sz = bss_sec["size"] if bss_sec else 0

    # Place segments in the EXL image
    text_off = HDR_SIZE
    ro_off   = align_up(text_off + len(text_blob), FILE_ALIGN)
    data_off = align_up(ro_off   + len(ro_blob),   FILE_ALIGN)

    info(verbose, f"[SEGMENT] .text: {len(text_secs)} sections -> off=0x{text_off:08x} sz=0x{len(text_blob):x}")

    for s in text_secs:
        info(verbose, f"  - {s['name']}: align={s['align']} size=0x{s['size']:x} img_off=0x{(text_off + text_relmap[s['idx']]):08x}")

    info(verbose, f"[SEGMENT] .ro:   {len(ro_secs)} sections -> off=0x{ro_off:08x}   sz=0x{len(ro_blob):x}")

    for s in ro_secs:
        info(verbose, f"  - {s['name']}: align={s['align']} size=0x{s['size']:x} img_off=0x{(ro_off + ro_relmap[s['idx']]):08x}")

    info(verbose, f"[SEGMENT] .data: {len(data_secs)} sections -> off=0x{data_off:08x} sz=0x{len(data_blob):x}")

    for s in data_secs:
        info(verbose, f"  - {s['name']}: align={s['align']} size=0x{s['size']:x} img_off=0x{(data_off + data_relmap[s['idx']]):08x}")

    info(verbose, f"[SEGMENT] .bss: sz=0x{bss_sz:x}")

    # Global map: section index -> absolute image offset (S base)
    sec_img_base = {}

    for s in text_secs:
        sec_img_base[s["idx"]] = text_off + text_relmap[s["idx"]]

    for s in ro_secs:
        sec_img_base[s["idx"]]   = ro_off   + ro_relmap[s["idx"]]

    for s in data_secs:
        sec_img_base[s["idx"]] = data_off + data_relmap[s["idx"]]

    if bss_sec:
        sec_img_base[bss_sec["idx"]] = data_off + len(data_blob)

    # Buffers for patching
    text_buf = bytearray(text_blob)
    ro_buf   = bytearray(ro_blob)
    data_buf = bytearray(data_blob)

    # Helper: get target buf + base from sec_idx
    sec_by_idx = {s["idx"]: s for s in elf.sections}

    def get_target_buf_and_base(secidx: int):
        s = sec_by_idx.get(secidx)

        if not s:
            return None, -1

        base = sec_img_base.get(secidx, -1)

        if base < 0:
            return None, -1

        if s in text_secs:
            return text_buf, base - text_off

        if s in ro_secs:
            return ro_buf, base - ro_off

        if s in data_secs:
            return data_buf, base - data_off

        return None, -1

    # Helpers for EXL names
    def norm_exl(name: str) -> str:
        if not name:
            return "diffc.exl"

        if not name.endswith(".exl"):
            return f"{name}.exl"

        return name

    libname = norm_exl(libname)
    default_exl = norm_exl(default_exl)

    # Strtab
    strtab = bytearray(b"\x00")
    strmap = {"": 0}

    def add_str(s: str) -> int:
        if s in strmap:
            return strmap[s]

        try:
            enc = s.encode("utf-8")
        except Exception:
            fail(f"Invalid UTF-8 string: {s!r}")

        off = len(strtab)
        strtab.extend(enc + b"\x00")
        strmap[s] = off

        return off

    add_str(libname)
    add_str(default_exl)

    # Exports: defined FUNC/OBJECT in ALLOC sections
    exl_exports = []

    def add_export(name_off: int, value_off: int, is_func: bool) -> None:
        exl_exports.append((u32(name_off, "sym name_off"), u32(value_off, "sym val_off"), 0 if is_func else 1))

    all_symtabs = elf.symtabs + elf.dynsyms

    def sym_defined(sym: dict) -> bool:
        sh = sym["shndx"]

        return (sh != SHN_UNDEF) and (sym["type"] != STT_FILE) and (sym["type"] != STT_TLS)

    for tab in all_symtabs:
        for sym in tab["symbols"]:
            name = sym["name"]

            if not name:
                continue

            if sym["type"] in (STT_FILE, STT_SECTION, STT_TLS):
                continue

            if not sym_defined(sym):
                continue

            base = sec_img_base.get(sym["shndx"], -1)

            if base < 0:
                continue

            value_off = (base + sym["value"]) & 0xffffffff
            name_off  = add_str(name)
            is_func = (sym["type"] == STT_FUNC) or (sym["type"] == STT_NOTYPE and sym["value"] != 0)
            add_export(name_off, value_off, is_func)
            info(verbose, f"[EXPORT] {name} -> off=0x{value_off:08x} ({'func' if is_func else 'obj'})")

    # Imports
    exl_imports = []
    import_map = {}
    sym_import_overrides = load_import_map(imports_map)

    def import_target(sym_nm: str) -> str:
        if sym_nm in sym_import_overrides:
            return norm_exl(sym_import_overrides[sym_nm])

        return default_exl

    def add_import(exl_nm: str, sym_nm: str, is_func: bool) -> int:
        if not sym_nm:
            fail("Attempt to create import with empty symbol name")

        exl_nm = norm_exl(exl_nm)
        key = (exl_nm, sym_nm, 0 if is_func else 1)
        idx = import_map.get(key, -1)

        if idx >= 0:
            return idx

        e_off = add_str(exl_nm)
        s_off = add_str(sym_nm)
        idx = len(exl_imports)
        exl_imports.append((e_off, s_off, 0 if is_func else 1, 0))
        import_map[key] = idx
        info(verbose, f"[IMPORT] idx={idx} {exl_nm}:{sym_nm} type={'func' if is_func else 'obj'}")

        return idx

    reloc_table = []
    reloc_sites = set()

    def add_reloc(img_off: int, idx: int, dex_type: int) -> None:
        reloc_table.append((u32(img_off, "reloc off"), u32(idx, "reloc idx"), u32(dex_type, "reloc type"), 0))
        reloc_sites.add(u32(img_off, "reloc site"))

    # Reloc iteration
    def iter_reloc_sections():
        for sec in elf.sections:
            if sec["type"] in (SHT_REL, SHT_RELA):
                yield sec

    def get_sym_from_reloc(sec_rel: dict, sym_index: int) -> dict:
        link = sec_rel["link"]

        for tab in all_symtabs:
            if tab["sec_index"] == link:
                syms = tab["symbols"]

                if 0 <= sym_index < len(syms):
                    return syms[sym_index]

        return {}

    def read_addend(target_buf: bytearray, r_off: int) -> int:
        if r_off < 0 or r_off + 4 > len(target_buf):
            fail(f"Reloc r_offset out of bounds in target (off=0x{r_off:x}, len=0x{len(target_buf):x})")

        return struct.unpack_from("<I", target_buf, r_off)[0]

    def local_S(sym: dict) -> int:
        if not sym:
            return -1

        if sym["type"] == STT_SECTION:
            return sec_img_base.get(sym["shndx"], -1)

        if sym_defined(sym):
            base = sec_img_base.get(sym["shndx"], -1)

            if base < 0:
                return -1

            return (base + sym["value"]) & 0xffffffff

        return -1

    # Pass 1: ELF REL/RELA -> initial patches + DEX relocs
    for rsec in iter_reloc_sections():
        tgt_secidx = rsec["info"]
        tgt_buf, rel_base = get_target_buf_and_base(tgt_secidx)

        if tgt_buf is None:
            fail(f"Reloc section {rsec['name']} points to unknown/unpacked target idx={tgt_secidx}")

        entsz = rsec["entsize"] if rsec["entsize"] else (12 if rsec["type"] == SHT_REL else 12+4)
        count = 0 if rsec["size"] == 0 else rsec["size"] // entsz

        tgt_base_abs = sec_img_base[tgt_secidx]
        info(verbose, f"[RELOCSEC] {rsec['name']} -> sec#{tgt_secidx} entries={count}")

        for i in range(count):
            off = rsec["off"] + i * entsz
            r_offset = le32(raw, off + 0)
            r_info   = le32(raw, off + 4)
            r_addend = le32(raw, off + 8) if rsec["type"] == SHT_RELA else 0

            r_type = r_info & 0xff
            r_symi = (r_info >> 8) & 0xffffff

            # r_offset points into target buffer, validate
            if not (0 <= r_offset <= len(tgt_buf) - 4):
                fail(f"Reloc r_offset out of range in target section idx={tgt_secidx}: off=0x{r_offset:x} len=0x{len(tgt_buf):x}")

            img_off = u32(tgt_base_abs + r_offset, "reloc img_off")

            sym = get_sym_from_reloc(rsec, r_symi) if r_symi != 0 else {}
            A = r_addend if rsec["type"] == SHT_RELA else read_addend(tgt_buf, r_offset)

            if r_type in (R_386_GOT32, R_386_GOTPC, R_386_GOTOFF, R_386_GLOB_DAT, R_386_JMP_SLOT, R_386_RELATIVE, R_386_COPY):
                fail(f"No support for GOT/PLT/dynamic reloc type={r_type} in {rsec['name']} (off=0x{r_offset:x})")

            if r_type in (R_386_PC32, R_386_PLT32):
                S = local_S(sym) if sym else -1

                if S != -1:
                    P = img_off
                    val = (S + A - P) & 0xffffffff
                    struct.pack_into("<I", tgt_buf, r_offset, val)
                    info(verbose, f"[PC32 local] @{img_off:08x} sym='{sym.get('name','')}' set=0x{val:08x}")
                else:
                    nm = sym.get("name","") if sym else ""
                    target_exl = import_target(nm)
                    imp_idx = add_import(target_exl, nm, True)
                    struct.pack_into("<I", tgt_buf, r_offset, 0)
                    add_reloc(img_off, imp_idx, DEX_PC32)
                    info(verbose, f"[PC32 ext] @{img_off:08x} sym='{nm}' -> import idx={imp_idx} exl={target_exl}")

            elif r_type == R_386_32:
                S = local_S(sym) if sym else -1
                name = sym.get("name","") if sym else ""

                if S != -1:
                    init = (S + A) & 0xffffffff
                    struct.pack_into("<I", tgt_buf, r_offset, init)
                    add_reloc(img_off, 0, DEX_RELATIVE)
                    info(verbose, f"[ABS32 rel] @{img_off:08x} init=0x{init:08x} sym='{name}'")
                else:
                    if (not sym) or (not name):
                        struct.pack_into("<I", tgt_buf, r_offset, A & 0xffffffff)
                        add_reloc(img_off, 0, DEX_RELATIVE)
                        info(verbose, f"[ABS32 no-sym] @{img_off:08x} A=0x{A:08x} -> RELATIVE")
                    else:
                        is_func = (sym["type"] == STT_FUNC) or (sym["type"] == STT_NOTYPE and sym["value"] != 0)
                        target_exl = import_target(name)
                        imp_idx = add_import(target_exl, name, is_func)
                        add_reloc(img_off, imp_idx, DEX_ABS32)
                        info(verbose, f"[ABS32 ext] @{img_off:08x} sym='{name}' -> import idx={imp_idx} exl={target_exl}")

            elif r_type == R_386_NONE:
                info(verbose, f"[NONE] @{img_off:08x}")
            else:
                fail(f"Unexpected reloc type={r_type} in {rsec['name']}")

    # Pass 2: sweep .rodata/.data for raw file offsets, add DEX_RELATIVE
    text = bytes(text_buf)
    ro   = bytes(ro_buf)
    dat  = bytes(data_buf)

    # File ranges that count as sections, excluding header
    sec_ranges = []

    if len(text):
        sec_ranges.append((text_off, text_off + len(text)))

    if len(ro):
        sec_ranges.append((ro_off, ro_off + len(ro)))

    if len(dat):
        sec_ranges.append((data_off, data_off + len(dat)))

    def in_section_file_ranges(x: int) -> bool:
        for (lo, hi) in sec_ranges:
            if lo <= x < hi:
                return True

        return False

    # Equivalent to loaders dex_file_span_end
    end_span = align_up(max(
        (data_off + len(dat) + bss_sz),
        (ro_off + len(ro)),
        (text_off + len(text)),
        (text_off + 0x10)
    ), FILE_ALIGN)

    def sweep_region_for_offsets(buf: bytearray, region_base_off: int, tag: str) -> int:
        if not buf:
            return 0

        patched = 0

        # 4-byte aligned sweep
        for off in range(0, len(buf) - 3, 4):
            img_off = region_base_off + off

            # Skip if already has reloc at this position
            if img_off in reloc_sites:
                continue

            val = struct.unpack_from("<I", buf, off)[0]

            # Heuristic: value must point into some file section, excluding header
            if in_section_file_ranges(val):
                add_reloc(img_off, 0, DEX_RELATIVE)
                patched += 1

                if verbose:
                    print(f"[DATA-SWEEP] {tag} +0x{off:06x} (img@0x{img_off:08x}) val=0x{val:08x} -> add DEX_RELATIVE")

        return patched

    patched_ro  = sweep_region_for_offsets(ro_buf,   ro_off,   ".rodata")
    patched_dat = sweep_region_for_offsets(data_buf, data_off, ".data")

    if verbose:
        print(f"[DATA-SWEEP] .rodata patched={patched_ro}, .data patched={patched_dat}")

    # Final bytes
    text = bytes(text_buf)
    ro   = bytes(ro_buf)
    dat  = bytes(data_buf)

    # Table placements
    cur = align_up(data_off + len(dat), FILE_ALIGN)
    import_off = cur
    cur += 16 * len(exl_imports)
    reloc_off  = cur
    cur += 16 * len(reloc_table)
    symtab_off = cur
    cur += 12 * len(exl_exports)
    strtab_off = cur
    cur += len(strtab)

    # Header
    hdr = bytearray(HDR_SIZE)

    def W32(o,v):
        struct.pack_into("<I", hdr, o, u32(v, f"hdr@{o:#x}"))

    W32(0x00, DEX_MAGIC)
    W32(0x04, DEX_VER_MAJ)
    W32(0x08, DEX_VER_MIN)
    # entry_offset = .text start in image, relative within image
    W32(0x0C, text_off)
    W32(0x10, text_off)
    W32(0x14, len(text))
    W32(0x18, ro_off)
    W32(0x1C, len(ro))
    W32(0x20, data_off)
    W32(0x24, len(dat))
    W32(0x28, bss_sz)
    W32(0x2C, import_off if exl_imports else 0)
    W32(0x30, len(exl_imports))
    W32(0x34, reloc_off  if reloc_table else 0)
    W32(0x38, len(reloc_table))
    W32(0x3C, symtab_off if exl_exports else 0)
    W32(0x40, len(exl_exports))
    W32(0x44, strtab_off if strtab else 0)
    W32(0x48, len(strtab))

    with open(output_path, "wb") as out:
        out.write(hdr)

        # TEXT
        out.write(text)
        pad = ro_off - (HDR_SIZE + len(text))

        if pad < 0:
            fail("ro_off backtracks before .text")

        if pad:
            out.write(b"\x00" * pad)

        # RO
        out.write(ro)
        pad = data_off - (ro_off + len(ro))

        if pad < 0:
            fail("data_off backtracks before .rodata")

        if pad:
            out.write(b"\x00" * pad)

        # DATA
        out.write(dat)

        # Align to tables
        tables_start = align_up(data_off + len(dat), FILE_ALIGN)
        pad = tables_start - (data_off + len(dat))

        if pad < 0:
            fail("tables_start backtracks before .data end")

        if pad:
            out.write(b"\x00" * pad)

        info(verbose, f"[ALIGN] tables_start=0x{tables_start:08x} import_off=0x{import_off:08x} reloc_off=0x{reloc_off:08x} symtab_off=0x{symtab_off:08x} strtab_off=0x{strtab_off:08x}")

        # Tables
        if exl_imports:
            out.seek(import_off)

            for e_off, s_off, t, _ in exl_imports:
                out.write(struct.pack("<IIII", e_off, s_off, t, 0))

        if reloc_table:
            out.seek(reloc_off)

            for off, si, t, _ in reloc_table:
                out.write(struct.pack("<IIII", off, si, t, 0))

        if exl_exports:
            out.seek(symtab_off)

            for name_off, val_off, t in exl_exports:
                out.write(struct.pack("<III", name_off, val_off, t))

        out.seek(strtab_off)
        out.write(strtab)

        if verbose:
            end_off = strtab_off + len(strtab)
            print("=== EXL BUILD ===")
            print(f"libname='{libname}'")
            print(f".text  off=0x{text_off:08x} sz=0x{len(text):x}")
            print(f".rodat off=0x{ro_off:08x}   sz=0x{len(ro):x}")
            print(f".data  off=0x{data_off:08x} sz=0x{len(dat):x}")
            print(f".bss   sz=0x{bss_sz:x}")
            print(f"imports off=0x{import_off:08x} cnt={len(exl_imports)}")
            print(f"relocs  off=0x{reloc_off:08x}  cnt={len(reloc_table)}")
            print(f"symtab  off=0x{symtab_off:08x} cnt={len(exl_exports)}")
            print(f"strtab  off=0x{strtab_off:08x} sz=0x{len(strtab):x}")
            print(f"[SIZE] wrote_end=0x{end_off:08x}")


def main() -> None:
    ap = argparse.ArgumentParser(description="ELF -> DEX EXL builder (pure Python, ELF32 i386)")
    ap.add_argument("input_elf")
    ap.add_argument("output_exl")
    ap.add_argument("libname", help="EXL name, e.g. diffc.exl")
    ap.add_argument("--default-exl", default="diffc.exl",
                    help="Default EXL for undefined symbols (default: diffc.exl)")
    ap.add_argument("--imports-map", default=None,
                    help="Optional imports_map.txt (sym -> exl)")
    ap.add_argument("--verbose", "-v", action="store_true")
    args = ap.parse_args()

    inp = Path(args.input_elf)
    out = Path(args.output_exl)

    if not inp.exists():
        fail(f"Input ELF not found: {inp}")

    build_exl(inp, out, args.libname, args.default_exl, args.imports_map, args.verbose)


if __name__ == "__main__":
    main()
