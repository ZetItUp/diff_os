# -*- coding: utf-8 -*-
# Tool: ELF32 -> DEX/EXL image builder for Different OS
#
# Viktigt i denna version:
# - Alla DEX-reloker skrivs ut korrekt (fixad indentering).
# - DEX_RELATIVE: måladress skrivs som fil-offset i bilden; loader gör image_base + offset.
# - DEX_ABS32 (intern): S + A -> fil-offset och platsen skrivs med fil-offset.
# - DEX_PC32 (intern): använder S (ingen addend -4); loader räknar disp = S - P.
# - symbolfält i reloc-poster är STRTAB-offset till symbolnamn (externa/interna) för tydlig dv.
# - DPAR ligger i början av .ro så verktyg hittar det.
# - R_386_PC32 -> DEX_PC32 (ingen heuristik som kan svälja poster).
#
from typing import List, Tuple, Optional, Dict, Set
import struct
import sys
import argparse

def _dbg(enabled: bool, msg: str) -> None:
    if enabled:
        sys.stderr.write(msg + "\n")

# ---------- ELF constants ----------
ELF_MAGIC    = b"\x7fELF"
ELFCLASS32   = 1
ELFDATA2LSB  = 1

SHT_NULL     = 0
SHT_PROGBITS = 1
SHT_SYMTAB   = 2
SHT_STRTAB   = 3
SHT_RELA     = 4
SHT_NOBITS   = 8
SHT_REL      = 9
SHT_DYNSYM   = 11

SHF_WRITE     = 0x1
SHF_ALLOC     = 0x2
SHF_EXECINSTR = 0x4

STB_LOCAL  = 0
STB_GLOBAL = 1
STB_WEAK   = 2

STT_NOTYPE = 0
STT_OBJECT = 1
STT_FUNC   = 2
STT_SECTION= 3
STT_FILE   = 4

# i386 relocs
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

# ---------- DEX/EXL constants ----------
DEX_MAGIC     = 0x58454400  # "DEX\0"
DEX_VER_MAJOR = 1
DEX_VER_MINOR = 0

DEX_ABS32    = 0
DEX_PC32     = 2
DEX_RELATIVE = 8

# DEX params (DXPP)
DEX_PARAMS_MAGIC = 0x44504152  # "DPAR"

# x86 opcodes
X86_CALL_REL32 = 0xE8
X86_JMP_REL32  = 0xE9

# Thunk-sida i ditt system (se kernel-loggar)
THUNK_PAGE_TOP = 0x7FFEF000  # stack_top ska ligga här

# ---- Historical link-base (behålls endast för DXPP default) ----
FORCED_IMAGE_BASE = 0x40000000

# ---------- Helpers ----------
def _align(x: int, a: int) -> int:
    return (x + (a - 1)) & ~(a - 1)

def _rd(path: str, off: int, size: int) -> bytes:
    with open(path, "rb") as f:
        f.seek(off)
        d = f.read(size)
        if len(d) != size:
            raise IOError("EOF while reading")
        return d

# ---------- Models ----------
class Sec:
    __slots__ = ("idx","name","sh_type","sh_flags","sh_addr","sh_offset","sh_size","sh_link","sh_info","sh_addralign","sh_entsize")
    def __init__(self, idx: int, name: str, sh_type: int, sh_flags: int, sh_addr: int, sh_offset: int, sh_size: int, sh_link: int, sh_info: int, sh_addralign: int, sh_entsize: int):
        self.idx=idx; self.name=name; self.sh_type=sh_type; self.sh_flags=sh_flags
        self.sh_addr=sh_addr; self.sh_offset=sh_offset; self.sh_size=sh_size
        self.sh_link=sh_link; self.sh_info=sh_info; self.sh_addralign=sh_addralign; self.sh_entsize=sh_entsize

class Sym:
    __slots__=("name","st_name","st_value","st_size","st_info","st_other","st_shndx")
    def __init__(self, name: str, st_name: int, st_value: int, st_size: int, st_info: int, st_other: int, st_shndx: int):
        self.name=name; self.st_name=st_name; self.st_value=st_value; self.st_size=st_size; self.st_info=st_info; self.st_other=st_other; self.st_shndx=st_shndx
    @property
    def bind(self) -> int: return self.st_info >> 4
    @property
    def typ(self) -> int:  return self.st_info & 0xF

class Rel:
    __slots__=("tgt_sec_name","r_offset","r_info","r_addend","sym")
    def __init__(self, tgt_sec_name: str, r_offset: int, r_info: int, r_addend: Optional[int], sym: Optional[Sym]):
        self.tgt_sec_name=tgt_sec_name; self.r_offset=r_offset; self.r_info=r_info
        self.r_addend=r_addend; self.sym=sym
    @property
    def r_type(self) -> int: return self.r_info & 0xFF
    @property
    def r_symidx(self) -> int: return self.r_info >> 8

class Elf:
    __slots__=("path","quiet","e_entry","sections","symtabs","reltabs","_by_index")
    def __init__(self, path: str, quiet: bool=False):
        self.path=path; self.quiet=quiet
        self.e_entry=0
        self.sections: List[Sec]=[]
        self.symtabs: List[Tuple[str,List[Sym]]] = []
        self.reltabs: List[Tuple[str,str,List[Rel]]] = []
        self._by_index: Dict[int, Sec] = {}
        self._parse()

    def _parse(self) -> None:
        e = _rd(self.path, 0, 52)
        if e[:4]!=ELF_MAGIC or e[4]!=ELFCLASS32 or e[5]!=ELFDATA2LSB:
            raise ValueError("Only ELF32 little-endian is supported")
        self.e_entry = int.from_bytes(e[24:28], "little")
        shoff   = int.from_bytes(e[32:36], "little")
        shentsz = int.from_bytes(e[46:48], "little")
        shnum   = int.from_bytes(e[48:50], "little")
        shstrndx= int.from_bytes(e[50:52], "little")

        shdrs = _rd(self.path, shoff, shentsz * shnum)
        shstr_off = int.from_bytes(shdrs[shentsz*shstrndx + 16: shentsz*shstrndx + 20], "little")
        shstr_sz  = int.from_bytes(shdrs[shentsz*shstrndx + 20: shentsz*shstrndx + 24], "little")
        shstr     = _rd(self.path, shstr_off, shstr_sz)

        def nm(off: int) -> str:
            if off >= len(shstr):
                return ""
            j = shstr.find(b"\x00", off)
            if j == -1:
                j = len(shstr)
            return shstr[off:j].decode("utf-8", "replace")

        by_index: Dict[int, Sec] = {}
        for i in range(shnum):
            sh = shdrs[i*shentsz:(i+1)*shentsz]
            s = Sec(
                i,
                nm(int.from_bytes(sh[0:4], "little")),
                int.from_bytes(sh[4:8], "little"),
                int.from_bytes(sh[8:12], "little"),
                int.from_bytes(sh[12:16], "little"),
                int.from_bytes(sh[16:20], "little"),
                int.from_bytes(sh[20:24], "little"),
                int.from_bytes(sh[24:28], "little"),
                int.from_bytes(sh[28:32], "little"),
                int.from_bytes(sh[32:36], "little"),
                int.from_bytes(sh[36:40], "little"),
            )
            self.sections.append(s)
            by_index[i] = s
        self._by_index = by_index

        # Symbols (keep ELF order)
        for s in self.sections:
            if s.sh_type in (SHT_SYMTAB, SHT_DYNSYM):
                if s.sh_entsize not in (0, 16) or (s.sh_size % 16) != 0:
                    continue
                strsec = by_index.get(s.sh_link)
                if not strsec:
                    continue
                strtab = _rd(self.path, strsec.sh_offset, strsec.sh_size)
                data   = _rd(self.path, s.sh_offset, s.sh_size)
                recs: List[Sym] = []
                for i in range(s.sh_size // 16):
                    ent = data[i*16:(i+1)*16]
                    st_name  = int.from_bytes(ent[0:4], "little")
                    st_value = int.from_bytes(ent[4:8], "little")
                    st_size  = int.from_bytes(ent[8:12],"little")
                    st_info  = ent[12]
                    st_other = ent[13]
                    st_shndx = int.from_bytes(ent[14:16],"little")
                    nm_s = ""
                    if st_name < len(strtab):
                        j = strtab.find(b"\x00", st_name)
                        nm_s = strtab[st_name:(j if j!=-1 else len(strtab))].decode("utf-8", "replace")
                    recs.append(Sym(nm_s, st_name, st_value, st_size, st_info, st_other, st_shndx))
                self.symtabs.append((s.name, recs))

        # Relocations (keep section order and entry order)
        for s in self.sections:
            if s.sh_type not in (SHT_REL, SHT_RELA):
                continue
            tgt = by_index.get(s.sh_info)
            if not tgt:
                continue
            symtab: Optional[List[Sym]] = None
            symsec = by_index.get(s.sh_link)
            if symsec:
                for name, lst in self.symtabs:
                    if name == symsec.name:
                        symtab = lst
                        break
            data = _rd(self.path, s.sh_offset, s.sh_size)
            entsz = 8 if s.sh_type == SHT_REL else 12
            if s.sh_entsize not in (0, entsz):
                continue
            cnt = s.sh_size // entsz
            rels: List[Rel] = []
            for i in range(cnt):
                ent = data[i*entsz:(i+1)*entsz]
                r_off  = int.from_bytes(ent[0:4], "little")
                r_info = int.from_bytes(ent[4:8], "little")
                r_add  = int.from_bytes(ent[8:12],"little") if s.sh_type == SHT_RELA else None
                sym: Optional[Sym] = None
                if symtab:
                    si = r_info >> 8
                    if 0 <= si < len(symtab):
                        sym = symtab[si]
                rels.append(Rel(tgt.name, r_off, r_info, r_add, sym))
            self.reltabs.append((tgt.name, s.name, rels))

# ---------- Image layout ----------
class MapEnt:
    __slots__=("kind","name","base_va","size","file_off")
    def __init__(self, kind: str, name: str, base_va: int, size: int, file_off: int):
        self.kind=kind; self.name=name; self.base_va=base_va; self.size=size; self.file_off=file_off

def _collect_parts(elf: Elf):
    text: List[Sec] = []; ro: List[Sec] = []; data: List[Sec] = []; bss_sz = 0
    for s in elf.sections:
        if not (s.sh_flags & SHF_ALLOC):
            continue
        if s.sh_type == SHT_NOBITS:
            bss_sz += s.sh_size
            continue
        if (s.sh_flags & SHF_EXECINSTR) or s.name.startswith(".text"):
            text.append(s)
        elif s.name.startswith(".rodata"):
            ro.append(s)
        else:
            data.append(s)
    text.sort(key=lambda s: (s.sh_addr, s.sh_offset))
    ro.sort(key=lambda s: (s.sh_addr, s.sh_offset))
    data.sort(key=lambda s: (s.sh_addr, s.sh_offset))
    return text, ro, data, bss_sz

def _dxpp_blob() -> bytes:
    # Layout: magic(0),ver_major(4),ver_minor(6),flags(8),
    # argc(12),argv(16),envc(20),envp(24),
    # cmdline(28),cwd(32),image_base(36),image_size(40),
    # stack_top(44),stack_limit(48),reserved...
    return struct.pack(
        "<IHHI" + "I"*10 + "I"*8,
        DEX_PARAMS_MAGIC, 1, 0, 0,  # magic, ver_major, ver_minor, flags
        0, 0, 0, 0,                 # argc, argv, envc, envp
        0, 0,                       # cmdline, cwd
        0, 0,                       # image_base, image_size (patchas)
        0, 0,                       # stack_top, stack_limit (patchas)
        0,0,0,0,0,0,0,0            # reserved[8]
    )

def _build_image_with_dxpp_in_ro(elf: Elf, put_dxpp: bool):
    img = bytearray()
    maps: List[MapEnt] = []
    cur = 0
    hdr_pad = 0x100
    img.extend(b"\x00" * hdr_pad); cur = hdr_pad

    def add_secs(kind: str, secs: List[Sec]):
        nonlocal cur
        start = _align(cur, 16)
        if start > len(img):
            img.extend(b"\x00" * (start - len(img)))
        cur = start
        total_sz = 0
        for s in secs:
            cur = _align(cur, max(1, s.sh_addralign))
            data = _rd(elf.path, s.sh_offset, s.sh_size)
            if cur > len(img):
                img.extend(b"\x00" * (cur - len(img)))
            img.extend(data)
            maps.append(MapEnt(kind, s.name, s.sh_addr, s.sh_size, cur))
            cur += s.sh_size
            total_sz += s.sh_size
        return start, total_sz

    text, ro, data, bss_sz = _collect_parts(elf)
    text_off,  text_sz  = add_secs(".text", text)
    ro_off,    ro_sz    = add_secs(".ro",   ro)
    dxpp_off_saved: Optional[int] = None
    if put_dxpp:
        dxpp_blob = _dxpp_blob()
        # Lägg DXPP i början av .ro
        img[ro_off:ro_off] = dxpp_blob
        # Skjut fram alla map-entries som ligger på/efter ro_off
        delta = len(dxpp_blob)
        for m in maps:
            if m.file_off >= ro_off:
                m.file_off += delta
        ro_sz += delta
        dxpp_off_saved = ro_off
        _dbg(not elf.quiet, f"[DXPP] placed at .ro file_off=0x{ro_off:08x}")

    data_off,  data_sz  = add_secs(".data", data)
    # Link base enbart för DXPP default
    link_base: int = FORCED_IMAGE_BASE

    return img, maps, (text_off, text_sz, ro_off, ro_sz, data_off, data_sz, bss_sz, hdr_pad, link_base, dxpp_off_saved)

def _va2off(maps: List[MapEnt], va: int, prefer_kind: Optional[str]=None) -> Optional[int]:
    for m in maps:
        if prefer_kind and m.kind != prefer_kind:
            continue
        if m.base_va <= va < m.base_va + m.size:
            return m.file_off + (va - m.base_va)
    for m in maps:
        if m.base_va <= va < m.base_va + m.size:
            return m.file_off + (va - m.base_va)
    return None

def _va2off_in_section(maps: List[MapEnt], va: int, sect_name: str) -> Optional[int]:
    for m in maps:
        if m.name == sect_name and (m.base_va <= va < m.base_va + m.size):
            return m.file_off + (va - m.base_va)
    return None

def _sym_abs_va(elf: Elf, sym: Sym) -> Optional[int]:
    if sym is None:
        return None
    if sym.st_shndx <= 0 or sym.st_shndx >= len(elf.sections):
        return None
    sec = elf._by_index.get(sym.st_shndx)
    if not sec:
        return None
    return (sec.sh_addr + sym.st_value) & 0xFFFFFFFF

def _pick_entry(elf: Elf, maps: List[MapEnt], entry_symbol: Optional[str]) -> int:
    if entry_symbol:
        for _tab, lst in elf.symtabs:
            for s in lst:
                if s.name == entry_symbol and s.typ == STT_FUNC and s.st_value:
                    va = _sym_abs_va(elf, s)
                    _dbg(not elf.quiet, f"[ENTRY] user requested '{entry_symbol}', abs_va={hex(va) if va is not None else 'None'}")
                    if va is not None:
                        return va
    for _tab, lst in elf.symtabs:
        for s in lst:
            if s.name == "main" and s.typ == STT_FUNC and s.st_value:
                va = _sym_abs_va(elf, s)
                _dbg(not elf.quiet, f"[ENTRY] prefer 'main' abs_va={hex(va) if va is not None else 'None'}")
                if va is not None:
                    return va
    if elf.e_entry:
        _dbg(not elf.quiet, f"[ENTRY] using ELF e_entry={hex(elf.e_entry)}")
        return elf.e_entry
    for _tab, lst in elf.symtabs:
        for s in lst:
            if s.name == "_start" and s.typ == STT_FUNC and s.st_value:
                va = _sym_abs_va(elf, s)
                _dbg(not elf.quiet, f"[ENTRY] found _start abs_va={hex(va) if va is not None else 'None'}")
                if va is not None:
                    return va
    text = [m for m in maps if m.kind == ".text" and m.size > 0]
    if text:
        _dbg(not elf.quiet, f"[ENTRY] fallback to .text base {hex(text[0].base_va)}")
        return text[0].base_va
    raise ValueError("No entry found")

# ---------- Extraction in original order ----------
def _collect_imports_in_reloc_order(elf: Elf, rels_ordered: List[Tuple[str, Rel]]) -> Tuple[List[str], Dict[str,int]]:
    seen: Dict[str, None] = {}
    types: Dict[str, int] = {}
    out: List[str] = []
    for _tgt_name, r in rels_ordered:
        s = r.sym
        if not s:
            continue
        undef = (s.st_shndx == 0)
        if not undef:
            continue
        name = s.name
        if not name:
            continue
        if name not in seen:
            seen[name] = None
            types[name] = s.typ
            out.append(name)
    return out, types

def _collect_exports_in_elf_order(elf: Elf, maps: List[MapEnt]) -> List[Tuple[str,int,int,int]]:
    seen: Set[str] = set()
    out: List[Tuple[str,int,int,int]] = []
    for _tabname, lst in elf.symtabs:
        for s in lst:
            if not s.name or s.name in seen:
                continue
            if s.st_shndx == 0:
                continue  # undefined
            sec = elf._by_index.get(s.st_shndx)
            if not sec or not (sec.sh_flags & SHF_ALLOC):
                continue
            abs_va = _sym_abs_va(elf, s)
            if abs_va is None:
                continue
            voff = _va2off_in_section(maps, abs_va, sec.name) if sec else _va2off(maps, abs_va)
            if voff is None:
                voff = _va2off(maps, abs_va)
            if voff is None:
                continue
            out.append((s.name, abs_va, s.typ, voff))
            seen.add(s.name)
    return out

def _collect_rels_ordered(elf: Elf, maps: List[MapEnt], img: bytearray, dbg: bool, link_base: int):
    ordered_pairs: List[Tuple[str, Rel]] = []  # (tgt_name, Rel) i exakt läsordning
    out = []

    def va_to_off_in_tgt(va: int, tgt_name: str) -> Optional[int]:
        off = _va2off_in_section(maps, va, tgt_name)
        if off is None:
            off = _va2off(maps, va)
        return off

    alloc_idx = {s.idx for s in elf.sections if (s.sh_flags & SHF_ALLOC)}

    for tgt_name, _secname, lst in elf.reltabs:
        tgt = next((s for s in elf.sections if s.name == tgt_name), None)
        if not tgt:
            continue
        base_va = tgt.sh_addr or 0

        for r in lst:
            ordered_pairs.append((tgt_name, r))
            P_link  = base_va + r.r_offset
            off     = va_to_off_in_tgt(P_link, tgt_name)
            if off is None:
                raise ValueError(f"Reloc VA 0x{P_link:x} cannot be mapped (section {tgt_name})")

            rtype   = r.r_type
            symname = (r.sym.name if (r.sym and r.sym.name) else None)

            if r.r_addend is not None:
                A_orig = r.r_addend & 0xFFFFFFFF
            else:
                A_orig = struct.unpack("<I", img[off:off+4])[0] & 0xFFFFFFFF

            if rtype in (R_386_COPY, R_386_GOT32, R_386_GOTPC, R_386_GOTOFF):
                raise ValueError(f"Reloc type {rtype} requires GOT/rtld and is unsupported")

            is_internal = (r.sym is not None and r.sym.st_shndx in alloc_idx)

            if rtype == R_386_NONE:
                continue
            elif rtype == R_386_32:
                kind = DEX_ABS32
            elif rtype == R_386_PC32:
                kind = DEX_PC32
            elif rtype == R_386_PLT32:
                kind = DEX_PC32
                if not symname:
                    raise ValueError("PLT32 without symbol")
            elif rtype == R_386_RELATIVE:
                kind = DEX_RELATIVE
                symname = None
            elif rtype in (R_386_GLOB_DAT, R_386_JMP_SLOT):
                kind = DEX_ABS32
                if not symname:
                    raise ValueError("GLOB_DAT/JMP_SLOT without symbol")
            else:
                raise ValueError(f"Unsupported reloc type {rtype}")

            _dbg(dbg,
                 "[REL] tgt={} off=0x{:08x} rtype={} kind={} sym={} A=0x{:08x}".format(
                     tgt_name, off, rtype, kind, (symname if symname else "<none>"),
                     A_orig
                 ))

            out.append((off, kind, symname, is_internal, r.sym if r else None, tgt_name, A_orig, P_link))

    return out, ordered_pairs

def _synthesize_missing_pc32(img: bytearray, text_off: int, text_sz: int,
                             rels: List[Tuple[int,int,Optional[str],bool,Optional[Sym],str,int,int]],
                             dbg: bool):
    pc32_sites: Set[int] = {off for (off, kind, _sn, _in, _so, _tn, _A, _P) in rels if kind == DEX_PC32}
    end = text_off + text_sz
    i = text_off
    missing = 0
    while i + 5 <= end:
        op = img[i]
        if op in (X86_CALL_REL32, X86_JMP_REL32):
            imm_off = i + 1
            imm = struct.unpack("<I", img[imm_off:imm_off+4])[0]
            if imm == 0xFFFFFFFC and (imm_off not in pc32_sites):
                missing += 1
                _dbg(dbg, "[SANITY] CALL/JMP placeholder missing reloc at file_off=0x{:08x} (.text+0x{:04x})".format(
                    imm_off, (imm_off - text_off)))
        i += 1
    if missing:
        raise ValueError("Build error: missing PC32 reloc for {} site(s)".format(missing))
    return rels

def _sanity_validate_reloc_ranges(img_len: int, rels: List[Tuple[int,int,Optional[str],bool,Optional[Sym],str,int,int]]) -> None:
    for off, _k, _s, _i, _o, _t, _A, _P in rels:
        if not (0 <= off <= img_len - 4):
            raise ValueError("Build error: reloc offset 0x{:08x} out of range".format(off))

def _choose_default_stack_size(image_size: int) -> int:
    if image_size <= 64 * 1024:
        return 64 * 1024
    if image_size <= 256 * 1024:
        return 128 * 1024
    if image_size <= 1024 * 1024:
        return 256 * 1024
    return 512 * 1024

# ---------- Write DEX/EXL ----------
def _write_dex_like(elf: Elf, out_path: str, as_exl: bool, default_exl: Optional[str], entry_symbol: Optional[str], dbg: bool) -> None:
    img, maps, layout = _build_image_with_dxpp_in_ro(elf, put_dxpp=(not as_exl))
    text_off, text_sz, ro_off, ro_sz, data_off, data_sz, bss_sz, hdr_pad, link_base, dxpp_off = layout

    # Relocs (ordered) -> imports by first-seen order
    rels, rel_pairs = _collect_rels_ordered(elf, maps, img, dbg, link_base)
    _sanity_validate_reloc_ranges(len(img), rels)
    rels = _synthesize_missing_pc32(img, text_off, text_sz, rels, dbg)
    _sanity_validate_reloc_ranges(len(img), rels)

    # Imports (no sorting). Build index for name -> import index
    imports, import_types = _collect_imports_in_reloc_order(elf, rel_pairs)
    import_index: Dict[str,int] = {name: idx for idx, name in enumerate(imports)}  # kvar ifall du vill använda index senare

    # Symbols (exports) i ELF-ordning
    exports = _collect_exports_in_elf_order(elf, maps)

    # --- Bestäm entry_off robust ---
    entry_off: Optional[int] = None

    if entry_symbol:
        for (name, _abs_va, _st, voff) in exports:
            if name == entry_symbol:
                entry_off = voff
                _dbg(dbg, f"[ENTRY] from exports: '{entry_symbol}' -> file_off=0x{entry_off:08x}")
                break

    if entry_off is None:
        for (name, _abs_va, _st, voff) in exports:
            if name == "main":
                entry_off = voff
                _dbg(dbg, f"[ENTRY] from exports: 'main' -> file_off=0x{entry_off:08x}")
                break

    if entry_off is None:
        for (name, _abs_va, _st, voff) in exports:
            if name == "_start":
                entry_off = voff
                _dbg(dbg, f"[ENTRY] from exports: '_start' -> file_off=0x{entry_off:08x}")
                break

    if entry_off is None:
        entry_va  = _pick_entry(elf, maps, entry_symbol)
        entry_off = _va2off(maps, entry_va, prefer_kind=".text")
        if entry_off is None:
            raise ValueError("Could not map entry VA to file offset (fallback)")
        _dbg(dbg, f"[ENTRY] fallback via VA mapping -> file_off=0x{entry_off:08x}")

    # String table (offset 0 = empty string)
    strtab = bytearray(b"\x00")
    name_off: Dict[str,int] = {"": 0}

    def add_name(n: Optional[str]) -> int:
        if not n:
            return 0
        off = name_off.get(n)
        if off is not None:
            return off
        off = len(strtab)
        strtab.extend(n.encode("utf-8") + b"\x00")
        name_off[n] = off
        return off

    # Imports (för DEX; EXL får inga imports)
    imp_recs = bytearray()
    if not as_exl and imports:
        exlname = (default_exl.strip() if (default_exl and default_exl.strip()) else "diffc.exl")
        exl_noff = add_name(exlname)
        for sym in imports:
            sym_noff = add_name(sym)
            stt = import_types.get(sym, STT_NOTYPE)
            imp_type = 0 if stt == STT_FUNC else (1 if stt == STT_OBJECT else 0)
            imp_recs.extend(struct.pack("<IIII", exl_noff, sym_noff, imp_type, 0))

    # Exports
    sym_recs = bytearray()
    for (name, _abs_va, st_type, value_off) in exports:
        noff = add_name(name)
        dex_typ = 0 if st_type == STT_FUNC else (1 if st_type == STT_OBJECT else 0)
        sym_recs.extend(struct.pack("<III", noff, value_off, dex_typ))

    # Relocs emission (behåll ordningen).
    rel_recs = bytearray()
    for (off, kind, symname, is_internal, symobj, _tgt, A_orig, _P_link) in rels:
        if kind == DEX_RELATIVE:
            # A_orig tolkas som länkad VA -> mappa till fil-offset och skriv in i bilden
            voff = _va2off(maps, A_orig)
            if voff is None:
                raise ValueError(f"RELATIVE target VA 0x{A_orig:08x} cannot be mapped to file offset")
            img[off:off+4] = struct.pack("<I", voff)
            sym_field = 0

        else:
            if symname and (not is_internal):
                # extern symbol -> STRTAB-offset till namnet (för dv)
                sym_field = add_name(symname)
            else:
                # intern symbol -> räkna mål-VA och mappa till fil-offset; symfält = symbolnamn
                if symobj is None:
                    raise ValueError("Internal relocation lacks symbol object")
                S_abs = _sym_abs_va(elf, symobj)
                if S_abs is None:
                    raise ValueError("Cannot compute absolute VA for internal symbol")

                if kind == DEX_PC32:
                    target_va = S_abs          # ingen addend för PC32 (placeholder -4 ignoreras)
                else:  # DEX_ABS32
                    target_va = (S_abs + A_orig) & 0xFFFFFFFF

                voff = _va2off(maps, target_va)
                if voff is None:
                    raise ValueError(f"Internal target VA 0x{target_va:08x} cannot be mapped to file offset")

                # hjälp loadern för ABS32: skriv in fil-offset i bilden
                if kind == DEX_ABS32:
                    img[off:off+4] = struct.pack("<I", voff)

                intern_name = symobj.name if symobj.name else f"@off_{voff:08x}"
                sym_field = add_name(intern_name)

        rel_recs.extend(struct.pack("<IIII", off, sym_field, kind, 0))  # <-- INSIDE LOOP (fix)

    if hdr_pad < 0x100:
        hdr_pad = 0x100

    reloc_off  = _align(len(img), 16); img.extend(b"\x00" * (reloc_off - len(img)));  img.extend(rel_recs)
    str_off    = _align(len(img), 16); img.extend(b"\x00" * (str_off   - len(img)));  img.extend(strtab)
    sym_off    = _align(len(img), 16); img.extend(b"\x00" * (sym_off   - len(img)));  img.extend(sym_recs)
    if not as_exl:
        imp_off = _align(len(img), 16); img.extend(b"\x00" * (imp_off  - len(img)));  img.extend(imp_recs)
    else:
        imp_off = 0

    # Debug
    _dbg(dbg, "=== BUILD {} HEADER ===".format("EXL" if as_exl else "DEX"))
    _dbg(dbg, "entry_off=0x{:08x}".format(entry_off))
    _dbg(dbg, ".text off=0x{:08x} sz={}".format(text_off, text_sz))
    _dbg(dbg, ".ro   off=0x{:08x} sz={}".format(ro_off, ro_sz))
    _dbg(dbg, ".data off=0x{:08x} sz={}".format(data_off, data_sz))
    _dbg(dbg, ".bss  sz={}".format(bss_sz))
    if not as_exl:
        _dbg(dbg, "DXPP is at start of .ro (will be patched)")
        _dbg(dbg, "import off=0x{:08x} cnt={}".format(imp_off, (len(imp_recs)//16)))
    _dbg(dbg, "reloc  off=0x{:08x} cnt={}".format(reloc_off, (len(rel_recs)//16)))
    _dbg(dbg, "str    off=0x{:08x} sz ={}".format(str_off, len(strtab)))
    _dbg(dbg, "sym    off=0x{:08x} cnt={}".format(sym_off, (len(sym_recs)//12)))

    # Header (19 x uint32)
    header_fields = (
        DEX_MAGIC, DEX_VER_MAJOR, DEX_VER_MINOR,
        entry_off,
        text_off,  text_sz,
        ro_off,    ro_sz,
        data_off,  data_sz,
        bss_sz,
        (0 if as_exl else imp_off), (0 if as_exl else (len(imp_recs)//16)),
        reloc_off, (len(rel_recs)//16),
        sym_off,   (len(sym_recs)//12),
        str_off,   len(strtab),
    )
    fmt = "<" + "I"*19
    hdr = struct.pack(fmt, *header_fields)
    if len(hdr) > hdr_pad:
        raise ValueError("Header exceeds reserved padding (0x100)")
    img[0:len(hdr)] = hdr

    # ---- PATCH DXPP: image_base + image_size + stack_top + stack_limit ----
    if (not as_exl) and (dxpp_off is not None):
        cur_magic = struct.unpack_from("<I", img, dxpp_off)[0]
        if cur_magic != DEX_PARAMS_MAGIC:
            struct.pack_into("<I", img, dxpp_off + 0, DEX_PARAMS_MAGIC)
            struct.pack_into("<H", img, dxpp_off + 4, 1)  # ver_major
            struct.pack_into("<H", img, dxpp_off + 6, 0)  # ver_minor
            struct.pack_into("<I", img, dxpp_off + 8, 0)  # flags

        image_base = FORCED_IMAGE_BASE & 0xFFFFFFFF  # default; kernel patchar verkligt värde
        image_size = len(img)           & 0xFFFFFFFF

        stk_size = _choose_default_stack_size(image_size)
        stk_top  = THUNK_PAGE_TOP
        stk_lim  = (stk_top - stk_size) & 0xFFFFFFFF

        struct.pack_into("<I", img, dxpp_off + 36, image_base)
        struct.pack_into("<I", img, dxpp_off + 40, image_size)
        struct.pack_into("<I", img, dxpp_off + 44, stk_top)
        struct.pack_into("<I", img, dxpp_off + 48, stk_lim)

        _dbg(dbg, f"[DXPP] patch @.ro image_base=0x{image_base:08x} image_size={image_size}")
        _dbg(dbg, f"[DXPP] patch @.ro stack_top=0x{stk_top:08x} stack_limit=0x{stk_lim:08x} (size={stk_size})")

    with open(out_path, "wb") as f:
        f.write(img)

# ---------- CLI ----------
def run(argv: list, mode: str) -> int:
    p = argparse.ArgumentParser()
    p.add_argument("input")
    p.add_argument("-o", "--output", required=True)
    p.add_argument("--default-exl", dest="default_exl")
    p.add_argument("--entry-symbol", dest="entry_symbol")
    p.add_argument("-q", "--quiet", action="store_true")
    args = p.parse_args(argv[1:])

    as_exl = (mode == "exl")
    elf = Elf(args.input, quiet=args.quiet)
    _write_dex_like(elf, args.output, as_exl, args.default_exl, args.entry_symbol, dbg=not args.quiet)
    return 0

def main_tool(argv=None, mode="dex"):
    if argv is None:
        argv = sys.argv
    return run(argv, mode)

if __name__ == "__main__":
    sys.exit(run(sys.argv, mode="dex"))

