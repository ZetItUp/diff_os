#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import argparse
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.sections import SymbolTableSection

# =========================
#  DEX / EXL-konstanter
# =========================
DEX_MAGIC     = 0x58454400  # "DEX\0"
DEX_VER_MAJ   = 1
DEX_VER_MIN   = 0
HDR_SIZE      = 0x100
FILE_ALIGN    = 0x1000

# DEX reloc-typer
DEX_ABS32     = 0
DEX_PC32      = 2
DEX_RELATIVE  = 8

# ELF i386 reloc-typer
R_386_32      = 1
R_386_PC32    = 2
R_386_PLT32   = 4

def align_up(x, a): return (x + (a - 1)) & ~(a - 1)

def read_sec_bytes(elf, name):
    s = elf.get_section_by_name(name)
    return s.data() if s else b""

def read_bss_size(elf):
    s = elf.get_section_by_name(".bss")
    return s["sh_size"] if s else 0

def sec_base_in_image(elf, sec_index, text_off, ro_off, data_off):
    s = elf.get_section(sec_index)
    if not s: return None
    n = s.name
    if n == ".text":   return text_off
    if n == ".rodata": return ro_off
    if n == ".data":   return data_off
    return None

def buf_for_target(elf, sec_index, text_buf, ro_buf, data_buf):
    s = elf.get_section(sec_index)
    if not s: return None
    n = s.name
    if n == ".text":   return text_buf
    if n == ".rodata": return ro_buf
    if n == ".data":   return data_buf
    return None

def get_any_symtab(elf):
    for sec in elf.iter_sections():
        if isinstance(sec, SymbolTableSection) or sec['sh_type'] == 'SHT_SYMTAB':
            return sec
    return None

def iter_reloc_sections(elf):
    for sec in elf.iter_sections():
        if sec['sh_type'] in ('SHT_REL', 'SHT_RELA'):
            yield sec

def load_diffc_exports(diffc_elf_path):
    if not diffc_elf_path:
        return set()
    with open(diffc_elf_path, "rb") as f:
        elf = ELFFile(f)
        symtab = get_any_symtab(elf)
        if not symtab:
            return set()
        names = set()
        for sym in symtab.iter_symbols():
            name = sym.name or ""
            if not name:
                continue
            st_type  = sym['st_info']['type']
            st_shndx = sym['st_shndx']
            if st_type in ('STT_SECTION', 'STT_FILE') or st_shndx == 0:
                continue
            is_func = (st_type == 'STT_FUNC') or (st_type == 'STT_NOTYPE' and sym['st_value'] != 0)
            is_obj  = (st_type == 'STT_OBJECT')
            if is_func or is_obj:
                names.add(name)
        return names

def build_exl(input_elf, output_exl, libname, import_exl=None, diffc_elf=None, diffc_name="diffc.exl", verbose=False):
    diffc_syms = load_diffc_exports(diffc_elf)

    with open(input_elf, "rb") as f:
        elf = ELFFile(f)

        # --- Sektioner ---
        text   = read_sec_bytes(elf, ".text")
        rodata = read_sec_bytes(elf, ".rodata")
        data   = read_sec_bytes(elf, ".data")
        bss_sz = read_bss_size(elf)

        text_off = 0x100
        ro_off   = align_up(text_off + len(text), FILE_ALIGN)
        data_off = align_up(ro_off   + len(rodata), FILE_ALIGN)

        text_buf = bytearray(text)
        ro_buf   = bytearray(rodata)
        data_buf = bytearray(data)

        # --- Strtab ---
        strtab = bytearray()
        strmap = {}
        def add_str(s: str) -> int:
            if s in strmap: return strmap[s]
            off = len(strtab)
            strtab.extend(s.encode("utf-8") + b"\x00")
            strmap[s] = off
            return off

        add_str(libname)

        # --- Symboltabell ---
        symtab = get_any_symtab(elf)

        exl_exports = []   # (name_off, value_off, type)
        undef = {}         # name -> is_func

        if symtab:
            for sym in symtab.iter_symbols():
                name = sym.name or ""
                if not name:
                    continue

                # (valfritt filter) hoppa över system_* om du lagt till det i din version
                # if name.startswith("system_"):
                #     continue

                st_type  = sym['st_info']['type']
                st_shndx = sym['st_shndx']  # 0 = UND
                is_func  = (st_type == 'STT_FUNC') or (st_type == 'STT_NOTYPE' and sym['st_value'] != 0)
                is_obj   = (st_type == 'STT_OBJECT')

                if st_type in ('STT_SECTION', 'STT_FILE'):
                    continue

                if st_shndx == 0:
                    undef[name] = is_func
                    continue

                if not is_func and not is_obj:
                    continue

                base = sec_base_in_image(elf, st_shndx, text_off, ro_off, data_off)
                if base is None:
                    continue

                value_off = base + sym['st_value']
                name_off  = add_str(name)

                if not any(e[0] == name_off for e in exl_exports):
                    exl_exports.append((name_off, value_off, 0 if is_func else 1))

        # --- Imports ---
        exl_imports = []  # (exl_off, sym_off, type, 0)

        def choose_import_target(sym_name: str) -> str:
            if diffc_syms and (sym_name in diffc_syms) and (libname != diffc_name):
                return diffc_name
            return import_exl or libname

        for nm, is_func in sorted(undef.items()):
            exl_nm = choose_import_target(nm)
            exl_off = add_str(exl_nm)
            sym_off = add_str(nm)
            exl_imports.append((exl_off, sym_off, 0 if is_func else 1, 0))

        # --- Relocations ---
        reloc_table = []  # (img_off, sym_or_import_idx, dex_type, 0)

        def find_or_add_import(exl_nm: str, sym_nm: str, is_func=True) -> int:
            e_off = add_str(exl_nm)
            s_off = add_str(sym_nm)
            for i,(E,S,t,_) in enumerate(exl_imports):
                if E == e_off and S == s_off and t == (0 if is_func else 1):
                    return i
            idx = len(exl_imports)
            exl_imports.append((e_off, s_off, 0 if is_func else 1, 0))
            return idx

        for relsec in iter_reloc_sections(elf):
            tgt_secidx = relsec['sh_info']
            tgt_base = sec_base_in_image(elf, tgt_secidx, text_off, ro_off, data_off)
            tgt_buf  = buf_for_target(elf, tgt_secidx, text_buf, ro_buf, data_buf)
            if tgt_base is None or tgt_buf is None:
                continue

            for r in relsec.iter_relocations():
                r_off   = r['r_offset']
                img_off = tgt_base + r_off
                rtype   = r['r_info_type']
                symi    = r['r_info_sym']
                sym     = symtab.get_symbol(symi) if symtab else None
                sname   = sym.name if sym else ""

                # REL (i386): addend ligger i ordet
                A = 0
                if r_off + 4 <= len(tgt_buf):
                    A = struct.unpack_from("<I", tgt_buf, r_off)[0]

                if rtype in (R_386_PC32, R_386_PLT32):
                    if sym and sym['st_shndx'] != 0:
                        # Lokal symbol: patcha PC-relativt direkt: val = S + A - P
                        src_base = sec_base_in_image(elf, sym['st_shndx'], text_off, ro_off, data_off)
                        if src_base is not None:
                            S = src_base + sym['st_value']
                            P = img_off
                            val = (S + A - P) & 0xffffffff
                            struct.pack_into("<I", tgt_buf, r_off, val)
                            if verbose:
                                print(f"[PC32 local] off=0x{img_off:08x} sym='{sname}' set=0x{val:08x}")
                            # Ingen reloc/import för interna anrop
                        else:
                            # fallback som extern (borde ej hända)
                            target = choose_import_target(sname)
                            imp_idx = find_or_add_import(target, sname, True)
                            reloc_table.append((img_off, imp_idx, DEX_PC32, 0))
                            if verbose:
                                print(f"[PC32 local-miss→import] off=0x{img_off:08x} sym='{sname}' -> '{target}' idx={imp_idx}")
                    else:
                        # Extern symbol → import
                        target = choose_import_target(sname)
                        imp_idx = find_or_add_import(target, sname, True)
                        reloc_table.append((img_off, imp_idx, DEX_PC32, 0))
                        if verbose:
                            print(f"[PC32 ext]  off=0x{img_off:08x} sym='{sname}' -> import '{target}' idx={imp_idx}")

                elif rtype == R_386_32:
                    if sym and sym['st_shndx'] != 0:
                        # Lokal symbol i denna bild: initiera till S + A ; markera RELATIVE
                        src_base = sec_base_in_image(elf, sym['st_shndx'], text_off, ro_off, data_off)
                        if src_base is None:
                            continue
                        S = src_base + sym['st_value']
                        init = (S + A) & 0xffffffff
                        struct.pack_into("<I", tgt_buf, r_off, init)
                        reloc_table.append((img_off, 0, DEX_RELATIVE, 0))
                        if verbose:
                            print(f"[ABS32 rel] off=0x{img_off:08x} init=0x{init:08x}")

                    elif sym is None or symi == 0 or not sname:
                        # ABS32 utan symbol (STN_UNDEF / tomt namn) → behandla som basrelativ
                        struct.pack_into("<I", tgt_buf, r_off, A)
                        reloc_table.append((img_off, 0, DEX_RELATIVE, 0))
                        if verbose:
                            print(f"[ABS32 abs(no-sym)] off=0x{img_off:08x} A=0x{A:08x} -> RELATIVE")

                    else:
                        # Extern symbol → ABS32 import
                        target = choose_import_target(sname)
                        imp_idx = find_or_add_import(target, sname, False)
                        reloc_table.append((img_off, imp_idx, DEX_ABS32, 0))
                        if verbose:
                            print(f"[ABS32 ext] off=0x{img_off:08x} sym='{sname}' -> import '{target}' idx={imp_idx}")
                else:
                    if verbose:
                        print(f"[WARN] unknown ELF reloc type={rtype} at r_off=0x{r_off:08x}")

        # --- Slutliga bytes ---
        text = bytes(text_buf)
        ro   = bytes(ro_buf)
        dat  = bytes(data_buf)

        # --- Tabellplaceringar ---
        cur = align_up(data_off + len(dat), FILE_ALIGN)
        import_off = cur;  cur += 16 * len(exl_imports)    # <IIII>
        reloc_off  = cur;  cur += 16 * len(reloc_table)    # <IIII>
        symtab_off = cur;  cur += 12 * len(exl_exports)    # <III>
        strtab_off = cur;  cur += len(strtab)

        # --- Header ---
        hdr = bytearray(HDR_SIZE)
        def w32(o,v): struct.pack_into("<I", hdr, o, v & 0xffffffff)
        w32(0x00, DEX_MAGIC)
        w32(0x04, DEX_VER_MAJ); w32(0x08, DEX_VER_MIN)
        w32(0x0C, text_off)
        w32(0x10, text_off); w32(0x14, len(text))
        w32(0x18, ro_off);   w32(0x1C, len(ro))
        w32(0x20, data_off); w32(0x24, len(dat))
        w32(0x28, bss_sz)
        w32(0x2C, import_off if exl_imports else 0); w32(0x30, len(exl_imports))
        w32(0x34, reloc_off  if reloc_table else 0); w32(0x38, len(reloc_table))
        w32(0x3C, symtab_off if exl_exports else 0); w32(0x40, len(exl_exports))
        w32(0x44, strtab_off if strtab else 0);      w32(0x48, len(strtab))

        # --- Skriv EXL ---
        with open(output_exl, "wb") as out:
            out.write(hdr)
            out.write(text)
            out.write(b"\x00" * (ro_off - (HDR_SIZE + len(text))))
            out.write(ro)
            out.write(b"\x00" * (data_off - (ro_off + len(ro))))
            out.write(dat)
            for e_off, s_off, t, z in exl_imports:
                out.write(struct.pack("<IIII", e_off, s_off, t, z))
            for off, si, t, z in reloc_table:
                out.write(struct.pack("<IIII", off, si, t, z))
            for name_off, val_off, t in exl_exports:
                out.write(struct.pack("<III", name_off, val_off, t))
            out.write(strtab)

        if verbose:
            print("=== EXL BUILD ===")
            print(f"libname='{libname}'  diffc_syms={len(diffc_syms)}  diffc_name='{diffc_name}'")
            print(f".text  off=0x{text_off:08x} sz=0x{len(text):x}")
            print(f".rodat off=0x{ro_off:08x}   sz=0x{len(ro):x}")
            print(f".data  off=0x{data_off:08x} sz=0x{len(dat):x}")
            print(f".bss   sz=0x{bss_sz:x}")
            print(f"imports off=0x{import_off:08x} cnt={len(exl_imports)}")
            print(f"relocs  off=0x{reloc_off:08x}  cnt={len(reloc_table)}")
            print(f"symtab  off=0x{symtab_off:08x} cnt={len(exl_exports)}")
            print(f"strtab  off=0x{strtab_off:08x} sz=0x{len(strtab):x}")

def main():
    ap = argparse.ArgumentParser(description="ELF → DEX EXL-builder (export-all, robust reloc)")
    ap.add_argument("input_elf")
    ap.add_argument("output_exl")
    ap.add_argument("libname", help="EXL-namnet, t.ex. diffc.exl eller hello.exl")
    ap.add_argument("--import-exl", default=None, help="Fallback-EXL för imports")
    ap.add_argument("--diffc-elf", default=None, help="Path till DiffC ELF för att auto-mappa imports till diffc.exl")
    ap.add_argument("--diffc-name", default="diffc.exl", help="Namnet på DiffC EXL i importtabellen")
    ap.add_argument("--verbose", action="store_true")
    args = ap.parse_args()
    build_exl(args.input_elf, args.output_exl, args.libname,
              import_exl=args.import_exl,
              diffc_elf=args.diffc_elf,
              diffc_name=args.diffc_name,
              verbose=args.verbose)

if __name__ == "__main__":
    main()

