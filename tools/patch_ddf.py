#!/usr/bin/env python3
# All comments are written in English.

import sys
import struct
from elftools.elf.elffile import ELFFile
from elftools.elf.enums import ENUM_RELOC_TYPE_i386

DDF_MAGIC = b'DDF\x00'

# ---- Small helpers ----------------------------------------------------------

def pad4(x):
    return (x + 3) & ~3

def sh_off(s):
    return int(s.header['sh_offset']) if s else 0

def sh_size(s):
    return int(s.header['sh_size']) if s else 0

def sh_addr(s):
    return int(s.header['sh_addr']) if s else 0

def is_reloc_section(s):
    name = s.name or ""
    # i386 typically uses SHT_REL (.rel.*). Be permissive but only accept .rel.*
    return name.startswith(".rel.")

def read_best_symtab(elf):
    # Prefer full symtab; fall back to dynsym if needed
    for nm in ('.symtab', '.dynsym'):
        st = elf.get_section_by_name(nm)
        if st and st.num_symbols() > 0:
            return st
    return None

def find_sym_vma(elf, name):
    for nm in ('.symtab', '.dynsym'):
        st = elf.get_section_by_name(nm)
        if not st:
            continue
        for sym in st.iter_symbols():
            if sym.name == name:
                return int(sym['st_value'])
    return None

def u32(x):
    return x & 0xFFFFFFFF

def as_i32(x):
    return x - 0x100000000 if (x & 0x80000000) else x

# ---- Main -------------------------------------------------------------------

def main():
    if len(sys.argv) != 3:
        print("usage: patch_ddf.py <in.elf> <out.ddf>")
        sys.exit(1)

    inp = sys.argv[1]
    outp = sys.argv[2]

    with open(inp, 'rb') as f:
        elf = ELFFile(f)

        text = elf.get_section_by_name('.text')
        ro   = elf.get_section_by_name('.rodata')
        data = elf.get_section_by_name('.data')
        bss  = elf.get_section_by_name('.bss')

        t_sz, r_sz, d_sz, b_sz = sh_size(text), sh_size(ro), sh_size(data), sh_size(bss)
        t_vma, r_vma, d_vma, b_vma = sh_addr(text), sh_addr(ro), sh_addr(data), sh_addr(bss)

        # Lay out: header(80) + .text + .rodata + .data + symtab + strtab + relocs + .bss (zero filled)
        cur = 80

        def take(sz):
            # Reserve a chunk in the output file image
            nonlocal cur
            if sz == 0:
                return 0, 0
            off = cur
            cur = pad4(cur + sz)
            return off, sz

        t_off, _ = take(t_sz)
        r_off, _ = take(r_sz)
        d_off, _ = take(d_sz)

        # Create/prime output with header space and copy raw section payloads
        with open(outp, 'wb') as out:
            out.write(b'\x00' * 80)

            def copy(sec, dst):
                if not sec or sh_size(sec) == 0 or dst == 0:
                    return
                out.seek(dst)
                out.write(sec.data())

            copy(text, t_off)
            copy(ro,   r_off)
            copy(data, d_off)

        # ---- Build DDF symbol and string tables --------------------------------

        syms = []                 # list of tuples (name_off, value_off, type)
        strs = bytearray(b'\x00') # string table with leading NUL
        name_to_idx = {}          # symbol name -> DDF index

        def add_sym(name, value_off, stype=0):
            if value_off is None:
                return None
            idx = len(syms)
            name_off = len(strs)
            strs.extend(name.encode('ascii', 'ignore') + b'\x00')
            syms.append((name_off, int(value_off) & 0xFFFFFFFF, int(stype) & 0xFFFFFFFF))
            name_to_idx[name] = idx
            return idx

        # Map target VMAs to packed offsets inside the DDF file image
        def pack_off_for_vma(vma):
            if vma is None:
                return None
            # .text
            if t_vma and t_sz and t_vma <= vma < t_vma + t_sz:
                return t_off + (vma - t_vma)
            # .rodata
            if r_vma and r_sz and r_vma <= vma < r_vma + r_sz:
                return r_off + (vma - r_vma)
            # .data
            if d_vma and d_sz and d_vma <= vma < d_vma + d_sz:
                return d_off + (vma - d_vma)
            # .bss (deferred placement)
            if b_vma and b_sz and b_vma <= vma < b_vma + b_sz:
                return ('BSS', vma - b_vma)
            return None

        # Expose entrypoints (prefer ddf_* names, fall back to common aliases)
        for nm in ('ddf_driver_init', 'ddf_driver_exit', 'ddf_driver_irq', 'init', 'exit', 'irq'):
            v = find_sym_vma(elf, nm)
            po = pack_off_for_vma(v)
            # Entrypoints cannot live in .bss
            if isinstance(po, tuple):
                po = None
            if v is not None and po is not None:
                add_sym(nm, po)

        # IRQ number: read from .ddf_meta (first u32), else from an actual variable's initial value if present
        irq_number = 0
        meta = elf.get_section_by_name('.ddf_meta')
        if meta and sh_size(meta) >= 4:
            blob = meta.data()
            irq_number = struct.unpack('<I', blob[:4])[0] & 0xFFFFFFFF
        else:
            v = find_sym_vma(elf, 'ddf_irq_number')
            if v is not None:
                # If the variable is in .data/.rodata, read its initial value from the input ELF
                for sec in (data, ro):
                    if sec and sh_addr(sec) <= v < sh_addr(sec) + sh_size(sec):
                        f.seek(sh_off(sec) + (v - sh_addr(sec)))
                        irq_number = struct.unpack('<I', f.read(4))[0] & 0xFFFFFFFF
                        break
            # Only expose symbol if it is mappable into file image (not .bss)
            po = pack_off_for_vma(v) if v is not None else None
            if isinstance(po, tuple):
                po = None
            if po is not None:
                add_sym('ddf_irq_number', po)

        # Write symbol table (if any)
        s_off = 0
        if syms:
            s_off = cur
            with open(outp, 'r+b') as pf:
                pf.seek(s_off)
                for (no, vo, ty) in syms:
                    pf.write(struct.pack('<III', no, vo, ty))
            cur = pad4(s_off + len(syms) * 12)

        # Write string table (if non-trivial)
        st_off = 0
        if len(strs) > 1:
            st_off = cur
            with open(outp, 'r+b') as pf:
                pf.seek(st_off)
                pf.write(bytes(strs))
            cur = pad4(st_off + len(strs))

        # ---- Build map from input *places* (where a relocated word lives) to packed offsets

        maps = []

        def map_place_section(sec, dst_off):
            if sec and sh_size(sec):
                maps.append((sh_off(sec), sh_off(sec) + sh_size(sec), dst_off))

        map_place_section(text, t_off)
        map_place_section(ro,   r_off)
        map_place_section(data, d_off)

        def place_packed_off(place_file_off):
            for lo, hi, base in maps:
                if lo <= place_file_off < hi:
                    return base + (place_file_off - lo)
            return None

        # ---- Collect and translate relocations ---------------------------------

        reloc_entries = []  # tuples: (r_offset, r_type, r_symidx, r_addend)
        elf_symtab = read_best_symtab(elf)

        # Walk all .rel.* sections and translate each relocation
        for relsec in elf.iter_sections():
            if not is_reloc_section(relsec):
                continue

            # Relocations apply to some target section (SHT_REL -> sh_info points to that sec)
            tgt = elf.get_section(int(relsec.header['sh_info']))
            if not tgt or sh_size(tgt) == 0:
                continue

            sec_vma = sh_addr(tgt)
            sec_off = sh_off(tgt)
            sec_sz  = sh_size(tgt)

            for rel in relsec.iter_relocations():
                raw_off = int(rel['r_offset'])
                if not (sec_vma <= raw_off < sec_vma + sec_sz):
                    # Out-of-range relocation (defensive skip)
                    continue

                r_off_in_sec   = raw_off - sec_vma
                place_file_off = sec_off + r_off_in_sec
                place_pack_off = place_packed_off(place_file_off)
                if place_pack_off is None:
                    # Should not happen for .text/.rodata/.data; ignore if it does
                    continue

                # Current 32-bit field value at relocation site
                f.seek(place_file_off)
                field_u32 = struct.unpack('<I', f.read(4))[0]

                ddf_r_type   = None
                ddf_r_symidx = 0xFFFFFFFF
                ddf_r_addend = 0

                sym = elf_symtab.get_symbol(int(rel['r_info_sym'])) if elf_symtab else None
                sym_name  = sym.name if sym else ''
                sym_shndx = sym['st_shndx'] if sym else 'SHN_UNDEF'
                sym_def   = (sym is not None and sym_shndx != 'SHN_UNDEF')

                rtype = rel['r_info_type']

                if rtype == ENUM_RELOC_TYPE_i386['R_386_PC32']:
                    # Field holds A = signed disp; target is (P+4)+A
                    if sym_def and (sym_name in name_to_idx):
                        # Keep symbol-relative form so loader can compute S + A - P
                        ddf_r_type   = 2  # DDF_RELOC_REL32
                        ddf_r_symidx = name_to_idx[sym_name]
                        ddf_r_addend = as_i32(field_u32)
                    else:
                        # Convert to module-relative target (packed offset)
                        target_vma = u32(raw_off + 4 + as_i32(field_u32))
                        tpo = pack_off_for_vma(target_vma)
                        if tpo is None or isinstance(tpo, tuple):
                            # PC32 into unmapped or .bss is unexpected; skip defensively
                            continue
                        ddf_r_type   = 2
                        ddf_r_symidx = 0xFFFFFFFF
                        ddf_r_addend = u32(tpo)

                elif rtype == ENUM_RELOC_TYPE_i386['R_386_32']:
                    # Field holds (S_old + A). We want to write a module-relative absolute pointer.
                    if sym_def and (sym_name in name_to_idx):
                        # Keep a named ABS32 so loader writes S_new + A
                        S_old = u32(sym['st_value'])
                        A     = u32(field_u32 - S_old)
                        ddf_r_type   = 1  # DDF_RELOC_ABS32
                        ddf_r_symidx = name_to_idx[sym_name]
                        ddf_r_addend = A
                    else:
                        # Compute packed target offset for (S_old + A) or raw field if no symbol
                        S_old = u32(sym['st_value']) if sym_def else 0
                        A     = u32(field_u32 - S_old) if sym_def else u32(field_u32)
                        target_vma = u32(S_old + A) if sym_def else u32(field_u32)
                        tpo = pack_off_for_vma(target_vma)
                        if tpo is None:
                            # Target not representable; skip
                            continue
                        if isinstance(tpo, tuple):
                            # Target is in .bss: convert to RELATIVE(base + (bss_off + boff)) later
                            # Store a placeholder; we will patch it once bss_off is known.
                            _, boff = tpo
                            reloc_entries.append((place_pack_off, 3, 0xFFFFFFFF, ('BSS', boff)))
                            continue
                        # Target in text/rodata/data → RELATIVE(base + tpo)
                        ddf_r_type   = 3  # DDF_RELOC_RELATIVE
                        ddf_r_symidx = 0xFFFFFFFF
                        ddf_r_addend = u32(tpo)

                else:
                    # Unknown/unsupported relocation type -> skip defensively
                    continue

                reloc_entries.append((place_pack_off, ddf_r_type, ddf_r_symidx, ddf_r_addend))

        # ---- Decide final places for reloc table and .bss ----------------------

        # End of fixed payload so far
        end_min = max(
            t_off + t_sz,
            r_off + r_sz,
            d_off + d_sz,
            80  # header
        )

        tmp_end = end_min
        if syms:
            tmp_end = max(tmp_end, pad4(s_off + len(syms) * 12))
        if len(strs) > 1:
            tmp_end = max(tmp_end, pad4(st_off + len(strs)))

        # Reloc table goes next
        reloc_entries.sort(key=lambda x: x[0])  # stable, deterministic layout
        reloc_off = pad4(tmp_end)
        reloc_cnt = len(reloc_entries)

        # Compute .bss start after reloc table
        bss_off = pad4(reloc_off + reloc_cnt * 16) if b_sz else 0

        # Patch any ABS32->.bss placeholders now that bss_off is known
        fixed = []
        for (o, t, si, a) in reloc_entries:
            if isinstance(a, tuple) and a[0] == 'BSS':
                _, boff = a
                a = u32(bss_off + boff)
            fixed.append((o, t, si, a))
        reloc_entries = fixed

        # ---- Write reloc table and header --------------------------------------

        if reloc_cnt:
            with open(outp, 'r+b') as pf:
                pf.seek(reloc_off)
                for (o, t, si, a) in reloc_entries:
                    pf.write(struct.pack('<IIII',
                        int(o) & 0xFFFFFFFF,
                        int(t) & 0xFFFFFFFF,
                        int(si) & 0xFFFFFFFF,
                        int(a) & 0xFFFFFFFF
                    ))

        # Resolve entrypoints again for header (prefer ddf_* names)
        init_v = find_sym_vma(elf, 'ddf_driver_init') or find_sym_vma(elf, 'init')
        exit_v = find_sym_vma(elf, 'ddf_driver_exit') or find_sym_vma(elf, 'exit')
        irq_v  = find_sym_vma(elf, 'ddf_driver_irq')  or find_sym_vma(elf, 'irq')

        def pack_off_no_bss(v):
            po = pack_off_for_vma(v)
            return None if isinstance(po, tuple) else po

        init_off = pack_off_no_bss(init_v) or 0
        exit_off = pack_off_no_bss(exit_v) or 0
        irq_off  = pack_off_no_bss(irq_v)  or 0

        # Prepare and write header (matches your ddf_header_t: 80 bytes)
        hdr = struct.pack(
            '<4s' + 'I' * 19,
            DDF_MAGIC,                # magic
            init_off,                 # init_offset
            exit_off,                 # exit_offset
            irq_off,                  # irq_offset
            (s_off if syms else 0),   # symbol_table_offset
            (len(syms) if syms else 0),   # symbol_table_count
            (st_off if len(strs) > 1 else 0),  # strtab_offset
            1, 0,                     # version major/minor
            (reloc_off if reloc_cnt else 0), reloc_cnt,  # reloc table
            t_off, t_sz,              # .text
            r_off, r_sz,              # .rodata
            d_off, d_sz,              # .data
            bss_off, b_sz,            # .bss (file extends here, zero-filled)
            int(irq_number) & 0xFFFFFFFF  # irq_number (0 if not provided)
        )

        with open(outp, 'r+b') as pf:
            pf.seek(0)
            pf.write(hdr)
            # Ensure file length covers reloc table and .bss area (zero-filled)
            file_end = (bss_off + b_sz) if b_sz else (reloc_off + reloc_cnt * 16)
            if file_end > 0:
                pf.seek(file_end - 1)
                pf.write(b'\x00')

    # Diagnostics (human friendly)
    print(f"[DDF] wrote {outp}")
    print(f"[DDF] text@0x{t_off:08x} ro@0x{r_off:08x} data@0x{d_off:08x} bss@0x{bss_off:08x} (bss_sz=0x{b_sz:x})")
    print(f"[DDF] sym@0x{(s_off if syms else 0):08x} count={len(syms) if syms else 0}  str@0x{(st_off if len(strs) > 1 else 0):08x}")
    print(f"[DDF] rel@0x{(reloc_off if reloc_cnt else 0):08x} count={reloc_cnt}")
    print(f"[DDF] entry init@+0x{init_off:08x} exit@+0x{exit_off:08x} irq@+0x{irq_off:08x} irq_num={irq_number}")

if __name__ == '__main__':
    main()

