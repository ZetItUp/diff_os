#!/usr/bin/env python3
import sys
import struct
from elftools.elf.elffile import ELFFile

DDF_MAGIC = b'DDF\x00'


def pad4(x):
    # Align to 4 bytes
    aligned = (x + 3) & ~3

    return aligned


def find_section(elf, name):
    # Find a section by name and warn if missing
    sec = elf.get_section_by_name(name)

    if not sec:
        print(f"[DDF Patcher] WARNING: Section {name} not found")

    return sec


def find_symbol_value(elf, name):
    # Read the 32-bit little-endian value of a symbol by resolving its file offset
    for section in elf.iter_sections():
        if not hasattr(section, 'iter_symbols'):
            continue

        for sym in section.iter_symbols():
            if sym.name == name:
                vma = sym.entry['st_value']

                for s in elf.iter_sections():
                    sh = s.header
                    start = sh['sh_addr']
                    end = start + sh['sh_size']

                    if start <= vma < end:
                        offset = sh['sh_offset'] + (vma - start)

                        with open(elf.stream.name, "rb") as f:
                            f.seek(offset)
                            val_bytes = f.read(4)

                            return int.from_bytes(val_bytes, byteorder="little")

    return 0


def section_off_and_size(sec):
    # Return (file_offset, size) for a section or (0, 0) if missing
    if sec:

        return sec['sh_offset'], sec['sh_size']

    else:

        return 0, 0


def main():
    if len(sys.argv) != 3:
        print("Usage: patch_ddf.py <input.elf> <output.ddf>")

        sys.exit(1)

    elf_path = sys.argv[1]
    ddf_path = sys.argv[2]

    with open(elf_path, 'rb') as f:
        elf = ELFFile(f)

        text_sec = find_section(elf, '.text')
        rodata_sec = find_section(elf, '.rodata')
        data_sec = find_section(elf, '.data')
        bss_sec = find_section(elf, '.bss')
        symtab_sec = find_section(elf, '.ddf_symtab')
        strtab_sec = find_section(elf, '.ddf_strtab')
        reloc_sec = (
            find_section(elf, '.ddf_reloc')
            or find_section(elf, '.reloc')
            or find_section(elf, '.ddf_relocation')
        )

        # Offsets/sizes for relevant sections
        text_off, text_size = section_off_and_size(text_sec)
        rodata_off, rodata_size = section_off_and_size(rodata_sec)
        data_off, data_size = section_off_and_size(data_sec)
        bss_vma = bss_sec['sh_addr'] if bss_sec else 0
        bss_size = bss_sec['sh_size'] if bss_sec else 0

        # Symbol/strtab/reloc offsets and sizes
        symtab_off, symtab_size = section_off_and_size(symtab_sec)
        strtab_off, strtab_size = section_off_and_size(strtab_sec)
        reloc_off, reloc_size = section_off_and_size(reloc_sec)

        # Calculate symbol table count (each entry is 12 bytes)
        symbol_table_count = symtab_size // 12 if symtab_size else 0

        # Resolve entrypoint symbol virtual addresses
        def get_addr(symname):
            for s in elf.iter_sections():
                if not hasattr(s, 'iter_symbols'):
                    continue

                for sym in s.iter_symbols():
                    if sym.name == symname:

                        return sym['st_value']

            return 0

        init_addr = get_addr('ddf_driver_init')
        exit_addr = get_addr('ddf_driver_exit')
        irq_addr = get_addr('ddf_driver_irq')

        # Find the last written byte in the input file among content sections
        content_sections = []

        for sec in [text_sec, rodata_sec, data_sec, symtab_sec, strtab_sec, reloc_sec]:
            if sec:
                off = sec['sh_offset']
                size = sec['sh_size']

                if size > 0:
                    content_sections.append((off, size))

        # Compute the effective file payload end
        if content_sections:
            file_end = max([off + size for off, size in content_sections])
        else:
            file_end = 0

        # Place .bss right after the last content section, aligned to 4 bytes
        bss_off = pad4(file_end)

        # Header layout: magic + 19 u32 fields
        # Fields: magic, init, exit, irq, symtab_off, symcount, strtab_off, ver_major, ver_minor,
        # reloc_off, reloc_count, text_off, text_size, ro_off, ro_size, data_off, data_size, bss_off, bss_size, irq_number
        header_fmt = '<4s19I'
        header_size = struct.calcsize(header_fmt)

        # Header is placed at the beginning of the output file
        header_off = 0

        irq_number = find_symbol_value(elf, "ddf_irq_number")
        print(f"[DDF Patcher] IRQ for driver found, patching IRQ {irq_number}")

        # Build the header blob
        header = struct.pack(
            header_fmt,
            DDF_MAGIC,             # 0 magic
            init_addr,             # 1 init_offset
            exit_addr,             # 2 exit_offset
            irq_addr,              # 3 irq_offset
            symtab_off,            # 4 symbol_table_offset
            symbol_table_count,    # 5 symbol_table_count
            strtab_off,            # 6 strtab_offset
            1,                     # 7 version_major
            0,                     # 8 version_minor
            reloc_off,             # 9 reloc_table_offset
            reloc_size // 4 if reloc_size else 0,  # 10 reloc_table_count
            text_off,              # 11 text_offset
            text_size,             # 12 text_size
            rodata_off,            # 13 rodata_offset
            rodata_size,           # 14 rodata_size
            data_off,              # 15 data_offset
            data_size,             # 16 data_size
            bss_off,               # 17 bss_offset
            bss_size,              # 18 bss_size
            irq_number             # 19 irq_number
        )

        # Debug output to verify computed data
        print(f"[DDF Patcher] Header offsets/sizes:")
        print(f"\t\t.text       @ 0x%x, size=%x" % (text_off, text_size))
        print(f"\t\t.rodata     @ 0x%x, size=%x" % (rodata_off, rodata_size))
        print(f"\t\t.data       @ 0x%x, size=%x" % (data_off, data_size))
        print(f"\t\t.bss        @ 0x%x, size=%x" % (bss_off, bss_size))
        print(f"\t\t.ddf_symtab @ 0x%x, size=%x, count=%x" % (symtab_off, symtab_size, symbol_table_count))
        print(f"\t\t.ddf_strtab @ 0x%x, size=%x" % (strtab_off, strtab_size))
        print(f"\t\t.ddf_reloc  @ 0x%x, size=%x" % (reloc_off, reloc_size))
        print(f"[DDF Patcher] Entrypoints: init=0x%x, exit=0x%x, irq=0x%x" % (init_addr, exit_addr, irq_addr))
        print(f"[DDF Patcher] Header struct size: %x" % (header_size))
        print(f"[DDF Patcher] Module total (RAM, incl bss): 0x%x" % (bss_off + bss_size))

        # Write the patched DDF
        with open(elf_path, 'rb') as inf, open(ddf_path, 'wb') as outf:
            # Header first
            outf.write(header)

            # Copy the content payload that follows the original ELF header
            inf.seek(header_size)
            outf.write(inf.read(file_end - header_size))

            # Pad zeros up to bss_offset
            if bss_off > file_end:
                outf.write(b'\x00' * (bss_off - file_end))

        print(f"[DDF Patcher] DDF written: {ddf_path}")


if __name__ == "__main__":
    main()

