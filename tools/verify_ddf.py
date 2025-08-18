#!/usr/bin/env python3
import sys
import struct

def read_cstr(data, off):
    out = []
    n = len(data)
    i = off
    while i < n:
        b = data[i]
        if b == 0:
            break
        out.append(b)
        i += 1
    try:
        return bytes(out).decode('utf-8')
    except:
        return ''

def main(filename):
    with open(filename, "rb") as f:
        data = f.read()

    if len(data) < 80 or data[:4] != b'DDF\x00':
        print("Not a valid DDF file (missing magic or too short)")
        return 1

    # ddf_header_t: magic + 19 x uint32
    header = struct.unpack("<4s19I", data[:80])
    (magic,
     init_off,
     exit_off,
     irq_off,
     symtab_off,
     symcount,
     strtab_off,
     ver_major,
     ver_minor,
     reloc_off,
     reloc_count,
     text_off,
     text_size,
     ro_off,
     ro_size,
     data_off,
     data_size,
     bss_off,
     bss_size,
     irq_number) = header

    print("DDF Header:")
    print(f"  magic               : {magic!r}")
    print(f"  init_offset         : 0x{init_off:08x}")
    print(f"  exit_offset         : 0x{exit_off:08x}")
    print(f"  irq_offset          : 0x{irq_off:08x}")
    print(f"  symbol_table_offset : 0x{symtab_off:08x}")
    print(f"  symbol_table_count  : {symcount}")
    print(f"  strtab_offset       : 0x{strtab_off:08x}")
    print(f"  version_major       : {ver_major}")
    print(f"  version_minor       : {ver_minor}")
    print(f"  reloc_table_offset  : 0x{reloc_off:08x}")
    print(f"  reloc_table_count   : {reloc_count}")
    print(f"  text_offset         : 0x{text_off:08x}")
    print(f"  text_size           : 0x{text_size:08x}")
    print(f"  rodata_offset       : 0x{ro_off:08x}")
    print(f"  rodata_size         : 0x{ro_size:08x}")
    print(f"  data_offset         : 0x{data_off:08x}")
    print(f"  data_size           : 0x{data_size:08x}")
    print(f"  bss_offset          : 0x{bss_off:08x}")
    print(f"  bss_size            : 0x{bss_size:08x}")
    print(f"  irq_number          : {irq_number}")

    file_size = len(data)
    module_total = max(file_size, bss_off + bss_size)

    # Grundsanitet
    def in_file(off, sz):
        return off + sz <= file_size

    ok = True
    if not in_file(text_off, text_size):
        print("ERROR: .text out of file range"); ok = False
    if not in_file(ro_off, ro_size):
        print("ERROR: .rodata out of file range"); ok = False
    if not in_file(data_off, data_size):
        print("ERROR: .data out of file range"); ok = False
    if symtab_off and not in_file(symtab_off, symcount * 12):
        print("ERROR: .ddf_symtab out of file range"); ok = False
    # strtab storlek okänd i header; vi kan bara kontrollera att offset finns
    if strtab_off >= file_size:
        print("ERROR: .ddf_strtab offset beyond file"); ok = False
    if reloc_off and not in_file(reloc_off, reloc_count * 16):
        print("ERROR: .ddf_reloc out of file range (by count)"); ok = False

    # Symboler: dumpa några och validera att value_offset ligger inom [0, module_total)
    if symtab_off and symcount:
        sym_blob = data[symtab_off:symtab_off + symcount * 12]
        # Lägg ett rimligt tak på strtab-läsning
        strtab_blob = data[strtab_off:] if strtab_off < file_size else b''

        for i in range(symcount):
            noff, valoff, typ = struct.unpack_from('<III', sym_blob, i * 12)
            name = read_cstr(strtab_blob, noff) if noff < len(strtab_blob) else ''
            within = (valoff < module_total)
            print(f"  Symbol[{i:03d}] name_off={noff:5d} value_off=0x{valoff:08x} type={typ}  name='{name}'  {'OK' if within else 'OUT-OF-RANGE'}")
            if not within:
                ok = False

    print(f"\nModule total (incl. BSS in RAM): {module_total} bytes")
    print("VERIFY:", "OK" if ok else "FAILED")
    return 0 if ok else 2

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]) if len(sys.argv) >= 2 else 1)

