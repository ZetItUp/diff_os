#!/usr/bin/env python3
import sys
import re

def main(nm_file, out_file):
    REQUIRED_SYMBOLS = {
        'ddf_driver_init',
        'ddf_driver_exit',
        'ddf_driver_irq'
    }

    symbols = []
    found_required = set()

    NM_REGEX = re.compile(r'^([0-9a-fA-F]+)\s+([TtDdBbRr])\s+(.+)$')

    with open(nm_file, 'r') as f:
        for line in f:
            line = line.strip()
            m = NM_REGEX.match(line)

            if not m:
                continue

            addr_hex, typ, name = m.groups()

            if not name or name.startswith('.') or name.startswith('$') or name == 'ddf_header':
                continue

            if typ.upper() in ('T',):
                sym_type = 0  # Function
            elif typ.upper() in ('D', 'B', 'R'):
                sym_type = 1  # Data
            else:
                continue

            # We do not write absolute addresses here
            # value_offset should be offset from module start according to ddf.h
            # This is determined in the patch step from ELF -> DDF
            symbols.append((name, sym_type))

            if name in REQUIRED_SYMBOLS:
                found_required.add(name)

    missing = REQUIRED_SYMBOLS - found_required

    if missing:
        print(f"ERROR: Missing required symbols: {sorted(missing)}")
        sys.exit(1)

    # Build string table starting with NUL
    string_table = bytearray(b'\x00')
    name_offsets = {}

    for name, _ in symbols:
        if name not in name_offsets:
            # 4-byte alignment
            pad = (-len(string_table)) & 3

            if pad:
                string_table.extend(b'\x00' * pad)

            name_offsets[name] = len(string_table)
            string_table.extend(name.encode('utf-8') + b'\x00')

    with open(out_file, 'w') as out:
        out.write('/* Automatically generated DDF symbol table - DO NOT EDIT */\n')
        out.write('#include "drivers/ddf.h"\n\n')

        out.write('__attribute__((section(".ddf_strtab"), aligned(4), used))\n')
        out.write('static const unsigned char ddf_string_table[] = {\n    ')

        for i in range(0, len(string_table), 16):
            chunk = string_table[i:i+16]
            out.write(', '.join(f'0x{b:02x}' for b in chunk))

            if i + 16 < len(string_table):
                out.write(',\n    ')
            else:
                out.write('\n')

        out.write('};\n\n')

        out.write('__attribute__((section(".ddf_symtab"), aligned(4), used))\n')
        out.write('ddf_symbol_t ddf_symbol_table[] = {\n')

        for name, sym_type in symbols:
            out.write('    {\n')
            out.write(f'        .name_offset = {name_offsets[name]},\n')
            out.write(f'        .value_offset = 0, /* patched to DDF file offset by patch_ddf.py */\n')
            out.write(f'        .type = {sym_type}\n')
            out.write('    },\n')

        out.write('};\n\n')

        out.write(f'const uint32_t ddf_symbol_table_count = {len(symbols)};\n')

        out.write('\n/* Summary:\n')
        out.write(f'   Total symbols: {len(symbols)}\n')
        out.write(f'   String table size: {len(string_table)} bytes\n')
        out.write('*/\n')

    print(f"Successfully generated symbol table with {len(symbols)} entries")
    print(f"String table size: {len(string_table)} bytes")
    print(f"Output file: {out_file}")


if __name__ == "__main__":
    if len(sys.argv) != 2 and len(sys.argv) != 3:
        print("DDF Symbol Table Generator")
        print("Usage: gen_ddf_symbol_table.py <nm_output.txt> <output.c>")
        sys.exit(1)

    try:
        main(sys.argv[1], sys.argv[2])
    except Exception as e:
        print(f"ERROR: {e}")
        sys.exit(1)
