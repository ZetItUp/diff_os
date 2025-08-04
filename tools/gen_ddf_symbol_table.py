#!/usr/bin/env python3
import sys

def main(nm_file, out_file):
    symbols = []
    required_symbols = {'ddf_driver_init', 'ddf_driver_exit', 'ddf_driver_irq'}
    found_required = set()

    # Parse nm output
    with open(nm_file) as f:
        for line in f:
            parts = line.strip().split()
            if len(parts) < 3:
                continue
            
            addr, typ, name = parts[0], parts[1], ' '.join(parts[2:])
            
            # Skip local/uninteresting symbols
            if not name or name[0] in ('.', '$') or name == 'ddf_header':
                continue
            
            # Handle different symbol types
            if typ.upper() in ['T', 't']:  # Text/code
                sym_type = 0
            elif typ.upper() in ['D', 'd', 'B', 'b', 'R', 'r']:  # Data
                sym_type = 1
            else:
                continue

            addr_int = int(addr, 16)
            symbols.append((name, addr_int, sym_type))
            
            if name in required_symbols:
                found_required.add(name)

    # Verify required symbols
    missing = required_symbols - found_required
    if missing:
        print(f"ERROR: Missing required symbols: {missing}")
        sys.exit(1)

    # Build string table
    string_table = bytearray(b'\x00')  # Start with null byte
    offsets = {}
    
    for name, _, _ in symbols:
        if name not in offsets:
            name_bytes = name.encode('utf-8') + b'\x00'
            offsets[name] = len(string_table)
            string_table.extend(name_bytes)

    # Generate C code
    with open(out_file, 'w') as out:
        out.write('#include "drivers/ddf.h"\n\n')
        out.write('__attribute__((section(".ddf_strtab"), used)) \n')
        out.write('static const char string_table[] = {\n    ')
        
        # Write string table as hex bytes
        for i, byte in enumerate(string_table):
            out.write(f'0x{byte:02x}, ')
            if (i+1) % 16 == 0:
                out.write('\n    ')
        out.write('\n};\n\n')
        
        out.write('__attribute__((section(".ddf_symtab"), used)) \n')
        out.write('ddf_symbol_t ddf_symbol_table[] = {\n')
        for name, addr, typ in symbols:
            out.write(f'    {{ .name_offset = {offsets[name]}, ')
            out.write(f'.value_offset = 0x{addr:x}, ')
            out.write(f'.type = {typ} }}, // {name}\n')
        out.write('};\n\n')
        
        out.write(f'const uint32_t ddf_symbol_table_count = {len(symbols)};\n')

    print(f"Generated symbol table with {len(symbols)} entries")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: gen_ddf_symbol_table.py <nm_output.txt> <output.c>")
        sys.exit(1)
    main(sys.argv[1], sys.argv[2])
