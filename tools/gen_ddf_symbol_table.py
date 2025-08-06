#!/usr/bin/env python3
import sys
import re

def main(nm_file, out_file):
    REQUIRED_SYMBOLS = {
        'ddf_driver_init',
        'ddf_driver_exit', 
        'ddf_driver_irq'
    }
    
    # Store symbols here
    symbols = []
    found_required = set()
    symbol_count = 0

    # Regex to collect nm output
    NM_REGEX = re.compile(r'^([0-9a-fA-F]+)\s+([TtDdBbRr])\s+(.+)$')

    # Read nm output and collect symbols
    with open(nm_file, 'r') as f:
        for line in f:
            line = line.strip()
            match = NM_REGEX.match(line)
            if not match:
                continue

            addr, typ, name = match.groups()
            
            # Ignore unwanted symbols
            if (not name or 
                name.startswith('.') or 
                name.startswith('$') or 
                name == 'ddf_header'):
                continue

            # Check symbol type
            if typ.upper() in ['T', 't']:                           # Text/code
                sym_type = 0
            elif typ.upper() in ['D', 'd', 'B', 'b', 'R', 'r']:     # Data
                sym_type = 1
            else:
                continue

            addr_int = int(addr, 16)
            symbols.append((name, addr_int, sym_type))
            
            if name in REQUIRED_SYMBOLS:
                found_required.add(name)

    # Verify all symbols
    missing = REQUIRED_SYMBOLS - found_required
    if missing:
        print(f"ERROR: Missing required symbols: {missing}")
        sys.exit(1)

    # Build a stringtable
    string_table = bytearray(b'\x00')                               # Null byte at the start
    name_offsets = {}
    
    for name, _, _ in symbols:
        if name not in name_offsets:
            # 4-byte alignment for each string
            padding = (4 - (len(string_table) % 4) % 4)
            string_table.extend(b'\x00' * padding)
            
            # Save offset and store in string
            name_offsets[name] = len(string_table)
            string_table.extend(name.encode('utf-8') + b'\x00')

    # Generate C code for symboltable
    with open(out_file, 'w') as out:
        # Header
        out.write('/* Automatically generated DDF symbol table - DO NOT EDIT */\n')
        out.write('#include "drivers/ddf.h"\n\n')
        
        # Stringtable
        out.write('__attribute__((section(".ddf_strtab"), aligned(4), used))\n')
        out.write('static const char ddf_string_table[] = \n{\n    ')
        
        # Write the stringtable as hex bytes
        for i in range(0, len(string_table), 16):
            chunk = string_table[i:i+16]
            out.write(', '.join(f'0x{b:02x}' for b in chunk))
            out.write(',\n    ' if i+16 < len(string_table) else '\n')
        
        out.write('};\n\n')
        
        # Symboltable
        out.write('__attribute__((section(".ddf_symtab"), aligned(4), used))\n')
        out.write('ddf_symbol_t ddf_symbol_table[] = \n{\n')
        
        for name, addr, typ in symbols:
            out.write(f'    {{\n        .name_offset = {name_offsets[name]},\n')
            out.write(f'        .value_offset = 0x{addr:x},\n')
            out.write(f'        .type = {typ}\n    }}, // {name}\n')
        
        out.write('};\n\n')
        
        # Symbolcount
        out.write(f'const uint32_t ddf_symbol_table_count = {len(symbols)};\n')
        
        # Debug-info
        out.write('\n/* Symbol table summary:\n')
        out.write(f'   Total symbols: {len(symbols)}\n')
        out.write(f'   String table size: {len(string_table)} bytes\n')
        out.write('*/\n')

    print(f"Successfully generated symbol table with {len(symbols)} entries")
    print(f"String table size: {len(string_table)} bytes")
    print(f"Output file: {out_file}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("DDF Symbol Table Generator")
        print("Usage: gen_ddf_symbol_table.py <nm_output.txt> <output.c>")
        sys.exit(1)
    
    try:
        main(sys.argv[1], sys.argv[2])
    except Exception as e:
        print(f"ERROR: {str(e)}")
        sys.exit(1)
