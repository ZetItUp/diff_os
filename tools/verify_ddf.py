#!/usr/bin/env python3
import sys
import struct
import os

DDF_MAGIC = 0x00464444
COMMON_HEADER_OFFSETS = [0x0000, 0x1000, 0x0800, 0x2000]  # Vanliga header-platser

def find_ddf_header(f):
    """Sök dynamiskt efter DDF-header"""
    for offset in COMMON_HEADER_OFFSETS:
        f.seek(offset)
        magic_bytes = f.read(4)
        if len(magic_bytes) == 4 and struct.unpack("<I", magic_bytes)[0] == DDF_MAGIC:
            return offset
    return None

def read_ddf_header(f, offset):
    """Läs DDF-header från given offset"""
    f.seek(offset)
    header_fmt = "<6I2I"  # magic, init, exit, irq, symtab, symcount, name_ptr, version
    data = f.read(32)
    if len(data) != 32:
        return None
    
    return dict(zip(
        ["magic", "init", "exit", "irq", "symtab", "symcount", "name_ptr", "version_major", "version_minor"],
        struct.unpack(header_fmt, data)
    ))

def main(filename):
    if not os.path.exists(filename):
        print(f"ERROR: File '{filename}' not found")
        return 1

    with open(filename, "rb") as f:
        # Hitta header dynamiskt
        header_offset = find_ddf_header(f)
        if header_offset is None:
            print("ERROR: Could not find DDF header (magic number 0x00464444)")
            print("Tried offsets:", [f"0x{o:x}" for o in COMMON_HEADER_OFFSETS])
            return 1

        print(f"Found DDF header at offset 0x{header_offset:x}")

        # Läs header
        header = read_ddf_header(f, header_offset)
        if not header:
            print("ERROR: Invalid DDF header format")
            return 1

        print("\nDDF Header:")
        for k, v in header.items():
            print(f"  {k:15}: 0x{v:08x}")

        # Verifiera kritiska symboler
        required = {
            'init': header['init'],
            'exit': header['exit'], 
            'irq': header['irq']
        }
        
        print("\nCritical Symbols:")
        for name, offset in required.items():
            print(f"  {name:15}: 0x{offset:08x} {'(OK)' if offset else '(MISSING)'}")

        return 0

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <driver_file>")
        sys.exit(1)
    
    sys.exit(main(sys.argv[1]))
