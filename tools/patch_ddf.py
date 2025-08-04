#!/usr/bin/env python3
import sys
import struct
import os

def patch_ddf(filename, init, exit, irq, symtab, symcount, header_offset=0x1000):
    """Patcha DDF-headern med absolut säkerhet"""
    try:
        # Validera input
        init = int(init, 16) if isinstance(init, str) else int(init)
        exit = int(exit, 16) if isinstance(exit, str) else int(exit)
        irq = int(irq, 16) if isinstance(irq, str) else int(irq)
        symtab = int(symtab, 16) if isinstance(symtab, str) else int(symtab)
        symcount = int(symcount)
        header_offset = int(header_offset, 16) if isinstance(header_offset, str) else int(header_offset)

        # Öppna filen i binärläge
        with open(filename, "r+b") as f:
            # Verifiera magic number
            f.seek(header_offset)
            magic = struct.unpack("<I", f.read(4))[0]
            if magic != 0x00464444:
                print(f"ERROR: Invalid magic number 0x{magic:x} at offset 0x{header_offset:x}")
                return False

            print(f"Patching DDF header at offset 0x{header_offset:x}:")
            print(f"  init:    0x{init:x}")
            print(f"  exit:    0x{exit:x}")
            print(f"  irq:     0x{irq:x}")
            print(f"  symtab:  0x{symtab:x}")
            print(f"  count:   {symcount}")

            # Patcha fälten
            f.seek(header_offset + 4)
            f.write(struct.pack("<I", init))  # init_offset
            f.write(struct.pack("<I", exit))  # exit_offset
            f.write(struct.pack("<I", irq))   # irq_offset
            f.write(struct.pack("<I", symtab))  # symbol_table_offset
            f.write(struct.pack("<I", symcount))  # symbol_table_count

            # Verifiera patching
            f.seek(header_offset + 4)
            patched = struct.unpack("<5I", f.read(20))
            if patched != (init, exit, irq, symtab, symcount):
                print("ERROR: Verification failed - values not written correctly")
                return False

            print("Patching verified successfully!")
            return True

    except Exception as e:
        print(f"ERROR: {str(e)}")
        return False

if __name__ == "__main__":
    if len(sys.argv) != 7:
        print("DDF Driver Patching Tool")
        print("Usage: patch_ddf.py <file> <init> <exit> <irq> <symtab> <symcount>")
        print("All offsets must be in hex format (e.g. 0x288)")
        sys.exit(1)

    if not patch_ddf(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], sys.argv[5], sys.argv[6]):
        sys.exit(1)
