import sys
import struct

def main(filename):
    with open(filename, "rb") as f:
        data = f.read()
    if data[:4] != b'DDF\x00':
        print("Not a valid DDF file (missing magic)")
        return 1

    header = struct.unpack("<11I", data[:44])
    print("DDF Header:")
    print(f"  magic               : 0x{header[0]:08x}")
    print(f"  init                : 0x{header[1]:08x}")
    print(f"  exit                : 0x{header[2]:08x}")
    print(f"  irq                 : 0x{header[3]:08x}")
    print(f"  symtab              : 0x{header[4]:08x}")
    print(f"  symcount            : 0x{header[5]:08x}")
    print(f"  strtab_offset       : 0x{header[6]:08x}")
    print(f"  version_major       : 0x{header[7]:08x}")
    print(f"  version_minor       : 0x{header[8]:08x}")
    print(f"  reloc_table_offset  : 0x{header[9]:08x}")
    print(f"  reloc_table_count   : 0x{header[10]:08x}")

    symtab_offset = header[4]
    symcount = header[5]
    for i in range(symcount):
        entry = struct.unpack_from('<III', data, symtab_offset + i*12)
        print(f"  Symbol[{i}] name_off={entry[0]} value_off={entry[1]} type={entry[2]}")

if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))

