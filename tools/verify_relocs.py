#!/usr/bin/env python3
"""
Verify that all relocations from an ELF file are properly converted to DEX/EXL format.
Compares relocations between the ELF dump and the final DEX/EXL file.
"""

import sys
import struct
import subprocess

# Relocation types
R_386_32 = 1
R_386_PC32 = 2
R_386_GOT32 = 3
R_386_PLT32 = 4
R_386_COPY = 5
R_386_GLOB_DAT = 6
R_386_JMP_SLOT = 7
R_386_RELATIVE = 8
R_386_GOTOFF = 9
R_386_GOTPC = 10
R_386_GOT32X = 43

# DEX relocation types
DEX_ABS32 = 1
DEX_PC32 = 2
DEX_REL32 = 3

ELF_TYPE_NAMES = {
    1: "R_386_32",
    2: "R_386_PC32",
    3: "R_386_GOT32",
    4: "R_386_PLT32",
    5: "R_386_COPY",
    6: "R_386_GLOB_DAT",
    7: "R_386_JMP_SLOT",
    8: "R_386_RELATIVE",
    9: "R_386_GOTOFF",
    10: "R_386_GOTPC",
    43: "R_386_GOT32X",
}

DEX_TYPE_NAMES = {
    1: "DEX_ABS32",
    2: "DEX_PC32",
    3: "DEX_REL32",
}

def read_elf_relocations(dump_file):
    """Read relocations from elfdump output."""
    relocs = []
    with open(dump_file, 'r') as f:
        for line in f:
            if line.startswith("RELOC "):
                parts = line.split()
                kv = {}
                for part in parts[1:]:
                    if '=' in part:
                        k, v = part.split('=', 1)
                        kv[k] = v

                try:
                    offset = int(kv.get('offset', '0'), 16)
                    rtype = int(kv.get('type', '0'))
                    symidx = int(kv.get('symidx', '-1'))
                    symname = kv.get('symname', '')
                    secidx = int(kv.get('secidx', '0'))

                    relocs.append({
                        'offset': offset,
                        'type': rtype,
                        'symidx': symidx,
                        'symname': symname,
                        'secidx': secidx,
                    })
                except (ValueError, KeyError) as e:
                    print(f"Warning: Failed to parse reloc line: {line.strip()} - {e}")

    return relocs

def read_dex_relocations(dex_file):
    """Read relocations from DEX/EXL file."""
    relocs = []

    with open(dex_file, 'rb') as f:
        # Read DEX header
        magic = f.read(4)
        if magic != b'\x00DEX':  # DEX magic
            print(f"Error: {dex_file} is not a valid DEX file (magic={magic.hex()})")
            return relocs

        version = struct.unpack('<I', f.read(4))[0]
        flags = struct.unpack('<I', f.read(4))[0]
        entry_point = struct.unpack('<I', f.read(4))[0]
        image_base = struct.unpack('<I', f.read(4))[0]
        image_size = struct.unpack('<I', f.read(4))[0]

        # Section headers
        text_offset = struct.unpack('<I', f.read(4))[0]
        text_size = struct.unpack('<I', f.read(4))[0]
        rodata_offset = struct.unpack('<I', f.read(4))[0]
        rodata_size = struct.unpack('<I', f.read(4))[0]
        data_offset = struct.unpack('<I', f.read(4))[0]
        data_size = struct.unpack('<I', f.read(4))[0]
        bss_offset = struct.unpack('<I', f.read(4))[0]
        bss_size = struct.unpack('<I', f.read(4))[0]

        # Import table
        import_offset = struct.unpack('<I', f.read(4))[0]
        import_count = struct.unpack('<I', f.read(4))[0]

        # Relocation table
        reloc_offset = struct.unpack('<I', f.read(4))[0]
        reloc_count = struct.unpack('<I', f.read(4))[0]

        # Symbol table
        symbol_offset = struct.unpack('<I', f.read(4))[0]
        symbol_count = struct.unpack('<I', f.read(4))[0]

        # Read relocations
        if reloc_count > 0 and reloc_offset > 0:
            try:
                f.seek(reloc_offset)
                for i in range(reloc_count):
                    data = f.read(16)  # 4 fields * 4 bytes
                    if len(data) < 16:
                        print(f"Warning: Incomplete relocation entry #{i}")
                        break

                    offset = struct.unpack('<I', data[0:4])[0]
                    import_idx = struct.unpack('<I', data[4:8])[0]
                    rtype = struct.unpack('<I', data[8:12])[0]
                    addend = struct.unpack('<I', data[12:16])[0]

                    relocs.append({
                        'offset': offset,
                        'type': rtype,
                        'import_idx': import_idx,
                        'addend': addend,
                    })
            except Exception as e:
                print(f"Error reading relocations: {e}")

    return relocs

def compare_relocations(elf_dump, dex_file, verbose=False):
    """Compare relocations between ELF and DEX."""
    print(f"Reading ELF relocations from {elf_dump}...")
    elf_relocs = read_elf_relocations(elf_dump)
    print(f"  Found {len(elf_relocs)} ELF relocations")

    print(f"\nReading DEX relocations from {dex_file}...")
    dex_relocs = read_dex_relocations(dex_file)
    print(f"  Found {len(dex_relocs)} DEX relocations")

    # Count by type
    print("\n=== ELF Relocation Type Summary ===")
    elf_by_type = {}
    for r in elf_relocs:
        rtype = r['type']
        elf_by_type[rtype] = elf_by_type.get(rtype, 0) + 1

    for rtype in sorted(elf_by_type.keys()):
        type_name = ELF_TYPE_NAMES.get(rtype, f"UNKNOWN({rtype})")
        count = elf_by_type[rtype]
        print(f"  {type_name:20s}: {count:6d} relocations")

    print("\n=== DEX Relocation Type Summary ===")
    dex_by_type = {}
    for r in dex_relocs:
        rtype = r['type']
        dex_by_type[rtype] = dex_by_type.get(rtype, 0) + 1

    for rtype in sorted(dex_by_type.keys()):
        type_name = DEX_TYPE_NAMES.get(rtype, f"UNKNOWN({rtype})")
        count = dex_by_type[rtype]
        print(f"  {type_name:20s}: {count:6d} relocations")

    # Build offset maps for DEX relocations
    dex_by_offset = {}
    for r in dex_relocs:
        dex_by_offset[r['offset']] = r

    # Check for missing/incorrect relocations
    print("\n=== Checking for Missing or Incorrect Relocations ===")

    missing = []
    type_mismatch = []
    found = []

    # We need to map ELF offsets to image offsets
    # This requires understanding section mappings
    # For now, let's focus on detecting patterns

    # Count PC32 relocations in ELF that should be in DEX
    pc32_in_elf = [r for r in elf_relocs if r['type'] == R_386_PC32]
    pc32_in_dex = [r for r in dex_relocs if r['type'] == DEX_PC32]

    print(f"\nPC32 Relocations:")
    print(f"  ELF has {len(pc32_in_elf)} R_386_PC32 relocations")
    print(f"  DEX has {len(pc32_in_dex)} DEX_PC32 relocations")

    if verbose and len(pc32_in_elf) > 0:
        print("\n  Sample PC32 relocations from ELF:")
        for r in pc32_in_elf[:10]:
            print(f"    offset=0x{r['offset']:08x} symname={r['symname']}")

    # Check GOT32X conversions
    got32x_in_elf = [r for r in elf_relocs if r['type'] == R_386_GOT32X]
    print(f"\nGOT32X Relocations:")
    print(f"  ELF has {len(got32x_in_elf)} R_386_GOT32X relocations")
    print(f"  (These are converted to direct calls or PC32 in DEX)")

    # Look for specific problematic relocations
    print("\n=== Searching for Specific Issues ===")

    # Find W_CheckNumForName PC32 relocations
    w_check_pc32 = [r for r in elf_relocs if r['type'] == R_386_PC32 and 'W_CheckNumForName' in r['symname']]
    if w_check_pc32:
        print(f"\nFound {len(w_check_pc32)} PC32 relocations to W_CheckNumForName in ELF:")
        for r in w_check_pc32:
            print(f"  offset=0x{r['offset']:08x} type={ELF_TYPE_NAMES.get(r['type'])} symname={r['symname']}")

            # Check if there's a corresponding DEX relocation
            # Note: offset mapping is complex, so this is approximate
            if r['offset'] in dex_by_offset:
                dex_r = dex_by_offset[r['offset']]
                print(f"    -> Found in DEX: offset=0x{dex_r['offset']:08x} type={DEX_TYPE_NAMES.get(dex_r['type'])}")
            else:
                print(f"    -> NOT FOUND in DEX at same offset (may be at different offset due to section mapping)")

    return {
        'elf_count': len(elf_relocs),
        'dex_count': len(dex_relocs),
        'elf_by_type': elf_by_type,
        'dex_by_type': dex_by_type,
        'pc32_elf': len(pc32_in_elf),
        'pc32_dex': len(pc32_in_dex),
    }

def main():
    if len(sys.argv) < 3:
        print("Usage: verify_relocs.py <dump.txt> <output.dex> [--verbose]")
        print("\nCompares relocations between ELF dump and DEX/EXL file")
        print("to verify all relocations are properly converted.")
        sys.exit(1)

    dump_file = sys.argv[1]
    dex_file = sys.argv[2]
    verbose = '--verbose' in sys.argv or '-v' in sys.argv

    result = compare_relocations(dump_file, dex_file, verbose)

    print("\n=== Summary ===")
    print(f"Total ELF relocations: {result['elf_count']}")
    print(f"Total DEX relocations: {result['dex_count']}")

    if result['pc32_elf'] > result['pc32_dex']:
        print(f"\n⚠️  WARNING: ELF has {result['pc32_elf']} PC32 relocations but DEX only has {result['pc32_dex']}")
        print("   Some PC32 relocations may not have been converted!")

    if result['elf_count'] > result['dex_count'] * 2:
        print(f"\n⚠️  WARNING: DEX has significantly fewer relocations than ELF")
        print("   This may indicate some relocations were resolved at link time")

if __name__ == '__main__':
    main()
