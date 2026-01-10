#!/usr/bin/env python3
import sys
import struct
import os

# DEX magic and relocation types
DEX_MAGIC = 0x58454400  # "DEX\0"
DEX_ABS32 = 0
DEX_PC32 = 2
DEX_RELATIVE = 8

# Simulate user space addresses
SIMULATED_IMAGE_BASE = 0x40000000
USER_MIN = 0x00001000
USER_MAX = 0xC0000000

def is_user_va(addr):
    """Check if address is in user range"""
    return USER_MIN <= addr < USER_MAX

def read_dex_header(data):
    """Parse DEX header"""
    if len(data) < 0x100:
        return None

    magic = struct.unpack_from("<I", data, 0)[0]
    
    if magic != DEX_MAGIC:
        return None

    hdr = {}
    hdr['magic'] = magic
    hdr['version_major'] = struct.unpack_from("<I", data, 4)[0]
    hdr['version_minor'] = struct.unpack_from("<I", data, 8)[0]
    hdr['entry_offset'] = struct.unpack_from("<I", data, 12)[0]
    hdr['text_offset'] = struct.unpack_from("<I", data, 16)[0]
    hdr['text_size'] = struct.unpack_from("<I", data, 20)[0]
    hdr['rodata_offset'] = struct.unpack_from("<I", data, 24)[0]
    hdr['rodata_size'] = struct.unpack_from("<I", data, 28)[0]
    hdr['data_offset'] = struct.unpack_from("<I", data, 32)[0]
    hdr['data_size'] = struct.unpack_from("<I", data, 36)[0]
    hdr['bss_size'] = struct.unpack_from("<I", data, 40)[0]
    hdr['import_table_offset'] = struct.unpack_from("<I", data, 44)[0]
    hdr['import_table_count'] = struct.unpack_from("<I", data, 48)[0]
    hdr['reloc_table_offset'] = struct.unpack_from("<I", data, 52)[0]
    hdr['reloc_table_count'] = struct.unpack_from("<I", data, 56)[0]
    hdr['symbol_table_offset'] = struct.unpack_from("<I", data, 60)[0]
    hdr['symbol_table_count'] = struct.unpack_from("<I", data, 64)[0]
    hdr['strtab_offset'] = struct.unpack_from("<I", data, 68)[0]
    hdr['strtab_size'] = struct.unpack_from("<I", data, 72)[0]

    return hdr

def read_imports(data, hdr):
    """Read import table"""
    imports = []
    offset = hdr['import_table_offset']

    for i in range(hdr['import_table_count']):
        if offset + 16 > len(data):
            print(f"ERROR: Import {i} extends beyond file")
            break

        exl_name_off = struct.unpack_from("<I", data, offset)[0]
        sym_name_off = struct.unpack_from("<I", data, offset + 4)[0]
        import_type = struct.unpack_from("<I", data, offset + 8)[0]

        # Read strings
        exl_name = ""
        sym_name = ""

        if exl_name_off < hdr['strtab_size']:
            str_off = hdr['strtab_offset'] + exl_name_off
            end = data.find(b'\0', str_off)
            
            if end != -1:
                exl_name = data[str_off:end].decode('utf-8', errors='replace')

        if sym_name_off < hdr['strtab_size']:
            str_off = hdr['strtab_offset'] + sym_name_off
            end = data.find(b'\0', str_off)
            
            if end != -1:
                sym_name = data[str_off:end].decode('utf-8', errors='replace')

        imports.append({
            'exl': exl_name,
            'symbol': sym_name,
            'type': import_type,
            'idx': i
        })
        
        offset += 16

    return imports

def read_relocations(data, hdr):
    """Read relocation table"""
    relocs = []
    offset = hdr['reloc_table_offset']

    for i in range(hdr['reloc_table_count']):
        if offset + 16 > len(data):
            print(f"ERROR: Relocation {i} extends beyond file")
            
            break

        rel_offset = struct.unpack_from("<I", data, offset)[0]
        rel_idx = struct.unpack_from("<I", data, offset + 4)[0]
        rel_type = struct.unpack_from("<I", data, offset + 8)[0]

        relocs.append({
            'offset': rel_offset,
            'idx': rel_idx,
            'type': rel_type
        })
        
        offset += 16

    return relocs

def simulate_import_resolution(imports):
    """
    Simulate resolving imports to user-space addresses
    Returns a list of simulated addresses for each import
    """
    import_addrs = []
    
    # Simulate EXL being loaded at a different user address
    simulated_exl_base = 0x50000000

    for i, imp in enumerate(imports):
        # Simulate address for this import
        # In reality, this would come from the EXL symbol table
        simulated_addr = simulated_exl_base + (i * 0x100)

        if not is_user_va(simulated_addr):
            print(f"ERROR: Simulated import {i} ({imp['exl']}:{imp['symbol']}) "
                  f"resolves to kernel VA 0x{simulated_addr:08x}")
            return None

        import_addrs.append(simulated_addr)

    return import_addrs

def apply_relocations(image, hdr, relocs, import_addrs, verbose=False):
    """
    Apply relocations to the image
    Returns (success, errors)
    """
    errors = []
    image_base = SIMULATED_IMAGE_BASE
    image_size = len(image)

    if verbose:
        print(f"\nApplying {len(relocs)} relocations to image at 0x{image_base:08x}")
        print(f"Image size: 0x{image_size:08x}")

    for i, rel in enumerate(relocs):
        offset = rel['offset']
        idx = rel['idx']
        rtype = rel['type']

        # Check bounds
        if offset + 4 > image_size:
            errors.append(f"Reloc {i}: offset 0x{offset:08x} + 4 exceeds image size 0x{image_size:08x}")
            
            continue

        # Read old value
        old_value = struct.unpack_from("<I", image, offset)[0]
        target_va = image_base + offset

        if rtype == DEX_ABS32:
            # Absolute 32-bit relocation: replace with absolute address
            if idx >= len(import_addrs):
                errors.append(f"Reloc {i} (ABS32): idx {idx} >= import count {len(import_addrs)}")
                
                continue

            new_value = import_addrs[idx]

            if not is_user_va(new_value):
                errors.append(f"Reloc {i} (ABS32): resolved to kernel VA 0x{new_value:08x}")

            struct.pack_into("<I", image, offset, new_value)

            if verbose and offset >= hdr['entry_offset'] and offset < hdr['entry_offset'] + 0x200:
                print(f"  ABS32 @0x{offset:08x} (VA=0x{target_va:08x}): "
                      f"0x{old_value:08x} -> 0x{new_value:08x} (import {idx})")

        elif rtype == DEX_PC32:
            # PC-relative 32-bit: S - P
            # S = symbol address (from import)
            # P = address of next instruction (target + 4)
            if idx >= len(import_addrs):
                errors.append(f"Reloc {i} (PC32): idx {idx} >= import count {len(import_addrs)}")
                
                continue

            S = import_addrs[idx]
            P = target_va + 4
            disp = (S - P) & 0xFFFFFFFF

            # Check if this looks like a valid call/jmp displacement
            # Should be within reasonable range for code
            if disp > 0x7FFFFFFF:
                # Negative displacement
                actual_disp = disp - 0x100000000
                
                if actual_disp < -0x40000000:
                    errors.append(f"Reloc {i} (PC32): displacement {actual_disp} seems too large")
            
            elif disp > 0x40000000:
                errors.append(f"Reloc {i} (PC32): displacement 0x{disp:08x} seems too large")

            struct.pack_into("<I", image, offset, disp)

            if verbose and offset >= hdr['entry_offset'] and offset < hdr['entry_offset'] + 0x200:
                print(f"  PC32  @0x{offset:08x} (VA=0x{target_va:08x}): "
                      f"S=0x{S:08x} P=0x{P:08x} disp=0x{disp:08x} "
                      f"old=0x{old_value:08x} (import {idx})")

        elif rtype == DEX_RELATIVE:
            # Image-relative: add image base
            new_value = (old_value + image_base) & 0xFFFFFFFF

            if not is_user_va(new_value):
                errors.append(f"Reloc {i} (REL): resolved to kernel/invalid VA 0x{new_value:08x}")

            struct.pack_into("<I", image, offset, new_value)

            if verbose and offset >= hdr['entry_offset'] and offset < hdr['entry_offset'] + 0x200:
                print(f"  REL   @0x{offset:08x} (VA=0x{target_va:08x}): "
                      f"0x{old_value:08x} + base -> 0x{new_value:08x}")

        else:
            errors.append(f"Reloc {i}: unknown type {rtype}")

    return len(errors) == 0, errors

def scan_for_suspicious_pointers(image, hdr, relocated_offsets, verbose=False):
    """
    Scan the image for suspicious pointer values that might not have been relocated
    """
    warnings = []

    # Create a set of offsets that were relocated
    relocated_set = set(relocated_offsets)

    sections = []
    if hdr['rodata_size'] > 0:
        sections.append(('rodata', hdr['rodata_offset'], hdr['rodata_size']))
    
    if hdr['data_size'] > 0:
        sections.append(('data', hdr['data_offset'], hdr['data_size']))

    for sect_name, sect_start, sect_size in sections:
        sect_end = sect_start + sect_size

        # Scan 4-byte aligned offsets (pointers are typically aligned)
        for off in range(sect_start, sect_end - 3, 4):
            # Skip if this offset was relocated
            if off in relocated_set:
                continue

            # Read 4-byte value
            val = struct.unpack_from("<I", image, off)[0]

            # Check for values that look like file offsets (should have been relocated)
            # But only if they're not zero or obviously not pointers
            if 0x100 < val < len(image) and val < 0x00100000:
                # This might be an unrelocated file offset
                warnings.append(f"[{sect_name}] Possible unrelocated offset at 0x{off:08x}: value=0x{val:08x}")

            # Check for kernel-space pointers (definitely wrong in user code)
            if val >= 0xC0000000 and val != 0xFFFFFFFF:
                warnings.append(f"[{sect_name}] Kernel-space pointer at 0x{off:08x}: value=0x{val:08x}")

    return warnings

def verify_text_section(image, hdr, relocated_offsets, verbose=False):
    """
    Verify that the .text section contains valid x86 instructions
    """
    errors = []
    text_start = hdr['text_offset']
    text_end = text_start + hdr['text_size']

    # Check entry point
    entry_off = hdr['entry_offset']
    if entry_off >= text_start and entry_off < text_end:
        # Read first few bytes of entry
        entry_bytes = image[entry_off:entry_off+16]

        # Check for some common valid instruction patterns
        if entry_bytes == b'\x00' * 16:
            errors.append(f"Entry point at 0x{entry_off:08x} is all zeros")

        # Check for invalid opcodes that should never appear at entry
        if entry_bytes[0] in [0xF4, 0xFA, 0xFB]:  # HLT, CLI, STI
            errors.append(f"Entry point starts with privileged instruction: 0x{entry_bytes[0]:02x}")

        if verbose:
            print(f"\nEntry point bytes at 0x{entry_off:08x}:")
            print(f"  {entry_bytes.hex()}")

    # Scan for suspicious unrelocated pointers
    warnings = scan_for_suspicious_pointers(image, hdr, relocated_offsets, verbose)
    
    if warnings and verbose:
        print(f"\nSuspicious pointer scan found {len(warnings)} warnings:")
        
        for i, warn in enumerate(warnings[:20]):
            print(f"  {warn}")
        
        if len(warnings) > 20:
            print(f"  ... and {len(warnings) - 20} more warnings")

    return len(errors) == 0, errors

def verify_dex_with_relocation(filepath, verbose=False):
    """Main verification function with relocation simulation"""
    print(f"Verifying DEX file with relocation simulation: {filepath}")
    print("=" * 80)

    if not os.path.exists(filepath):
        print(f"ERROR: File not found: {filepath}")
        
        return False

    with open(filepath, 'rb') as f:
        data = bytearray(f.read())

    file_size = len(data)
    print(f"File size: 0x{file_size:08x} ({file_size} bytes)")

    # Parse header
    hdr = read_dex_header(data)
    
    if not hdr:
        print("ERROR: Invalid DEX file (bad magic)")
        
        return False

    print(f"\nDEX Header:")
    print(f"  Magic: 0x{hdr['magic']:08x}")
    print(f"  Version: {hdr['version_major']}.{hdr['version_minor']}")
    print(f"  Entry: 0x{hdr['entry_offset']:08x}")
    print(f"  .text:   0x{hdr['text_offset']:08x} size=0x{hdr['text_size']:08x}")
    print(f"  .rodata: 0x{hdr['rodata_offset']:08x} size=0x{hdr['rodata_size']:08x}")
    print(f"  .data:   0x{hdr['data_offset']:08x} size=0x{hdr['data_size']:08x}")
    print(f"  .bss:    size=0x{hdr['bss_size']:08x}")
    print(f"  Imports: {hdr['import_table_count']} at 0x{hdr['import_table_offset']:08x}")
    print(f"  Relocs:  {hdr['reloc_table_count']} at 0x{hdr['reloc_table_offset']:08x}")
    print(f"  Symbols: {hdr['symbol_table_count']} at 0x{hdr['symbol_table_offset']:08x}")
    print(f"  Strtab:  size=0x{hdr['strtab_size']:08x} at 0x{hdr['strtab_offset']:08x}")

    # Calculate image size
    max_end = hdr['data_offset'] + hdr['data_size'] + hdr['bss_size']
    tmp = hdr['rodata_offset'] + hdr['rodata_size']
    
    if tmp > max_end:
        max_end = tmp
    
    tmp = hdr['text_offset'] + hdr['text_size']
    
    if tmp > max_end:
        max_end = tmp
    
    tmp = hdr['entry_offset'] + 16
    
    if tmp > max_end:
        max_end = tmp

    # Page align
    image_size = (max_end + 0xFFF) & ~0xFFF
    print(f"  Calculated image size: 0x{image_size:08x}")

    # Read imports and relocations
    print("\nReading imports and relocations...")
    imports = read_imports(data, hdr)
    relocs = read_relocations(data, hdr)

    print(f"  {len(imports)} imports")
    print(f"  {len(relocs)} relocations")

    if verbose and len(imports) > 0:
        print("\nImports:")
        
        for imp in imports[:10]:  # Show first 10
            print(f"  [{imp['idx']}] {imp['exl']}:{imp['symbol']}")
        
        if len(imports) > 10:
            print(f"  ... and {len(imports) - 10} more")

    # Create image copy for relocation
    print("\nCreating relocated image...")
    image = bytearray(image_size)

    # Copy sections (like dex_loader.c does)
    if hdr['text_size'] > 0:
        image[hdr['text_offset']:hdr['text_offset']+hdr['text_size']] = \
            data[hdr['text_offset']:hdr['text_offset']+hdr['text_size']]

    if hdr['rodata_size'] > 0:
        image[hdr['rodata_offset']:hdr['rodata_offset']+hdr['rodata_size']] = \
            data[hdr['rodata_offset']:hdr['rodata_offset']+hdr['rodata_size']]

    if hdr['data_size'] > 0:
        image[hdr['data_offset']:hdr['data_offset']+hdr['data_size']] = \
            data[hdr['data_offset']:hdr['data_offset']+hdr['data_size']]

    # BSS is already zero-filled
    # Simulate import resolution
    print("\nSimulating import resolution...")
    import_addrs = simulate_import_resolution(imports)
    
    if import_addrs is None:
        print("ERROR: Import resolution failed")
        
        return False

    # Apply relocations
    print("\nApplying relocations...")
    success, errors = apply_relocations(image, hdr, relocs, import_addrs, verbose=verbose)

    if not success:
        print(f"\nERROR: Relocation failed with {len(errors)} errors:")
        
        for err in errors:
            print(f"  {err}")
        
        return False

    # Collect relocated offsets
    relocated_offsets = [r['offset'] for r in relocs]

    # Verify text section
    print("\nVerifying .text section...")
    success, text_errors = verify_text_section(image, hdr, relocated_offsets, verbose=verbose)

    if not success:
        print(f"\nERROR: Text verification failed:")
        
        for err in text_errors:
            print(f"  {err}")
        
        return False

    print("\n" + "=" * 80)
    print("SUCCESS: DEX file passed all checks")
    print(f"  Simulated image base: 0x{SIMULATED_IMAGE_BASE:08x}")
    print(f"  Simulated entry point: 0x{SIMULATED_IMAGE_BASE + hdr['entry_offset']:08x}")
    
    return True

if __name__ == '__main__':
    if len(sys.argv) < 2:
        print(f"Usage: {sys.argv[0]} <dex_file> [-v|--verbose]")
        sys.exit(1)

    filepath = sys.argv[1]
    verbose = '-v' in sys.argv or '--verbose' in sys.argv

    success = verify_dex_with_relocation(filepath, verbose=verbose)
    sys.exit(0 if success else 1)
