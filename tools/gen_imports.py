#!/usr/bin/env python3
import sys
import os
import json
import subprocess
import struct
from pathlib import Path

USAGE = "Usage: gen_imports.py <elf_path> <out_dir> [libmap_json] [default_exl=diffc.exl]"

DEX_MAGIC = 0x58454400  # "DEX\0"
HDR_SIZE = 0x100

def u32(buf, off):
    return struct.unpack_from("<I", buf, off)[0]

def cstr_at(buf, off):
    if off >= len(buf):
        return ""

    end = buf.find(b"\x00", off)
    
    if end < 0:
        end = len(buf)
    
    return buf[off:end].decode("utf-8", errors="replace")

def read_exl_exports(exl_path):
    """Read exported symbols from an EXL file"""
    try:
        with open(exl_path, "rb") as f:
            hdr = f.read(HDR_SIZE)
            
            if len(hdr) != HDR_SIZE or u32(hdr, 0x00) != DEX_MAGIC:
                return []

            # Read strtab
            strtab_off = u32(hdr, 0x44)
            strtab_len = u32(hdr, 0x48)
            
            if strtab_off == 0 or strtab_len == 0:
                return []

            f.seek(strtab_off)
            strtab = f.read(strtab_len)

            # Read symbol table
            sym_off = u32(hdr, 0x3C)
            sym_cnt = u32(hdr, 0x40)
            
            if sym_off == 0 or sym_cnt == 0:
                return []

            f.seek(sym_off)
            symbols = []
            
            for i in range(sym_cnt):
                raw = f.read(12)
                
                if len(raw) != 12:
                    break
                
                name_off, val_off, typ = struct.unpack("<III", raw)
                name = cstr_at(strtab, name_off)
                
                if name:
                    symbols.append(name)

            return symbols
    except Exception:
        return []

def scan_exl_directory(exl_dir):
    """Scan directory for .exl files and build symbol -> exl mapping"""
    sym_to_exl = {}

    if not os.path.isdir(exl_dir):
        return sym_to_exl

    for filename in os.listdir(exl_dir):
        if not filename.endswith(".exl"):
            continue

        exl_path = os.path.join(exl_dir, filename)
        symbols = read_exl_exports(exl_path)

        for sym in symbols:
            # Don't overwrite if already mapped
            if sym not in sym_to_exl:
                sym_to_exl[sym] = filename

    return sym_to_exl

def normalize_exl(name):
    if not name:
        return "diffc.exl"
    
    name = str(name).strip()
    
    if not name.endswith(".exl"):
        name += ".exl"
    
    return name

def load_libmap(path):
    if not path or not os.path.exists(path):
        return {}
    
    with open(path, "r", encoding="utf-8") as f:
        data = json.load(f)
    
    sym_to_exl = {}
    
    if all(isinstance(v, list) for v in data.values()):
        for exl, syms in data.items():
            for s in syms:
                sym_to_exl[str(s)] = normalize_exl(exl)
    else:
        for s, exl in data.items():
            sym_to_exl[str(s)] = normalize_exl(exl)
    
    return sym_to_exl

def get_undefined_symbols(elf_path):
    try:
        res = subprocess.run(
            ["i386-elf-nm", "-u", elf_path],
            check=False,
            capture_output=True,
            text=True
        )
        
        syms = []
        
        for line in res.stdout.splitlines():
            line = line.strip()
            
            if not line:
                continue
            
            parts = line.split()
            sym = parts[-1]
            syms.append(sym)
        
        return sorted(set(syms))
    except FileNotFoundError:
        print("error: i386-elf-nm not found in PATH", file=sys.stderr)
        
        return []

def main():
    if len(sys.argv) < 3:
        print(USAGE, file=sys.stderr)
        sys.exit(2)

    elf_path = sys.argv[1]
    out_dir = sys.argv[2]
    libmap_json = sys.argv[3] if len(sys.argv) >= 4 else None
    default_exl = sys.argv[4] if len(sys.argv) >= 5 else "diffc.exl"

    Path(out_dir).mkdir(parents=True, exist_ok=True)

    syms = get_undefined_symbols(elf_path)

    # Auto-discover symbols from .exl files in image/system/exls/
    script_dir = Path(__file__).parent
    exl_dir = script_dir.parent / "image" / "system" / "exls"
    auto_map = scan_exl_directory(str(exl_dir))

    # Load static libmap.json (lower priority)
    static_map = load_libmap(libmap_json)

    # Merge: auto-discovered symbols take priority over static map
    sym_to_exl_map = {**static_map, **auto_map}

    sym2lib = {}
    default_exl = normalize_exl(default_exl)

    for s in syms:
        exl = normalize_exl(sym_to_exl_map.get(s, default_exl))
        sym2lib[s] = exl

    libs = sorted(set(sym2lib.values())) if sym2lib else []

    with open(os.path.join(out_dir, "undefined.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(syms) + ("\n" if syms else ""))

    with open(os.path.join(out_dir, "imports_map.txt"), "w", encoding="utf-8") as f:
        if sym2lib:
            f.write("\n".join(f"{k} -> {v}" for k, v in sorted(sym2lib.items())) + "\n")

    with open(os.path.join(out_dir, "libs.txt"), "w", encoding="utf-8") as f:
        if libs:
            f.write("\n".join(libs) + "\n")

    print(f"[INFO] {Path(elf_path).name}: imports={len(syms)} libs={','.join(libs)}")

if __name__ == "__main__":
    main()
