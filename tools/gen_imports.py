#!/usr/bin/env python3
import sys, os, json, subprocess, shlex
from pathlib import Path

USAGE = "usage: gen_imports.py <elf_path> <out_dir> [libmap_json] [default_exl=diffc]"

def load_libmap(p):
    if not p or not os.path.exists(p):
        return {}
    with open(p, "r", encoding="utf-8") as f:
        data = json.load(f)
    # Stöder två format:
    # 1) exl-> [sym,...]
    # 2) sym -> exl
    sym_to_exl = {}
    if all(isinstance(v, list) for v in data.values()):
        # exl->list
        for exl, syms in data.items():
            for s in syms:
                sym_to_exl[str(s)] = exl
    else:
        # antag sym->exl
        for s, exl in data.items():
            sym_to_exl[str(s)] = str(exl)
    return sym_to_exl

def get_undefined_symbols(elf_path):
    # i386-elf-nm -u <elf>
    try:
        res = subprocess.run(
            ["i386-elf-nm", "-u", elf_path],
            check=False, capture_output=True, text=True
        )
        syms = []
        for line in res.stdout.splitlines():
            line = line.strip()
            if not line:
                continue
            # Format brukar vara: "                 U printf" ELLER "U printf"
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
    elf_path   = sys.argv[1]
    out_dir    = sys.argv[2]
    libmap_json= sys.argv[3] if len(sys.argv) >= 4 else None
    default_exl= sys.argv[4] if len(sys.argv) >= 5 else "diffc"

    Path(out_dir).mkdir(parents=True, exist_ok=True)

    syms = get_undefined_symbols(elf_path)
    sym_to_exl_map = load_libmap(libmap_json)

    sym2lib = {}
    for s in syms:
        exl = sym_to_exl_map.get(s, default_exl)
        sym2lib[s] = exl

    libs = sorted(set(sym2lib.values())) if sym2lib else []

    # Skriv artefakter
    with open(os.path.join(out_dir, "undefined.txt"), "w", encoding="utf-8") as f:
        f.write("\n".join(syms) + ("\n" if syms else ""))

    with open(os.path.join(out_dir, "imports_map.txt"), "w", encoding="utf-8") as f:
        if sym2lib:
            f.write("\n".join(f"{k} -> {v}" for k,v in sorted(sym2lib.items())) + "\n")

    with open(os.path.join(out_dir, "libs.txt"), "w", encoding="utf-8") as f:
        if libs:
            f.write("\n".join(libs) + "\n")

    print(f"[INFO] {Path(elf_path).name}: imports={len(syms)} libs={','.join(libs)}")

if __name__ == "__main__":
    main()

