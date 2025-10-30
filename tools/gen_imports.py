#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
gen_imports.py
--------------
Skapar hjälp-artifakter för elf2dex:
- imports_map.txt (lista på importerade symboler per lib)
- libs.txt (biblioteksnamn)
- libmap.json (key->symbol för PC32 CALL/JMP med disp=-4)

Den här versionen är robustare:
- Läser .text-bytes primärt från <builddir>/text.bin (om elfdump skrivit ut den).
- Om text.bin saknas försöker den läsa TEXT_HEX-raden i dump.txt (om sådan finns)
  och skriver då även ut text.bin.
- Klarar också äldre dumpformat (utan TEXT_HEX) men då kan PC32-signaturer utebli.

Användning:
  python3 gen_imports.py <obj_or_superobj> <builddir> <libmap.json> <lib1> [<lib2> ...] [fallback_symbol]
Exempel:
  python3 gen_imports.py build/doom.o build build/libmap.json diffc exit

fallback_symbol (sista argumentet som inte är en lib) används för att fylla i
okända PC32-signaturer. Om den utelämnas används "exit".
"""
import sys, os, json, re, binascii, zlib
from pathlib import Path
from typing import Dict, List, Tuple

# ---------- Hjälpfunktioner ----------
def write_text(p: Path, s: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, 'w', encoding='utf-8') as f:
        f.write(s)

def write_json(p: Path, obj: dict):
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, 'w', encoding='utf-8') as f:
        json.dump(obj, f, indent=2, sort_keys=True)

def read_text(p: Path) -> str:
    with open(p, 'r', encoding='utf-8') as f:
        return f.read()

def crc_key(b: bytes) -> int:
    """Samma nyckel som elf2dex för PC32-ställen: CRC32 över signaturfönster."""
    return zlib.crc32(b) & 0xFFFFFFFF

def find_pc32_sites(text: bytes) -> List[int]:
    """
    Hitta CALL/JMP (-4) ställen.
    matcha:
      E8 FC FF FF FF   (CALL rel32=-4)
      E9 FC FF FF FF   (JMP  rel32=-4)
      0F 8? FC FF FF FF (Jcc rel32=-4) – ovanligt men ta med
    Returnerar listan av byte-offset i .text där OPCODE börjar.
    """
    sites = []
    n = len(text)
    mm = memoryview(text)
    # CALL/JMP
    for i in range(0, n - 5):
        op = mm[i]
        if op in (0xE8, 0xE9) and mm[i+1] == 0xFC and mm[i+2] == 0xFF and mm[i+3] == 0xFF and mm[i+4] == 0xFF:
            sites.append(i)
    # Jcc 0F 8x
    for i in range(0, n - 6):
        if mm[i] == 0x0F and (mm[i+1] & 0xF0) == 0x80:
            if mm[i+2] == 0xFC and mm[i+3] == 0xFF and mm[i+4] == 0xFF and mm[i+5] == 0xFF:
                sites.append(i)
    sites.sort()
    return sites

def signature_at(text: bytes, i: int, before: int = 32, after: int = 0) -> bytes:
    """
    Bygg en signatur för nyckelberäkning.
    Empiriskt har elf2dex använt ett fönster *före* platsen inkl. själva hoppet.
    Vi tar 32 byte före + själva instruktionslängden (5 för E8/E9, 6 för 0F 8x).
    """
    op = text[i]
    instr_len = 5
    if op == 0x0F:  # jcc
        instr_len = 6
    start = max(0, i - before)
    end = min(len(text), i + instr_len)
    return text[start:end]

def load_text_bytes(builddir: Path) -> Tuple[bytes, str]:
    """
    Försök i ordning:
      1) builddir/text.bin (råa bytes)
      2) builddir/dump.txt -> TEXT_HEX ... bytes=<hex>
    Returnerar (bytes, källa).
    """
    tb = builddir / 'text.bin'
    if tb.exists():
        return tb.read_bytes(), 'text.bin'
    dt = builddir / 'dump.txt'
    if dt.exists():
        s = read_text(dt)
        # Förväntat format: en rad som innehåller "TEXT_HEX" och "bytes="
        m = re.search(r'TEXT_HEX[^\n]*bytes=([0-9A-Fa-f]+)', s)
        if m:
            hexstr = m.group(1)
            b = binascii.unhexlify(hexstr)
            # Spara som text.bin för framtida körningar
            with open(tb, 'wb') as f:
                f.write(b)
            return b, 'dump:TEXT_HEX'
    return b'', ''

# ---------- Huvud ----------
def main():
    if len(sys.argv) < 5:
        print("Usage: gen_imports.py <obj/superobj> <builddir> <libmap.json> <lib1> [<lib2> ...] [fallback_symbol]", file=sys.stderr)
        sys.exit(2)

    obj = Path(sys.argv[1])
    builddir = Path(sys.argv[2])
    libmap_path = Path(sys.argv[3])

    # Allt efter tredje argumentet är libs och ev. fallback-symbol.
    args_tail = sys.argv[4:]
    fallback = 'exit'
    libs: List[str] = []
    if args_tail:
        # Om sista token inte ser ut som ett lib-namn (har punkt), låt den vara fallback.
        # Men enklare: om användaren skickar fler än ett lib och sista heter "exit" etc – 
        # vi accepterar alltid sista som fallback om den INTE är namnet på ett vanligt runtime-lib.
        # Lista kända libs? onödigt – vi gör det konfigurerbart:
        libs = args_tail[:-1] or []
        fallback = args_tail[-1]
        # Om användaren *inte* tänkte skicka fallback, och bara hade ett lib, då vill vi
        # tolka allt som libs. Heuristik: om fallback ser ut som lib-namn, lägg tillbaka.
        if '.' in fallback or fallback.endswith(('exl','a','so')):
            libs = args_tail
            fallback = 'exit'
    libs = [l for l in libs if l]  # städa

    # Skriv ut hjälpfiler (för konsistens med tidigare script)
    write_text(builddir / 'libs.txt', '\n'.join(libs) + '\n')
    write_text(builddir / 'imports_map.txt', '')  # kan fyllas av elverktyg senare

    # Ladda tidigare libmap (merge)
    libmap: Dict[str, str] = {}
    if libmap_path.exists():
        try:
            libmap = json.loads(read_text(libmap_path))
        except Exception:
            libmap = {}

    # Läs .text bytes
    text_bytes, source = load_text_bytes(builddir)

    if not text_bytes:
        # Kunde inte läsa bytes: skriv ändå tom libmap (eller behåll befintlig),
        # så att bygget kan gå vidare men elf2dex varnar själv.
        write_json(libmap_path, libmap)
        print("[WARN] kunde inte hitta .text-bytes (varken text.bin eller TEXT_HEX i dump.txt) -> libmap oförändrad")
        print(f"[INFO] libs={libs}, fallback={fallback}")
        return

    # Hitta PC32-call/jmp/jcc med disp=-4
    sites = find_pc32_sites(text_bytes)

    # Bygg nycklar
    new_entries = 0
    for i in sites:
        sig = signature_at(text_bytes, i)
        key = crc_key(sig)
        skey = str(key)
        if skey not in libmap:
            libmap[skey] = fallback
            new_entries += 1

    write_json(libmap_path, libmap)

    print(f"[INFO] .text-källa: {source}")
    print(f"[INFO] hittade PC32-sites: {len(sites)}")
    print(f"[INFO] nya libmap-entries: {new_entries} -> {libmap_path}")
    if new_entries == 0:
        print("[INFO] (inget nytt att lägga till – kan bero på att libmap redan innehåller alla nycklar)")

if __name__ == '__main__':
    main()

