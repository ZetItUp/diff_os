#!/usr/bin/env python3
"""
rsbuild.py - Generate a compact resource blob (.rsbin) from a .rs description.

Usage:
    python3 rsbuild.py <path_to_program_dir>

Behavior:
    - Looks for <dir>/<basename>.rs (basename is the directory name).
    - If not found, falls back to programs/default.rs.
    - Performs placeholder substitution:
        $APP_TITLE, $WINDOW_TITLE -> directory basename
        $APP_VERSION_MAJOR -> 1 (default)
        $APP_VERSION_MINOR -> 0 (default)
        $APP_ICON_NAME    -> directory basename
        $APP_ICON_DATA    -> empty string by default
        $STRING_KEY       -> empty string
        $STRING_VALUE     -> empty string
    - STRING entries are optional; if present, they are included.
    - Emits <dir>/<basename>.rsbin with a simple header + entry table +
      string table + data blob.
    - Prints debug output for everything parsed.
"""

import hashlib
import os
import struct
import sys
from typing import Dict, List, Tuple


MAGIC = 0x53525845  # 'DEXRS' truncated to 4 bytes (EXRS little-endian)
VERSION = 1

TYPE_STRING = 1
TYPE_U32 = 2
TYPE_BLOB = 3


def fnv1a_32(s: str) -> int:
    h = 0x811C9DC5
    for b in s.encode("utf-8"):
        h ^= b
        h = (h * 0x01000193) & 0xFFFFFFFF
    return h


class Entry:
    def __init__(self, name: str, etype: int, data: bytes):
        self.name = name
        self.etype = etype
        self.data = data
        self.name_off = 0
        self.data_off = 0


def load_rs_file(dir_path: str, fallback: str) -> Tuple[str, str]:
    base = os.path.basename(os.path.abspath(dir_path))
    candidate = os.path.join(dir_path, f"{base}.rs")
    if os.path.isfile(candidate):
        return candidate, base
    return fallback, base


def substitute(value: str, base: str) -> str:
    replacements = {
        "$APP_TITLE": base,
        "$WINDOW_TITLE": base,
        "$APP_VERSION_MAJOR": "1",
        "$APP_VERSION_MINOR": "0",
        "$APP_ICON_NAME": base,
        "$APP_ICON_DATA": "",
        "$STRING_KEY": "",
        "$STRING_VALUE": "",
    }
    out = value
    for k, v in replacements.items():
        out = out.replace(k, v)
    return out


def parse_rs(lines: List[str], base: str) -> List[Entry]:
    entries: List[Entry] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or line.startswith(";"):
            continue

        parts = line.split()
        if len(parts) < 2:
            continue

        key = parts[0]
        rest = " ".join(parts[1:])
        rest = substitute(rest, base)
        tokens = rest.split()

        if key == "APPLICATION_TITLE":
            entries.append(Entry(key, TYPE_STRING, rest.encode("utf-8")))
        elif key == "WINDOW_TITLE":
            entries.append(Entry(key, TYPE_STRING, rest.encode("utf-8")))
        elif key == "APPLICATION_VERSION_MAJOR":
            try:
                val = int(rest, 0)
            except ValueError:
                val = 1
            entries.append(Entry(key, TYPE_U32, struct.pack("<I", val)))
        elif key == "APPLICATION_VERSION_MINOR":
            try:
                val = int(rest, 0)
            except ValueError:
                val = 0
            entries.append(Entry(key, TYPE_U32, struct.pack("<I", val)))
        elif key == "APPLICATION_ICON":
            icon_name = tokens[0] if tokens else ""
            icon_data = " ".join(tokens[1:]) if len(tokens) > 1 else ""
            blob = struct.pack("<H", len(icon_name)) + icon_name.encode("utf-8") + icon_data.encode("utf-8")
            entries.append(Entry(key, TYPE_BLOB, blob))
        elif key == "STRING":
            if len(tokens) >= 1:
                var_name = tokens[0]
                value = " ".join(tokens[1:]) if len(tokens) > 1 else ""
                entries.append(Entry(var_name, TYPE_STRING, value.encode("utf-8")))
        else:
            # Unknown keys treated as string data
            entries.append(Entry(key, TYPE_STRING, rest.encode("utf-8")))

    return entries


def build_blob(entries: List[Entry]) -> Tuple[bytes, int, int, int]:
    # String table
    strtab: Dict[str, int] = {}
    strbuf = bytearray()
    for e in entries:
        if e.name not in strtab:
            off = len(strbuf)
            strbuf += e.name.encode("utf-8") + b"\x00"
            strtab[e.name] = off
        e.name_off = strtab[e.name]

    # Data block
    data = bytearray()
    for e in entries:
        e.data_off = len(data)
        data += e.data

    # Header fields
    entry_count = len(entries)
    strtab_off = 0  # immediately after header+table
    entry_size = 5 * 4  # name_hash, type, name_off, data_off, data_size
    header_size = 6 * 4  # magic, version, count, strtab_off, strtab_size, data_off
    table_size = entry_count * entry_size
    strtab_off = header_size + table_size
    # Align string table to 4 bytes
    strtab_pad = (4 - (strtab_off % 4)) % 4
    strtab_off += strtab_pad
    strtab_size = len(strbuf)
    data_off = strtab_off + strtab_size
    data_pad = (4 - (data_off % 4)) % 4
    data_off += data_pad

    buf = bytearray()
    buf += struct.pack("<I", MAGIC)
    buf += struct.pack("<I", VERSION)
    buf += struct.pack("<I", entry_count)
    buf += struct.pack("<I", strtab_off)
    buf += struct.pack("<I", strtab_size)
    buf += struct.pack("<I", data_off)

    # Entry table
    for e in entries:
        buf += struct.pack("<I", fnv1a_32(e.name))
        buf += struct.pack("<I", e.etype)
        buf += struct.pack("<I", e.name_off + strtab_off)
        buf += struct.pack("<I", e.data_off + data_off)
        buf += struct.pack("<I", len(e.data))

    # Pad to string table start
    buf += b"\x00" * strtab_pad
    buf += strbuf
    buf += b"\x00" * data_pad
    buf += data

    return bytes(buf), strtab_off, strtab_size, data_off


def debug_dump(entries: List[Entry], blob: bytes, out_path: str, strtab_off: int, strtab_size: int, data_off: int):
    print(f"[RSBUILD] wrote {out_path} ({len(blob)} bytes)")
    print(f"[RSBUILD] header: magic=0x{MAGIC:08x} ver={VERSION} entries={len(entries)} strtab_off={strtab_off} strtab_sz={strtab_size} data_off={data_off}")
    print(f"[RSBUILD] entries: {len(entries)}")
    for e in entries:
        # Show value preview for convenience (truncate long blobs)
        if e.etype == TYPE_STRING:
            val = e.data.decode('utf-8', errors='replace')
            preview = f"'{val}'"
        elif e.etype == TYPE_U32:
            val = struct.unpack('<I', e.data)[0]
            preview = f"{val}"
        else:
            # For blobs, show a short hex preview
            hex_preview = e.data[:16].hex()
            preview = f"blob[{len(e.data)}] 0x{hex_preview}" + ("..." if len(e.data) > 16 else "")
        print(f"  - name='{e.name}' type={e.etype} size={len(e.data)} value={preview}")


def main():
    if len(sys.argv) != 2:
        print("Usage: rsbuild.py <program_dir>")
        sys.exit(1)

    dir_path = os.path.abspath(sys.argv[1])
    if not os.path.isdir(dir_path):
        print(f"Error: {dir_path} is not a directory")
        sys.exit(1)

    fallback = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "programs", "default.rs"))
    rs_file, base = load_rs_file(dir_path, fallback)

    with open(rs_file, "r", encoding="utf-8") as f:
        lines = f.readlines()

    entries = parse_rs(lines, base)
    blob, strtab_off, strtab_size, data_off = build_blob(entries)

    out_path = os.path.join(dir_path, f"{base}.rsbin")
    with open(out_path, "wb") as f:
        f.write(blob)

    debug_dump(entries, blob, out_path, strtab_off, strtab_size, data_off)


if __name__ == "__main__":
    main()
