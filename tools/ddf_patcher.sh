#!/usr/bin/env bash
set -euo pipefail

# In-/ut-kataloger (kan override: bash tools/ddf_patcher.sh obj ../image/system/drivers)
IN_DIR="${1:-obj}"
OUT_DIR="${2:-../image/system/drivers}"

mkdir -p "$OUT_DIR"

shopt -s nullglob

for elf in "$IN_DIR"/*.ddf.elf; do
    # Skippa *_nosym.ddf.elf om du genererar sådana
    if [[ "$elf" == *"_nosym.ddf.elf" ]]; then
        echo "Skipping nosym file: $(basename "$elf")"
        continue
    fi

    base="$(basename "$elf" .ddf.elf)"
    out="$OUT_DIR/$base.ddf"

    echo "Processing: $(basename "$elf")"

    # Valfri utskrift (lämna kvar om du vill se offsets före patch):
    if command -v readelf >/dev/null 2>&1; then
        init_off=$(readelf -sW "$elf" | awk '/ ddf_driver_init$/{print $2}' | head -n1)
        exit_off=$(readelf -sW "$elf" | awk '/ ddf_driver_exit$/{print $2}' | head -n1)
        irq_off=$(readelf -sW "$elf"  | awk '/ ddf_driver_irq$/{print  $2}' | head -n1)
        symcnt=$(readelf -S "$elf" | awk '/\.ddf_symtab/{print $6}' | head -n1)
        printf "Offsets:\n  init:    0x%08s\n  exit:    0x%08s\n  irq:     0x%08s\n  symtab:  %s\n" \
            "${init_off:-0}" "${exit_off:-0}" "${irq_off:-0}" "${symcnt:-0}"
    fi

    # KÖR PATCHERN KORREKT: in-ELF och ut-DDF
    if ! python3 ../tools/patch_ddf.py "$elf" "$out"; then
        echo "ERROR: Patching failed for $(basename "$elf")"
        exit 1
    fi
done

echo "[DRIVERS] Patch complete -> $OUT_DIR"

