#!/bin/bash

DRIVERS_DIR="../drivers/obj"
TOOLS_DIR="../tools"

patch_file()
{
    local elf="$1"
    echo "Processing: $(basename "$elf")"

    # Get offsets without spaces
    local init_off
    init_off=$(nm -n "$elf" | awk '/ ddf_driver_init$/ {printf "0x%08x", strtonum("0x"$1); exit}')

    local exit_off
    exit_off=$(nm -n "$elf" | awk '/ ddf_driver_exit$/ {printf "0x%08x", strtonum("0x"$1); exit}')

    local irq_off
    irq_off=$(nm -n "$elf" | awk '/ ddf_driver_irq$/ {printf "0x%08x", strtonum("0x"$1); exit}')

    local symtab_off
    symtab_off=$(nm -n "$elf" | awk '/ ddf_symbol_table$/ {printf "0x%08x", strtonum("0x"$1); exit}')

    # Make sure we have at least init, exit and irq offsets
    if [[ -z "$init_off" || -z "$exit_off" || -z "$irq_off" ]]
    then
        echo "ERROR: Missing critical symbols in $(basename "$elf")"

        return 1
    fi

    # Count symbols
    local sym_count=0
    local nm_file="${elf%.ddf.elf}_nosym.nm.txt"

    if [[ -f "$nm_file" ]]
    then
        sym_count=$(grep -c '^[0-9a-fA-F]' "$nm_file")
    fi

    if [[ -z "$symtab_off" ]]
    then
        symtab_off="0x00000000"
    fi

    echo "Offsets:"
    echo "  init:    $init_off"
    echo "  exit:    $exit_off"
    echo "  irq:     $irq_off"
    echo "  symtab:  $symtab_off"
    echo "  count:   $sym_count"

    # Patch the DDF file
    python3 "$TOOLS_DIR/patch_ddf.py" "$elf" "$init_off" "$exit_off" "$irq_off" "$symtab_off" "$sym_count"
    if [[ $? -ne 0 ]]
    then
        echo "ERROR: Patching failed for $(basename "$elf")"

        return 1
    fi
}

for elf in "$DRIVERS_DIR"/*.ddf.elf
do
    if [[ "$elf" != *_nosym.ddf.elf ]]
    then
        patch_file "$elf"
    else
        echo "Skipping nosym file: $(basename "$elf")"
    fi
done

