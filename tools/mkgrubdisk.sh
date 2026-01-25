#!/bin/bash
# mkgrubdisk.sh - Create a GRUB-bootable disk image with Diff filesystem
#
# Layout:
# - Sector 0: MBR with GRUB boot.img (first stage)
# - Sectors 1-63: GRUB core.img (second stage)
# - Sectors 64-2047: kernel.elf (loaded by GRUB)
# - Sector 2048+: Diff filesystem (accessed by kernel via ATA)
#
# Usage: ./mkgrubdisk.sh <output.img> <size_mb> <kernel.elf>

set -e

if [ $# -ne 3 ]; then
    echo "Usage: $0 <output.img> <size_mb> <kernel.elf>"
    exit 1
fi

OUTPUT="$1"
SIZE_MB="$2"
KERNEL="$3"

# Configuration
KERNEL_START_SECTOR=512     # Where kernel.elf is stored (256KB offset, after GRUB core.img)
FS_START_SECTOR=16384       # Where Diff filesystem starts (8MB offset)
SECTOR_SIZE=512

# Calculate total sectors
TOTAL_SECTORS=$((SIZE_MB * 1024 * 1024 / SECTOR_SIZE))

# Check kernel size fits in the gap
KERNEL_SIZE=$(stat -c %s "$KERNEL")
KERNEL_SECTORS=$(( (KERNEL_SIZE + SECTOR_SIZE - 1) / SECTOR_SIZE ))
MAX_KERNEL_SECTORS=$((FS_START_SECTOR - KERNEL_START_SECTOR))

if [ $KERNEL_SECTORS -gt $MAX_KERNEL_SECTORS ]; then
    echo "ERROR: kernel.elf ($KERNEL_SECTORS sectors) too large for boot gap ($MAX_KERNEL_SECTORS sectors)"
    exit 1
fi

echo "[GRUBDISK] Creating ${SIZE_MB}MB disk image: $OUTPUT"
echo "[GRUBDISK] Kernel: $KERNEL ($KERNEL_SIZE bytes, $KERNEL_SECTORS sectors)"

# Create empty disk image
dd if=/dev/zero of="$OUTPUT" bs=512 count=$TOTAL_SECTORS status=none

# Create MBR partition table
# Single partition for Diff filesystem starting at sector 2048
cat > /tmp/partitions.txt << EOF
label: dos
unit: sectors

start=$FS_START_SECTOR, size=$((TOTAL_SECTORS - FS_START_SECTOR)), type=c8, bootable
EOF

sfdisk --no-reread "$OUTPUT" < /tmp/partitions.txt 2>/dev/null || true
rm /tmp/partitions.txt

echo "[GRUBDISK] Partition table created"

# Write kernel.elf to sectors 64+
dd if="$KERNEL" of="$OUTPUT" bs=512 seek=$KERNEL_START_SECTOR conv=notrunc status=none
echo "[GRUBDISK] Kernel written at sector $KERNEL_START_SECTOR"

# Create GRUB embedded config that loads kernel from disk sectors
# Using blocklist syntax: (hd0)sector+count
cat > /tmp/grub_embed.cfg << EOF
set root=(hd0)
set timeout=0

multiboot (hd0)${KERNEL_START_SECTOR}+${KERNEL_SECTORS}
boot
EOF

echo "[GRUBDISK] Creating GRUB core.img..."

# Create GRUB core.img with embedded config and required modules
GRUB_CORE="/tmp/core.img"

grub-mkimage -O i386-pc -o "$GRUB_CORE" \
    -c /tmp/grub_embed.cfg \
    -p "(hd0)" \
    biosdisk part_msdos multiboot boot

rm /tmp/grub_embed.cfg

CORE_SIZE=$(stat -c %s "$GRUB_CORE")
echo "[GRUBDISK] core.img size: $CORE_SIZE bytes"

# Check core.img fits before kernel area
CORE_SECTORS=$(( (CORE_SIZE + SECTOR_SIZE - 1) / SECTOR_SIZE ))
if [ $CORE_SECTORS -gt $((KERNEL_START_SECTOR - 1)) ]; then
    echo "ERROR: GRUB core.img too large ($CORE_SECTORS sectors)"
    rm "$GRUB_CORE"
    exit 1
fi

# Get GRUB boot.img (MBR bootstrap)
GRUB_BOOT="/usr/lib/grub/i386-pc/boot.img"

if [ ! -f "$GRUB_BOOT" ]; then
    echo "ERROR: GRUB boot.img not found at $GRUB_BOOT"
    rm "$GRUB_CORE"
    exit 1
fi

# Write boot.img to MBR (first 440 bytes only, preserve partition table area)
dd if="$GRUB_BOOT" of="$OUTPUT" bs=440 count=1 conv=notrunc status=none

# Write core.img starting at sector 1
dd if="$GRUB_CORE" of="$OUTPUT" bs=512 seek=1 conv=notrunc status=none

rm "$GRUB_CORE"

echo "[GRUBDISK] GRUB installed"
echo "[GRUBDISK] Layout:"
echo "  Sector 0:    MBR (GRUB boot)"
echo "  Sectors 1-$((KERNEL_START_SECTOR-1)):  GRUB core.img"
echo "  Sectors $KERNEL_START_SECTOR-$((KERNEL_START_SECTOR + KERNEL_SECTORS - 1)): kernel.elf"
echo "  Sectors $FS_START_SECTOR+: Diff filesystem"
echo "[GRUBDISK] Done: $OUTPUT"
