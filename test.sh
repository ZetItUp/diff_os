# Hämta start_sector från FileTable, entry 2:
# (offset = file_table_sector * 512 + 2 * 128 + 0x4C)

IMG=build/diffos.img
FS_START_LBA=2048

# Hämta FileTable LBA:
ft_lba=$(xxd -p -s $((FS_START_LBA*512 + 0x0C)) -l 4 "$IMG" | tac -rs.. | xargs | sed 's/ //g')
ft_lba_dec=$((0x$ft_lba))

# Kernel entry offset:
kernel_entry_offset=$((ft_lba_dec*512 + 2*128))
# Start sector (little-endian):
kernel_sector=$(xxd -p -s $((kernel_entry_offset + 0x4C)) -l 4 "$IMG" | tac -rs.. | xargs | sed 's/ //g')
kernel_sector_dec=$((0x$kernel_sector))

# Skriv ut 1K data där kernel.bin _borde_ börja:
hexdump -C -s $((kernel_sector_dec*512)) -n 1024 "$IMG"

