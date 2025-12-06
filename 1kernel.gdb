set logging file log.txt
set logging enabled on
set logging overwrite on
file build/kernel.elf
target remote localhost:1234
