set pagination off
file build/kernel.elf
set architecture i386
set disassemble-next-line on
set confirm off
target remote | qemu-system-i386 -display none -m 64M -serial file:serial.log -no-reboot -no-shutdown -d guest_errors,trace:ioport_* -D qemu.log -drive id=disk,file=build/diffos.img,if=ide,format=raw -chardev file,id=dbg,path=/home/zet/os/debugcon.log -device isa-debugcon,iobase=0xe9,chardev=dbg -gdb stdio -S
b system_call_dispatch
continue
