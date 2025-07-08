all:
	nasm -f bin boot/boot.asm -o boot.bin
	nasm -f bin kernel/arch/x86_64/cpu/pmode.asm -o pmode.bin
	cat boot.bin pmode.bin > os.img
	qemu-system-i386 -fda os.img

