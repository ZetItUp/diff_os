@echo off
setlocal

REM Källa: WSL UNC-path
set SRC=\\wsl.localhost\kali-linux\home\zet\os\build\diffos.img

REM Mål: lokal NTFS-path
set DST=C:\temp\diffos.img

REM Skapa katalog om den saknas
if not exist "C:\temp" (
    mkdir "C:\temp"
)

echo Kopierar %SRC% till %DST% ...
copy /Y "%SRC%" "%DST%"
if errorlevel 1 (
    echo Kopieringen misslyckades. Kan inte lasa diffos.img via WSL-UNC.
    pause
    exit /b 1
)

echo Startar QEMU med snabbare grafik...

"C:\Program Files\qemu\qemu-system-i386.exe" ^
    -monitor stdio ^
    -m 64M ^
    -serial file:"C:\temp\serial.log" ^
    -no-reboot ^
    -no-shutdown ^
    -d guest_errors,trace:ioport_* ^
    -D "C:\temp\qemu.log" ^
    -drive id=disk,file="%DST%",if=ide,format=raw ^
    -chardev file,id=dbg,path="C:\temp\debugcon.log" ^
    -device isa-debugcon,iobase=0xe9,chardev=dbg ^
    -display sdl,gl=on ^
    -vga std

endlocal
