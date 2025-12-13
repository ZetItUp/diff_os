@echo off
setlocal

REM Källa: WSL UNC-path
set SRC=Z:\home\zet\os\build\diffos.img

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

REM Performance options:
REM   -accel whpx      = Windows Hypervisor Platform (requires Hyper-V enabled)
REM   -accel tcg,thread=multi = Multi-threaded TCG (fallback if WHPX unavailable)
REM   -cpu max         = Use best available CPU features

"C:\Program Files\qemu\qemu-system-i386.exe" ^
    -accel tcg,thread=multi ^
    -monitor stdio ^
    -m 64M ^
    -serial file:"C:\temp\serial.log" ^
    -no-reboot ^
    -no-shutdown ^
    -boot c ^
    -hda "%DST%" ^
    -chardev file,id=dbg,path="C:\temp\debugcon.log" ^
    -device isa-debugcon,iobase=0xe9,chardev=dbg ^
    -display sdl,gl=on,show-cursor=off ^
    -vga std

endlocal
