#!/bin/bash
set -e

# Validate inputs
if [ "$#" -ne 2 ]; then
    echo "Usage: $0 <input_file> <output_file>"
    exit 1
fi

input_file=$1
output_file=$2

if [ ! -f "$input_file" ]; then
    echo "Error: Input file '$input_file' does not exist."
    exit 1
fi

# Validate dependencies
programs=( "python3" "nasm" "x86_64-w64-mingw32-gcc" "sed" "grep" "awk" "dd" )
for program in "${programs[@]}"
do
    if ! command -v "$program" 2>&1 >/dev/null
    then
        echo "$program is required by this script but could not be found"
        exit 1
    fi
done

oworkdir=$(pwd)
sworkdir=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )
workdir=$(mktemp -d)
echo "[+] Working directory: $workdir"
echo "[*] Copying files..."
cp -r $sworkdir/shellcode/* "$workdir/"

# CODASM encode input file
echo "[*] CODASM encoding file..."
python3 $sworkdir/codasm.py -i $input_file -ob "$workdir/codasm_payload.bin" -oc "$workdir/codasm_decoder.h" -op "$workdir/codasm_payload.h" -vbch 0.9 -v

cd $workdir

# Extract & apply stub vars
echo "[*] Extracting stub vars..."
CA_PAYLOAD_LEN=$(grep -oP 'uint32_t CA_PAYLOAD_LEN = \K\d+' codasm_payload.h)
CA_OUTPUT_LEN=$(grep -oP 'uint32_t CA_OUTPUT_LEN = \K\d+' codasm_payload.h)
CA_XORKEY=$(grep -oP 'uint64_t CA_XORKEY = \K0x[0-9A-Fa-f]+' codasm_payload.h)

sed -i -e "s/%CA_PAYLOAD_LEN%/$CA_PAYLOAD_LEN/g" stub.asm
sed -i -e "s/%CA_OUTPUT_LEN%/$CA_OUTPUT_LEN/g" stub.asm
sed -i -e "s/%XOR%/$CA_XORKEY/g" stub.asm

# Compile stub
echo "[*] Compile stub..."
nasm -f win64 stub.asm -o stub.o

# Generate stub hashes
echo "[*] Generate API hashes..."
python3 generate_hashes.py
cat api_resolve.h | grep "#define CRYPT_KEY"

# Compile executable
echo "[*] Compile executable..."
x86_64-w64-mingw32-gcc codasm_stub.c stub.o -o codasm_pic.exe -Os -fno-asynchronous-unwind-tables -nostdlib -fno-ident -fpack-struct=8 -falign-functions=1 -s -ffunction-sections -falign-jumps=1 -w -falign-labels=1 -fPIC -Wl,-s,--no-seh,--enable-stdcall-fixup -masm=intel

# Extract shellcode
echo "[*] Extract shellcode..."

offset=$(objdump -h "codasm_pic.exe" | grep -w '.text' | awk '{print "0x"$6}')
size=$(objdump -h "codasm_pic.exe" | grep -w '.text' | awk '{print "0x"$3}')

offset_dec=$((offset))
size_dec=$((size))

cd $oworkdir
dd if="$workdir/codasm_pic.exe" of="$output_file" bs=1 skip=$offset_dec count=$size_dec

# Cleanup
echo "[*] Cleanup..."
ls -la $workdir
rm -rf $workdir

# Done
echo "[*] Done!"
ent $output_file | grep "Entropy = "
ls -la $output_file