#!/bin/python3
"""CODASM entrypoint
Encodes arbitrary data into C code which will be mapped to the .text section when compiled.
The encoded data mimics real x64_86 assembly."""

from typing import Tuple
import argparse
import datetime
import logging
import os
import pathlib
import random
import sys
import generator

from common import PayloadInstruction, Result, XorKey, parse_instruction_templates
from entropy import shannon_entropy

INTRO = r"""
    ░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓███████▓▒░ ░▒▓██████▓▒░ ░▒▓███████▓▒░▒▓██████████████▓▒░  
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓████████▓▒░░▒▓██████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░      ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░      ░▒▓█▓▒░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
    ░▒▓██████▓▒░  ░▒▓██████▓▒░░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░▒▓███████▓▒░░▒▓█▓▒░░▒▓█▓▒░░▒▓█▓▒░ 
                                                                                       
"""

logging.basicConfig()
LOGGER = logging.getLogger("CODASM")

LOGGER.debug("Loading JSON instruction definitions")

VAL_NUM_BYTES_MIN = 64
VAL_NUM_BYTES_MAX = 256
VAL_ENC_CHANCE = 0.1

PLINS, PSINS, _, PUSHPOPINS = parse_instruction_templates()
INS = PLINS + PSINS


def generate_method(payload: bytes, xorkey: XorKey) -> Result:
    """Takes a random number of bytes of the payload and converts it into a pseudo-ASM method"""

    stacksize = random.randint(1, 10) * 8
    res = Result("", b'', payload)
    numbytes = min(len(payload), random.randint(
        VAL_NUM_BYTES_MIN, VAL_NUM_BYTES_MAX))
    processed = numbytes

    LOGGER.debug(
        "Generating method: %s stacksize, hosting %s bytes of payload", stacksize, numbytes)

    # Store stack pointer
    res.update_pseudo(f"push rbp ; Encoding {numbytes} bytes", "55")
    # Move former stack pointer to stack bottom pointer
    res.update_pseudo("mov rbp,rsp", "48 89 e5")
    # Move stack pointer to make space for locals
    res.update_pseudo(f"sub RSP, 0x{stacksize:02X}",
                      f"48 83 EC {stacksize:02X}")

    while numbytes > 0:
        if random.random() > VAL_ENC_CHANCE:
            res.update(random.choice(PSINS).generate(res.payload, xorkey))
        else:
            _ins: PayloadInstruction = random.choice([
                i for i in PLINS if i.payload_length <= numbytes
            ])
            res.update(_ins.generate(res.payload, xorkey))
            numbytes -= _ins.payload_length

    # Restore stack pointer
    res.update_pseudo(f"add RSP, 0x{stacksize:02X}",
                      f"48 83 C4 {stacksize:02X}")

    # Append retn
    res.update_pseudo("retn", "C3")

    # Append CCs
    for _ in range(len(res.bin) % 8):
        res.update_pseudo("; Padding", "CC")

    LOGGER.debug("Generated %i ASM chars/%s bytes (%.2f%%)",
                 len(res.asm), len(res.bin), (len(res.bin)/processed * 100))

    return res


def read_input(file: str) -> Tuple[Result, int]:
    """Reads a binary input file and returns a Result instance and the content's length"""

    with open(file, "rb") as inputfile:
        res = Result("", b'', inputfile.read())
        payload_len = len(res.payload)
    return res, payload_len


def output_decoder(out_c: str):
    """Generates the decoder C-code and writes it to the specified path"""

    LOGGER.info("Writing C code to %s", out_c)
    sourcepath = os.path.join(pathlib.Path(
        os.path.abspath(__file__)).parent.absolute(), "decode.h")
    with open(sourcepath, "r", encoding='utf-8') as cin:
        with open(out_c, "w", encoding='utf-8') as cout:
            cout.write(
                cin.read()
                .replace("// %GENERATED%", generator.generate_checks())
            )


def output_payload(out_p: str, out_c: str, res: Result, xor_key: XorKey, payload_len: int):
    """Writes the encoded payload (pseudo-ASM) to the specified path"""

    LOGGER.info("Writing embedded payload to %s", out_p)

    def gethexline(i):
        return ', '.join(f'0x{x:02X}' for x in res.bin[i:i+12])

    with open(out_p, "w", encoding='utf-8') as outfile:
        payload_hex = ",\n\t".join(
            gethexline(i) for i in range(0, len(res.bin), 12)
        )
        outfile.write(rf"""#ifndef CODASM_PAYLOAD
#define CODASM_PAYLOAD
#include <stdlib.h>
#include "{out_c}"

INTEXT uint8_t CA_PAYLOAD[{len(res.bin)}] = {{
    {payload_hex}
}};

uint32_t CA_PAYLOAD_LEN = {len(res.bin)};
uint32_t CA_OUTPUT_LEN = {payload_len};
uint64_t CA_XORKEY = 0x{''.join(f"{x:02X}" for x in reversed(xor_key.bin))};

#endif // CODASM_PAYLOAD

/* Generated using CODASM at {datetime.datetime.now().isoformat()}
Sample usage:
int main() {{
    uint8_t* output = (uint8_t*)malloc(CA_OUTPUT_LEN);
    int32_t res = 0;
    if ((res = decode((uint8_t*)CA_PAYLOAD, CA_PAYLOAD_LEN, output, CA_OUTPUT_LEN, CA_XORKEY)) < 0)
        return 1; // Some doo-doo happened, breakpoint the decode method

    if (res == 0x42) // Add de-facto defunct call to encoded blob so bin-rev software follows this path and attempts to disassemble
        ((void (*)(int))CA_PAYLOAD)(0x22);

    // You successfully recovered the payload, do something fun with it here :)
    return 0;
}}*/""")


def output_asm(args, res, xor_key):
    """Writes the generated pseudo-ASM code to the specified path"""

    LOGGER.info(
        "Writing ASM to %s; XOR key: %s",
        args.out_asm,
        ' '.join(f'{x:02X}' for x in xor_key.bin))

    with open(args.out_asm, "w", encoding='utf-8') as outasm:
        outasm.write(res.asm)


def output_bin(args, res, xor_key):
    """Writes the binary representation of the generated pseudo-ASM to the specified path"""

    LOGGER.info(
        "Writing bytes to %s; XOR key: %s", args.out_bin, ' '.join(f'{x:02X}' for x in xor_key.bin))

    with open(args.out_bin, "wb") as outbin:
        outbin.write(res.bin)


def main():
    """Entrypoint"""

    print(INTRO)

    global VAL_NUM_BYTES_MIN
    global VAL_NUM_BYTES_MAX
    global VAL_ENC_CHANCE

    parser = argparse.ArgumentParser(description="CODASM encoding utility",
                                     epilog="Note: ASM output is meant to be used for manual reference only.")

    parser.add_argument("-i", "--input", required=True,
                        help="Path to the input file to encode as ASM/binary instructions")

    parser.add_argument("-oa", "--out-asm", required=False,
                        help="Path to write the generated ASM instructions to")
    parser.add_argument("-ob", "--out-bin", required=False,
                        help="Path to write the generated binary instructions to")
    parser.add_argument("-oc", "--out-c", default="codasm_decoder.h",
                        help="Path to write the generated CODASM decoder to")
    parser.add_argument("-op", "--out-p", default="codasm_payload.h",
                        help="Path to write the embedded payload to")
    parser.add_argument("--rng", default=None, type=int, required=False,
                        help="Seed for randomization (xor-key, order of payload instructions, order of decoding operations)")
    parser.add_argument("-vbmin", "--val-bytes-min", default=VAL_NUM_BYTES_MIN,
                        type=int, help=f"Minimum number of bytes to encode into a single method (default {VAL_NUM_BYTES_MIN})")
    parser.add_argument("-vbmax", "--val-bytes-max", default=VAL_NUM_BYTES_MAX,
                        type=int, help=f"Maximum number of bytes to encode into a single method (default {VAL_NUM_BYTES_MAX})")
    parser.add_argument("-vbch", "--val-bytes-chance", default=VAL_ENC_CHANCE,
                        type=float, help=f"Chance for an operation to become encode data rather than becoming a dummy (0.1-0.9, default {VAL_ENC_CHANCE})")
    parser.add_argument("-v", "--verbose", default=0,
                        action="count", help="Level of output verbosity (0-3, default 0)")

    args = parser.parse_args(sys.argv[1:])

    VAL_NUM_BYTES_MIN = min(args.val_bytes_min, args.val_bytes_max)
    VAL_NUM_BYTES_MAX = max(args.val_bytes_min, args.val_bytes_max)
    VAL_ENC_CHANCE = max(0.1, min(0.9, float(args.val_bytes_chance)))

    if args.rng is not None:
        random.seed(args.rng)
    else:
        _seed = int(datetime.datetime.now().timestamp())
        LOGGER.debug("Initialized RNG seed to %s", _seed)

    LOGGER.setLevel(
        {0: logging.ERROR, 1: logging.INFO}.get(args.verbose, logging.DEBUG)
    )

    if not args.out_c or not args.out_p:
        parser.error("Missing required options -oc/--out-c or -op/--out-p")

    LOGGER.debug("Processing arguments non-interactively")
    res, payload_len = read_input(args.input)
    ent_start = shannon_entropy(res.payload)
    xor_key = XorKey(bytes(random.randint(1, 255) for _ in range(8)))

    while len(res.payload) > 0:
        res.update(generate_method(res.payload, xor_key))

    ent_end = shannon_entropy(res.bin)

    LOGGER.info("Encoded %i bytes of payload into %i bytes of ASM instructions (%.2f%%), entropy: %f => %f (%f%%)",
                payload_len, len(res.bin), len(res.bin) / payload_len * 100, round(ent_start, 2), round(ent_end, 2), round(ent_end/ent_start*100, 2))

    if args.out_asm:
        output_asm(args, res, xor_key)
    if args.out_bin:
        output_bin(args, res, xor_key)

    output_decoder(args.out_c)
    output_payload(args.out_p, args.out_c, res, xor_key, payload_len)

    LOGGER.info("Done!")


if __name__ == '__main__':
    try:
        main()
    except Exception as exception:
        LOGGER.exception(exception, exc_info=True)
        
