"""CODASM code generator"""

import random
from common import PayloadInstruction, PseudoInstruction, parse_instruction_templates


PLINS, PSINS, STINS, PUSHPOPINS = parse_instruction_templates()


def generate_pl(ins: PayloadInstruction) -> str:
    """Generates a decoder for a given payload instruction template"""

    bytechecks = " && ".join([
        f"buffer_peek(input, {i}) == 0x{x:02X}"
        for i, x in enumerate(ins.opcode_bytes)
    ])
    extractions = "\n    ".join([
        r"""temp = (uint8_t)(buffer_read(input) ^ xorkey_get(key, key_idx));
        LOGF("%02X ", temp);
        buffer_write(output, temp);"""
        for _ in range(ins.payload_length)
    ])
    payload_length = len(ins.bin) - ins.payload_length - ins.payload_offset
    postadvance = f"buffer_advance(input, {payload_length});" \
        if (payload_length) > 0 else ""

    return \
        rf"""    // Payload: {ins.asm} ({' '.join(f"{x:02X}" for x in ins.bin)})
    if (buffer_has(input, {len(ins.bin)}) && buffer_has(output, {ins.payload_length}) && {bytechecks}) {{
        LOGF("[*] PL Offset %08X: {ins.asm} - [ ", input->index);
        buffer_advance(input, {ins.payload_offset});
        {extractions}
        LOG("]\n");
        {postadvance}
        return {ins.payload_length};
    }}"""


def generate_ps(ins: PseudoInstruction) -> str:
    """Generates a decoder for a given pseudo instruction template"""

    bytechecks = " && ".join([
        f"buffer_peek(input, {i}) == 0x{x:02X}" for i, x in enumerate(ins.opcode_bytes)
    ])
    return \
        rf"""    // Pseudo: {ins.asm} ({' '.join(f"{x:02X}" for x in ins.bin)})
    if (buffer_has(input, {len(ins.bin)}) && {bytechecks}) {{
        LOGF("[*] PS Offset %08X: {ins.asm}\n", input->index);
        buffer_advance(input, {len(ins.bin)});
        return 0;
    }}"""


def generate_pp(push: PseudoInstruction, pop: PseudoInstruction) -> str:
    """Generates a decoder for the given push and pop pseudo instruction pair"""

    return f"{generate_ps(push)}\n{generate_ps(pop)}"


def generate_c3() -> str:
    """Generates a decoder for the (hardcoded) C3 pseudo instruction"""

    return \
        r"""    // retn (C3)
    if (buffer_has(input, 1) && buffer_peek(input) == 0xC3) {
        buffer_advance(input, 1);
        return 0;
    }"""


def generate_checks() -> str:
    """Generates decoders for all parsed instruction templates and shuffles them"""

    checks = [generate_pl(i) for i in PLINS] + \
        [generate_ps(i) for i in PSINS] + \
        [generate_ps(i) for i in STINS] + \
        [generate_pp(push, pop) for push, pop in PUSHPOPINS]

    random.shuffle(checks)

    return "\n".join(checks)
