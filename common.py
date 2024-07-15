"""Classes and methods used by multiple modules"""

from dataclasses import dataclass
import json
import os
import pathlib
import random
import struct
from typing import List, Tuple


@dataclass
class XorKey:
    """Convenience class to hold and manage an XOR key"""

    bin: bytes
    index: int = 0

    def encrypt(self, data: bytes) -> bytes:
        """Encrypts the given blob using this XOR key. Advances the key's index."""

        res = bytes([
            (x ^ self.bin[(self.index + i) % len(self.bin)]) & 0xFF
            for i, x in enumerate(data)
        ])
        self.index += len(data)
        return res

    def copy(self) -> 'XorKey':
        """Copy this key's data into a new XOR key instance"""
        return XorKey(self.bin, self.index)


@dataclass
class Result:
    """Class to hold generated pseudo-ASM, raw and encoded payloads"""

    asm: str  # Pseudo-ASM
    bin: bytes  # Encoded payload
    payload: bytes  # Raw payload

    def update(self, other: 'Result'):
        """Appends another Result's data to this instance"""

        self.asm = self.asm.strip() + "\n" + other.asm.strip()
        self.bin = self.bin + other.bin
        self.payload = other.payload  # Keep the same payload

    def update_pseudo(self, _asm: str, _bin: str):
        """Append new data to the pseudo-ASM and encoded payload"""

        self.asm = self.asm.strip() + "\n" + _asm.strip()
        self.bin = self.bin + bytes([int(hx, 16) for hx in _bin.split(" ")])


class Instruction:
    """Generic base class representing ASM instructions"""

    @property
    def can_process(self) -> bool:
        raise NotImplementedError

    @property
    def encoding_length(self) -> int:
        raise NotImplementedError

    @property
    def opcode_bytes(self) -> bytes:
        raise NotImplementedError

    def generate(self, payload: bytes, xorkey: XorKey) -> Result:
        raise NotImplementedError

    def as_dict(self) -> dict:
        raise NotImplementedError


@dataclass
class PayloadInstruction(Instruction):
    """Class representing ASM instructions that may encode actual payload"""
    asm: str
    bin: bytes
    payload_offset: int
    payload_length: int
    rnd_offset: int = None
    rnd_length: int = None

    @property
    def can_process(self) -> bool:
        return True

    @property
    def encoding_length(self) -> int:
        return len(self.bin)

    @property
    def opcode_bytes(self) -> bytes:
        offset = self.rnd_offset \
            if self.rnd_offset is not None \
            else len(self.bin)

        return bytes(self.bin[:min(self.payload_offset, offset)])

    def as_dict(self) -> dict:
        return {
            "asm": self.asm,
            "bin": ' '.join(f"{x:02X}" for x in self.bin),
            "payload_offset": self.payload_offset,
            "payload_length": self.payload_length,
            "rnd_offset": self.rnd_offset,
            "rnd_length": self.rnd_length
        }

    def _get_asm(self, payload: bytes, rnd: int, xorkey: XorKey) -> str:
        _payload = xorkey.encrypt(payload)
        _asm = self.asm
        if "(r64)" in _asm:
            _asm = _asm.replace("(r64)", f"0x{rnd:016X}")
        if "(r32)" in _asm:
            _asm = _asm.replace("(r32)", f"0x{(rnd & 0xFFFFFFFF):08X}")
        if "(r16)" in _asm:
            _asm = _asm.replace("(r16)", f"0x{(rnd & 0xFFFF):04X}")
        if "(r8)" in _asm:
            _asm = _asm.replace("(r8)", f"0x{(rnd & 0xFF):02X}")

        _hex = "".join(f"{x:02X}" for x in reversed(_payload))
        _asm = _asm.replace(
            "(s)", f"0x{_hex.ljust(self.payload_length * 2, '0')}")

        return _asm + f" ; [ {' '.join(f'{x:02X}' for x in payload)} ]"

    @staticmethod
    def _serialize_int(number: int, length: int) -> bytes:
        """Serializes a number of given size into its individual bytes"""

        if length == 1:
            fmt = "B"
            number = number & 0xFF
        if length == 2:
            fmt = "H"
            number = number & 0xFFFF
        if length == 4:
            fmt = "I"
            number = number & 0xFFFFFFFF
        if length == 8:
            fmt = "Q"
            number = number & 0xFFFFFFFFFFFFFFFF
        return struct.pack(fmt, number)

    def _get_bin(self, payload: bytes, rnd: int, xorkey: XorKey) -> bytes:
        payload = xorkey.encrypt(payload)
        _bin = bytearray(self.bin)
        if self.rnd_offset is not None:
            _bin[self.rnd_offset:self.rnd_offset +
                 self.rnd_length] = PayloadInstruction._serialize_int(rnd, self.rnd_length)

        _bin[self.payload_offset:self.payload_offset +
             self.payload_length] = payload
        return bytes(_bin)

    def generate(self, payload: bytes, xorkey: XorKey) -> Result:
        _rnd = random.randint(0, 0xFFFFFFFFFFFFFFFF)
        return Result(
            self._get_asm(payload[:self.payload_length],
                          _rnd,
                          xorkey.copy()
                          ),
            self._get_bin(payload[:self.payload_length],
                          _rnd,
                          xorkey
                          ),
            payload[self.payload_length:]
        )


@dataclass
class PseudoInstruction(Instruction):
    """Class representing ASM instructions that serve as pure filler"""

    asm: str
    bin: bytes
    opcode_length: int = None

    @property
    def can_process(self) -> bool:
        return False

    @property
    def encoding_length(self) -> int:
        return len(self.bin)

    @property
    def opcode_bytes(self) -> bytes:
        length = self.opcode_length \
            if self.opcode_length is not None\
            else len(self.bin)

        return bytes(self.bin[:length])

    def as_dict(self) -> dict:
        return {
            "asm": self.asm,
            "bin": ' '.join(f"{x:02X}" for x in self.bin),
        }

    def generate(self, payload: bytes, xorkey: XorKey) -> Result:
        return Result(self.asm, self.bin, payload)


def create_payload_instruction(asm: str,
                               bindata: str,
                               payload_offset: int,
                               payload_length: int = 1,
                               rnd_offset: int = None,
                               rnd_length: int = None) -> PayloadInstruction:
    """Instantiates a PayloadInstruction from the provided data"""

    binbytes = bytes([int(hx, 16) for hx in bindata.split(" ")])

    return PayloadInstruction(asm.lower(),
                              binbytes,
                              payload_offset,
                              payload_length,
                              rnd_offset,
                              rnd_length)


def create_pseudo_instruction(asm: str,
                              bindata: str,
                              opcode_length: int = None) -> PseudoInstruction:
    """Instantiates a PseudoInstruction from the provided data"""

    binbytes = bytes([int(hx, 16) for hx in bindata.split(" ")])

    return PseudoInstruction(asm.lower(), binbytes, opcode_length)


def parse_instruction_templates() -> Tuple[
        List[PayloadInstruction],
        List[PseudoInstruction],
        List[PseudoInstruction],
        List[Tuple[PseudoInstruction, PseudoInstruction]]]:
    """Parses the instructions templates from codasm.json"""

    jsondefsfile = os.path.join(pathlib.Path(
        os.path.abspath(__file__)).parent.absolute(), "codasm.json")

    # Load templates from definition file
    with open(jsondefsfile, "r", encoding='utf-8') as j:
        _data = json.load(j)
        plins: List[PayloadInstruction] = [
            create_payload_instruction(**ins) for ins in _data["payload_instructions"]]
        psins: List[PseudoInstruction] = [
            create_pseudo_instruction(**ins) for ins in _data["pseudo_instructions"]]
        stins: List[PseudoInstruction] = [
            create_pseudo_instruction(**ins) for ins in _data["stack_instructions"]]
        pushpopins: List[Tuple[PseudoInstruction, PseudoInstruction]] = [(
            create_pseudo_instruction(**(ins["push"])),
            create_pseudo_instruction(**(ins["pop"])))
            for ins in _data["pushpop_instructions"]]

    return (plins, psins, stins, pushpopins)
