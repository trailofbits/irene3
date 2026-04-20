#!/usr/bin/env python3
"""Patch a Mach-O arm64 iOS binary to set LC_ENCRYPTION_INFO_64.cryptid = 1.

This creates a synthetic fixture that triggers irene-ghidra's FairPlay
detection path. The binary's __TEXT is still plain bytes; only the
cryptid flag is flipped, which is enough for static analysers that
refuse to process encrypted binaries.

Usage:
    build-encrypted-stub.py <input.macho> <output.macho>
"""
import struct
import sys

LC_ENCRYPTION_INFO_64 = 0x2C

def main(src_path: str, dst_path: str) -> None:
    with open(src_path, "rb") as fh:
        buf = bytearray(fh.read())

    magic = struct.unpack_from("<I", buf, 0)[0]
    if magic != 0xFEEDFACF:
        raise SystemExit(f"not a Mach-O 64-bit little-endian: magic=0x{magic:08x}")
    ncmds = struct.unpack_from("<I", buf, 16)[0]
    offset = 32  # start of load commands on 64-bit

    for _ in range(ncmds):
        cmd, cmdsize = struct.unpack_from("<II", buf, offset)
        if cmd == LC_ENCRYPTION_INFO_64:
            # Layout: cmd cmdsize cryptoff cryptsize cryptid pad
            cryptid_off = offset + 16
            old = struct.unpack_from("<I", buf, cryptid_off)[0]
            struct.pack_into("<I", buf, cryptid_off, 1)
            print(f"patched cryptid: {old} -> 1 (at file offset 0x{cryptid_off:x})")
            break
        offset += cmdsize
    else:
        raise SystemExit("LC_ENCRYPTION_INFO_64 not found; is this an iOS binary?")

    with open(dst_path, "wb") as fh:
        fh.write(buf)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
