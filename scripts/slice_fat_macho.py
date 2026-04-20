#!/usr/bin/env python3
"""Slice a Mach-O fat / universal binary into per-arch Mach-O files.

Ghidra's loader can already pick a slice on import, but some
workflows (bulk spec extraction scripts, external tooling) want the
slice on disk as a standalone Mach-O. This script does that with
only `struct` from the Python stdlib — no need for `lipo` or `lief`.

Supports both 32-bit (`FAT_MAGIC` / `FAT_CIGAM`) and 64-bit
(`FAT_MAGIC_64` / `FAT_CIGAM_64`) fat headers. Outputs one file per
slice named `<stem>.<arch>.<out-ext>` (default `out-ext` is the
input's extension or empty).

Usage:
    slice_fat_macho.py list <input>
    slice_fat_macho.py extract <input> [--arch <cpu-type>] [--output-dir <dir>]
    slice_fat_macho.py extract-all <input> [--output-dir <dir>]

Examples:
    slice_fat_macho.py list MyApp
    slice_fat_macho.py extract MyApp --arch arm64 -o /tmp/slices
    slice_fat_macho.py extract-all MyApp -o /tmp/slices
"""
from __future__ import annotations

import argparse
import os
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

FAT_MAGIC    = 0xCAFEBABE
FAT_CIGAM    = 0xBEBAFECA  # byte-swapped, seen in little-endian readers
FAT_MAGIC_64 = 0xCAFEBABF
FAT_CIGAM_64 = 0xBFBAFECA

MH_MAGIC     = 0xFEEDFACE
MH_MAGIC_64  = 0xFEEDFACF
MH_CIGAM     = 0xCEFAEDFE
MH_CIGAM_64  = 0xCFFAEDFE

# CPU type constants (partial; the ones iOS / macOS binaries commonly use).
CPU_TYPE_NAMES = {
    0x07:       "x86",
    0x01000007: "x86_64",
    0x0C:       "arm",
    0x0100000C: "arm64",
    0x0200000C: "arm64_32",
    0x12:       "ppc",
    0x01000012: "ppc64",
}
# Names → cpu types for `--arch` lookup.
ARCH_NAME_TO_TYPE = {v: k for k, v in CPU_TYPE_NAMES.items()}
# Friendly aliases.
ARCH_NAME_TO_TYPE["arm64e"] = 0x0100000C
ARCH_NAME_TO_TYPE["amd64"] = 0x01000007


@dataclass(frozen=True)
class Slice:
    cpu_type: int
    cpu_subtype: int
    offset: int
    size: int
    align: int

    @property
    def arch_label(self) -> str:
        base = CPU_TYPE_NAMES.get(self.cpu_type, f"cpu{self.cpu_type:#010x}")
        # Distinguish arm64e from arm64 via the ARM64E subtype = 2.
        if self.cpu_type == 0x0100000C and (self.cpu_subtype & 0x00FFFFFF) == 2:
            return "arm64e"
        return base


def _read_fat(fh) -> List[Slice]:
    fh.seek(0)
    magic = struct.unpack(">I", fh.read(4))[0]
    if magic not in (FAT_MAGIC, FAT_MAGIC_64):
        raise SystemExit(
            f"not a fat Mach-O (magic=0x{magic:08x}); single-slice input is "
            "already usable as-is."
        )
    nfat = struct.unpack(">I", fh.read(4))[0]
    is_64 = magic == FAT_MAGIC_64
    slices: List[Slice] = []
    for _ in range(nfat):
        if is_64:
            # fat_arch_64: cputype, cpusubtype, offset, size, align, reserved
            rec = fh.read(32)
            cpu_type, cpu_subtype, offset, size, align, _reserved = struct.unpack(
                ">IIQQII", rec
            )
        else:
            # fat_arch: cputype, cpusubtype, offset, size, align
            rec = fh.read(20)
            cpu_type, cpu_subtype, offset, size, align = struct.unpack(">IIIII", rec)
        slices.append(
            Slice(cpu_type=cpu_type, cpu_subtype=cpu_subtype,
                  offset=offset, size=size, align=align)
        )
    return slices


def _is_fat(path: Path) -> bool:
    with path.open("rb") as fh:
        head = fh.read(4)
    if len(head) != 4:
        return False
    magic = struct.unpack(">I", head)[0]
    return magic in (FAT_MAGIC, FAT_MAGIC_64)


def cmd_list(args) -> int:
    path = Path(args.input)
    if not _is_fat(path):
        print(f"{path}: not a fat Mach-O", file=sys.stderr)
        return 1
    with path.open("rb") as fh:
        slices = _read_fat(fh)
    print(f"{path}: {len(slices)} slices")
    for i, s in enumerate(slices):
        print(
            f"  [{i}] {s.arch_label:<10} "
            f"cpu=0x{s.cpu_type:08x} subtype=0x{s.cpu_subtype:08x} "
            f"offset=0x{s.offset:x} size=0x{s.size:x} align=2^{s.align}"
        )
    return 0


def _extract_one(src_path: Path, slc: Slice, out_dir: Path, stem_arch: Optional[str]) -> Path:
    with src_path.open("rb") as fh:
        fh.seek(slc.offset)
        payload = fh.read(slc.size)
    if len(payload) != slc.size:
        raise SystemExit(
            f"short read on {src_path}: wanted {slc.size} bytes at "
            f"offset {slc.offset}, got {len(payload)}"
        )
    arch = stem_arch or slc.arch_label
    stem = src_path.name
    # Strip trailing executable bit / don't add an extension we don't have.
    out_name = f"{stem}.{arch}"
    out_path = out_dir / out_name
    out_path.write_bytes(payload)
    out_path.chmod(0o755)
    return out_path


def cmd_extract(args) -> int:
    src = Path(args.input)
    if not _is_fat(src):
        print(f"{src}: not a fat Mach-O — nothing to extract", file=sys.stderr)
        return 1
    with src.open("rb") as fh:
        slices = _read_fat(fh)

    out_dir = Path(args.output_dir) if args.output_dir else src.parent
    out_dir.mkdir(parents=True, exist_ok=True)

    if args.arch:
        wanted = ARCH_NAME_TO_TYPE.get(args.arch.lower())
        if wanted is None:
            print(
                f"unknown --arch '{args.arch}'; "
                f"supported: {', '.join(sorted(ARCH_NAME_TO_TYPE))}",
                file=sys.stderr,
            )
            return 2
        matches = [
            s for s in slices
            if s.cpu_type == wanted and (
                args.arch.lower() != "arm64e" or
                (s.cpu_subtype & 0x00FFFFFF) == 2
            )
        ]
        if not matches:
            print(f"no slice matching arch '{args.arch}' in {src}", file=sys.stderr)
            return 1
        if len(matches) > 1:
            print(
                f"multiple slices match arch '{args.arch}'; extracting the first",
                file=sys.stderr,
            )
        out = _extract_one(src, matches[0], out_dir, args.arch.lower())
        print(out)
        return 0

    out = _extract_one(src, slices[0], out_dir, None)
    print(out)
    return 0


def cmd_extract_all(args) -> int:
    src = Path(args.input)
    if not _is_fat(src):
        print(f"{src}: not a fat Mach-O — nothing to extract", file=sys.stderr)
        return 1
    with src.open("rb") as fh:
        slices = _read_fat(fh)
    out_dir = Path(args.output_dir) if args.output_dir else src.parent
    out_dir.mkdir(parents=True, exist_ok=True)
    for s in slices:
        out = _extract_one(src, s, out_dir, None)
        print(out)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="slice_fat_macho.py")
    sub = parser.add_subparsers(dest="cmd", required=True)

    list_p = sub.add_parser("list", help="print slice metadata")
    list_p.add_argument("input")
    list_p.set_defaults(func=cmd_list)

    ex_p = sub.add_parser("extract", help="extract one slice")
    ex_p.add_argument("input")
    ex_p.add_argument("--arch", help="e.g. arm64, arm64e, x86_64")
    ex_p.add_argument("-o", "--output-dir")
    ex_p.set_defaults(func=cmd_extract)

    all_p = sub.add_parser("extract-all", help="extract every slice")
    all_p.add_argument("input")
    all_p.add_argument("-o", "--output-dir")
    all_p.set_defaults(func=cmd_extract_all)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
