#!/usr/bin/env python3
"""Wrapper around external tools that extract individual dylibs from
an iOS / macOS dyld shared cache.

iOS system libraries (Foundation, UIKit, WebKit, ...) do not ship as
stand-alone Mach-O files — they are packed into the dyld shared
cache (`dyld_shared_cache_arm64` or similar on iOS, and
`/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/...` on
macOS Big Sur+). To analyse an iOS app's imports, users need to
extract the relevant dylibs first.

This script is a thin front-end that picks between two well-known
extractors depending on what's available on PATH:

  * `dsc_extractor` from Apple's open-source dyld
    (https://github.com/apple/dyld).
  * `ipsw` from Blacktop (https://github.com/blacktop/ipsw)
    [preferred when available — it also handles iOS 16+ cache
    splits out of the box].

Re-implementing the dyld shared-cache format in pure Python is
explicitly out of scope for this script (the format changes every
iOS release; keeping pace is a job for tools whose sole focus is
that format).

Usage:
    extract_from_dyld_cache.py check                      # print which backends are available
    extract_from_dyld_cache.py list <cache>               # list dylibs in the cache
    extract_from_dyld_cache.py extract <cache> <dylib-path> -o <out-dir>
    extract_from_dyld_cache.py extract-all <cache> -o <out-dir>

Examples:
    extract_from_dyld_cache.py list /path/to/dyld_shared_cache_arm64e
    extract_from_dyld_cache.py extract dyld_shared_cache_arm64e \\
        /System/Library/Frameworks/Foundation.framework/Foundation \\
        -o /tmp/slices
"""
from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional


@dataclass(frozen=True)
class Backend:
    name: str
    check: str   # command to verify presence
    list_cmd: List[str]
    # Formatted per-call — {cache}, {dylib}, {out} placeholders.
    extract_one_cmd: List[str]
    extract_all_cmd: List[str]
    post_hint: str = ""


BACKENDS: List[Backend] = [
    Backend(
        name="ipsw",
        check="ipsw",
        list_cmd=["ipsw", "dyld", "info", "{cache}"],
        extract_one_cmd=["ipsw", "dyld", "extract", "{cache}", "--dylib", "{dylib}", "--output", "{out}"],
        extract_all_cmd=["ipsw", "dyld", "extract-all", "{cache}", "--output", "{out}"],
        post_hint="ipsw handles iOS 16+ multi-file caches (including the `_aux` / `_data` suffixes) transparently.",
    ),
    Backend(
        name="dsc_extractor",
        check="dsc_extractor",
        list_cmd=["dsc_extractor", "-list", "{cache}"],
        extract_one_cmd=["dsc_extractor", "{cache}", "{out}", "-dylib", "{dylib}"],
        extract_all_cmd=["dsc_extractor", "{cache}", "{out}"],
        post_hint="dsc_extractor is Apple's reference tool; on iOS 16+ caches you may need to pass the primary cache file and keep its companions alongside it.",
    ),
]


def find_backend(preferred: Optional[str] = None) -> Optional[Backend]:
    for b in BACKENDS:
        if preferred and b.name != preferred:
            continue
        if shutil.which(b.check):
            return b
    return None


def render(cmd_template: List[str], **kwargs: str) -> List[str]:
    return [c.format(**kwargs) for c in cmd_template]


def run(cmd: List[str]) -> int:
    print(f"$ {' '.join(cmd)}", file=sys.stderr)
    return subprocess.call(cmd)


# ------------------------------------------------------------------ #

def cmd_check(_args) -> int:
    found_any = False
    for b in BACKENDS:
        path = shutil.which(b.check)
        mark = "ok" if path else "missing"
        print(f"  [{mark:>7}] {b.name:<16} {path or ''}")
        if path and b.post_hint:
            print(f"              {b.post_hint}")
        if path:
            found_any = True
    if not found_any:
        print(
            "\nNo dyld-cache extractor found on PATH. Install one of:\n"
            "  * blacktop/ipsw  (homebrew: `brew install blacktop/tap/ipsw`)\n"
            "  * apple/dyld's dsc_extractor  (build from https://github.com/apple/dyld)",
            file=sys.stderr,
        )
        return 1
    return 0


def cmd_list(args) -> int:
    cache = Path(args.cache)
    if not cache.exists():
        print(f"cache not found: {cache}", file=sys.stderr)
        return 2
    backend = find_backend(args.backend)
    if backend is None:
        print("no dyld-cache extractor on PATH; run `check` for install hints", file=sys.stderr)
        return 1
    return run(render(backend.list_cmd, cache=str(cache)))


def cmd_extract(args) -> int:
    cache = Path(args.cache)
    if not cache.exists():
        print(f"cache not found: {cache}", file=sys.stderr)
        return 2
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    backend = find_backend(args.backend)
    if backend is None:
        print("no dyld-cache extractor on PATH; run `check` for install hints", file=sys.stderr)
        return 1
    return run(render(backend.extract_one_cmd, cache=str(cache), dylib=args.dylib, out=str(out)))


def cmd_extract_all(args) -> int:
    cache = Path(args.cache)
    if not cache.exists():
        print(f"cache not found: {cache}", file=sys.stderr)
        return 2
    out = Path(args.output_dir)
    out.mkdir(parents=True, exist_ok=True)
    backend = find_backend(args.backend)
    if backend is None:
        print("no dyld-cache extractor on PATH; run `check` for install hints", file=sys.stderr)
        return 1
    return run(render(backend.extract_all_cmd, cache=str(cache), out=str(out)))


def main() -> int:
    parser = argparse.ArgumentParser(prog="extract_from_dyld_cache.py")
    parser.add_argument(
        "--backend",
        choices=[b.name for b in BACKENDS],
        help="force a specific backend (default: first one found on PATH)",
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    check_p = sub.add_parser("check", help="show which backends are available")
    check_p.set_defaults(func=cmd_check)

    list_p = sub.add_parser("list", help="list dylibs in the cache")
    list_p.add_argument("cache")
    list_p.set_defaults(func=cmd_list)

    ex_p = sub.add_parser("extract", help="extract a single dylib")
    ex_p.add_argument("cache")
    ex_p.add_argument("dylib", help="full install name, e.g. /System/Library/Frameworks/Foundation.framework/Foundation")
    ex_p.add_argument("-o", "--output-dir", required=True)
    ex_p.set_defaults(func=cmd_extract)

    all_p = sub.add_parser("extract-all", help="extract every dylib")
    all_p.add_argument("cache")
    all_p.add_argument("-o", "--output-dir", required=True)
    all_p.set_defaults(func=cmd_extract_all)

    args = parser.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
