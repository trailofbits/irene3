import graphviz
import json
import argparse
import sys
import os
from typing import Optional, Dict, Any


class PatchFinder:
    def __init__(self, patch_specs) -> None:
        patches = patch_specs["patches"]
        self.patch_by_addr = dict([(int(ptch["patch-addr"], 0), ptch)
                                   for ptch in patches])

    def find_patch(self, addr: int) -> Optional[Dict[str, Any]]:
        return self.patch_by_addr.get(addr, None)


def render(patch_specs, args):
    digraph = graphviz.Digraph("Patches")

    if args.apply_patches:
        finder = PatchFinder(patch_specs)
        to_add = json.load(args.apply_patches)
        for ptch in to_add["patches"]:
            target = finder.find_patch(int(ptch["patch-addr"], 0))
            if target:
                target["patch-code"] = ptch["patch-code"]

    for nd in patch_specs["patches"]:
        addr = nd["patch-addr"]
        digraph.node(addr,
                     f"{addr}" + r":\l\l" + nd["patch-code"].replace("\n", r"\l"), shape="rectangle")

        for e in nd["edges"]:
            digraph.edge(nd["patch-addr"], e)

    digraph.render(args.output_file, format=args.format, view=args.view)


def find_patch(patch_specs, args):
    finder = PatchFinder(patch_specs)

    target_patch = finder.find_patch(args.target_block_id)
    if not target_patch:
        sys.exit(
            f"{hex(args.target_block_id)} is not an available block in the target file, available ids are: {[hex(addr) for addr in finder.patch_by_addr]}")

    return target_patch


def extract_subprogram(patch_specs, args):
    ptch = find_patch(patch_specs, args)
    cd = ptch["patch-code"]
    args.output_file.write(cd)


def patch_subprogram(patch_specs, args):
    ptch = find_patch(patch_specs, args)

    curr_patches = {"patches": []}
    if os.path.exists(args.output_file):
        with open(args.output_file, "r") as f:
            curr_patches = json.load(f)

    ptch["patch-code"] = args.input_c.read()
    curr_patches["patches"].append(ptch)

    with open(args.output_file, "w") as f:
        json.dump(curr_patches, f, indent=4)


def main():
    prsr = argparse.ArgumentParser()
    prsr.add_argument("target_json", type=argparse.FileType('r'))

    subparsers = prsr.add_subparsers(required=True)
    render_prsr = subparsers.add_parser(
        "render", help="render the patcheable decompilation in a graphviz format")

    render_prsr.add_argument("output_file",
                             type=str)
    render_prsr.add_argument("--format", type=str)
    render_prsr.add_argument("--view", action="store_true")
    render_prsr.add_argument(
        "--apply-patches", type=argparse.FileType('r'), help="a set of patches to apply before viewing")
    render_prsr.set_defaults(func=render)

    extract_subprogram_prsr = subparsers.add_parser(
        "extract_subprogram", help="extract a basic block's decompilation for patching")
    extract_subprogram_prsr.add_argument(
        "target_block_id", type=lambda x: int(x, 0), help="the address id of the block to extract")
    extract_subprogram_prsr.add_argument(
        "output_file", type=argparse.FileType('w'), help="the file to write the C to")
    extract_subprogram_prsr.set_defaults(func=extract_subprogram)

    patch_subprogram_prsr = subparsers.add_parser(
        "patch_subprogram", help="Produce a patch definition where the semantics for a basic block are replaced with the given semantics. If the given file already exists, adds the patch to a working set of patches")
    patch_subprogram_prsr.add_argument(
        "target_block_id", type=lambda x: int(x, 0), help="the address id of the block to extract")
    patch_subprogram_prsr.add_argument(
        "input_c", type=argparse.FileType('r'), help="the new C semantics for this block")
    patch_subprogram_prsr.add_argument(
        "output_file", type=str, help="the patch definition file")
    patch_subprogram_prsr.set_defaults(func=patch_subprogram)

    args = prsr.parse_args()
    patch_specs = json.load(args.target_json)
    args.func(patch_specs, args)


if __name__ == "__main__":
    main()
