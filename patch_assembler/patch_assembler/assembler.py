import patcherex
import argparse
from patcherex.backends.detourbackend import DetourBackend
from patcherex.patches import InsertCodePatch
from IPython import embed
import json
import os
import sys

START_TOK = ".fnstart"
END_TOK = ".Lfunc_end"


# THUNK:
"""
        self.name_map["pie_thunk"] = self.get_current_code_position()
        thunk_loc = self.get_current_code_position() + 4
        thunk_l = (0xffff & thunk_loc)
        thunk_h = (0xffff & (thunk_loc >> 16))

        pie_thunk = f\"""
        mov r0, pc
        movw r5, #{thunk_l}
        movt r5, #{thunk_h}
        sub r0, r5
        bx lr
        \"""

        new_code = self.compile_asm(pie_thunk,
                                        self.get_current_code_position(),
                                        self.name_map, is_thumb=True)
        self.added_code += new_code
        self.ncontent = utils.bytes_overwrite(self.ncontent, new_code)

"""


def main():
    prsr = argparse.ArgumentParser("patch assembly compiler")
    prsr.add_argument("--in_assembly", type=argparse.FileType('r'))
    prsr.add_argument("--metadata", type=argparse.FileType('r'))
    prsr.add_argument("--trim_heuristics", action="store_true", default=True)
    prsr.add_argument("target_binary")
    args = prsr.parse_args()

    backend = DetourBackend(args.target_binary)
    base = backend.project.loader.main_object.min_addr

    meta = json.load(args.metadata)
    target_addr = base + meta['patch_offset_from_base']
    base_reg = meta['base_register']
    free_regs: list = meta['free_regs']

    if len(free_regs) == 0:
        print(
            "Compiler needs at least one free freg to compute a PIE thunk, please add one")
        sys.exit(-1)

    thunk_loc_reg = free_regs.pop()

    asm: str = args.in_assembly.read()

    if args.trim_heuristics:
        buf = ""
        for line in asm.split(os.linesep):
            if START_TOK in line:
                st = asm.find(START_TOK)
                asm = asm[st + len(START_TOK):]
                buf = ""
            if END_TOK in line:
                break
            buf += line + os.linesep
        asm = buf

    def create_patch(insert_addr: int) -> str:
        # TODO(Ian): this is only right if we are in thumb
        thunk_loc = insert_addr + 4
        thunk_l = (0xffff & thunk_loc)
        thunk_h = (0xffff & (thunk_loc >> 16))
        # TODO(Ian) insert a free reg
        thunk = f"""
        mov {base_reg}, pc
        movw {thunk_loc_reg}, #{thunk_l}
        movt {thunk_loc_reg}, #{thunk_h}
        sub {base_reg}, {thunk_loc_reg}
        """

        res = thunk + asm.replace("{", "{{").replace("}", "}}")
        print(res)
        return res

    # so we want to setup the target reg with this thunk and then execute our code

    backend.apply_patches([InsertCodePatch(target_addr, create_patch)])
    backend.save("/tmp/bin")


if __name__ == "__main__":
    main()
