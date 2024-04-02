import argparse
from patcherex2 import *
from patcherex2.patches import Patch
from patcherex2.components.allocation_managers.allocation_manager import MemoryFlag
from .targets import RelocTarget
import logging
import json
import os
import re
import logging

logger = logging.getLogger(__name__)


class InsertPIEInstructionPatch(Patch):
    def __init__(
        self, addr, instrs, base_reg, detour_pos=-1, no_rewrite_thumb=False
    ) -> None:
        self.addr = addr
        self.instrs = instrs
        self.base_reg = base_reg
        self.detour_pos = detour_pos
        self.no_rewrite_thumb = no_rewrite_thumb

    def apply(self, p):
        is_thumb = p.binary_analyzer.is_thumb(self.addr)

        moved_instrs = p.utils.get_instrs_to_be_moved(self.addr)
        assert moved_instrs is not None, f"Cannot insert instruction at {self.addr:x}"
        moved_instrs_len = len(
            p.assembler.assemble(
                moved_instrs,
                self.addr,  # TODO: we don't really need this addr, but better than 0x0 because 0x0 is too far away from the code
                is_thumb=is_thumb,
            )
        )

        load_addr_size = len(
            p.assembler.assemble(
                p.target.emit_load_addr(self.addr),
                self.addr,
                is_thumb=is_thumb,
            )
        )
        # calculate the expected size of the trampoline
        # by summing the size of the compiled instructions
        # excluding the POINTER_HANDLER, the size of the
        # expanded POINTER_HANDLER pseudo-instruction
        trampoline_size = (
            len(
                p.assembler.assemble(
                    "\n".join(
                        [
                            line
                            for line in self.instrs.splitlines()
                            if "POINTER_HANDLER" not in line
                        ]
                    )
                    + "\n"
                    + moved_instrs
                    + "\n"
                    + p.archinfo.jmp_asm.format(dst=hex(self.addr + moved_instrs_len)),
                    self.addr,  # TODO: we don't really need this addr, but better than 0x0 because 0x0 is too far away from the code
                    is_thumb=is_thumb,
                )
            )
            + len(re.findall("POINTER_HANDLER", self.instrs)) * load_addr_size
        )
        thunk_instrs_len = 0
        # emit thunk with addr instead of the trampoline address to calculate the size
        print(p.target.emit_thunk(self.base_reg, self.addr, is_thumb))
        thunk_instrs_len = len(
            p.assembler.assemble(
                p.target.emit_thunk(self.base_reg, self.addr, is_thumb),
                self.addr,
                is_thumb=is_thumb,
            )
        )
        trampoline_size += thunk_instrs_len

        if self.detour_pos == -1:
            trampoline_block = p.allocation_manager.allocate(
                trampoline_size, align=0x4, flag=MemoryFlag.RX
            )  # TODO: get alignment from arch info
            logger.debug(f"Allocated trampoline block: {trampoline_block}")
            detour_pos = trampoline_block.mem_addr
        else:
            detour_pos = self.detour_pos

        base_addr = detour_pos
        if not p.binary_analyzer.p.loader.main_object.pic:
            base_addr -= p.binary_analyzer.load_base
        instrs = (
            p.target.emit_thunk(self.base_reg, base_addr, is_thumb=is_thumb)
            + self.instrs
        )
        instrs = self.rewrite_addresses(
            p,
            instrs,
            self.addr,
            detour_pos,
            is_thumb=is_thumb,
            no_rewrite_thumb=self.no_rewrite_thumb,
        )

        p.utils.insert_trampoline_code(
            self.addr,
            instrs,
            detour_pos=detour_pos,
        )

    @staticmethod
    def rewrite_addresses(
        p, instrs, addr, mem_addr, is_thumb=False, no_rewrite_thumb=False
    ):
        pointer_pat = re.compile(
            r"POINTER_HANDLER (?P<register>[^, ]+), [^0-9]?(?P<imm>[0-9]+)(, [^0-9]?(?P<repair_if_moved>[0-1]))?"
        )

        # uses a fake address to get the approximate size of
        load_addr_insns_size = len(
            p.assembler.assemble(p.target.emit_load_addr(addr)))

        instrs_size = (
            len(
                p.assembler.assemble(
                    "\n".join(
                        [
                            line
                            for line in instrs.splitlines()
                            if "POINTER_HANDLER" not in line
                        ]
                    ),
                    addr,
                    is_thumb=p.binary_analyzer.is_thumb(addr),
                )
            )
            + len(pointer_pat.findall(instrs)) * load_addr_insns_size
        )

        # rewrite addresses
        new_instrs = []
        for line in instrs.splitlines():
            line = line.strip()
            new_line = line
            if match_result := pointer_pat.search(line):
                reg_name = match_result.group("register")
                goto_addr = int(match_result.group("imm"))
                repair_if_moved = bool(
                    int(match_result.group("repair_if_moved")))
                # only rewrite goto addresses in between the start of the moved instructions
                # to the end of the moved instructions
                if (
                    repair_if_moved
                    and goto_addr - addr >= 0
                    and goto_addr - addr <= p.archinfo.jmp_size
                ):
                    # TODO: setting the thumb bit using is_thumb isn't always necessarily true
                    goto_addr = mem_addr + instrs_size + (goto_addr - addr)
                if is_thumb and not no_rewrite_thumb:
                    goto_addr = goto_addr | int(is_thumb)
                new_line = p.target.emit_load_addr(
                    goto_addr, reg_name=reg_name)
                logger.debug(f"POINTER_HANDLER -> {new_line}")
            new_instrs.append(new_line)
        instrs = "\n".join(new_instrs)
        logger.debug(f"Replace addresses: {instrs}")
        return instrs


# this works by searching for the function size calculation
# to grab the labels that the assembler emits for the start
# and end of the function and using those to identify where
# the core of the function instructions are
# also we collect all directives with labels outside of the
# function instructions and stick them at the bottom
def trim_asm(asm: str):
    size_directive_re = re.compile(
        r"^\s*\.size\s+[^,]+,\s*(?P<end_label>[^-]+)-(?P<start_label>\S+)$",
        re.MULTILINE,
    )
    label_directive_re = re.compile(r"^\s*([^:]+):")
    ignore_directive_re = re.compile(r"\s*\.(set)\s")
    data_directive_re = re.compile(r"^\s*\.(\S+)\s")
    buf = ""
    data_defs = []
    if size_match := size_directive_re.search(asm):
        start_label = size_match.group("start_label") + ":"
        end_label = size_match.group("end_label") + ":"
        in_func = False
        asm_lines = asm.splitlines()
        for i, line in enumerate(asm_lines):
            if start_label in line:
                in_func = True
            if end_label in line:
                in_func = False
                break
            if in_func:
                buf += line + os.linesep
            elif data_directive_re.search(line) and not ignore_directive_re.search(
                line
            ):
                if i > 0 and label_directive_re.search(asm_lines[i - 1]):
                    data_defs.append(asm_lines[i - 1] + os.linesep + line)
        asm = buf
        asm += "\n".join(data_defs)
    else:
        logger.error("Missing size directive! Assembly output not filtered.")
    return asm

def main():
    prsr = argparse.ArgumentParser("patch assembly compiler")
    prsr.add_argument("--in_assembly", type=argparse.FileType("r"))
    prsr.add_argument("--metadata", type=argparse.FileType("r"))
    prsr.add_argument("--output", required=True, type=str)
    prsr.add_argument("--trim_heuristics", action="store_true", default=True)
    prsr.add_argument(
        "--detour_pos", type=lambda x: int(x, 0), default=-1, help="Address to free space (if known)"
    )
    prsr.add_argument("--no_rewrite_thumb", action="store_true", default=False)
    prsr.add_argument("target_binary")
    args = prsr.parse_args()

    patcher = Patcherex(
        args.target_binary,
        target_cls=RelocTarget.detect_reloc_target(args.target_binary),
    )
   
    meta = json.load(args.metadata)
    target_addr = meta["patch_offset_from_base"]
    base_reg = meta["base_register"]

    if not patcher.binary_analyzer.p.loader.main_object.pic:
        # Patcherex expects absolute address for non PIE binaries
        target_addr += patcher.binary_analyzer.p.loader.main_object.mapped_base

    asm: str = args.in_assembly.read()

    if args.trim_heuristics:
        asm = trim_asm(asm)
        print(f"Trimmed asm: {asm}")

    logging.getLogger("patcherex2").setLevel("DEBUG")

    print(f"Inserting patch to {target_addr:x}")
    patcher.patches.append(
        InsertPIEInstructionPatch(
            target_addr,
            asm,
            base_reg=base_reg,
            detour_pos=args.detour_pos,
            no_rewrite_thumb=args.no_rewrite_thumb,
        )
    )

    # so we want to setup the target reg with this thunk and then execute our code
    patcher.apply_patches()
    patcher.binfmt_tool.save_binary(args.output)


if __name__ == "__main__":
    main()
