from patcherex2.targets.elf_arm_linux import ElfArmLinux
from .reloc_target import RelocTarget

class ElfArmRelocLinux(RelocTarget, ElfArmLinux):
    # Emits a thunk which calculates the base address
    # by subtracting the patch insertion address from
    # the current pc and stores it in the given register
    @staticmethod
    def emit_thunk(base_reg, insert_addr, is_thumb=False):
        scratch_reg = "r4" if base_reg.lower() == "r3" else "r3"
        # need to add 4/8 here since pc
        # points to the next instruction
        thunk_loc = insert_addr + (4 if is_thumb else 8)
        thunk_l = 0xFFFF & thunk_loc
        thunk_h = 0xFFFF & (thunk_loc >> 16)
        thunk_instrs = f"""
        mov {base_reg}, pc
        push {{{scratch_reg}}}
        movw {scratch_reg}, #{thunk_l}
        movt {scratch_reg}, #{thunk_h}
        sub {base_reg}, {scratch_reg}
        pop {{{scratch_reg}}}
        """
        return thunk_instrs

    @staticmethod
    def emit_load_addr(addr, reg_name=None):
        # place holder register to get size
        if reg_name is None:
            reg_name = "r2"
        addr_l = 0xFFFF & addr
        addr_h = 0xFFFF & (addr >> 16)
        load_instrs = f"""
        movw {reg_name}, #{addr_l}
        movt {reg_name}, #{addr_h}
        """
        return load_instrs
