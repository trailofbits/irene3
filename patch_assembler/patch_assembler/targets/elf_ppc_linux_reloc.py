from patcherex2.targets.elf_ppc_linux import ElfPpcLinux
from .reloc_target import RelocTarget

class ElfPpcRelocLinux(RelocTarget, ElfPpcLinux):
    # Emits a thunk which calculates the base address
    # by subtracting the patch insertion address from
    # the current pc and stores it in the given register
    @staticmethod
    def emit_thunk(base_reg, insert_addr, is_thumb=False):
        scratch_reg1 = "%r4" if base_reg == "%r3" else "%r3"
        scratch_reg2 = "%r12" if base_reg == "%r11" else "%r11"

        # add 20 since base_reg will contain
        # the addr + 20
        thunk_loc = insert_addr + 20
        thunk_l = 0xFFFF & thunk_loc
        thunk_h = 0xFFFF & (thunk_loc >> 16)
        thunk_instrs = f"""
        stwu %r1, -8(%r1)
        stw {scratch_reg2}, 4(%r1)
        stw {scratch_reg1}, 0(%r1)
        mflr {scratch_reg2}
        bl lb
        lb:
        mflr {base_reg}
        lis {scratch_reg1}, {thunk_h}
        ori {scratch_reg1}, {scratch_reg1}, {thunk_l}
        sub {base_reg}, {base_reg}, {scratch_reg1}
        mtlr {scratch_reg2}
        lwz {scratch_reg1}, 0(%r1)
        lwz {scratch_reg2}, 4(%r1)
        addi %r1, %r1, 8
        """

        return thunk_instrs

    @staticmethod
    def emit_load_addr(addr, reg_name=None):
        if reg_name is None:
            reg_name = "%r1"
        addr_l = 0xFFFF & addr
        addr_h = 0xFFFF & (addr >> 16)
        load_instrs = f"""
        lis {reg_name}, {addr_h}
        ori {reg_name}, {reg_name}, {addr_l}
        """
        return load_instrs
