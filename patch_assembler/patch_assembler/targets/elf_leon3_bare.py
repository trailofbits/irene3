from patcherex2.targets.elf_leon3_bare import ElfLeon3Bare
from .reloc_target import RelocTarget
from patcherex2.components.binfmt_tools.elf import ELF


class ElfArmRelocLinux(RelocTarget, ElfLeon3Bare):
    # Emits a thunk which calculates the base address
    # by subtracting the patch insertion address from
    # the current pc and stores it in the given register
    @staticmethod
    def emit_thunk(base_reg, insert_addr, is_thumb=False):
        scratch_reg = "g2" if base_reg.lower() == "g3" else "g3"
        # sparc places the address of the call into o7 so we want to incorporate the size everything up to the call (3 insn)
        size_of_pre_label = 12
        thunk_loc = insert_addr + size_of_pre_label
        thunk_instrs = f"""
        sub %sp, 8, %sp
        st %o7, [%sp]
        st %{scratch_reg}, [%sp+4]
        call lb
        nop
        lb:
        mov %o7, %{base_reg}
        set {thunk_loc},%{scratch_reg}
        sub %{base_reg}, %{scratch_reg}, %{base_reg} 
        ld [%sp + 4], %{scratch_reg}
        ld [%sp], %o7
        add %sp, 8, %sp
        """
        return thunk_instrs

    @staticmethod
    def emit_load_addr(addr, reg_name=None):
        # place holder register to get size
        if reg_name is None:
            reg_name = "g1"

        if reg_name.startswith("%"):
            reg_name = reg_name[1:]
        load_instrs = f"""
        set {addr}, %{reg_name}
        """
        return load_instrs

    def get_binfmt_tool(self, binfmt_tool):
        binfmt_tool = binfmt_tool or "pyelftools"
        if binfmt_tool == "pyelftools":
            return ELF(self.p, self.binary_path)
        raise NotImplementedError()
