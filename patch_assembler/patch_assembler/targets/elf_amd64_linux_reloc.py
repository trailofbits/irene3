from patcherex2.targets.elf_amd64_linux import ElfAmd64Linux
from .reloc_target import RelocTarget

class ElfAmd64RelocLinux(RelocTarget, ElfAmd64Linux):
    @staticmethod
    def emit_thunk(base_reg, insert_addr, is_thumb=False):
        scratch_reg = "r13" if base_reg.lower() == "r12" else "r12"
        thunk_loc = insert_addr + 14
        # move past the red zone so we
        # don't clobber any locals
        thunk_instrs = f"""
        sub rsp, 128
        push {scratch_reg}
        call lb
        lb:
        pop {base_reg}
        mov {scratch_reg}, {thunk_loc}
        sub {base_reg}, {scratch_reg}
        pop {scratch_reg}
        add rsp, 128
        """
        return thunk_instrs

    @staticmethod
    def emit_load_addr(addr, reg_name=None):
        if reg_name is None:
            reg_name = "r13"
        load_instrs = f"""
        mov {reg_name}, {addr}
        """
        return load_instrs
