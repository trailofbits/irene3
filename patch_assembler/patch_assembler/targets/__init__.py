from .elf_amd64_linux_reloc import ElfAmd64RelocLinux
from .elf_arm_linux_reloc import ElfArmRelocLinux
from .elf_ppc_linux_reloc import ElfPpcRelocLinux
from .reloc_target import RelocTarget


__all__ = [
    "ElfAmd64RelocLinux",
    "ElfArmRelocLinux",
    "ElfPpcRelocLinux",
    "RelocTarget"
]
