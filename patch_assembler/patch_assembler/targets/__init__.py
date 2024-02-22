from .elf_x86_64_linux_reloc import ElfX8664RelocLinux
from .elf_arm_linux_reloc import ElfArmRelocLinux
from .elf_ppc_linux_reloc import ElfPpcRelocLinux
from .reloc_target import RelocTarget


__all__ = [
    "ElfX8664RelocLinux",
    "ElfArmRelocLinux",
    "ElfPpcRelocLinux",
    "RelocTarget"
]
