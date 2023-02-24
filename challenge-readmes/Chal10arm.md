# Challenge 10: Beagle Bone Black

This document serves as a walkthrough for generating a canidate
patch as a solution to Chal 10 on the Beagle Bone. The walkthrough assumes the steps in `INSTALL.md` have been completed. The goal is to replace a check of the form `(num_packets > ceil((float)size/7)` with `((num_packets * 7) != size)`.

## Ghidra Setup/Reverse Engineering

IRENE decompiles single functions that the user intends to develop a patch for. This workflow assumes that the user already knows what function they want to patch (`transport_handler` in this challenge) and that the user has setup the types of the function and it's callees as would occur in a typical reverse engineering workflow. These function signatures and names can be produced by other teams working on function matching problems (ie. BSI) and imported into the Ghidra database to jump-start this reverse engineering process. 

For the purpose of the walkthough, we have provided a Ghidra database `arm-program_c.vuln.chal-10.gzf` that can be imported into Ghidra with `File > Import file... > Browse to the .gzf `

