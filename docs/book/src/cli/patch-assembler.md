# Inserting a Compiled Patch into a Binary

The final command line step to produce a patched binary is to assemble the lowered .S file into a detour in the target binary. The patch assembler can perform this task using Patcherex. Run:

`python -m patch_assembler.assembler --metadata <.json> --output <output binary> <target input binary>`

This command will attempt to trim assembly to assembly that keystone can operate over, and then run patcherex to insert a detour based patch.

`--detour_pos` can be used to specify a free space location rather than attempting to allocate free space.