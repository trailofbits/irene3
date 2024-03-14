# Lifting a Specified Block to PatchLang

Given a specification exported from Ghidra `irene3-lift` can lift the specification to a PatchLang module for editing. 

All operations are performed with respect to a block identifier. `irene3-examine-spec --spec <spec.pb>` prints information about block identifiers. To identify the block representing addr one could run `irene3-examine-spec <spec.pb> | grep <addr in hex>`. The block size is printed next to the block identifier to help identify zero byte blocks.

Once the target block UID is identified, run:
`irene3-lift --uid <UID> <spec.pb> <output_directory>`

This command will lift a .irene file which is a PatchLang module for the target block. Edit the region corresponding to the target UID and save the patched file.
