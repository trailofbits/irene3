# Lowering a PatchLang Block to Assembly

Once the .irene PatchLang module has been patched irene-lower can lower the module to assembly. Run:
`irene3-lower --uid <UID> <target .irene> <output directory>`

There are additional options:
- `--feature_list`: comma separated LLVM feature list `ie. +thumb_mode`
- `--cpu`: LLVM CPU string (ie. cortex-a8)
- `--backend`: ARM, PPC, X86, and X86_64 if not specified will attempt to use a generic backend. It is recommended to use the backend for your target architecture.

This command will produce a .S and .json file that the [patch assembler](patch-assembler.md) can consume. It will additionally save intermediate artifacts.