# PatchLang workflow

2. Open Ghidra project
3. Import target libc -> rename to libc.so.6 and put in a folder
4. Analyze libc + get address of desired function
5. Import target binary -> set up options to import libraries from project folder
6. Analyze target binary
7. In Symbol tree imports on the left, right click libc.so.6 and `Create External Location`
8. Add desired symbol + address of desired function. Set symbol type to external function
9. Right click on the function in the Symbol tree and `Edit Function` and fix up the type
10. export protobuf spec for given function
11. Add additional symbols, semicolon separated
12. `irene3-patchir-codegen --spec input.pb --mlir_out output.mlir`
13. `irene3-examine-spec -spec input.proto | grep ${TARGET_ADDRESS} | awk '{print $3}'`
14. `irene3-patchlang-lift -mlir_in output.mlir -target_uid <uid> >output.patchlang`
15. edit patch lang
16. `irene3-patchlang2patchir --input output.patchlang --output patch.mlir`
17. `irene3-patchir-compiler --patch_def patch.mlir --region-uid <uid> --cpu cortex-a8 --json_metadata out.json --out out.S`
18. `python patch_assembler/assembler.py --in_assembly out.S --metadata out.json lib.so --out lib.patched.so`
