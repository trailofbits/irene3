# Instructions
## Files
 * chal9-program_c.gcc.vuln.gzf
   * Ghidra database for challenge 9 with fixups for challenge 9 `transport_handler`
 * chal9_backup_spec_transport_handler.pb
   * Protobuf specification export for challenge 9 `transport_handler`
 * ghidra_10.1.5_PUBLIC_20221011_irene-ghidra.zip
   * IRENE3 Ghidra plugin for generating protobuf specifications
 * irene3.tar.gz
   * Docker container archive which contains a precompiled version of `irene3-decompile` with all the required dependencies
 * shallow_irene.zip
   * Shallow clone of the source code of our tool

## Ghidra instructions
* Install Ghidra 10.1.5
* Install Ghidra plugin
  * File -> Install Extensions -> Green plus sign on to right -> Path to Ghidra plugin (ghidra_10.1.5_PUBLIC_20221011_irene-ghidra.zip)
  * Restart Ghidra
* Load Binary
  * Fix inaccuracies with Ghidra, fix types, name symbols
* Run export specification script
  * Navigate to function of interest
  * Script Manager -> `_NEW_` -> Specify Single Function
  * Save export file to somewhere, this file is a protobuf file that will get loaded into our tool, `irene3-decompile`

## IRENE3 Instructions
* Install Docker
* Load Docker image
  * `docker load -i irene3.tar.gz` 
* Start container
  * `docker run -it -v <DIRECTORY_CONTAINING_PROTOBUF>:/workspace irene3 /bin/bash`
* Run decompiler inside container
  * Get C output
    * `irene3-decompile -spec <path-to-protobuf> -c_out o.c`
  * Get IR output
    * `irene3-decompile -spec <path-to-protobuf> -ir_out o.ll`
  * Get BC output
    * `irene3-decompile -spec <path-to-protobuf> -bc_out o.bc`
