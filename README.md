# IRENE-3

IRENE-3 is a decompilation tool that ties together anvill, remill, rellic, and ghidra to lift compileable llvm and C from a binary.

The decompilation provides syncrhonization between Ghidra and VSCode allowing for seamless navigation between source and binary. 

Goals
* Heuristics/learned information should be explicitly recorded in a form that users can modify 
* If there is missing information, the decompiler should error and let the user know what was missing from the specification
* Encode a chain of IR transformations that are indpendent of analysis, they encode the facts required to jump up one IR link.
* Provide support for adding new IR layers, with new specification requirements at arbitrary points within the chain.

Anti-Goals
* Supporting multiple concurrent users
* Being a distributed system
* Encoding decisions and heuristics into the core lifting pipeline
* Performance (Currently)
* Provide UI components outside of typical RE workflow

## Repository Layout

* `data_specifications` contains schemas for specifications of analysis information used to transform IRs. Currently, these schemas are expressed in protobuf
* `irene-ghidra` a ghidra plugin for exporting first layer specifications from Ghidra to bootstrap decompilation.
* `bin` contains C++ code for different binary utilities
* `lib` contains C++ code for the library
* `include` contains public headers for the library
* `cmake` contains CMake helpers

## IRENE Ghidra Development Instructions

Install just with `brew install just` and get a copy of Ghidra (Currently 10.1.5) from [Ghidra Releases](https://github.com/NationalSecurityAgency/ghidra/releases)

Then add gradle.properties to the assume unchanged list with `git update-index --assume-unchanged gradle.properties`

Afterwards you can modify gradle.properties with the path to your Ghidra install without having those changes pushed to main.

You can also add the GHIDRA_INSTALL_DIR to your environment variables, but your IDE may not pick the environment variable up depending on your situation.  

`just test-irene-ghidra` will run the unit tests for the plugin. 

Provided your `gradle.properties` file is up to date any Scala IDE should work without any setup. Given the mixing of Java and Scala an IDE that supports both is ideal. Vscode with Metals + the Java extension pack works well. 

## IRENE C++ Development Instructions

* Install `just` with your package manager
* Install latest version of `cmake`
* Install `clang-14` and `lld-14`
* Install `g++-multilib`
* Install `ninja-build`
* Install or compile `cxx-common`
* Initialize submodules with `just git-submodules`
* Set path to `VCPKG_ROOT` in `.env`
* Set path to `CMAKE_INSTALL_PREFIX` in `.env`

`just build-irene3-cpp` will compile the C++ project
`just install-irene3-cpp` will compile and install the C++ project to the specified install prefix
`just test-irene3-cpp` will compile and install the C++ project to the specified install prefix and do a simple test for output on some sample specifications

