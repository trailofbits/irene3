# IRENE-3

IRENE-3 is a decompilation tool that ties together Anvill, Remill, Rellic, and Ghidra to emit compileable LLVM IR and C from a binary.

We envision IRENE-3 as an interactive tool that synchronizes a binary view in Ghidra and a source-code view in VSCode, allowing for seamless navigation between source and binary. 

Goals
* Heuristics/learned information should be explicitly recorded in a form that users can inspect and modify
* The decompiler should not guess: missing or incomplete information should abort the decompilation process, while letting the user know what is missing from the specification
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
* `irene-ghidra` a Ghidra plugin for exporting first layer specifications from Ghidra to bootstrap decompilation.
* `bin` contains C++ code for different binary utilities
* `lib` contains C++ code for the library
* `include` contains public headers for the library
* `scripts` contains miscellaneous scripts for installing prerequisites and running tests
* `cmake` contains CMake helpers

## IRENE Build Instructions (Docker)

### Set up Binary Ninja AMP License
```sh
export BN_LICENSE=$(cat ./licenses/amp-program-wide-headless-binja.json)
```

### Build Docker Image

```sh
just build-docker
```

### Decompile a test specification to C
```sh
docker run -it -v $PWD/tests/specs:/app \
    irene3:latest \
    /opt/trailofbits/bin/irene3-decompile \
    -spec /app/test-hello-elf-x64.spec.json \
    -c_out -
```

### Decompile a test specification to LLVM IR
```sh
docker run -it -v $PWD/tests/specs:/app \
    irene3:latest \
    /opt/trailofbits/bin/irene3-decompile \
    -spec /app/test-hello-elf-x64.spec.json \
    -c_out /dev/null \
    -ir_out -
```
## IRENE Build Instructions (Native)

### Set up Binary Ninja AMP License
```sh
export BN_LICENSE=$(cat ./licenses/amp-program-wide-headless-binja.json)
```
### Ensure git user + email is setup
```sh
if ! git config --global --get user.email; then
    git config --global user.email "root@localhost"
fi
if ! git config --global --get user.name; then
    git config --global user.name "root"
fi
```
#### Install prerequisites
```sh
./scripts/install-prereqs.sh
just install-prereqs
```
### Build + Install IRENE3
```sh
just install-irene3
```
### Verify Installation
To verify installation worked, first we run the unit tests:
```sh
# test the IRENE3 Ghidra Plugin
just test-irene3-ghidra

# test the C++ Decompilation Portion
just test-irene3-cpp
```

### Decompile a Binary to C
```sh
just decompile-binary ./tests/bins/test-hello-elf-x64 o.c
just decompile-binary-ll ./tests/bins/test-hello-elf-x64 o.ll
just decompile-spec ./tests/specs/test-hello-elf-x64.spec.json o.c
just decompile-spec-ll ./tests/specs/test-hello-elf-x64.spec.json o.ll
```

## IRENE Ghidra Development Instructions

Install `just` with `brew install just` and get a copy of Ghidra (Currently 10.1.5) from [Ghidra Releases](https://github.com/NationalSecurityAgency/ghidra/releases)

Then add `gradle.properties` to the assume unchanged list with `git update-index --assume-unchanged gradle.properties`

Afterwards you can modify `gradle.properties` with the path to your Ghidra install without having those changes pushed to main.

You can also set the `GHIDRA_INSTALL_DIR` environment variable, but your IDE may not recognize the environment variable. 

`just test-irene3-ghidra` will run the unit tests for the plugin. 

Provided your `gradle.properties` file is up to date any Scala IDE should work without any setup. Given the mixing of Java and Scala an IDE that supports both is ideal. VScode with Metals + the Java extension pack works well. 

## IRENE C++ Development Instructions

* Run `./scripts/install-prereqs.sh` to install `just`
* Install the rest of the dependencies with `just install-prereqs`
* Install BinaryNinja and install it to the `python3` path
* (Optional) Set path to `CMAKE_INSTALL_PREFIX` in `.env`, this determines where the compiled artifacts will be installed to
* (M1 Only) Set path to `VCPKG_ROOT` to compiled `cxx-common`
* Build and install IRENE3 `just install-irene3`

`just build-irene3-cpp` will compile the C++ project
`just install-irene3-cpp` will compile and install the C++ project to `./install/bin` the specified install prefix
`just test-irene3-cpp` will do a simple test for output on some sample specifications and a simple roundtrip test
