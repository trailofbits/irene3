set dotenv-load
LLVM_VERSION := "14"
CXX_COMMON_VERSION := "0.2.10"
CXX_COMMON_ARCH := if "x86_64" == arch() { "amd64" } else { "arm64" }
CXX_COMMON_NAME := if "macos" == os() {
      "vcpkg_macos-11_llvm-" + LLVM_VERSION + "_xcode-13.0_" + CXX_COMMON_ARCH
    } else {
      "vcpkg_ubuntu-20.04_llvm-" + LLVM_VERSION + "_" + CXX_COMMON_ARCH
    }
CXX_COMMON_URL := "https://github.com/lifting-bits/cxx-common/releases/download/v" + CXX_COMMON_VERSION + "/" + CXX_COMMON_NAME + ".tar.xz"

CMAKE_OS := os()
CMAKE_ARCH := if "macos" == "{{CMAKE_OS}}" { "universal" } else { arch() }
CMAKE_VERSION := "3.24.2"
CMAKE_DIR := "cmake-"+CMAKE_VERSION+"-"+CMAKE_OS+"-"+CMAKE_ARCH

VIRTUAL_ENV := env_var_or_default("VIRTUAL_ENV", justfile_directory() + "/venv")
BINJA_PATH := env_var_or_default("BINJA_PATH", justfile_directory() + "/deps/binaryninja")
BN_LICENSE := `cat "./scripts/amp-program-headless-license.json"`
DOCKER_CMD := "docker"

# Add local cmake to path
export PATH := env_var("PATH") + ":" + justfile_directory() + "/deps/" + CMAKE_DIR + "/bin"
# Use clang (apple clang) on MacOS, otherwise clang-{{LLVM_VERSION}}
export CC := if "macos" == os() {"clang"} else { "clang-" + LLVM_VERSION }
export CXX := if "macos" == os() {"clang++"} else { "clang++-" + LLVM_VERSION }
export VCPKG_ROOT := env_var_or_default("VCPKG_ROOT", justfile_directory() + "/deps/" + CXX_COMMON_NAME)
export CMAKE_INSTALL_PREFIX := env_var_or_default("CMAKE_INSTALL_PREFIX", justfile_directory() + "/install")

default:
    @just --list

build-irene3-ghidra: install-ghidra
    ./gradlew build -PIRENEGHIDRA_AUTO_REMOVE

install-irene3-ghidra:
    ./gradlew install -PIRENEGHIDRA_AUTO_REMOVE

run-ghidra: install-irene3-ghidra
    ./deps/ghidra/ghidraRun

build-docker:
    {{DOCKER_CMD}} build -t irene3 {{justfile_directory()}} -f Dockerfile --build-arg BN_LICENSE="${BN_LICENSE}"

test-irene3-ghidra:
    ./gradlew test

install-cxx-common:
    #!/usr/bin/env bash
    if [[ ! -f "deps/cxx-common.tar.xz" ]]
    then
        mkdir -p deps
        echo "Downloading {{CXX_COMMON_NAME}}.tar.xz to deps/cxx-common.tar.xz"
        curl -sL "{{CXX_COMMON_URL}}" -o deps/cxx-common.tar.xz
        echo "Extracting cxx-common"
        tar -xJf deps/cxx-common.tar.xz -C deps
    fi

install-ninja:
    #!/usr/bin/env bash
    if [[ "macos" == "{{os()}}" ]]; then
        brew install ninja
    elif [[ "linux" == "{{os()}}" ]]; then
        sudo apt-get install -y ninja-build
    else
       echo "Unsupported os: {{os()}}"
       exit 1
    fi

install-prereqs: install-cxx-common install-ghidra install-cmake install-clang install-ninja
    #!/usr/bin/env bash
    if [[ "linux" == "{{os()}}" ]]; then
        set -x
        if [ "$(uname -m)" = "aarch64" ]; then dpkg --add-architecture armhf; fi
        sudo apt-get update
        sudo apt-get install -y --no-install-recommends \
          "$( [ "$(uname -m)" != "aarch64" ] && echo "g++-multilib")" \
          "$( [ "$(uname -m)" = "aarch64" ] && echo "libstdc++-*-dev:armhf")" \
          python3-venv
    fi

install-clang:
    #!/usr/bin/env bash
    # sanity check: do not overwrite a clang-{{LLVM_VERSION}} installation
    if ! command -v "clang-{{LLVM_VERSION}}" &>/dev/null
    then
         if [[ "{{os()}}" == "linux" ]]; then
             mkdir -p deps
             curl -sL https://apt.llvm.org/llvm.sh -o deps/llvm.sh
             pushd deps 2>/dev/null && chmod +x llvm.sh && sudo ./llvm.sh {{LLVM_VERSION}} && popd 2>/dev/null
             sudo apt install -y lld-{{LLVM_VERSION}}
         else
             echo "clang-{{LLVM_VERSION}} must be installed manually on {{os()}}"
         fi
    else
        echo "clang-{{LLVM_VERSION}} already installed"
    fi

install-cmake:
    #!/usr/bin/env bash
    if [[ ! -f "deps/cmake.tar.gz" ]]; then
        mkdir -p deps
        CMAKE_FILE={{CMAKE_DIR}}.tar.gz
        echo "Downloading ${CMAKE_FILE} to deps/cmake.tar.gz"
        curl -sL https://github.com/Kitware/CMake/releases/download/v{{CMAKE_VERSION}}/${CMAKE_FILE} \
             -o deps/cmake.tar.gz >/dev/null
        tar -xzf deps/cmake.tar.gz -C deps
        echo "Validating CMake Installation"
        cmake --version
    fi

install-ghidra:
    #!/usr/bin/env bash
    if [[ ! -d "deps/ghidra" ]]; then
         mkdir -p deps
         echo "Downloading Ghidra"
         curl -sL \
         https://github.com/NationalSecurityAgency/ghidra/releases/download/Ghidra_10.1.5_build/ghidra_10.1.5_PUBLIC_20220726.zip \
         --output deps/ghidra.zip
         echo "Extracting Ghidra"
         cd deps && unzip -qq ghidra.zip && mv ghidra_10.1.5_PUBLIC ghidra && cd ..
         echo "GHIDRA_INSTALL_DIR={{justfile_directory()}}/deps/ghidra" >./gradle.properties
    fi

format-cpp:
    find bin/ lib/ include/ -name "*.cpp" -exec clang-format -i {} \;

format-cmake:
    find . -not -path './vendor/**' -not -path './builds/**' -name "CMakeLists.txt" -exec cmake-format --config=.cmake-format.py -i {} \;

git-submodules:
    git submodule update --init --recursive

build-remill-cpp: git-submodules
    mkdir -p deps
    cmake -S vendor/remill -B deps/remill-build -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DVCPKG_ROOT=${VCPKG_ROOT} && cmake --build deps/remill-build -j $(nproc)

install-remill: build-remill-cpp
    mkdir -p deps
    cmake --build deps/remill-build --target install

setup-venv:
    [ -f {{VIRTUAL_ENV}}/bin/python3 ] || python3 -m venv {{VIRTUAL_ENV}} && "{{VIRTUAL_ENV}}/bin/python3" -m ensurepip --upgrade

install-binja-headless: setup-venv
    #!/usr/bin/env bash
    source "{{VIRTUAL_ENV}}/bin/activate"
    if ! "{{VIRTUAL_ENV}}/bin/python3" -c "import binaryninja; print(binaryninja.core_version())"; then
        if [[ "linux" == "{{os()}}" ]] && [[ "x86_64" == "{{arch()}}" ]]; then
            if [[ ! -f "{{BINJA_PATH}}/api_REVISION.txt" ]]; then
                if [[ ! -f "deps/binja.zip" ]]; then
                    echo "Downloading Binary Ninja"
                    mkdir -p ./deps
                    "{{VIRTUAL_ENV}}/bin/pip3" install requests
                    "{{VIRTUAL_ENV}}/bin/python3" ./scripts/download_headless.py --dev --output deps/binja.zip -i -d "{{parent_directory(BINJA_PATH)}}"
                else
                    echo "Extracting binary ninja"
                    unzip ./deps/binja.zip -d "{{BINJA_PATH}}"
                fi
            else
                echo "Using existing install: $(cat {{BINJA_PATH}}/api_REVISION.txt)"
            fi
            "{{VIRTUAL_ENV}}/bin/python3" {{BINJA_PATH}}/scripts/install_api.py
        elif [[ "macos" == "{{os()}}" ]]; then
            "{{VIRTUAL_ENV}}/bin/python3" "/Applications/Binary Ninja.app/Contents/Resources/scripts/install_api.py"
        else
            echo "Automatic install of binary ninja python not supported"
            echo "Skipping install"
        fi
    fi

install-anvill-python: install-binja-headless
    #!/usr/bin/env bash
    cd vendor/anvill
    "{{VIRTUAL_ENV}}/bin/python3" ./setup.py install -f >/dev/null

build-irene3-cpp: install-remill
    cmake -S . -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DVCPKG_ROOT=${VCPKG_ROOT} -DIRENE3_ENABLE_INSTALL=ON --preset ninja-multi-vcpkg  && cmake --build --preset ninja-vcpkg-deb -j $(nproc)

install-irene3: build-irene3-cpp install-anvill-python
    cmake --build --preset ninja-vcpkg-deb --target install

test-irene3-cpp: install-irene3 install-anvill-python
    cmake --build --preset ninja-vcpkg-deb --target test

generate-spec binary out_json:
    #!/usr/bin/env bash
    "{{VIRTUAL_ENV}}/bin/python3" -m anvill --bin_in {{binary}} --spec_out {{out_json}} --entrypoint main --ignore_no_refs

temp_json := uuid() + ".json"

check-irene3-decompile:
    #!/usr/bin/env bash
    if [[ ! -e "${CMAKE_INSTALL_PREFIX}/bin/irene3-decompile" ]]; then
        echo "IRENE3 not installed"
        exit 1
    fi
    exit 0

decompile-binary binary out_c: (generate-spec binary temp_json) check-irene3-decompile
    "${CMAKE_INSTALL_PREFIX}/bin/irene3-decompile" -spec {{temp_json}} -c_out {{out_c}}
    rm -f {{temp_json}}

decompile-binary-ll binary out_ir: (generate-spec binary temp_json) check-irene3-decompile
    "${CMAKE_INSTALL_PREFIX}/bin/irene3-decompile" -spec {{temp_json}} -c_out /dev/null -ir_out {{out_ir}}
    rm -f {{temp_json}}

decompile-spec spec out_c: check-irene3-decompile
    "${CMAKE_INSTALL_PREFIX}/bin/irene3-decompile" -spec {{spec}} -c_out {{out_c}}

decompile-spec-ll spec out_ir: check-irene3-decompile
    "${CMAKE_INSTALL_PREFIX}/bin/irene3-decompile" -spec {{spec}} -c_out /dev/null -ir_out {{out_ir}}

clean:
    rm -rf install builds venv
