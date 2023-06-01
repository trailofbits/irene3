set dotenv-load
LLVM_VERSION := "16"
CXX_COMMON_VERSION := "0.4.1"
CXX_COMMON_ARCH := if "x86_64" == arch() { "amd64" } else { "arm64" }
CXX_COMMON_NAME := if "macos" == os() {
      "vcpkg_macos-11_llvm-" + LLVM_VERSION + "_xcode-13.0_" + CXX_COMMON_ARCH
    } else {
      "vcpkg_ubuntu-22.04_llvm-" + LLVM_VERSION + "_" + CXX_COMMON_ARCH
    }
CXX_COMMON_URL := "https://github.com/lifting-bits/cxx-common/releases/download/v" + CXX_COMMON_VERSION + "/" + CXX_COMMON_NAME + ".tar.xz"

CMAKE_OS := os()
CMAKE_ARCH := if "macos" == "{{CMAKE_OS}}" { "universal" } else { arch() }
CMAKE_VERSION := "3.24.2"
CMAKE_DIR := "cmake-"+CMAKE_VERSION+"-"+CMAKE_OS+"-"+CMAKE_ARCH

GHIDRA_TAG := "amp-ghidra-v0.0.2-rc2"
GHIDRA_MAJOR_VERSION := "10.3_DEV"
GHIDRA_MINOR_VERSION := "20230505"

VIRTUAL_ENV := env_var_or_default("VIRTUAL_ENV", justfile_directory() + "/venv")
DOCKER_CMD := "docker"

# Add local cmake to path
export PATH := env_var("PATH") + ":" + justfile_directory() + "/deps/" + CMAKE_DIR + "/bin"
# Use clang (apple clang) on MacOS, otherwise clang-{{LLVM_VERSION}}
export CC := if "macos" == os() {"clang"} else { "clang-" + LLVM_VERSION }
export CXX := if "macos" == os() {"clang++"} else { "clang++-" + LLVM_VERSION }
VCPKG_OS := if "macos" == os() { "osx" } else { "linux" }
VCPKG_ARCH := if "x86_64" == arch() { "x64" } else { "arm64" }
export VCPKG_TARGET_TRIPLET := env_var_or_default("VCPKG_TARGET_TRIPLET", VCPKG_ARCH + "-" + VCPKG_OS + "-rel")
export CMAKE_TOOLCHAIN_FILE := env_var_or_default("CMAKE_TOOLCHAIN_FILE", justfile_directory() + "/deps/" + CXX_COMMON_NAME + "/scripts/buildsystems/vcpkg.cmake")
export CMAKE_INSTALL_PREFIX := env_var_or_default("CMAKE_INSTALL_PREFIX", justfile_directory() + "/install")
export GHIDRA_INSTALL_DIR := env_var_or_default("GHIDRA_INSTALL_DIR", justfile_directory() + "/deps/ghidra")

default:
    @just --list

build-irene3-ghidra: install-ghidra
    ./gradlew build -PIRENEGHIDRA_AUTO_REMOVE

install-irene3-ghidra:
    ./gradlew install -PIRENEGHIDRA_AUTO_REMOVE

run-ghidra: install-irene3-ghidra
    ./deps/ghidra/ghidraRun

build-docker:
    {{DOCKER_CMD}} build -t irene3 {{justfile_directory()}} -f Dockerfile

lint-irene3-ghidra:
    ./gradlew spotlessCheck

format-irene3-ghidra:
    ./gradlew spotlessApply

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

setup-venv:
    #!/usr/bin/env bash
    if [[ ! -f "${VIRTUAL_ENV}/pyenv.cfg" ]]; then
        python3 -m venv "${VIRTUAL_ENV}"
    fi

install-prereqs: install-cxx-common install-ghidra install-cmake install-clang install-ninja setup-venv
    #!/usr/bin/env bash
    if [[ "linux" == "{{os()}}" ]]; then
        set -x
        if [ "$(uname -m)" = "aarch64" ]; then dpkg --add-architecture armhf; fi
        sudo apt-get update
        sudo apt-get install -y --no-install-recommends \
          "$( [ "$(uname -m)" != "aarch64" ] && echo "g++-multilib")" \
          "$( [ "$(uname -m)" = "aarch64" ] && echo "libstdc++-*-dev:armhf")"
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
    if [[ "$(awk -F'=' '/build\.date\.short/{print $2}' ./deps/ghidra/Ghidra/application.properties 2>/dev/null)" != "{{GHIDRA_MINOR_VERSION}}" ]]; then
      mkdir -p deps
      echo "Downloading Ghidra"
      curl -sL \
      https://github.com/trail-of-forks/ghidra/releases/download/{{GHIDRA_TAG}}/ghidra_{{GHIDRA_MAJOR_VERSION}}_{{GHIDRA_MINOR_VERSION}}.zip \
      --output deps/ghidra.zip
      echo "Extracting Ghidra"
      rm -rf ./deps/ghidra ./deps/ghidra_{{GHIDRA_MAJOR_VERSION}}
      cd deps && unzip -qq ghidra.zip && mv ghidra_{{GHIDRA_MAJOR_VERSION}} ghidra && cd ..
    fi
    echo "GHIDRA_INSTALL_DIR={{justfile_directory()}}/deps/ghidra" >{{justfile_directory()}}/gradle.properties

format-cpp:
    find bin/ lib/ include/ -name "*.cpp" -exec clang-format -i {} \;

format-cmake:
    find . -not -path './vendor/**' -not -path './builds/**' -name "CMakeLists.txt" -exec cmake-format --config=.cmake-format.py -i {} \;

git-submodules:
    #!/usr/bin/env bash
    if [[ -d .git ]]; then
        git submodule update --init --recursive
    fi

build-remill-cpp: git-submodules
    mkdir -p builds
    cmake -S vendor/remill -B builds/remill-build -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}" -DVCPKG_TARGET_TRIPLET="${VCPKG_TARGET_TRIPLET}" -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} && cmake --build builds/remill-build -j $(nproc)

install-remill: build-remill-cpp
    mkdir -p builds
    cmake --build builds/remill-build --target install

build-irene3-cpp: install-remill
    cmake -S . -DCMAKE_TOOLCHAIN_FILE="${CMAKE_TOOLCHAIN_FILE}" -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DVCPKG_TARGET_TRIPLET="${VCPKG_TARGET_TRIPLET}" -DIRENE3_ENABLE_INSTALL=ON --preset ninja-multi-vcpkg  && cmake --build --preset ninja-vcpkg-deb -j $(nproc)

install-irene3: build-irene3-cpp
    cmake --build --preset ninja-vcpkg-deb --target install

test-irene3-cpp: install-irene3
    cmake --build --preset ninja-vcpkg-deb --target test

check-irene3-decompile:
    #!/usr/bin/env bash
    if [[ ! -e "${CMAKE_INSTALL_PREFIX}/bin/irene3-decompile" ]]; then
        echo "IRENE3 not installed"
        exit 1
    fi
    exit 0

decompile-spec spec out_c: check-irene3-decompile
    "${CMAKE_INSTALL_PREFIX}/bin/irene3-decompile" -spec {{spec}} -c_out {{out_c}}

decompile-spec-ll spec out_ir: check-irene3-decompile
    "${CMAKE_INSTALL_PREFIX}/bin/irene3-decompile" -spec {{spec}} -c_out /dev/null -ir_out {{out_ir}}

clean:
    rm -rf install builds venv irene-ghidra/dist irene-ghidra/build

build-docker-eval: build-docker
    {{DOCKER_CMD}} build -t irene3-eval . -f eval.Dockerfile
