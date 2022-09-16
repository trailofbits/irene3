set dotenv-load

test-irene-ghidra:
    ./gradlew test

format-cpp:
    find bin/ lib/ include/ -name "*.cpp" -exec clang-format -i {} \;

format-cmake:
    find . -not -path './vendor/**' -not -path './builds/**' -name "CMakeLists.txt" -exec cmake-format --config=.cmake-format.py -i {} \;

git-submodules:
    git submodule update --init --recursive

build-remill-cpp:
    cmake -S vendor/remill -B remill-build -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DVCPKG_ROOT=${VCPKG_ROOT} && cmake --build remill-build -j $(nproc)

install-remill: build-remill-cpp
    cmake --build remill-build --target install

build-irene3-cpp:
    cmake -S . -DCMAKE_INSTALL_PREFIX=${CMAKE_INSTALL_PREFIX} -DVCPKG_ROOT=${VCPKG_ROOT} -DIRENE3_ENABLE_INSTALL=ON --preset ninja-multi-vcpkg && cmake --build --preset ninja-vcpkg-relwithdebinfo -j $(nproc)

install-irene3: build-irene3-cpp
    cmake --build --preset ninja-vcpkg-relwithdebinfo --target install

test-irene3-cpp: install-irene3 install-remill
    cmake --build --preset ninja-vcpkg-relwithdebinfo --target test
