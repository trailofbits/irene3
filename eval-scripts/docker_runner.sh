#!/bin/bash

python eval_scripts/run_differential_test.py -v --ghidra_path /app/deps/ghidra/ --csmith_path /builds/csmith/ --extra_compiler_flags "-target arm-linux-gnueabihf $3" --irene_eval /opt/trailofbits/bin/irene3-eval-tool  --runtime_env "qemu-arm -L /usr/arm-linux-gnueabihf/" -n $1 --compiler_path clang-17 $2
