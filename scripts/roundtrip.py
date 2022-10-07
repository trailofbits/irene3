#!/usr/bin/env python3

import unittest
import subprocess
import argparse
import shutil
import tempfile
import os
import sys


class RunError(Exception):
    def __init__(self, msg):
        self.msg = msg

    def __str__(self):
        return str(self.msg)

def write_command_log(cmd_description, cmd_exec, ws):
    with open(os.path.join(ws, "commands.log"), "a") as cmdlog:
        if cmd_description:
            cmdlog.write(f"# {cmd_description}\n")
        cmdlog.write(f"{cmd_exec}\n")

def run_cmd(cmd, timeout, description, ws):
    try:
        exec_cmd = f"{' '.join(cmd)}"
        sys.stdout.write(f"Running: {exec_cmd}\n")
        write_command_log(description, exec_cmd, ws)
        p = subprocess.run(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=timeout,
            universal_newlines=True,
        )
    except FileNotFoundError as e:
        raise RunError('Error: No such file or directory: "' + e.filename + '"')
    except PermissionError as e:
        raise RunError('Error: File "' + e.filename + '" is not an executable.')

    return p

def compile(self, clang, input, output, timeout, ws, options=None):
    cmd = []
    cmd.append(clang)
    if options is not None:
        cmd.extend(options)
    cmd.extend([input, "-o", output])
    p = run_cmd(
        cmd, timeout, description="Original source Clang compile command", ws=ws)

    if p.returncode != 0:
        with open(input) as f:
            print(f)

    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during compilation: %s" % p.stderr
    )
    self.assertEqual(p.returncode, 0, "clang failure")

    return p

def specify(self, specifier, input, output, timeout, ws):
    cmd = list(specifier) if isinstance(specifier, list) else [specifier]
    cmd.extend(["--bin_in", input])
    cmd.extend(["--spec_out", output])
    cmd.extend(["--entrypoint", "main"])
    cmd.extend(["--ignore_no_refs"])

    p = run_cmd(cmd, timeout, description="Spec generation command", ws=ws)

    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during specification: %s" % p.stderr
    )
    self.assertEqual(p.returncode, 0, "specifier failure: %s" % p.stderr)
    return p

def decompile(self, irene3, input, output, timeout, ws):
    cmd = [irene3]
    cmd.extend(
        ["--minloglevel", "3", "-spec", input, "-c_out", output]
    )
    p = run_cmd(cmd, timeout, description="Decompilation command", ws=ws)

    self.assertEqual(
        len(p.stderr), 0, "errors or warnings during decompilation: %s" % p.stderr
    )
    self.assertEqual(p.returncode, 0, "irene3-decomp failure: %s" % p.stderr)
    return p

def roundtrip(self, specifier, decompiler, filename, testname, clang, timeout, workspace):
    # Python refuses to add delete=False to the TemporaryDirectory constructor
    # with tempfile.TemporaryDirectory(prefix=f"{testname}_", dir=workspace) as tempdir:
    tempdir = tempfile.mkdtemp(prefix=f"{testname}_", dir=workspace)

    compiled = os.path.join(tempdir, f"{testname}_compiled")
    compile(self, clang, filename, compiled, timeout, tempdir)

    # capture binary run outputs
    compiled_output = run_cmd(
        [compiled], timeout, description="capture compilation output", ws=tempdir)

    rt_json = os.path.join(tempdir, f"{testname}_rt.json")
    specify(self, specifier, compiled, rt_json, timeout, tempdir)

    rt_c = os.path.join(tempdir, f"{testname}_rt.c")
    decompile(self, decompiler, rt_json, rt_c, timeout, tempdir)

    rebuilt = os.path.join(tempdir, f"{testname}_rebuilt")
    compile(self, clang, rt_c, rebuilt, timeout, tempdir, ["-Wno-everything"])
    # capture outputs of binary after roundtrip
    rebuilt_output = run_cmd(
        [rebuilt], timeout, description="Capture binary output after roundtrip", ws=tempdir)

    # Clean up tempdir if no workspace specified
    # otherwise keep it for debugging purposes
    if not workspace:
        shutil.rmtree(tempdir)

    self.assertEqual(compiled_output.stderr,
                     rebuilt_output.stderr, "Different stderr")
    self.assertEqual(compiled_output.stdout,
                     rebuilt_output.stdout, "Different stdout")
    self.assertEqual(compiled_output.returncode,
                     rebuilt_output.returncode, "Different return code")

class TestRoundtrip(unittest.TestCase):
    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("irene3", help="path to irene3-decomp")
    parser.add_argument("tests", help="path to test directory")
    parser.add_argument("clang", help="path to clang")
    parser.add_argument("workspace", nargs="?", default=None,
                        help="Where to save temporary unit test outputs")
    parser.add_argument("-t", "--timeout", help="set timeout in seconds", type=int)

    args = parser.parse_args()

    def test_generator(path, test_name):
        def test(self):
            specifier = [sys.executable, "-m", "anvill"]
            roundtrip(self, specifier, args.irene3, path, test_name, args.clang, args.timeout, args.workspace)

        return test

    for item in os.scandir(args.tests):
        if item.is_file():
            name, ext = os.path.splitext(item.name)
            # Allow for READMEs and data/headers
            if name.startswith("test-"):
                test_name = name.replace("-", "_")
                test = test_generator(item.path, test_name)
                setattr(TestRoundtrip, test_name, test)

    unittest.main(argv=[sys.argv[0]])
