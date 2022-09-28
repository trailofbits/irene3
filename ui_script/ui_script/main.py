import sys
import tempfile
import os
import subprocess
import argparse


class DecompilationJob:
    def __init__(self, bts: str, decomp_exec_path: str) -> None:
        self.bts = bts
        self.decomp_exec_path = decomp_exec_path
        self.tmpdir = tempfile.TemporaryDirectory()

    def __enter__(self):
        self.wdir = self.tmpdir.__enter__()
        return self

    def __exit__(self, exc, value, tb):
        self.tmpdir.__exit__(exc, value, tb)

    def get_bin_path(self):
        return os.path.join(self.wdir, "target_binary")

    def get_spec_path(self):
        return os.path.join(self.wdir, "target.spec")

    def specify_binary(self):
        # TODO this is hacky
        cmd = [sys.executable, "-m", "anvill", "--bin_in",
               self.get_bin_path(), "--spec_out", self.get_spec_path()]
        subprocess.run(cmd, check=True)

    def decompile_binary(self) -> bytes:
        cmd = [self.decomp_exec_path, "-spec", self.get_spec_path()]
        completed = subprocess.run(cmd, check=True, stdout=subprocess.PIPE)
        return completed.stdout

    def write_binary(self):
        with open(self.get_bin_path(), "wb") as f:
            f.write(self.bts)


def main():
    parser = argparse.ArgumentParser("UI Output")
    parser.add_argument(
        "decomp_binary", help="path to the decomp binary to run")
    args = parser.parse_args()
    input_str = sys.stdin.buffer.read()
    with DecompilationJob(input_str, args.decomp_binary) as decomp_job:
        decomp_job.write_binary()
        # TODO(Ian) split anvill main into something useful that can be invoked programatically
        decomp_job.specify_binary()
        sys.stdout.buffer.write(decomp_job.decompile_binary())


if __name__ == "__main__":
    main()
