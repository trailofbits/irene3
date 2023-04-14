import argparse
import os
import subprocess
from typing import Optional
import logging
from enum import Enum
import re
import random
import tempfile
import shutil
import multiprocessing
import tqdm
import errno


import signal
import functools

class TimeoutError(Exception):
    pass

def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wrapper

    return decorator

"""
Exposed command to generate one csmith test case and differentially test a recompiled binary.
"""


class Config:
    def __init__(self, args) -> None:
        self.ghidra_path = args.ghidra_path
        self.csmith_path = args.csmith_path
        self.extra_flags = args.extra_compiler_flags.split()
        self.num_test_cases = 1
        # stuck with clang since we need to do llvm... tail calling blocks could help a bit
        self.compiler_path = args.compiler_path
        self.irene_eval = args.irene_eval
        self.runner = args.runtime_env.split()


class TestCaseRes(Enum):
    SUCCESS = 1
    FAILED = 2
    INVALID = 3


class TestCase:
    def __init__(self, conf: Config, wdir: str, id: int, logging_level) -> None:
        self.conf = conf
        self.tc_name = f"test-case{id}"
        self.log_level = logging_level

        self.tdir = os.path.join(wdir, self.tc_name)
        os.makedirs(self.tdir, exist_ok=False)
        self.logfile_path = os.path.join(self.tdir, f"{self.tc_name}.log")
        self.stderr_path = os.path.join(self.tdir, "stderr")
        self.stdout_path = os.path.join(self.tdir, "stdout")


        self.c_file_path = os.path.join(self.tdir, "test.c")
        self.binary_path = os.path.join(self.tdir, "test-bin")
        self.ll_compiled_path = os.path.join(self.tdir, "test-compiled.ll")
        self.ll_decomp_path = os.path.join(self.tdir, "test-decomp.ll")
        self.csmith_ll_modified = os.path.join(
            self.tdir, "test-csmith-modified.ll")

        self.spec_path = os.path.join(self.tdir, "test-spec.pb")
        self.target_fname = None
        self.recompiled_binary = os.path.join(self.tdir, "test-bin-recompiled")
        self.success_dir = os.path.join(wdir, "success")
        os.makedirs(self.success_dir, exist_ok=True)
        self.fail_dir = os.path.join(wdir, "fail")
        os.makedirs(self.fail_dir, exist_ok=True)
        self.invalid_dir = os.path.join(wdir, "invalid")
        os.makedirs(self.invalid_dir, exist_ok=True)

    def init_logging(self):
        self.logger = logging.getLogger(self.tc_name)
        self.logger.setLevel(self.log_level)
        self.fh = logging.FileHandler(self.logfile_path)
        self.logger.handlers.clear()
        self.logger.addHandler(self.fh)

    def generate_c_file(self):
        csmith_bin = os.path.join(self.conf.csmith_path, "src", "csmith")
        with open(self.c_file_path, "w") as f:
            subprocess.run([csmith_bin, "--no-inline-function"],
                           stdout=f, check=True)
            self.logger.info(f"Saved new tc file to {self.c_file_path}")

    def get_compile_args(self, ouput_name, input_names):
        return [self.conf.compiler_path,
                f"-I{self.conf.csmith_path}/runtime", "-fno-inline-functions", "-gdwarf-4"] + self.conf.extra_flags + input_names + ["-o", ouput_name]

    def compile_tc_to_llvm(self):
        rargs = self.get_compile_args(
            self.ll_compiled_path, [self.c_file_path]) + ["-S", "-emit-llvm"]
        s = " ".join(rargs)
        self.logger.info(f"Compiling with command: {s}")
        self.run_command(rargs, check=True)
        self.logger.info(f"Wrote llvm in: {self.ll_compiled_path}")

    def compile_llvm_to_bin(self):
        rargs = self.get_compile_args(
            self.binary_path, [self.ll_compiled_path])
        s = " ".join(rargs)
        self.logger.info(f"Compiling with command: {s}")
        self.run_command(rargs, check=True)
        self.logger.info(f"Wrote bin in: {self.binary_path}")

    def collect_checksum(self, binary) -> Optional[str]:

        try:
            proc = self.run_command(
                self.conf.runner+[binary], stdout=subprocess.PIPE, timeout=5)
        except subprocess.TimeoutExpired:
            self.logger.error("Binary exited with timeout")
            return None

        if proc.returncode != 0:
            self.logger.error("Binary exited with non zero return code")
            return None

        return proc.stdout

    def run_command(self, comm, check=False, **kwargs):
        with open(self.stdout_path, "a+") as stdout:
            with open(self.stderr_path, "a+") as stderr:
                if "stdout" not in kwargs:
                    kwargs["stdout"] = stdout
                if "stderr" not in kwargs:
                    kwargs["stderr"] = stderr
                return subprocess.run(comm, check=check, **kwargs)

    def specify(self) -> bool:
        with tempfile.TemporaryDirectory() as pdir:
            exp_command = [os.path.join(self.conf.ghidra_path,
                                        "support", "analyzeHeadless"), pdir, self.tc_name, "-readOnly", "-deleteProject", "-import", self.binary_path,  "-postScript", "anvillHeadlessFunctionExport", self.spec_path, self.target_fname]
            coms = " ".join(exp_command)
            self.logger.info(f"Specifying with command: {coms}")
            r = self.run_command(exp_command)
            return r.returncode == 0 and os.path.exists(self.spec_path)

    def create_new_llvm(self) -> bool:
        return self.run_command([os.path.join(self.conf.irene_eval), "-csmith_ir_out", self.csmith_ll_modified, "-csmith_module",
                                 self.ll_compiled_path, "-decomp_ir_out", self.ll_decomp_path, "-fname", self.target_fname, "-spec", self.spec_path]).returncode == 0

    # TODO(Ian): this is dumb
    def select_random_repl_target(self):
        r = subprocess.run(["nm", self.binary_path],
                           stdout=subprocess.PIPE, check=True)
        c = r.stdout.decode()
        self.target_fname = random.choice(
            list(frozenset(re.findall("func_[0-9]+", c))))

        self.logger.info(f"Selected function to replace: {self.target_fname}")

    def recompile(self) -> bool:
        rargs = self.get_compile_args(
            self.recompiled_binary, [self.ll_decomp_path, self.csmith_ll_modified])
        s = " ".join(rargs)
        self.logger.info(f"Compiling with command: {s}")
        ret = self.run_command(rargs)
        self.logger.info(f"Wrote llvm in: {self.recompiled_binary}")
        return ret.returncode == 0

    def save_tc(self, rs: TestCaseRes):
        print("saving")
        if TestCaseRes.FAILED == rs:
            shutil.move(self.tdir, self.fail_dir)
        elif TestCaseRes.SUCCESS == rs:
            shutil.move(self.tdir, self.success_dir)
        else:
            shutil.move(self.tdir, self.invalid_dir)

    # TODO(Ian): probably more effecient to fan out and replace every function but that makes isolation hard, also shouldnt find
    # funcs by text because may be inlined idk if we want to let inlining happen tho because that reduces samples
    @timeout(240)
    def run_task(self) -> TestCaseRes:
        self.generate_c_file()
        self.compile_tc_to_llvm()
        self.compile_llvm_to_bin()

        orig_checksum = self.collect_checksum(self.binary_path)

        if not orig_checksum:
            self.logger.error("Could not get checksum from baseline binary")
            return TestCaseRes.INVALID

        self.select_random_repl_target()

        if not self.specify():
            self.logger.error("Failed to specify function")
            return TestCaseRes.FAILED

        if not self.create_new_llvm():
            self.logger.error("Failed to decompile")
            return TestCaseRes.FAILED

        if not self.recompile():
            self.logger.error("Failed to recompile")
            return TestCaseRes.FAILED

        second_checksum = self.collect_checksum(self.recompiled_binary)

        if orig_checksum == second_checksum:
            return TestCaseRes.SUCCESS
        else:
            self.logger.error("Checksum mismatch")
            return TestCaseRes.FAILED

    def run(self):
        self.init_logging()
        try:
            self.save_tc(self.run_task())
        except TimeoutError:
            self.logger.error("Timed out while running task")
            self.save_tc(TestCaseRes.INVALID)
        finally:
            for handler in self.logger.handlers[:]:
                handler.close()


def rtc(tc):
    tc.run()


def main():
    parser = argparse.ArgumentParser(
        "Test Runner", description="Runs a set of differential csmith tests against this release of irene")
    parser.add_argument("-n", type=int, required=True)
    parser.add_argument("--ghidra_path", type=str, required=True)
    parser.add_argument("--csmith_path", type=str, required=True)
    parser.add_argument("--extra_compiler_flags", default="")
    parser.add_argument("--runtime_env", default="")
    parser.add_argument("--compiler_path", required=True)
    parser.add_argument("--irene_eval", required=True)
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("outdir", type=str)

    args = parser.parse_args()

    conf = Config(args)
    print(f"Saving to {args.outdir}")

    with multiprocessing.Pool() as p:
        for _ in tqdm.tqdm(p.imap_unordered(rtc, [TestCase(conf, args.outdir, i,  logging.DEBUG if args.verbose else logging.INFO) for i in range(0, args.n)]), total=args.n):
            pass


if __name__ == "__main__":
    main()
