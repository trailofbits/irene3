#!/usr/bin/env python3


import argparse
import json
import logging
import subprocess
import tempfile
import re
import os

import weakref as _weakref

# python 3.11 compatibility
class TemporaryDirectory(tempfile.TemporaryDirectory):
    def __init__(self, delete=True, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # detach parent class finalizer, otherwise
        # it'll still cleanup
        self._finalizer.detach()
        self._delete = delete
        self._finalizer = _weakref.finalize(
            self, self._cleanup, self.name,
            warn_message="Implicitly cleaninng up {!r}".format(self),
            ignore_errors=self._ignore_cleanup_errors, delete=self._delete)

    @classmethod
    def _cleanup(cls, name, warn_message, ignore_errors=False, delete=True):
        if delete:
            super(TemporaryDirectory, cls)._cleanup(name, warn_message, ignore_errors)

    def __exit__(self, exc, value, tb):
        if self._delete:
            super().__exit__(exc, value, tb)

def decompile(
    orig_bin,
    out_ll,
    ghidra_path,
    lang_override=None,
    install_path=None,
    outputfile=None,
    check=True,
    keep_temp=False,
):
    env = os.environ.copy()
    if install_path is not None:
        env["PATH"] = install_path + os.pathsep + env["PATH"]

    logging.info(f"Binary: {orig_bin}")

    with TemporaryDirectory(delete=not keep_temp) as temp_dir:
        if keep_temp:
            logging.info(f"Directory: {temp_dir}")

        logging.info("Exporting specification from Ghidra")
        # get spec from ghidra
        spec = os.path.join(temp_dir, os.path.basename(orig_bin) + ".pb")
        analyze_headless = os.path.join(ghidra_path, "support", "analyzeHeadless")
        subprocess.run(
            [analyze_headless,
             temp_dir,
             "proj",
             "-readOnly",
             "-deleteProject"]
            + (["-processor", lang_override] if lang_override else [])
            + ["-import",
               orig_bin,
               "-postScript",
               "anvillHeadlessExportScript",
               spec],
            stdout=outputfile,
            stderr=outputfile,
            check=check
        )
        # lift
        logging.info("Lifting protobuf specification to LLVM IR")
        subprocess.run(
            ["irene3-decompile", "--spec", spec, "--ir_out", out_ll],
            stdout=outputfile,
            stderr=outputfile,
            env=env,
            check=check,
        )
        logging.info("Lifting complete")

def roundtrip(
    addr,
    spec,
    orig_bin,
    out_bin,
    cpu,
    features,
    backend,
    install_path=None,
    outputfile=None,
    check=True,
    keep_temp=False,
    patcher_flags=None,
):
    env = os.environ.copy()
    if install_path is not None:
        env["PATH"] = install_path + os.pathsep + env["PATH"]

    logging.info(f"Addr: 0x{addr:x}")
    logging.info(f"Spec: {spec}")
    logging.info(f"CPU: {cpu}")
    logging.info(f"Features: {features}")
    logging.info(f"Backend: {backend}")

    with TemporaryDirectory(delete=not keep_temp) as temp_dir:
        if keep_temp:
            logging.info(f"Directory: {temp_dir}")
        res = subprocess.run(
            ["irene3-examine-spec", "-spec", spec],
            capture_output=True,
            text=True,
            env=env,
        )
        block_uid_pat = re.compile(
            r"Block uid: (?P<uid>[0-9]+) address: (?P<address>[0-9a-f]+)"
        )
        block_uid = None
        for line in res.stdout.splitlines():
            if m := block_uid_pat.match(line.strip()):
                b_addr = int(m.group("address"), 16)
                if addr == b_addr:
                    block_uid = m.group("uid")
                    break

        if block_uid is None:
            if check:
                raise IndexError(f"No block uid found for 0x{addr:x}")
            else:
                logging.error(f"No block uid found for 0x{addr:x}")
            return

        mlir_lift = os.path.join(temp_dir, "irene.lift.mlir")
        mlir_lower = os.path.join(temp_dir, "irene.lower.mlir")
        patchlang_out = os.path.join(temp_dir, "irene.patchlang")
        metadata = os.path.join(temp_dir, "irene.metadata.json")
        out_asm = os.path.join(temp_dir, "irene.S")
        # lift
        logging.info("Lifting protobuf specification to PatchIR")
        subprocess.run(
            ["irene3-patchir-codegen", "--spec", spec, "--mlir_out", mlir_lift],
            stdout=outputfile,
            stderr=outputfile,
            env=env,
            check=check,
        )
        logging.info("Lifting PatchIR to PatchLang")
        subprocess.run(
            ["irene3-patchlang-lift", "-mlir_in", mlir_lift, "-target_uid", block_uid],
            stdout=open(patchlang_out, mode="w"),
            stderr=outputfile,
            env=env,
            check=check,
        )

        # lower
        logging.info("Lowering PatchLang to PatchIR")
        subprocess.run(
            [
                "irene3-patchlang2patchir",
                "-input",
                patchlang_out,
                "-output",
                mlir_lower,
            ],
            stdout=outputfile,
            stderr=outputfile,
            env=env,
            check=check,
        )
        logging.info("Compiling PatchIR to Assembly")
        subprocess.run(
            [
                "irene3-patchir-compiler",
                "-patch_def",
                mlir_lower,
                "-region_uid",
                block_uid,
                "-json_metadata",
                metadata,
                "-out",
                out_asm,
                "-cpu",
                cpu,
                "-features",
                features,
                "--backend",
                backend,
            ],
            stdout=outputfile,
            stderr=outputfile,
            env=env,
            check=check,
        )

        # patch assemble
        logging.info("Applying patch to binary")
        subprocess.run(
            [
                "patch-assembler",
                "--in_assembly",
                out_asm,
                "--metadata",
                metadata,
                orig_bin,
                "--out",
                out_bin,
            ] + (patcher_flags if patcher_flags is not None else []),
            stdout=outputfile,
            stderr=outputfile,
            env=env,
            check=check,
        )


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("root_dir")
    parser.add_argument("test_json", type=argparse.FileType("r"))
    parser.add_argument("--install_path")
    parser.add_argument("--ghidra_path", default="./deps/ghidra")
    levels = ("DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL")
    parser.add_argument("--log-level", default="INFO", choices=levels)
    parser.add_argument("--outputfile", default="-", type=argparse.FileType("w"))
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--keep-temp", action="store_true")
    parser.add_argument("--skip-roundtrip", default=False, action="store_true")
    parser.add_argument("--skip-decompile", default=False, action="store_true")

    args = parser.parse_args()
    logging.basicConfig(format="%(asctime)s %(levelname)-8s %(message)s",
                        level=args.log_level,
                        datefmt="%Y-%m-%d %H:%M:%S")

    test_spec = json.load(args.test_json)
    os.makedirs(os.path.join(args.root_dir, "out"), exist_ok=True)
    os.makedirs(os.path.join(args.root_dir, "decomp_ll"), exist_ok=True)
    for test in test_spec:
        if "roundtrip" in test["tests"] and not args.skip_roundtrip:
            output_bin = os.path.basename(test["bin"]) + "_patched"
            roundtrip(
                test["addr"],
                os.path.join(args.root_dir, test["spec"]),
                os.path.join(args.root_dir, test["bin"]),
                os.path.join(args.root_dir, "out", output_bin),
                cpu=test["cpu"],
                features=test["features"],
                backend=test["backend"],
                install_path=args.install_path,
                outputfile=args.outputfile,
                check=args.check,
                keep_temp=args.keep_temp,
                patcher_flags=test.get("patcher_flags"),
            )
        if "decompile" in test["tests"] and not args.skip_decompile:
            output_ll = os.path.basename(test["bin"]) + ".ll"
            decompile(
                os.path.join(args.root_dir, test["bin"]),
                os.path.join(args.root_dir, "decomp_ll", output_ll),
                args.ghidra_path,
                lang_override=test.get("lang_override"),
                install_path=args.install_path,
                outputfile=args.outputfile,
                check=args.check,
                keep_temp=args.keep_temp,
            )


if __name__ == "__main__":
    main()
