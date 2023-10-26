import argparse
import json
from pathlib import Path


def count_dirs(path: Path):
    if not path.exists():
        return 0
    count = 0
    for p in path.iterdir():
        assert p.is_dir()
        count += 1
    return count


def build_metrics(ghidra_stats, decompiler_stats, csmith_results: Path):
    ghidra_timeout = ghidra_stats.get("output.timeout", [])
    ghidra_zero_sized_output = ghidra_stats.get("output.zero-sized-output", [])
    ghidra_ignore_failure = ghidra_stats.get("outputignore_fail", [])
    ghidra_ignore_success = ghidra_stats.get("outputignore_success", [])
    ghidra_success = ghidra_stats.get("output.success", [])

    decompiler_timeout = decompiler_stats.get("output.timeout", [])
    decompiler_zero_sized_output = decompiler_stats.get("output.zero-sized-output", [])
    decompiler_ignore_failure = decompiler_stats.get("outputignore_fail", [])
    decompiler_ignore_success = decompiler_stats.get("outputignore_success", [])

    success = decompiler_stats.get("output.success", [])

    csmith_success = count_dirs(csmith_results / "success")
    csmith_failure = count_dirs(csmith_results / "fail")
    csmith_invalid = count_dirs(csmith_results / "invalid")

    metrics = {}

    job_stats = {}
    job_stats["challenge-ghidra-timeout"] = len(ghidra_timeout)
    job_stats["challenge-ghidra-zero-sized-output"] = len(ghidra_zero_sized_output)
    job_stats["challenge-ghidra-ignore-failure"] = len(ghidra_ignore_failure)
    job_stats["challenge-ghidra-ignore-success"] = len(ghidra_ignore_success)
    job_stats["challenge-ghidra-success"] = len(ghidra_success)

    job_stats["challenge-decompiler-timeout"] = len(decompiler_timeout)
    job_stats["challenge-decompiler-zero-sized-output"] = len(
        decompiler_zero_sized_output
    )
    job_stats["challenge-decompiler-ignore-failure"] = len(decompiler_ignore_failure)
    job_stats["challenge-decompiler-ignore-success"] = len(decompiler_ignore_success)

    job_stats["challenge-failure"] = (
        len(ghidra_timeout)
        + len(ghidra_zero_sized_output)
        + len(ghidra_ignore_failure)
        + len(decompiler_timeout)
        + len(decompiler_zero_sized_output)
        + len(decompiler_ignore_failure)
    )
    job_stats["challenge-success"] = len(success)

    job_stats["csmith-success"] = csmith_success
    job_stats["csmith-failure"] = csmith_failure
    job_stats["csmith-invalid"] = csmith_invalid

    challenge_stats = {}

    metrics["job-stats"] = job_stats
    metrics["challenge-stats"] = challenge_stats

    return metrics


def main():
    parser = argparse.ArgumentParser()

    parser.add_argument(
        "--ghidra-stats",
        help="The location of the spec generation `stats.json` file",
        required=True,
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        "--decompiler-stats",
        help="The location of the decompilation `stats.json` file",
        required=True,
        type=argparse.FileType("r"),
    )
    parser.add_argument(
        "--csmith-results",
        help="The location of the csmith results directory",
        required=True,
        type=Path,
    )

    # TODO(alex): Enable these when we've added them to the metrics nightly workflow.
    # parser.add_argument("--llvm-stats", help="", required=True, type=argparse.FileType("r"))

    parser.add_argument(
        "--output-metrics",
        help="The location to write the output metrics JSON file",
        required=True,
        type=argparse.FileType("w"),
    )

    args = parser.parse_args()

    ghidra_stats = json.load(args.ghidra_stats)
    decompiler_stats = json.load(args.decompiler_stats)

    metrics = build_metrics(ghidra_stats, decompiler_stats, args.csmith_results)

    json.dump(metrics, args.output_metrics)


if __name__ == "__main__":
    main()
