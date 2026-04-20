#!/usr/bin/env bash
set -euo pipefail

BINARY=""
IR_OUT=""
KEEP_SPEC=0

usage() {
    cat <<EOF
Usage: $0 --binary <path> --ir-out <path> [--keep-spec]

Lift an executable to LLVM IR via the irene3 pipeline:
  binary -> anvill spec (Ghidra headless) -> LLVM IR (irene3-decompile)

Options:
  --binary <path>    Input executable to lift.
  --ir-out <path>    Output LLVM IR file (.ll).
  --keep-spec        Keep the intermediate .proto spec alongside --ir-out.
  -h, --help         Show this help.

Environment:
  JAVA_HOME          If unset on macOS, defaults to /opt/homebrew/opt/openjdk@17
                     (Ghidra's bundled gradle 7.6 requires JDK <= 17).
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --binary)    BINARY="$2"; shift 2 ;;
        --ir-out)    IR_OUT="$2"; shift 2 ;;
        --keep-spec) KEEP_SPEC=1; shift ;;
        -h|--help)   usage; exit 0 ;;
        *) echo "Unknown argument: $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [[ -z "$BINARY" || -z "$IR_OUT" ]]; then
    echo "Error: --binary and --ir-out are required" >&2
    usage >&2
    exit 2
fi

if [[ ! -f "$BINARY" ]]; then
    echo "Error: binary not found: $BINARY" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"

if [[ "$(uname -s)" == "Darwin" && -z "${JAVA_HOME:-}" ]]; then
    export JAVA_HOME="/opt/homebrew/opt/openjdk@17"
    export PATH="$JAVA_HOME/bin:$PATH"
fi

JUST="${JUST:-just}"
if ! command -v "$JUST" >/dev/null 2>&1; then
    if [[ -x /opt/homebrew/bin/just ]]; then
        JUST=/opt/homebrew/bin/just
    else
        echo "Error: 'just' not found on PATH and /opt/homebrew/bin/just missing" >&2
        exit 1
    fi
fi

mkdir -p "$(dirname "$IR_OUT")"

if [[ $KEEP_SPEC -eq 1 ]]; then
    SPEC_PATH="${IR_OUT%.ll}.proto"
    cleanup() { :; }
else
    SPEC_PATH="$(mktemp -t irene3-spec.XXXXXX.proto)"
    cleanup() { rm -f "$SPEC_PATH"; }
fi
trap cleanup EXIT

cd "$REPO_ROOT"

echo ">>> binary -> spec: $BINARY -> $SPEC_PATH"
"$JUST" generate-spec "$BINARY" "$SPEC_PATH"

echo ">>> spec -> IR: $SPEC_PATH -> $IR_OUT"
"$JUST" decompile-spec-ll "$SPEC_PATH" "$IR_OUT"

echo ">>> done: $IR_OUT ($(wc -l <"$IR_OUT") lines)"
