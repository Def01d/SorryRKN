#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

GO_BIN="${GO:-$(command -v go || true)}"
if [ -z "$GO_BIN" ]; then
    echo "Go toolchain (>=1.24) is required to build libmirage.so" >&2
    exit 1
fi

SRC_ROOT="$(cd ../../windows/src && pwd)"
if [ ! -f "$SRC_ROOT/go.mod" ]; then
    echo "Missing Mirage Go module at $SRC_ROOT" >&2
    exit 1
fi

for abi in arm64-v8a x86_64; do
    case "$abi" in
        arm64-v8a) goarch=arm64 ;;
        x86_64) goarch=amd64 ;;
    esac
    dest="app/build/generated/mirage/jni/$abi"
    mkdir -p "$dest"
    (
        cd "$SRC_ROOT"
        CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" \
            "$GO_BIN" build -tags clientonly -trimpath -ldflags "-s -w" \
            -o "$(cd - >/dev/null && pwd)/$dest/libmirage.so" ./cmd/sorryrkn-mirage
    )
    chmod 755 "$dest/libmirage.so"
done
