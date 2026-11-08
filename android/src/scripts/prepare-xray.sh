#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=v26.10.31
cache="${XDG_CACHE_HOME:-$HOME/.cache}/sorryrkn/xray/$version"
mkdir -p "$cache" app/build/generated/xray/assets/licenses
for abi in arm64-v8a x86_64; do
  case "$abi" in
    arm64-v8a) arch=arm64-v8a; sha=ee7878bb47ce28ff5b068e2d173ba1a9fab20ca1aec94191644919ec08ba5f1d ;;
    x86_64) arch=amd64; sha=077f2f768de2356cea4a32598d333837fe0fa33ab540c4d508d9f17e2eb9e5b4 ;;
  esac
  archive="$cache/Xray-android-$arch.zip"
  if ! echo "$sha  $archive" | sha256sum --check --status 2>/dev/null; then
    part=$(mktemp "$cache/download.XXXXXXXX")
    trap 'rm -f -- "$part"' EXIT
    bash scripts/fetch-pinned.sh "https://github.com/XTLS/Xray-core/releases/download/$version/Xray-android-$arch.zip" "$sha" "$part"
    echo "$sha  $part" | sha256sum --check --status
    mv "$part" "$archive"
    trap - EXIT
  fi
  dest="app/build/generated/xray/jni/$abi"
  mkdir -p "$dest"
  unzip -p "$archive" xray > "$dest/libxray.so"
  chmod 755 "$dest/libxray.so"
  unzip -p "$archive" LICENSE > app/build/generated/xray/assets/licenses/Xray-core-MPL-2.0.txt
done
