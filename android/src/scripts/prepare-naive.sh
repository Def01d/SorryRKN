#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
version=v154.0.8037.49-5
cache="${XDG_CACHE_HOME:-$HOME/.cache}/sorryrkn/naive/$version"
mkdir -p "$cache" app/build/generated/naive/assets/licenses
get() {
    local name=$1 sha=$2 part
    if ! echo "$sha  $cache/$name" | sha256sum --check --status 2>/dev/null; then
        part=$(mktemp "$cache/part.XXXXXXXX")
        bash scripts/fetch-pinned.sh "https://github.com/klzgrad/naiveproxy/releases/download/$version/$name" "$sha" "$part"
        echo "$sha  $part" | sha256sum --check --status
        mv "$part" "$cache/$name"
    fi
}
for abi in arm64-v8a x86_64; do
    case "$abi" in
       arm64-v8a) sha=3a532e6894d87c1fca5c527d3598892627829c76cb5b75ed831555f384841bd0 ;;
       x86_64) sha=af3e8070e882f0008b6511394ae4d3737ece508e9b34abee94cb2f59ddb5e940 ;;
    esac
    name=naiveproxy-plugin-$version-$abi.apk
    get "$name" "$sha"
    dest="app/build/generated/naive/jni/$abi"
    mkdir -p "$dest"
    unzip -p "$cache/$name" "lib/$abi/libnaive.so" > "$dest/libnaive.so"
    chmod 755 "$dest/libnaive.so"
done
name="naiveproxy-$version-linux-x64"
get "$name.tar.xz" 80214dfea1767f6ecf63a3a79dc9f48b203460f51abc609357fff48dd5844c7d
tar -xOf "$cache/$name.tar.xz" "$name/LICENSE" > app/build/generated/naive/assets/licenses/NaiveProxy-Chromium.txt
