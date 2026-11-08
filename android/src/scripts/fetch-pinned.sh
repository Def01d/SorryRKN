#!/usr/bin/env bash
# Download an official release asset. Both paths must match the pinned digest.
set -euo pipefail
url=$1 hash=$2 dest=$3
if ! curl -fSsL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --retry 2 "$url" -o "$dest"; then
    [[ "$url" =~ ^https://github.com/([^/]+/[^/]+)/releases/download/([^/]+)/([^/]+)$ ]] || exit 1
    repo=${BASH_REMATCH[1]} tag=${BASH_REMATCH[2]} name=${BASH_REMATCH[3]}
    asset=$(curl -fSsL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 45 --retry 2 "https://api.github.com/repos/$repo/releases/tags/$tag" |
        python3 -c 'import json,sys; print(next(a["url"] for a in json.load(sys.stdin)["assets"] if a["name"]==sys.argv[1]))' "$name")
    [[ "$asset" == https://api.github.com/repos/*/releases/assets/* ]] || exit 1
    curl -fSsL --proto '=https' --proto-redir '=https' --connect-timeout 15 --max-time 180 --retry 2 -H 'Accept: application/octet-stream' "$asset" -o "$dest"
fi
printf '%s  %s\n' "$hash" "$dest" | sha256sum --check --status
