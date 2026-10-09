#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
# tpws intentionally rejects targets on the machine running it. For isolated
# socket tests ONLY, compile a separate binary allowing local echo servers.
# The Android build never reads this temporary source or this binary.
mkdir -p build
python - <<'PY'
from pathlib import Path
import re
import subprocess
import tempfile
source=Path('third_party/tpws')
with tempfile.TemporaryDirectory() as tmp:
    helper=Path(tmp)/'helpers.c'
    text=(source/'helpers.c').read_text()
    text=re.sub(r'bool check_local_ip\(const struct sockaddr \*saddr\)\n\{.*?\n\}',
                'bool check_local_ip(const struct sockaddr *saddr) { (void)saddr; return false; }',
                text, count=1, flags=re.S)
    helper.write_text(text)
    files=[str(p) for p in source.glob('*.c') if p.name!='helpers.c']
    # Linux sec.h needs the libcap-dev header. capget/capset are provided by
    # glibc, matching upstream's Linux Makefile; no extra -lcap is required.
    subprocess.run(['cc','-std=gnu99','-Os','-I'+str(source),str(helper),*files,'-lz','-lpthread','-o','build/test-tpws'], check=True)
PY
cc -std=c99 -D_DEFAULT_SOURCE -O2 -Ithird_party/byedpi \
  third_party/byedpi/main.c third_party/byedpi/packets.c third_party/byedpi/conev.c \
  third_party/byedpi/proxy.c third_party/byedpi/desync.c third_party/byedpi/mpool.c \
  third_party/byedpi/extend.c -o build/test-byedpi
PYTHONPATH=app/src/main/python .venv/bin/python -m pytest tests -q
