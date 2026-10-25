"""Offline consistency and shape checks for data shipped on both platforms."""
from pathlib import Path
import base64
import json
import re
import sys
from urllib.parse import urlsplit

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT/'android/src/app/src/main/python'))
from dns_profiles import parse_catalog

for name in ('dns-profiles.json','services.json'):
    data=(ROOT/name).read_bytes()
    for target in (ROOT/'android/src/app/src/main/python'/name.replace('-','_'), ROOT/'windows/src/internal/core'/name.replace('-','_')):
        assert target.read_bytes()==data,f'Out-of-sync bundled data: {target}'
    if name=='dns-profiles.json':
        c=parse_catalog(data)
        print(f"DNS: {len(c['profiles'])} valid profiles")
    else:
        c=json.loads(data);assert c['schema']==1 and len(c['services'])==8
        ids=set();domains=set()
        for s in c['services']:
            assert re.fullmatch('[a-z][a-z0-9-]{0,39}',s['id']) and s['id'] not in ids
            ids.add(s['id']);u=urlsplit(s['url'])
            assert u.scheme=='https' and not u.username and u.port in (None,443)
            for host in s['domains']:
                assert host not in domains and re.fullmatch(r'(?:[a-z0-9-]+\.)+[a-z]{2,}',host)
                domains.add(host)
        print(f'Services: {len(ids)} groups / {len(domains)} domains')
trust=json.loads((ROOT/'update-trust.json').read_text())
assert (ROOT/'android/src/app/src/main/python/update_trust.json').read_bytes()==(ROOT/'update-trust.json').read_bytes()
assert (ROOT/'windows/src/internal/core/update_trust.json').read_bytes()==(ROOT/'update-trust.json').read_bytes()
java=(ROOT/'android/src/app/src/main/java/dev/graybridge/UpdateTrust.java').read_text()
assert f'"{trust["key_id"]}"' in java and f'"{trust["public_key"]}"' in java
assert len(base64.b64decode(trust['public_key']))==91
fixture=(ROOT/'testdata/signed-update.json').read_bytes()
for name in ('windows/src/internal/core/testdata/signed-update.json','android/src/app/src/androidTest/assets/signed-update.json'):
    assert (ROOT/name).read_bytes()==fixture,name
print('Public update trust and signature fixtures synchronized.')
