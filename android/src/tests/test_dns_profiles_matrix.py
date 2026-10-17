import asyncio
import copy
import json
from pathlib import Path
import tempfile
import unittest

from dns_profiles import load_catalog, parse_catalog, providers, selected_profile
from dns_matrix import SERVICES, classify, scan
from smart_dns import SmartDNS


class CatalogTests(unittest.TestCase):
    def test_all_seven_profiles_are_distinct_and_valid(self):
        catalog=load_catalog()
        self.assertEqual(len(catalog['profiles']),7)
        self.assertEqual(len({p['url'] for p in catalog['profiles']}),7)
        self.assertEqual(providers(selected_profile('geohide-eu'))[0][1],'eu.geohide.ru')

    def test_rejects_unsafe_catalogs_without_replacing_cached_profile(self):
        catalog=load_catalog()
        for change in (
            lambda p:p.update(url='http://dns.example.com/dns-query'),
            lambda p:p.update(url='https://user:pass@dns.example.com/dns-query'),
            lambda p:p.update(url='https://localhost/dns-query'),
            lambda p:p.update(bootstrap=['127.0.0.1']),
            lambda p:p.update(bootstrap=['192.168.1.2']),
            lambda p:p.update(bootstrap=['::1']),
        ):
            bad=copy.deepcopy(catalog);change(bad['profiles'][0])
            with self.subTest(profile=bad['profiles'][0]):
                with self.assertRaises(ValueError):parse_catalog(json.dumps(bad))
        for bad in ('[]','null','{"schema":1,"profiles":[null]}'):
            with self.assertRaises(ValueError):parse_catalog(bad)

    def test_catalog_updates_preserve_bundled_user_choice(self):
        with tempfile.TemporaryDirectory() as directory:
            catalog=load_catalog();catalog['profiles']=catalog['profiles'][:1]
            Path(directory,'dns-profiles.json').write_text(json.dumps(catalog))
            self.assertEqual(selected_profile('malw',directory)['id'],'malw')

    def test_response_classification_does_not_claim_geoblock_for_every_403(self):
        self.assertEqual(classify('claude',403,{},b'Forbidden'),'denied')
        self.assertEqual(classify('claude',403,{},b'{"error":{"code":"unsupported_country_region_territory"}}'),'regional_refusal')
        self.assertEqual(classify('claude',200,{'cf-mitigated':'challenge'},b''),'challenge')
        self.assertEqual(classify('claude',302,{},b''),'login_unchecked')
        self.assertEqual(classify('claude',429,{},b''),'rate_limited')
        self.assertEqual(classify('claude',200,{},b'<html><script>var error="This service is not available in your country";</script>Claude</html>'),'reachable_public')
        self.assertEqual(classify('chatgpt',200,{},b'<html>OK</html>'),'invalid_response')
        self.assertEqual(classify('chatgpt',200,{},b'{"openai":{"id":"openai","type":"oauth"}}'),'reachable_public')


class MatrixTests(unittest.IsolatedAsyncioTestCase):
    async def test_selection_reaches_actual_smart_dns_and_own_ip_avoids_it(self):
        dns=SmartDNS(profile='geohide-us')
        try:self.assertEqual(dns.smart.providers[0][1],'us.geohide.ru')
        finally:await dns.close()
        direct=SmartDNS(profile='malw',own_ip=True)
        try:self.assertIsNone(direct.smart)
        finally:await direct.close()

    async def test_scan_is_bounded_and_preserves_order_and_configuration(self):
        catalog=load_catalog();before=copy.deepcopy(catalog);active=0;maximum=0
        async def check(profile,service):
            nonlocal active,maximum
            active+=1;maximum=max(active,maximum)
            await asyncio.sleep(.001);active-=1
            return {'service':service[0],'name':service[1],'state':'reachable_public'}
        result=await scan(catalog,check=check)
        self.assertLessEqual(maximum,8)
        self.assertEqual(catalog,before)
        self.assertFalse(result['selection_changed']);self.assertFalse(result['account_checked'])
        self.assertEqual(len(result['profiles']),7)
        for row in result['profiles']:self.assertEqual([r['service'] for r in row['results']],[s[0] for s in SERVICES])

    async def test_deadline_cancels_active_connections_and_leaves_unknowns(self):
        active=0
        async def slow(profile,service):
            nonlocal active
            active+=1
            try:await asyncio.sleep(10)
            finally:active-=1
        result=await scan(load_catalog(),check=slow,deadline=.02)
        self.assertEqual(active,0)
        self.assertTrue(all(c['state']=='not_checked' for p in result['profiles'] for c in p['results']))
