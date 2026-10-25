import asyncio
import datetime
import json
from pathlib import Path
import tempfile
import time
import unittest

from service_catalog import service_for_host
from service_routing import ServiceRouter, best_profile, fresh, selection
from dns_profiles import load_catalog
from smart_dns import SmartDNS
from user_rules import DomainRules


class ServiceRoutingTests(unittest.IsolatedAsyncioTestCase):
    def test_signed_fixture_rejects_tampering_and_expired_metadata(self):
        from update_trust import verified_payload
        path=Path(__file__).parents[1]/'app/src/androidTest/assets/signed-update.json'
        value=json.loads(path.read_text());now=value['signedAt']+1
        payload=verified_payload(path.read_bytes(),now)
        self.assertEqual(json.loads(payload)['versionCode'],1)
        for field in ('signed','signature','keyId'):
            bad=dict(value);bad[field]='AAAA'
            with self.assertRaises(ValueError):verified_payload(json.dumps(bad).encode(),now)
        with self.assertRaises(ValueError):verified_payload(path.read_bytes(),now+367*86400)
        with self.assertRaises(ValueError):verified_payload(path.read_bytes(),now-3600)
    async def test_actual_resolvers_follow_service_choices_and_direct_exception(self):
        dns=SmartDNS(profile='comss',service_dns={'chatgpt':'geohide-eu','gemini':'malw'},rules=DomainRules(direct=('direct.chatgpt.com',)))
        try:
            self.assertEqual(dns.smart_for('auth.openai.com').providers[0][1],'eu.geohide.ru')
            self.assertEqual(dns.smart_for('gemini.google.com').providers[0][1],'dns.malw.link')
            self.assertIs(dns.smart_for('direct.chatgpt.com'),dns.normal)
            self.assertEqual(service_for_host('chatgpt.com.evil.example'),'')
            self.assertEqual(service_for_host('notebooklm.google.com'),'notebooklm')
        finally:await dns.close()

    async def test_own_ip_creates_no_service_relay_transport(self):
        dns=SmartDNS(own_ip=True,service_dns={'chatgpt':'auto'})
        try:
            self.assertIsNone(dns.routing);self.assertEqual(dns.smart_pool,{})
            self.assertIs(dns.smart_for('chatgpt.com'),dns.normal)
        finally:await dns.close()

    async def test_recovery_requires_two_failures_and_ignores_manual_choices(self):
        router=ServiceRouter(choices={'chatgpt':'auto','gemini':'malw'})
        calls=[]
        async def check(profile,service):
            calls.append((profile['id'],service[0]))
            self.assertEqual(service[0],'chatgpt')
            return {'state':'transport_error' if profile['id']=='comss' else 'reachable_public'}
        await router.recover(check);self.assertEqual(router.profile('chatgpt.com'),'comss')
        router.checked=time.monotonic()-61
        await router.recover(check)
        self.assertNotEqual(router.profile('chatgpt.com'),'comss');self.assertEqual(router.profile('gemini.google.com'),'malw')
        before=len(calls);await router.recover(check);self.assertEqual(len(calls),before)

    async def test_challenge_and_rate_limit_do_not_rotate_exit(self):
        for state in ('challenge','rate_limited'):
            router=ServiceRouter(choices={'chatgpt':'auto'})
            async def check(profile,service):return {'state':state}
            for _ in range(3):
                router.checked=0;await router.recover(check)
            self.assertEqual(router.profile('chatgpt.com'),'comss')

    async def test_cancel_stops_probes_without_changing_routes(self):
        router=ServiceRouter(choices={'chatgpt':'auto'})
        active=asyncio.Event()
        async def check(profile,service):active.set();await asyncio.sleep(10)
        task=asyncio.create_task(router.recover(check));await active.wait();task.cancel()
        with self.assertRaises(asyncio.CancelledError):await task
        self.assertFalse(router.checking);self.assertEqual(router.profile('chatgpt.com'),'comss')

    def test_cache_requires_matching_network_and_fresh_timestamp(self):
        report={'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(),'network_key':'network-a',
                'profiles':[{'id':'geohide','results':[{'service':'chatgpt','state':'reachable_public'}]},
                            {'id':'comss','results':[{'service':'chatgpt','state':'reachable_public'}]}]}
        catalog=load_catalog()
        self.assertEqual(best_profile(report,'chatgpt','comss',catalog,'network-a'),'comss')
        report['profiles'][1]['results'][0]['state']='regional_refusal'
        self.assertEqual(best_profile(report,'chatgpt','comss',catalog,'network-a'),'geohide')
        self.assertEqual(best_profile(report,'chatgpt','comss',catalog,'network-b'),'comss')
        self.assertFalse(fresh(report,'network-a',time.time()+3600))
        for bad in ({'unknown':'comss'},{'chatgpt':'https://evil.example'},{'chatgpt':None}):
            with self.assertRaises(ValueError):selection(services=bad)
