"""DNS over verified HTTPS, with fixed bootstrap IPs and provider fallback."""
import asyncio
import struct
import secrets
import time
from collections import OrderedDict
import ipaddress
import httpx
import ssl
import certifi
from functools import lru_cache

PROVIDERS = (
    ("Google", "dns.google", "8.8.8.8"),
    ("Cloudflare", "cloudflare-dns.com", "1.1.1.1"),
    ("Quad9", "dns.quad9.net", "9.9.9.9"),
)


@lru_cache(maxsize=1)
def verified_context():
    # Only HTTP/1.1 DoH/probe transports share this context. Proxy WebSocket
    # and H2 contexts remain separate because they change ALPN/hostname policy.
    return ssl.create_default_context(cafile=certifi.where())


class PinnedTransport(httpx.AsyncBaseTransport):
    def __init__(self, inner, addresses):
        self.inner, self.addresses = inner, addresses

    async def handle_async_request(self, request):
        host = request.url.host
        # The same authenticated hostname may have several independent bootstrap
        # addresses. A host->IP dictionary alone silently collapses those routes.
        extensions = dict(request.extensions)
        address = extensions.pop('bootstrap_ip', None) or self.addresses.get(host)
        if address and request.url.scheme == "https":
            extensions['sni_hostname'] = host
            request = httpx.Request(request.method, request.url.copy_with(host=address),
                                    headers=request.headers, stream=request.stream, extensions=extensions)
        return await self.inner.handle_async_request(request)

    async def aclose(self):
        await self.inner.aclose()


def dns_name(data, start):
    """Read a bounded DNS name and reject invalid pointers, loops and labels."""
    labels, seen = [], set()
    offset, end, length = start, None, 1
    for _ in range(128):
        if offset in seen or offset >= len(data):
            raise ValueError('Invalid DNS name')
        seen.add(offset)
        size = data[offset]
        offset += 1
        if not size:
            return b'.'.join(labels).lower(), end if end is not None else offset
        if size & 0xc0 == 0xc0:
            if offset >= len(data):
                raise ValueError('Short DNS pointer')
            if end is None:
                end = offset + 1
            offset = ((size & 63) << 8) | data[offset]
            continue
        if size > 63 or offset + size > len(data):
            raise ValueError('Invalid DNS label')
        labels.append(bytes(data[offset:offset + size]))
        offset += size
        length += size + 1
        if length > 255:
            raise ValueError('Long DNS name')
    raise ValueError('Too many DNS pointers')


def dns_message(data):
    if not data or not 12 <= len(data) <= 65507:
        raise ValueError('Invalid DNS message size')
    identifier, flags, qd, an, ns, ar = struct.unpack('!6H', data[:12])
    if qd != 1 or an + ns + ar > 1024:
        raise ValueError('Unsupported DNS counts')
    name, offset = dns_name(data, 12)
    kind, cls = struct.unpack('!HH', data[offset:offset + 4])
    offset += 4
    records = []
    for index in range(an + ns + ar):
        owner, offset = dns_name(data, offset)
        rrtype, rrclass, ttl, size = struct.unpack('!HHIH', data[offset:offset + 10])
        ttl_offset = offset + 4
        offset += 10
        end = offset + size
        if end > len(data):
            raise ValueError('Short DNS record')
        if rrclass == 1 and (rrtype == 1 and size != 4 or rrtype == 28 and size != 16):
            raise ValueError('Invalid DNS address')
        if rrtype in (2, 5, 12, 39):
            _, name_end = dns_name(data, offset)
            if name_end != end:
                raise ValueError('Invalid DNS record name')
        records.append((index < an, owner, rrtype, rrclass, ttl_offset, ttl, offset, size))
        offset = end
    if offset != len(data):
        raise ValueError('Trailing DNS data')
    return identifier, flags, (name, kind, cls), records


def valid_answer(payload, answer):
    try:
        query_id, query_flags, question, _ = dns_message(payload)
        reply_id, flags, reply_question, _ = dns_message(answer)
        return (not query_flags & 0x8000 and reply_id == query_id and bool(flags & 0x8000)
                and flags & 0x7800 == query_flags & 0x7800 and question == reply_question
                and not flags & 0x0200 and flags & 15 in (0, 3))
    except (ValueError, struct.error, IndexError, TypeError):
        return False


def answer_names(answer, wanted, records):
    """Restrict address records to the question's answer-section CNAME chain."""
    aliases = {owner: dns_name(answer, offset)[0]
               for is_answer, owner, kind, cls, _, _, offset, _ in records
               if is_answer and kind == 5 and cls == 1}
    names = {wanted}
    for _ in range(len(aliases)):
        following = aliases.get(wanted)
        if following is None or following in names: break
        names.add(following)
        wanted = following
    return names


def ipv4_answers(query, answer):
    """Read bounded DNS records, including compressed names; reject malformed replies."""
    if not valid_answer(query, answer): return []
    try:
        _, flags, (wanted, _, _), records = dns_message(answer)
        if flags & 15: return []
        names = answer_names(answer, wanted, records)
        addresses = []
        for is_answer, owner, kind, cls, _, _, offset, size in records:
            if is_answer and owner in names and kind == 1 and cls == 1 and size == 4:
                ip = ipaddress.IPv4Address(bytes(answer[offset:offset+4]))
                if ip.is_global: addresses.append(str(ip))
        return addresses
    except (ValueError,struct.error,IndexError): return []


def cache_records(query, answer):
    """Return TTL offsets only for complete positive DNS answers."""
    if not valid_answer(query, answer) or len(answer) > 8192:
        return []
    try:
        _, flags, _, parsed = dns_message(answer)
        if not any(record[0] for record in parsed) or flags & 15: return []
        records = [(offset, ttl) for _, _, kind, _, offset, ttl, _, _ in parsed if kind != 41]
        return records if records and all(ttl > 0 for _, ttl in records) else []
    except (IndexError, struct.error, ValueError): return []


class Resolver:
    def __init__(self, port, transport=None,providers=PROVIDERS):
        self.providers=providers
        inner = transport or httpx.AsyncHTTPTransport(proxy=f"socks5://127.0.0.1:{port}" if port else None,
            verify=verified_context(), trust_env=False, limits=httpx.Limits(max_connections=16, max_keepalive_connections=6))
        self.client = httpx.AsyncClient(transport=PinnedTransport(inner,{host:ip for _,host,ip in providers}),
                                       timeout=2.5, trust_env=False, follow_redirects=False)
        self.preferred = None
        self.provider = ""
        self.cache = OrderedDict()
        self.inflight = {}
        self.last_addresses = OrderedDict()

    async def _query(self, provider, payload):
        name, host, address = provider
        try:
            async with self.client.stream("POST", f"https://{host}/dns-query",content=payload,
                headers={"Content-Type":"application/dns-message","Accept":"application/dns-message"},
                extensions={'bootstrap_ip': address}) as response:
                response.raise_for_status()
                answer = bytearray()
                async for chunk in response.aiter_bytes():
                    answer.extend(chunk)
                    if len(answer)>65507: return None
            if valid_answer(payload,answer): return provider,bytes(answer)
        except (httpx.HTTPError,OSError,ValueError):
            pass
        return None

    async def _lookup(self, payload):
        # No hostname resolution is needed to reach these providers. A blocked
        # Google resolver must not disable every Android application's DNS.
        if self.preferred and len(self.providers) == 1:
            try:
                result=await asyncio.wait_for(self._query(self.preferred,payload),1.5)
            except asyncio.TimeoutError: result=None
            if result:
                self.provider = result[0][0]
                return result[1]
        # Retry the only configured provider too: a transient stale socket
        # must not disable the Comss profile until a manual restart.
        candidates = sorted(self.providers, key=lambda provider: provider != self.preferred)
        async def attempt(provider):
            if self.preferred and provider != self.preferred:
                # Keep the working route first, but do not let a newly blocked
                # provider consume most of an application's DNS timeout.
                await asyncio.sleep(.2)
            return await self._query(provider, payload)
        tasks=[asyncio.create_task(attempt(p)) for p in candidates]
        try:
            async with asyncio.timeout(3):
                for completed in asyncio.as_completed(tasks):
                    result=await completed
                    if result:
                        self.preferred=result[0]; self.provider=result[0][0]
                        return result[1]
        except asyncio.TimeoutError:
            pass
        finally:
            for task in tasks:
                if not task.done(): task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
        return None

    async def query(self, payload):
        if not 12 <= len(payload) <= 4096: return None
        payload = bytes(payload)
        key = payload[2:]
        cached = self.cache.get(key)
        now = time.monotonic()
        if cached:
            stored, expires, answer, records = cached
            if now < expires:
                self.cache.move_to_end(key)
                wire = bytearray(answer); wire[:2] = payload[:2]
                for offset, ttl in records:
                    struct.pack_into('!I', wire, offset, max(0, ttl - int(now-stored)))
                return bytes(wire)
            self.cache.pop(key, None)
        entry = self.inflight.get(key)
        if entry is None:
            async def lookup():
                answer = await self._lookup(payload)
                records = cache_records(payload, answer) if answer else []
                if records:
                    stored = time.monotonic()
                    self.cache[key] = (stored, stored+min(30, min(ttl for _, ttl in records)), answer, records)
                    self.cache.move_to_end(key)
                    while len(self.cache) > 256: self.cache.popitem(last=False)
                return answer
            entry = [asyncio.create_task(lookup()), 0]
            self.inflight[key] = entry
        entry[1] += 1
        try:
            answer = await asyncio.shield(entry[0])
            return payload[:2] + answer[2:] if answer else None
        finally:
            entry[1] -= 1
            if entry[1] == 0:
                if self.inflight.get(key) is entry: self.inflight.pop(key, None)
                if not entry[0].done(): entry[0].cancel()
                await asyncio.gather(entry[0], return_exceptions=True)

    def invalidate(self, host):
        self.last_addresses.pop(host, None)
        labels=host.encode('idna').split(b'.')
        question=b''.join(bytes([len(label)])+label for label in labels)+b'\0'
        for key in list(self.cache):
            if key[10:].startswith(question):self.cache.pop(key,None)

    async def close(self):
        tasks = [entry[0] for entry in self.inflight.values()]
        self.inflight.clear(); self.cache.clear(); self.last_addresses.clear()
        for task in tasks: task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        await self.client.aclose()

    async def resolve(self, host):
        labels=host.encode('idna').split(b'.')
        if any(not label or len(label)>63 for label in labels): return None
        query=struct.pack('!6H',secrets.randbits(16),0x0100,1,0,0,0)
        query+=b''.join(bytes([len(label)])+label for label in labels)+b'\0\0\x01\0\x01'
        answer=await self.query(query)
        addresses=ipv4_answers(query,answer) if answer else []
        self.last_addresses[host] = tuple(dict.fromkeys(addresses))
        self.last_addresses.move_to_end(host)
        while len(self.last_addresses) > 256:
            self.last_addresses.popitem(last=False)
        return addresses[0] if addresses else None
