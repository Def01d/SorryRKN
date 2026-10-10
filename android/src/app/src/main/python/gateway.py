"""Loopback SOCKS5: TCP through zapret, DNS over HTTPS, direct UDP.
QUIC/443 to IP destinations is dropped to trigger TCP fallback even when the
app retained a pre-VPN DNS cache. Direct exclusions, STUN, RTP and DTLS pass.
"""
import asyncio
import contextlib
import copy
import datetime
import ipaddress
import json
import struct
import time
import httpx
from connection_health import configure
from doh import Resolver, PinnedTransport, verified_context
from traffic import Routes,read_initial
from smart_dns import SmartDNS, failure_response
from geo_route import GeoRoutes, GeoRouteError


TLS_FIRST_REPLY_TIMEOUT=10.0
AI_ROUTE_URL='https://chatgpt.com/api/auth/providers'
AI_ROUTE_TIMEOUT=8.0
AI_ROUTE_CACHE_TTL=120.0


def quic_datagram(payload):
    # TURN ChannelData overlaps QUIC's short-header fixed bit. Its declared
    # datagram size (optionally padded to four bytes, RFC 8656 section 12.4)
    # identifies voice traffic which must remain available on UDP/443.
    if len(payload)>=4 and 0x40<=payload[0]<=0x7f:
        length=int.from_bytes(payload[2:4],'big')
        if len(payload)-4 in (length,(length+3)//4*4):return False
    # QUIC's fixed bit distinguishes it from RTP(version2), DTLS and STUN.
    # Long headers also contain a supported version or version-negotiation 0.
    if not payload or not payload[0] & 0x40:
        return False
    return (not payload[0] & 0x80 or len(payload) >= 7 and
            int.from_bytes(payload[1:5], 'big') in (0, 1, 0x6b3343cf))

def encode_address(host, port):
    ip = ipaddress.ip_address(host)
    return bytes([1 if ip.version == 4 else 4]) + ip.packed + struct.pack("!H", port)


async def read_address(reader):
    kind = (await reader.readexactly(1))[0]
    if kind == 1:
        raw = await reader.readexactly(4)
        host = str(ipaddress.ip_address(raw))
    elif kind == 4:
        raw = await reader.readexactly(16)
        host = str(ipaddress.ip_address(raw))
    elif kind == 3:
        size = (await reader.readexactly(1))[0]
        raw = bytes([size]) + await reader.readexactly(size)
        host = raw[1:].decode("ascii")
    else:
        raise ValueError("Invalid SOCKS address")
    port_bytes = await reader.readexactly(2)
    return host, struct.unpack("!H", port_bytes)[0], bytes([kind]) + raw + port_bytes


def decode_datagram(data):
    if len(data) < 4 or data[:3] != b"\0\0\0":
        raise ValueError("Fragmented or invalid UDP packet")
    kind = data[3]
    if kind in (1, 4):
        size = 4 if kind == 1 else 16
        if len(data) < 4 + size + 2:
            raise ValueError("Short UDP address")
        host = str(ipaddress.ip_address(data[4:4 + size]))
        end = 4 + size
    elif kind == 3:
        if len(data) < 5:
            raise ValueError("Short UDP domain")
        end = 5 + data[4]
        if len(data) < end + 2:
            raise ValueError("Short UDP address")
        host = data[5:end].decode("ascii")
    else:
        raise ValueError("Invalid UDP address")
    port = struct.unpack("!H", data[end:end + 2])[0]
    return host, port, data[end + 2:]


class _RemoteUDP(asyncio.DatagramProtocol):
    def __init__(self, association):
        self.association = association

    def datagram_received(self, data, addr):
        a = self.association
        if a.client and not a.closed:
            a.transport.sendto(b"\0\0\0" + encode_address(addr[0], addr[1]) + data, a.client)


class UDPAssociation(asyncio.DatagramProtocol):
    def __init__(self, gateway):
        self.gateway = gateway
        self.client = None
        self.closed = False
        self.transport = None
        self.remotes = {}
        self.tasks = set()

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, addr):
        if self.closed or addr[0] != "127.0.0.1" or (self.client and addr != self.client):
            return
        try:
            host, port, payload = decode_datagram(data)
        except (ValueError, UnicodeError):
            return
        self.client = addr
        routes=self.gateway.routes
        direct=bool(routes and routes.rules.direct_address(host))
        protected=bool(routes and (routes.protected(host) or routes.rules.protected_address(host)))
        try:ipaddress.ip_address(host);ip_destination=True
        except ValueError:ip_destination=False
        if port==443 and not direct and (not routes or (ip_destination or protected) and quic_datagram(payload)):
            self.gateway.stats['quic_blocked']+=1
            return
        if len(self.tasks) >= 64:
            return
        task = asyncio.create_task(self.forward(host, port, payload))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def forward(self, host, port, payload):
        try:
            if port == 53:
                answer = await self.gateway.dns(payload)
                if answer and not self.closed:
                    self.transport.sendto(b"\0\0\0" + encode_address(host, port) + answer, self.client)
                return
            now = time.monotonic()
            for key, (transport, used) in list(self.remotes.items()):
                if now - used > 60:
                    transport.close()
                    self.remotes.pop(key, None)
            key = (host, port)
            if key not in self.remotes:
                if len(self.remotes) >= 32:
                    return
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: _RemoteUDP(self), remote_addr=key)
                if self.closed:
                    transport.close()
                    return
                previous = self.remotes.get(key)
                if previous:
                    transport.close()
                else:
                    self.remotes[key] = transport, now
            transport, _ = self.remotes[key]
            self.remotes[key] = transport, now
            transport.sendto(payload)
            self.gateway.stats['udp_forwarded']+=1
        except (OSError, ValueError, httpx.HTTPError):
            pass

    async def close(self):
        self.closed = True
        if self.transport:
            self.transport.close()
        for transport, _ in self.remotes.values():
            transport.close()
        self.remotes.clear()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class Gateway:
    def __init__(self, port=1081, upstream_port=1080, directory=None, routes=None):
        self.port, self.upstream_port = port, upstream_port
        self.server = None
        self.tasks = set()
        self.dns_limit = asyncio.Semaphore(16)
        self.resolver = None
        self.routes=Routes(directory,routes) if routes is not None else None
        self.stats = {"tcp_ok":0,"tcp_failed":0,"dns_ok":0,"dns_failed":0,"last_error":"",
                      "direct_tcp":0,"youtube_tcp":0,"discord_tcp":0,"ipv4_tcp":0,"ipv6_tcp":0,
                      "ai_tcp":0,"instagram_tcp":0,
                      "quic_blocked":0,"udp_forwarded":0,
                      "tx_bytes":0,"rx_bytes":0,"connect_failed":0,"relay_failed":0}
        self.stats.update(geo_attempts=0,geo_retries=0,geo_failures=0,geo_last_stage='',geo_last_endpoint='')
        self.geo = GeoRoutes(self.stats)
        self.ai_route_check = None
        self._ai_route_checked = 0
        self._ai_route_lock = asyncio.Lock()
        self._ai_route_task = None
        self._closed = False

    async def start(self):
        self._closed = False
        self.resolver = (SmartDNS(rules=self.routes.rules,own_ip=self.routes.own_ip,
                                 protected=self.routes.protected) if self.routes
                         else Resolver(self.upstream_port))
        self.server = await asyncio.start_server(self.accept, "127.0.0.1", self.port)
        self.port = self.server.sockets[0].getsockname()[1]

    def accept(self, reader, writer):
        if len(self.tasks) >= 512:
            writer.close()
            return
        task = asyncio.create_task(self.handle(reader, writer))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def dns(self, payload):
        if len(payload) < 12 or len(payload) > 4096:
            return None
        async with self.dns_limit:
            answer = await self.resolver.query(payload)
            self.stats["dns_ok" if answer else "dns_failed"] += 1
            if not answer: self.stats["last_error"] = "DNS: все HTTPS-провайдеры недоступны"
            return answer or failure_response(payload)

    async def check_dns(self):
        name=b"\x03www\x07youtube\x03com\0"
        query=struct.pack("!HHHHHH",0x4252,0x0100,1,0,0,0)+name+struct.pack("!HH",1,1)
        answer=await self.dns(query)
        ok=bool(answer and answer[3]&15==0 and struct.unpack("!H",answer[6:8])[0]>0)
        return {"ok":ok, "provider":self.resolver.provider, "error":"" if ok else "DNS недоступен"}

    async def check_ai_route(self):
        """Prefer an independently verified public ChatGPT route for new sockets.

        Only fixed, unauthenticated diagnostic GETs are sent. Application TLS
        remains opaque, user requests are never replayed, and open sockets are
        untouched. The probe uses the same direct Comss path as GeoRoutes; the
        Android service excludes this process UID from its own VPN.
        """
        async with self._ai_route_lock:
            if (self._closed or not self.routes or self.routes.own_ip or self.routes.group('chatgpt.com')!='ai'
                    or not isinstance(self.resolver,SmartDNS) or self.resolver.smart is None):
                return {'state':'disabled','verified':False,'authenticated_access':False}
            cached=self.ai_route_check
            if (cached and time.monotonic()-self._ai_route_checked<AI_ROUTE_CACHE_TTL
                    and (not cached.get('verified') or
                         self.resolver.preferred('chatgpt.com')==cached.get('selected_address'))):
                return dict(copy.deepcopy(cached),cached=True)
            self._ai_route_task=asyncio.create_task(self._check_ai_route())
            try:
                result=await self._ai_route_task
                self.ai_route_check=copy.deepcopy(result)
                self._ai_route_checked=time.monotonic()
                return result
            finally:
                self._ai_route_task=None

    async def _check_ai_route(self):
        result={'state':'unconfirmed','verified':False,'authenticated_access':False,
                'checked_at':datetime.datetime.now(datetime.timezone.utc).isoformat(timespec='seconds'),
                'candidates':[]}
        tasks=[]
        try:
            async with asyncio.timeout(AI_ROUTE_TIMEOUT):
                first=await self.resolver.resolve('chatgpt.com')
                addresses=self.resolver.candidates('chatgpt.com',first)[:4]
                if not addresses:
                    return dict(result,state='dns_failed')
                tasks=[asyncio.create_task(self._check_ai_candidate(address)) for address in addresses]
                for completed in asyncio.as_completed(tasks):
                    candidate=await completed
                    result['candidates'].append(candidate)
                    if candidate.get('verified') and self.resolver.prefer('chatgpt.com',candidate['address']):
                        address=candidate['address']
                        self.geo.failed.pop(('chatgpt.com',address,443),None)
                        result.update(state='verified_public',verified=True,selected_address=address)
                        return result
                if any(item.get('state')=='challenge' for item in result['candidates']):
                    result['state']='challenge'
        except asyncio.TimeoutError:
            result['state']='timeout'
        except (OSError,ValueError,httpx.HTTPError) as error:
            result['error']=type(error).__name__
        finally:
            for task in tasks:task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
        return result

    @staticmethod
    async def _check_ai_candidate(address):
        from service_probe import _classify
        result={'address':address,'state':'transport_error','verified':False}
        # One verified TLS pool per endpoint: no connection is reused under a
        # different TLS identity, and environment/system proxies are ignored.
        inner=httpx.AsyncHTTPTransport(verify=verified_context(),trust_env=False,retries=0,
            limits=httpx.Limits(max_connections=1,max_keepalive_connections=0))
        transport=PinnedTransport(inner,{'chatgpt.com':address})
        try:
            async with httpx.AsyncClient(transport=transport,trust_env=False,follow_redirects=False,timeout=4) as client:
                async with client.stream('GET',AI_ROUTE_URL,headers={'Accept':'application/json',
                    'Accept-Encoding':'identity','User-Agent':'SorryRKN-RouteCheck'}) as response:
                    body=bytearray()
                    async for chunk in response.aiter_raw():
                        body.extend(chunk[:65537-len(body)])
                        if len(body)>65536:break
                    result['http_status']=response.status_code
                    if len(body)>65536 or response.headers.get('content-encoding','identity') not in ('','identity'):
                        return dict(result,state='invalid_response')
                    result['state']=_classify(response.status_code,response.headers,bytes(body))
                    if response.status_code==200 and result['state']=='reachable_public':
                        try:
                            providers=json.loads(body)
                            provider=providers.get('openai',{})
                            verified=provider.get('id')=='openai' and provider.get('type')=='oauth'
                        except (ValueError,AttributeError,TypeError,RecursionError):
                            verified=False
                        result.update(verified=verified,state='verified_public' if verified else 'invalid_response')
        except (httpx.HTTPError,OSError,ValueError,asyncio.TimeoutError) as error:
            result['error']=type(error).__name__
        return result

    async def handle(self, reader, writer):
        remote_writer = None
        association = None
        phase='connect'
        try:
            greeting = await asyncio.wait_for(reader.readexactly(2), 10)
            if greeting[0] != 5 or greeting[1] == 0:
                return
            methods = await asyncio.wait_for(reader.readexactly(greeting[1]), 10)
            if 0 not in methods:
                writer.write(b"\x05\xff")
                await writer.drain()
                return
            writer.write(b"\x05\0")
            await writer.drain()
            head = await asyncio.wait_for(reader.readexactly(3), 10)
            if head[0] != 5 or head[2] != 0:
                return
            host, port, address = await asyncio.wait_for(read_address(reader), 10)
            if head[1] == 3:
                association = UDPAssociation(self)
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(
                    lambda: association, local_addr=("127.0.0.1", 0))
                bound_port = transport.get_extra_info("sockname")[1]
                writer.write(b"\x05\0\0" + encode_address("127.0.0.1", bound_port))
                await writer.drain()
                await reader.read()
            elif head[1] == 1 and port == 53:
                writer.write(b"\x05\0\0" + encode_address("127.0.0.1", 0))
                await writer.drain()
                while True:
                    size = struct.unpack("!H", await reader.readexactly(2))[0]
                    if size > 4096:
                        return
                    answer = await self.dns(await reader.readexactly(size))
                    if not answer:
                        return
                    writer.write(struct.pack("!H", len(answer)) + answer)
                    await writer.drain()
            elif head[1] == 1 and self.routes:
                self.stats['ipv6_tcp' if ':' in host else 'ipv4_tcp']+=1
                if port not in self.routes.inspect_ports:
                    # Server-first protocols (SSH/SMTP etc.) must not wait for
                    # a ClientHello before receiving the server's greeting.
                    remote_reader,remote_writer=await asyncio.wait_for(asyncio.open_connection(host,port),10)
                    configure(remote_writer)
                    writer.write(b'\x05\0\0'+encode_address('127.0.0.1',0));await writer.drain()
                    self.stats['tcp_ok']+=1;self.stats['direct_tcp']+=1;phase='relay'
                    await self.relay(reader,writer,remote_reader,remote_writer,self.stats)
                    return
                # Let the client send its encrypted ClientHello before choosing
                # the per-service native engine. Never acknowledge app data
                # upstream until the socket/handshake actually succeeds.
                writer.write(b'\x05\0\0'+encode_address('127.0.0.1',0));await writer.drain()
                initial,name=await read_initial(reader)
                if not initial:return
                if not name:
                    # Domain-form SOCKS requests may carry protocols without a
                    # visible HTTP Host/TLS SNI. Preserve their explicit target.
                    try:ipaddress.ip_address(host)
                    except ValueError:name=host.lower().rstrip('.')
                group=self.routes.group(name)
                destination=host
                explicit_direct=name and self.routes.rules.is_direct(name)
                if name and (group!='direct' or ':' in host or explicit_direct):
                    resolved=await self.resolver.resolve(name)
                    if resolved:destination=resolved
                    elif group!='direct' or explicit_direct and ':' not in host:raise OSError('Selected DNS unavailable')
                reply = b''
                geo_profile=group=='ai' and not self.routes.own_ip
                if geo_profile and name:
                    candidates=self.resolver.candidates(name,destination)
                    remote_reader,remote_writer,reply=await self.geo.connect(
                        name,candidates,port,initial,TLS_FIRST_REPLY_TIMEOUT,self.resolver.invalidate)
                elif group=='direct':
                    remote_reader,remote_writer=await asyncio.wait_for(asyncio.open_connection(destination,port),10)
                else:
                    selected_port=self.routes.port(group)
                    remote_reader,remote_writer=await asyncio.wait_for(asyncio.open_connection('127.0.0.1',selected_port),3)
                    async with asyncio.timeout(10):
                        remote_writer.write(b'\x05\x01\0');await remote_writer.drain()
                        if await remote_reader.readexactly(2)!=b'\x05\0':raise OSError('Native SOCKS greeting rejected')
                        remote_writer.write(b'\x05\x01\0'+encode_address(destination,port));await remote_writer.drain()
                        result=await remote_reader.readexactly(3)
                        await read_address(remote_reader)
                        if result!=b'\x05\0\0':raise OSError('Native SOCKS connect failed')
                configure(remote_writer)
                self.stats['tcp_ok']+=1;self.stats[group+'_tcp']+=1
                phase='relay'
                if not geo_profile:
                    remote_writer.write(initial);await remote_writer.drain();self.stats['tx_bytes']+=len(initial)
                if reply:
                    writer.write(reply);await writer.drain();self.stats['rx_bytes']+=len(reply)
                await self.relay(reader,writer,remote_reader,remote_writer,self.stats)
            elif head[1] == 1:
                remote_reader, remote_writer = await asyncio.wait_for(
                    asyncio.open_connection("127.0.0.1", self.upstream_port), 10)
                remote_writer.write(b"\x05\x01\0")
                await remote_writer.drain()
                if await remote_reader.readexactly(2) != b"\x05\0":
                    raise OSError("zapret rejected SOCKS greeting")
                remote_writer.write(b"\x05\x01\0" + address)
                await remote_writer.drain()
                result = await remote_reader.readexactly(3)
                _, _, bound = await read_address(remote_reader)
                writer.write(result + bound)
                await writer.drain()
                if result[1] != 0:
                    self.stats["tcp_failed"] += 1
                    self.stats["last_error"] = "SOCKS: код " + str(result[1])
                    return
                configure(remote_writer)
                self.stats["tcp_ok"] += 1
                phase='relay'
                await self.relay(reader, writer, remote_reader, remote_writer,self.stats)
            else:
                writer.write(b"\x05\x07\0" + encode_address("127.0.0.1", 0))
                await writer.drain()
        except (OSError, ValueError, UnicodeError, asyncio.IncompleteReadError,
                asyncio.TimeoutError, httpx.HTTPError) as error:
            if isinstance(error,GeoRouteError):phase='connect' if error.stage in ('connect','dns') else 'relay'
            self.stats["tcp_failed"] += 1
            self.stats[phase+'_failed']+=1
            self.stats["last_error"] = type(error).__name__
        finally:
            if association:
                await association.close()
            for output in (writer, remote_writer):
                if output:
                    output.close()
                    with contextlib.suppress(OSError, asyncio.CancelledError, asyncio.TimeoutError):
                        await asyncio.wait_for(output.wait_closed(), 1)

    @staticmethod
    async def relay(reader, writer, remote_reader, remote_writer,stats=None):
        async def copy(source, target,counter):
            while True:
                data = await source.read(65536)
                if not data:
                    with contextlib.suppress(OSError, AttributeError):
                        target.write_eof()
                    return
                target.write(data)
                await target.drain()
                if stats is not None:stats[counter]+=len(data)
        tasks = [asyncio.create_task(copy(reader, remote_writer,'tx_bytes')),
                 asyncio.create_task(copy(remote_reader, writer,'rx_bytes'))]
        try:
            done,_=await asyncio.wait(tasks,return_when=asyncio.FIRST_COMPLETED)
            for task in done:task.result()
            if tasks[1] in done:
                # Upstream EOF ends this session even if an app keeps its
                # local socket open. Do not accumulate abandoned relays.
                tasks[0].cancel()
            else:
                # Preserve a valid client half-close while the server replies.
                await tasks[1]
        finally:
            for task in tasks:task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)

    async def close(self):
        self._closed=True
        if self._ai_route_task:
            self._ai_route_task.cancel()
            await asyncio.gather(self._ai_route_task,return_exceptions=True)
        self.ai_route_check=None
        if self.server:
            self.server.close()
        tasks = list(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        if self.server:
            await self.server.wait_closed()
        if self.resolver: await self.resolver.close()
