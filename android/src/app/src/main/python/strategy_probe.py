"""Certificate-verified application responses through the tested SOCKS process."""
import asyncio
import json
import time
import httpx
from doh import Resolver, PinnedTransport, verified_context
from discord_gateway import check_gateway,HOST as GATEWAY_HOST

TARGETS = (("YouTube", "https://www.youtube.com/generate_204", 204),
           ("Discord", "https://discord.com/api/v10/gateway", 200))
CDN_TARGET=('Discord CDN','https://cdn.discordapp.com/embed/avatars/0.png',200)


def acceptable(name, response, payload):
    if name == "YouTube":
        return response.status_code == 204 and not payload
    if name == "Discord" and response.status_code == 200:
        try:
            return json.loads(payload).get("url") == "wss://gateway.discord.gg"
        except (ValueError, AttributeError):
            pass
    if name=='Discord CDN':
        return response.status_code==200 and payload.startswith(b'\x89PNG\r\n\x1a\n') and response.headers.get('content-type','').split(';')[0]=='image/png'
    return False


async def check(client, target):
    return (await check_detail(client,target))["ok"]


async def check_detail(client,target):
    name, url, _ = target
    detail={"name":name,"ok":False,"stage":"HTTP","error":""}
    try:
        async with client.stream("GET", url) as response:
            payload = bytearray()
            async for chunk in response.aiter_bytes():
                payload.extend(chunk)
                if len(payload) > 16384:
                    detail["error"]="Слишком большой ответ"
                    return detail
            detail["ok"]=acceptable(name,response,payload)
            if not detail["ok"]: detail["error"]="Неверный ответ HTTP "+str(response.status_code)
    except (httpx.HTTPError,OSError,ValueError) as error:
        chain=[]; current=error
        for _ in range(4):
            if current is None: break
            chain.append(type(current).__name__+": "+str(current)); current=current.__cause__
        message=" ".join(chain).lower()
        detail["stage"]="TLS" if any(x in message for x in ("certificate","ssl","tls")) else ("DNS" if "gaierror" in message else "TCP / SOCKS")
        detail["error"]=type(error).__name__
    return detail


async def probe_async(port, control, transport=None, verify=True, timeout=3, bootstrap=True,full_discord=False,addresses=None,gateway_check=None):
    if transport is None and bootstrap:
        # Use the same verified DoH path as the VPN. SOCKS remote DNS would
        # otherwise resolve target names using the operator's system DNS.
        resolver=Resolver(port)
        hosts={httpx.URL(target[1]).host for target in TARGETS}
        if full_discord:hosts.update((GATEWAY_HOST,httpx.URL(CDN_TARGET[1]).host))
        tasks={host:asyncio.create_task(resolver.resolve(host)) for host in hosts}
        try:
            while not all(task.done() for task in tasks.values()):
                if not control.keepRunning(): raise asyncio.CancelledError()
                await asyncio.sleep(.05)
            addresses={host:task.result() for host,task in tasks.items() if task.result()}
            provider=resolver.provider
        finally:
            for task in tasks.values(): task.cancel()
            await asyncio.gather(*tasks.values(),return_exceptions=True)
            await resolver.close()
        inner=httpx.AsyncHTTPTransport(proxy=f"socks5://127.0.0.1:{int(port)}",verify=verified_context() if verify is True else verify,trust_env=False)
        transport=PinnedTransport(inner,addresses)
        result=await probe_async(port,control,transport,verify,timeout,bootstrap=False,full_discord=full_discord,addresses=addresses,gateway_check=gateway_check)
        result["dns"]={"ok":bool(addresses),"provider":provider,"resolved":len(addresses),"total":len(hosts)}
        return result
    begin = time.monotonic()
    async with httpx.AsyncClient(proxy=f"socks5://127.0.0.1:{int(port)}" if transport is None else None,
                                 transport=transport, timeout=timeout, trust_env=False,
                                 verify=verify, follow_redirects=False, headers={"User-Agent": "GrayBridge/0.6"}) as client:
        discord_parts={}
        def discord_result():
            parts=[discord_parts.get(name,{'name':name,'ok':False,'stage':name,'error':'Таймаут'}) for name in ('API','Gateway','CDN')]
            failure=next((p for p in parts if not p['ok']),None)
            return {'name':'Discord','ok':failure is None,'api_ok':parts[0]['ok'],'gateway_ok':parts[1]['ok'],'cdn_ok':parts[2]['ok'],
                    'stage':'Discord' if failure is None else failure['stage'],'error':'' if failure is None else failure['error'],'parts':parts}
        async def http_check(target):
            if addresses is not None and httpx.URL(target[1]).host not in addresses:
                return {"name":target[0],"ok":False,"stage":"DNS","error":"Нет DNS-ответа"}
            return await check_detail(client,target)
        async def discord_check(target):
            async def gateway():
                if addresses is not None and GATEWAY_HOST not in addresses:
                    return {"name":"Gateway","ok":False,"stage":"DNS","error":"Нет DNS-ответа"}
                return await (gateway_check or check_gateway)(port,(addresses or {}).get(GATEWAY_HOST,'127.0.0.1'),verify,timeout)
            async def record(name,request):
                result=await request;result['name']=name;discord_parts[name]=result
            await asyncio.gather(record('API',http_check(target)),record('Gateway',gateway()),record('CDN',http_check(CDN_TARGET)))
            return discord_result()
        tasks = [asyncio.create_task(discord_check(target) if full_discord and target[0]=='Discord' else http_check(target)) for target in TARGETS]
        group = asyncio.gather(*tasks)
        try:
            # Total per-candidate deadline also bounds a peer sending bytes slowly.
            while not group.done():
                if not control.keepRunning():
                    raise asyncio.CancelledError()
                if time.monotonic() - begin > timeout+0.3:
                    details=[t.result() if t.done() and not t.cancelled() and not t.exception()
                             else discord_result() if full_discord and TARGETS[i][0]=='Discord'
                             else {"name":TARGETS[i][0],"ok":False,"stage":"TCP / TLS","error":"Таймаут"}
                             for i,t in enumerate(tasks)]
                    passed=sum(d["ok"] for d in details)
                    group.cancel()
                    await asyncio.gather(group, return_exceptions=True)
                    return {"passed": passed, "total": len(TARGETS), "complete": False,"targets":details}
                await asyncio.sleep(0.05)
            details=group.result()
            passed = sum(d["ok"] for d in details)
            return {"passed": passed, "total": len(TARGETS), "complete": passed == len(TARGETS),
                    "seconds": round(time.monotonic() - begin, 2),"targets":details}
        finally:
            if not group.done():
                group.cancel()
                await asyncio.gather(group, return_exceptions=True)


def probe(port, control):
    try:
        return json.dumps(asyncio.run(probe_async(port, control,full_discord=True)))
    except asyncio.CancelledError:
        return json.dumps({"cancelled": True, "passed": 0, "total": len(TARGETS), "complete": False})


def probe_dns(port,control):
    async def run():
        from doh import Resolver
        import struct
        resolver=Resolver(port)
        query=struct.pack("!HHHHHH",0x4252,0x0100,1,0,0,0)+b"\x03www\x07youtube\x03com\0"+struct.pack("!HH",1,1)
        task=asyncio.create_task(resolver.query(query))
        try:
            while not task.done():
                if not control.keepRunning(): raise asyncio.CancelledError()
                await asyncio.sleep(.05)
            answer=task.result()
            ok=bool(answer and answer[3]&15==0 and struct.unpack("!H",answer[6:8])[0]>0)
            return {"ok":ok,"provider":resolver.provider,"error":"" if ok else "DNS недоступен"}
        finally:
            task.cancel(); await asyncio.gather(task,return_exceptions=True)
            await resolver.close()
    try: return json.dumps(asyncio.run(run()),ensure_ascii=False)
    except asyncio.CancelledError: return json.dumps({"cancelled":True,"ok":False})
