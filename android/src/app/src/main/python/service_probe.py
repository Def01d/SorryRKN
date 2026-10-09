"""Bounded, unauthenticated service diagnostics through the active local gateway.

A reachable public page does not establish that login, conversations or the
user's account work. The probe owns only its new HTTP connection; it never
restarts a gateway, changes routing, or touches another application session.
"""
import asyncio
import datetime
import html
import json
import re
import socket
import ssl

import httpx

from doh import verified_context

CHATGPT_URL = "https://chatgpt.com/"
TOTAL_TIMEOUT = 8.0
MAX_BODY = 32768
_REGIONAL_CODE = "unsupported_country_region_territory"
_REGIONAL_TEXT = re.compile(
    r"\b(?:country,?\s*region,?\s*(?:or\s*)?territory\s+(?:is\s+)?not supported"
    r"|(?:openai(?:'s)?(?: services)?|chatgpt|this service)\s+(?:is|are)\s+not available in your (?:country|region)"
    r"|(?:your|this) (?:country|region) (?:is not supported|is unsupported))\b",
    re.IGNORECASE,
)


def _visible_text(body):
    # Strings in JavaScript bundles documenting an error are not evidence of a
    # refusal. This is deliberately a small conservative diagnostic classifier.
    text = body.decode("utf-8", "replace")
    text = re.sub(r"<(script|style)\b[^>]*>.*?(?:</\1\s*>|$)", " ", text,
                  flags=re.IGNORECASE | re.DOTALL)
    text = re.sub(r"<!--.*?(?:-->|$)", " ", text, flags=re.DOTALL)
    text = re.sub(r"<[^>]*>", " ", text)
    return " ".join(html.unescape(text).split())


def _regional_refusal(body):
    try:
        value = json.loads(body)
    except (ValueError, UnicodeError, RecursionError):
        value = None
    if isinstance(value, dict):
        error = value.get("error", value)
        if error == _REGIONAL_CODE:
            return True
        if isinstance(error, dict):
            if error.get("code") == _REGIONAL_CODE or error.get("type") == _REGIONAL_CODE:
                return True
            # Examine actual error fields, not arbitrary JSON configuration.
            return bool(_REGIONAL_TEXT.search(str(error.get("message", ""))))
        return False
    visible = _visible_text(body)
    return visible == _REGIONAL_CODE or bool(_REGIONAL_TEXT.search(visible))


def _classify(status, headers, body):
    if _regional_refusal(body):
        return "regional_refusal"
    if status == 403:
        lowered = body.lower()
        challenge = (headers.get("cf-mitigated", "").lower() == "challenge"
                     or (b"cf-chl-" in lowered or b"/cdn-cgi/challenge-platform/" in lowered)
                     and (b"cloudflare" in lowered or b"just a moment" in lowered))
        return "challenge" if challenge else "denied"
    if 300 <= status < 400:
        # No redirects are followed: their destination is not evidence that a
        # login or an authenticated ChatGPT session succeeds.
        return "login_unchecked"
    return "reachable_public" if status == 200 else "http_error"


def _error_stage(error):
    chain = []
    seen = set()
    current = error
    while current is not None and id(current) not in seen:
        chain.append(current)
        seen.add(id(current))
        current = current.__cause__ or current.__context__
    if any(isinstance(item, (ssl.SSLError, ssl.CertificateError)) for item in chain):
        return "TLS"
    if any(isinstance(item, socket.gaierror) for item in chain):
        return "DNS"
    if any(isinstance(item, (asyncio.TimeoutError, httpx.TimeoutException)) for item in chain):
        return "timeout"
    if isinstance(error, httpx.ProxyError):
        return "SOCKS"
    if isinstance(error, (httpx.ConnectError, ConnectionError, OSError)):
        return "TCP"
    return "HTTPS"


async def check_chatgpt(socks_port):
    """Return a safe public-page diagnostic in at most TOTAL_TIMEOUT seconds.

    The fixed URL has no credentials or user query. TLS certificates and host
    names are verified, environment proxies are ignored, cookies are not
    retained, and redirects are never followed. Cancellation closes only this
    probe's connection and is represented explicitly in the returned result.
    """
    result = {
        "service": "ChatGPT",
        "checked_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "authenticated_access": False,
        "state": "transport_error",
        "stage": "HTTPS",
        "error": "",
    }
    if isinstance(socks_port, bool) or not isinstance(socks_port, int) or not 1 <= socks_port <= 65535:
        return dict(result, stage="configuration", error="ValueError")
    try:
        async with asyncio.timeout(TOTAL_TIMEOUT):
            transport = httpx.AsyncHTTPTransport(
                proxy=f"socks5://127.0.0.1:{socks_port}", verify=verified_context(),
                trust_env=False, retries=0,
                limits=httpx.Limits(max_connections=1, max_keepalive_connections=0),
            )
            async with httpx.AsyncClient(
                transport=transport, trust_env=False, follow_redirects=False,
                timeout=httpx.Timeout(TOTAL_TIMEOUT),
            ) as client:
                async with client.stream("GET", CHATGPT_URL, headers={
                    "Accept": "text/html, application/json",
                    "Accept-Encoding": "identity",
                    "Cache-Control": "no-cache",
                    "User-Agent": "SorryRKN-ServiceCheck",
                }) as response:
                    result["http_status"] = response.status_code
                    body = bytearray()
                    async for chunk in response.aiter_raw():
                        body.extend(chunk[:MAX_BODY - len(body)])
                        if len(body) >= MAX_BODY:
                            break
                    # Do not decompress an unsolicited compressed body: a
                    # decompression bomb must not defeat the memory bound.
                    encoded = response.headers.get("content-encoding", "identity").lower()
                    examined = bytes(body) if encoded in ("", "identity") else b""
                    if encoded not in ("", "identity"):
                        result.update(state="http_error", error="UnsupportedContentEncoding")
                    else:
                        result["state"] = _classify(response.status_code, response.headers, examined)
                    result["body_bytes_examined"] = len(examined)
    except asyncio.CancelledError:
        result.update(state="cancelled", stage="cancelled", error="CancelledError")
    except (httpx.HTTPError, OSError, ValueError, asyncio.TimeoutError) as error:
        result.update(state="transport_error", stage=_error_stage(error), error=type(error).__name__)
    return result
