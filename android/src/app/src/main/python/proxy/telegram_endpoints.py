"""Verified DNS for Telegram's own WebSocket endpoints, without relay hosts."""
import asyncio
import ipaddress

from doh import Resolver
from .route_diagnostics import Attempt


def legacy_fronting(host, domain, sni='sprinthost.ru'):
    """The exact Telegram-owned compatibility endpoint used before 0.10.0."""
    return (host == '149.154.167.220' and sni == 'sprinthost.ru'
            and domain in ('kws2.web.telegram.org', 'kws2-1.web.telegram.org',
                           'kws4.web.telegram.org', 'kws4-1.web.telegram.org'))


def websocket_dc(dc):
    # Only DC1–5 have documented browser WebSocket entry points. In particular,
    # the legacy ws_domains(203) alias is not proof that DC2's DNS address can
    # serve DC203's CDN key. Keep CDN traffic on its known native TCP endpoint
    # unless an explicit WebSocket pin was configured for that DC.
    return dc if dc in (1, 2, 3, 4, 5) else None


class TelegramEndpoints:
    def __init__(self):
        self.resolver = None

    async def addresses(self, domain, pinned=None):
        if self.resolver is None:
            self.resolver = Resolver(None)
        result = []
        attempt = Attempt('dns', domain)
        attempt.stage('dns')
        try:
            first = await asyncio.wait_for(self.resolver.resolve(domain), 3.5)
            if first:
                result.extend((first, *self.resolver.last_addresses.get(domain, ())))
                attempt.success(answers=min(256, len(set(result))))
            else:
                # Resolver intentionally hides individual DoH peer errors. An
                # empty answer is evidence only of failed endpoint discovery.
                attempt.failure(LookupError())
        except asyncio.CancelledError:
            attempt.cancel()
            raise
        except (OSError, ValueError, asyncio.TimeoutError) as error:
            attempt.failure(error)
        finally:
            attempt.finish()
        # The configured Telegram address remains a fallback if HTTPS DNS is
        # unreachable or the current DNS address is filtered by the operator.
        if pinned:
            try:
                ipaddress.IPv4Address(pinned)
                result.append(pinned)
            except ipaddress.AddressValueError:
                pass
        unique = list(dict.fromkeys(result))
        return (unique[:3] + [pinned] if pinned in unique[4:]
                else unique[:4])

    async def close(self):
        if self.resolver is not None:
            await self.resolver.close()
            self.resolver = None
