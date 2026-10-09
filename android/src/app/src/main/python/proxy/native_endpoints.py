"""Small, first-party-only bootstrap list for native MTProto TCP transport.

Telegram documents TCP ports 80, 443 and 5222, except for dcOption entries
marked this_port_only: https://core.telegram.org/mtproto/transports#tcp
The production DC1--5 addresses and extra DC2 address are the official Android
bootstrap entries (flags=0, no secret), also present in TDLib:
https://github.com/DrKLO/Telegram/blob/master/TMessagesProj/jni/tgnet/ConnectionsManager.cpp
https://github.com/tdlib/td/blob/master/td/telegram/net/ConnectionCreator.cpp

This is not a general IP scanner. Unknown CDN/test endpoint port policies are
not inferred from ordinary production DCs; they retain their existing port.
"""
from .utils import DC_DEFAULT_IPS, DC_TEST_IPS


MAX_NATIVE_CANDIDATES = 4


def native_tcp_endpoints(dc, is_test_dc=False):
    address = (DC_TEST_IPS if is_test_dc else DC_DEFAULT_IPS).get(dc)
    if address is None:
        return ()
    if is_test_dc or dc not in (1, 2, 3, 4, 5):
        return ((address, 443),)
    endpoints = [(address, port) for port in (443, 5222, 80)]
    if dc == 2:
        endpoints.append(('95.161.76.100', 443))
    return tuple(endpoints)
