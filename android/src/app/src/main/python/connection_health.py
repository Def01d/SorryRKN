"""Detect dead TCP paths without timing out healthy idle application sessions."""
import socket
import asyncio
import contextlib
import ipaddress


async def open_socks(host, port, local_port):
    """Connect an explicit destination through a device-local SOCKS5 engine."""
    reader, writer = await asyncio.open_connection("127.0.0.1", local_port)
    try:
        writer.write(b"\x05\x01\x00")
        await writer.drain()
        if await reader.readexactly(2) != b"\x05\x00":
            raise OSError("Local SOCKS authentication rejected")
        address = ipaddress.ip_address(host)
        writer.write(b"\x05\x01\x00" + bytes([1 if address.version == 4 else 4])
                     + address.packed + port.to_bytes(2, "big"))
        await writer.drain()
        reply = await reader.readexactly(4)
        if reply[:3] != b"\x05\x00\x00":
            raise OSError("Local SOCKS destination rejected")
        if reply[3] == 1:
            await reader.readexactly(6)
        elif reply[3] == 4:
            await reader.readexactly(18)
        elif reply[3] == 3:
            size = (await reader.readexactly(1))[0]
            await reader.readexactly(size + 2)
        else:
            raise OSError("Invalid local SOCKS address")
        return reader, writer
    except BaseException:
        writer.close()
        with contextlib.suppress(AttributeError, OSError):
            writer.transport.abort()
        raise


def configure(writer):
    sock = writer.get_extra_info('socket')
    if sock is None:
        return
    for level, name, value in ((socket.SOL_SOCKET, 'SO_KEEPALIVE', 1),
                               (socket.IPPROTO_TCP, 'TCP_KEEPIDLE', 20),
                               (socket.IPPROTO_TCP, 'TCP_KEEPINTVL', 10),
                               (socket.IPPROTO_TCP, 'TCP_KEEPCNT', 3),
                               (socket.IPPROTO_TCP, 'TCP_USER_TIMEOUT', 45000)):
        option = getattr(socket, name, None)
        if option is not None:
            try:
                sock.setsockopt(level, option, value)
            except (OSError, AttributeError):
                pass
