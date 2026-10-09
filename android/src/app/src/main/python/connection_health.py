"""Detect dead TCP paths without timing out healthy idle application sessions."""
import socket


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
