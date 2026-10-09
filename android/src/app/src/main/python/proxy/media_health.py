"""Recover silent media requests, without probing or timing out idle chats."""
import asyncio
import contextlib
import logging
import time

from .stats import stats

MEDIA_RESPONSE_TIMEOUT = 60.0
CHECK_INTERVAL = 1.0
CLOSE_TIMEOUT = 1.0
log = logging.getLogger('tg-mtproto-proxy')
_active = set()


async def close_writer(writer):
    """TLS shutdown must not keep a failed session alive indefinitely."""
    writer.close()
    try:
        await asyncio.wait_for(writer.wait_closed(), CLOSE_TIMEOUT)
    except (OSError, asyncio.TimeoutError):
        with contextlib.suppress(AttributeError, OSError):
            writer.transport.abort()


class MediaHealth:
    def __init__(self, route, dc=None, progress=None, on_stall=None):
        self.route, self.dc = route, dc
        self.progress = progress or (lambda: 0.0)
        self.on_stall = on_stall
        self.awaiting_since = None
        self.last_data = 0.0
        self.writing_native = False
        self.stalled = False
        _active.add(self)

    def input(self):
        # Further requests cannot extend an already unanswered request forever.
        if self.awaiting_since is None:
            self.awaiting_since = time.monotonic()

    def received(self):
        self.last_data = time.monotonic()
        self.awaiting_since = None

    def delivered(self):
        # Time spent waiting for the native client to read must not consume
        # the remote response deadline of a concurrent request.
        self.last_data = time.monotonic()
        self.writing_native = False

    async def run(self):
        while True:
            await asyncio.sleep(CHECK_INTERVAL)
            if self.awaiting_since is None or self.writing_native:
                continue
            last = max(self.awaiting_since, self.last_data, self.progress())
            if time.monotonic() - last < MEDIA_RESPONSE_TIMEOUT:
                continue
            self.stalled = True
            stats.media_stalls += 1
            stats.last_media_stall = self.route + (f'/DC{self.dc}' if self.dc else '')
            log.warning('Media request stopped receiving data: route=%s dc=%s; '
                        'closing this native session for client retry', self.route, self.dc)
            if self.on_stall:
                self.on_stall()
            return

    def close(self):
        _active.discard(self)


def diagnostics():
    now = time.monotonic()
    sessions = list(_active)
    return {'active': len(sessions), 'waiting': sum(s.awaiting_since is not None for s in sessions),
            'sessions': [{'route': s.route, 'dc': s.dc,
                          'no_data_seconds': round(max(0, now - max(s.awaiting_since, s.last_data, s.progress())), 1)
                          if s.awaiting_since is not None else 0,
                          'client_backpressure': s.writing_native} for s in sessions[:16]]}
