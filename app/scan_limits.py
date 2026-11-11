"""Process-local admission, bounded JSON buffering and redacted request logs.

Release check: the server/proxy must validate its trusted proxy chain before it
sets the ASGI client identity. This module never reads forwarding headers.
Infrastructure/proxy log retention must be checked separately before release.
"""
from __future__ import annotations

import asyncio
import ipaddress
import logging
import secrets
import threading
import time
from collections import OrderedDict

from starlette.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

MAX_JSON_BYTES = 128 * 1024
MAX_IDENTITIES = 10_000
MAX_REQUEST_WORK = 32
MAX_BODY_READ_SECONDS = 10
_SCAN_PATHS = frozenset({'/v1/analyze-message', '/v1/analyze'})
_LOG = logging.getLogger('mobileshield.requests')


def client_identity(host: str | None) -> str:
    """Rate-limit key for a client address.

    One IPv6 subscriber usually controls a whole /64, so per-address IPv6 keys
    would let a single client rotate addresses to escape its limit.
    """
    if not host:
        return '<unknown>'
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return host
    if address.version == 4:
        return str(address)
    if address.ipv4_mapped is not None:
        return str(address.ipv4_mapped)
    return str(ipaddress.ip_network(f'{address}/64', strict=False))


class ScanRateLimiter:
    """Fixed one-minute window per client, held in process memory.

    The table is bounded. When it is full the oldest window is evicted instead
    of refusing new clients, so a flood of distinct addresses cannot lock every
    other user out. Multi-process deployments need a shared store (e.g. Redis).
    """
    def __init__(self, limit: int, *, clock=time.monotonic, max_identities: int = MAX_IDENTITIES):
        self.limit = limit
        self.max_identities = max_identities
        self._clock = clock
        self._identities: OrderedDict[str, tuple[float, int]] = OrderedDict()
        self._lock = threading.Lock()

    def _expire(self, now: float) -> None:
        while self._identities and next(iter(self._identities.values()))[0] <= now:
            self._identities.popitem(last=False)

    def expire(self) -> None:
        with self._lock:
            self._expire(self._clock())

    def allow(self, identity: str) -> bool:
        with self._lock:
            now = self._clock()
            self._expire(now)
            if self.limit <= 0:
                return False
            current = self._identities.get(identity)
            if current:
                expiry, count = current
                if count >= self.limit:
                    return False
                self._identities[identity] = (expiry, count + 1)
                return True
            while len(self._identities) >= self.max_identities:
                self._identities.popitem(last=False)
            self._identities[identity] = (now + 60, 1)
            return True


class RequestWorkAdmission:
    """Bound buffered/worker-bound requests; not a network inspection guard."""
    def __init__(self):
        self._active = 0
        self._lock = threading.Lock()

    def acquire(self) -> bool:
        with self._lock:
            if self._active >= MAX_REQUEST_WORK:
                return False
            self._active += 1
            return True

    def release(self) -> None:
        with self._lock:
            self._active -= 1


class _SuppressAccess(logging.Filter):
    def filter(self, record):
        return False


class _SanitizeServer(logging.Filter):
    def filter(self, record):
        if (isinstance(record.msg, str) and not record.args and not record.exc_info
                and not record.exc_text and not record.stack_info and record.msg in {
            'Waiting for application startup.', 'Application startup complete.',
            'Waiting for application shutdown.', 'Application shutdown complete.', 'Shutting down',
        }):
            return True
        # Uvicorn's protocol errors and exc_info may contain URLs, headers or
        # exception messages. Preserve occurrence/severity without those details.
        record.msg = 'route=<server-error> status=503 duration_ms=0 request_id=%s'
        record.args = (secrets.token_hex(16),)
        record.exc_info = record.exc_text = record.stack_info = None
        return True


def configure_private_server_logging() -> None:
    _LOG.setLevel(logging.INFO)
    if not _LOG.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(logging.Formatter('%(message)s'))
        _LOG.addHandler(handler)
    for name, filter_type in (('uvicorn.access', _SuppressAccess), ('uvicorn.error', _SanitizeServer)):
        logger = logging.getLogger(name)
        if not any(isinstance(f, filter_type) for f in logger.filters):
            logger.addFilter(filter_type())


class PrivateRequestMiddleware:
    """ASGI boundary: enforce byte cap before JSON parsing, even with no length."""
    def __init__(self, app, cors_origins=()):
        self.app = app
        self.cors_origins = cors_origins

    async def __call__(self, scope, receive, send):
        if scope['type'] != 'http':
            return await self.app(scope, receive, send)
        started = time.monotonic()
        request_id = secrets.token_hex(16)
        scope.setdefault('state', {})['request_id'] = request_id
        status_code = 503
        response_started = False
        work_admission = None

        async def private_send(message):
            nonlocal status_code, response_started
            if message['type'] == 'http.response.start':
                response_started = True
                status_code = message['status']
                headers = [(k, v) for k, v in message.get('headers', [])
                           if k.lower() not in (b'cache-control', b'x-request-id')]
                headers += [(b'cache-control', b'no-store'), (b'x-request-id', request_id.encode())]
                message = {**message, 'headers': headers}
            await send(message)

        async def reject(status, code):
            response = JSONResponse({'detail': code, 'request_id': request_id}, status_code=status)
            # Early rejection happens outside the ordinary CORS middleware.
            # Apply the same policy so the web client can read 413/429/503.
            await CORSMiddleware(response, allow_origins=self.cors_origins)(scope, receive, private_send)

        try:
            if scope.get('method') == 'POST':
                if scope.get('path') in _SCAN_PATHS:
                    client = scope.get('client')
                    identity = client_identity(client[0] if client else None)
                    if not scope['app'].state.scan_limiter.allow(identity):
                        return await reject(429, 'rate_limit_exceeded')
                # Every POST below is buffered, including redirects/unmatched
                # routes, so every body reader must consume the same work cap.
                admission = scope['app'].state.scan_work
                if not admission.acquire():
                    return await reject(503, 'analysis_unavailable')
                work_admission = admission
                # Count received bytes, not the declared Content-Length. Reject
                # oversized declarations early as well, without reading the body.
                for key, value in scope.get('headers', []):
                    if key.lower() == b'content-length':
                        try:
                            if int(value) > MAX_JSON_BYTES:
                                return await reject(413, 'body_too_large')
                        except ValueError:
                            return await reject(422, 'invalid_request')
                body = bytearray()
                try:
                    # asyncio's monotonic absolute deadline covers the entire
                    # buffer operation; a new chunk cannot renew the budget.
                    async with asyncio.timeout(MAX_BODY_READ_SECONDS):
                        while True:
                            part = await receive()
                            if part['type'] == 'http.disconnect':
                                return
                            chunk = part.get('body', b'')
                            if len(body) + len(chunk) > MAX_JSON_BYTES:
                                return await reject(413, 'body_too_large')
                            body.extend(chunk)
                            if not part.get('more_body', False):
                                break
                except TimeoutError:
                    return await reject(408, 'request_timeout')
                delivered = False
                async def buffered_receive():
                    nonlocal delivered
                    if not delivered:
                        delivered = True
                        return {'type': 'http.request', 'body': bytes(body), 'more_body': False}
                    return await receive()
                await self.app(scope, buffered_receive, private_send)
            else:
                await self.app(scope, receive, private_send)
        except Exception:
            # Never allow ServerErrorMiddleware/uvicorn to render/log exception
            # detail. A partial response cannot be replaced, but it is still no-store.
            if not response_started:
                await reject(503, 'analysis_unavailable')
        finally:
            if work_admission is not None:
                work_admission.release()
            route = getattr(scope.get('route'), 'path', '<unmatched>')
            _LOG.info('route=%s status=%s duration_ms=%s request_id=%s', route, status_code,
                      int((time.monotonic() - started) * 1000), request_id)
