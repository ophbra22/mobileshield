"""One bounded HTTP/TLS destination inspector; no cookies, proxies or subresources."""
from __future__ import annotations

from dataclasses import dataclass, field
import http.client
import ipaddress
import socket
import ssl
import threading
import time
from urllib.parse import urljoin

from app.detection.models import CertificateAnalysis, RedirectHop
from app.detection.network_policy import (
    DestinationBlocked, ambiguous_url_text, canonical_target, public_address, resolve_public,
)

MAX_BODY_BYTES = 256 * 1024
MAX_REDIRECTS = 5
MAX_INSPECTION_SECONDS = 20
_INSPECTION_GUARD = threading.BoundedSemaphore(2)


@dataclass
class UrlObservation:
    final_url: str | None = None
    hops: list[RedirectHop] = field(default_factory=list)
    tls: CertificateAnalysis | None = None
    html: str | None = None
    content_type: str | None = None
    completed_checks: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)


def _remaining(deadline, clock):
    remaining = deadline - clock()
    if remaining <= 0:
        raise TimeoutError('deadline_exceeded')
    return remaining


class _PinnedConnection(http.client.HTTPConnection):
    """Numeric socket connect, original Host/SNI, and an absolute-deadline abort.

    Socket timeouts alone permit servers to dribble headers indefinitely. The
    watchdog shuts down the socket even while HTTPResponse reads a header line.
    """
    def __init__(self, target, address, *, deadline, clock):
        super().__init__(target.hostname, target.port)
        self._target = target
        self._address = public_address(address)
        self._deadline = deadline
        self._clock = clock
        self._watchdog = None
        self._socket_lock = threading.Lock()
        self._reading_headers = False

    def _abort(self):
        with self._socket_lock:
            if self.sock is not None:
                try:
                    self.sock.shutdown(socket.SHUT_RDWR)
                except OSError:
                    pass
                self.sock.close()

    def connect(self):
        remaining = _remaining(self._deadline, self._clock)
        family = socket.AF_INET6 if ':' in self._address else socket.AF_INET
        with self._socket_lock:
            self.sock = socket.socket(family, socket.SOCK_STREAM)
            self.sock.settimeout(remaining)
        self._watchdog = threading.Timer(remaining, self._abort)
        self._watchdog.daemon = True
        self._watchdog.start()
        address = ((self._address, self.port, 0, 0) if family == socket.AF_INET6
                   else (self._address, self.port))
        self.sock.connect(address)
        if self._target.scheme == 'https':
            context = ssl.create_default_context()
            # Set self.sock before handshake so the deadline can abort TLS too.
            with self._socket_lock:
                self.sock = context.wrap_socket(self.sock, server_hostname=self._target.hostname,
                                                do_handshake_on_connect=False)
                self.sock.settimeout(_remaining(self._deadline, self._clock))
            self.sock.do_handshake()
        _remaining(self._deadline, self._clock)

    def getresponse(self):
        self._reading_headers = True
        try:
            return super().getresponse()
        finally:
            self._reading_headers = False

    def close(self):
        # HTTPConnection.getresponse() calls close for a close-delimited
        # response. We make exactly one request and retain socket ownership
        # until inspect's finally, so the body stays under the watchdog.
        if self._reading_headers:
            return
        if self._watchdog is not None:
            self._watchdog.cancel()
            self._watchdog.join()
        super().close()


def _open_connection(target, address, *, deadline, clock):
    return _PinnedConnection(target, address, deadline=deadline, clock=clock)


def _certificate(cert) -> CertificateAnalysis:
    def name(key):
        values = cert.get(key)
        return ', '.join(f'{k}={v}' for item in values for k, v in item) if values else None
    # Successful verified TLS already checked hostname, chain and validity.
    return CertificateAnalysis(name('issuer'), name('subject'), cert.get('notBefore'),
                               cert.get('notAfter'), True, True)


class SafeTransport:
    def __init__(self, *, resolver=resolve_public, connector=_open_connection, clock=time.monotonic):
        self._resolver = resolver
        self._connector = connector
        self._clock = clock

    def inspect(self, url: str, *, deadline: float) -> UrlObservation:
        result = UrlObservation()
        deadline = min(deadline, self._clock() + MAX_INSPECTION_SECONDS)
        acquired = False
        try:
            # Validate even when queue is full; never send unsafe URLs to DNS.
            target = canonical_target(url)
            acquired = _INSPECTION_GUARD.acquire(timeout=_remaining(deadline, self._clock))
            if not acquired:
                raise TimeoutError('deadline_exceeded')
            for redirect_count in range(MAX_REDIRECTS + 1):
                _remaining(deadline, self._clock)
                answers = self._resolver(target, deadline=deadline)
                if not answers:
                    raise OSError('inspection_failed')
                # Recheck *every* answer, including those from injected resolvers.
                addresses = tuple(public_address(answer) for answer in answers)
                _remaining(deadline, self._clock)
                connection = response = None
                try:
                    connection = self._connector(target, addresses[0], deadline=deadline, clock=self._clock)
                    connection.connect()
                    if target.scheme == 'https':
                        result.tls = _certificate(connection.sock.getpeercert())
                        self._completed(result, 'tls')
                    else:
                        result.tls = None
                    connection.sock.settimeout(_remaining(deadline, self._clock))
                    host = f'[{target.hostname}]' if ':' in target.hostname else target.hostname
                    connection.request('GET', target.path_query, headers={
                        'Host': host, 'Accept-Encoding': 'identity', 'Connection': 'close',
                        'User-Agent': 'MobileShield/1.0',
                    })
                    connection.sock.settimeout(_remaining(deadline, self._clock))
                    response = connection.getresponse()
                    _remaining(deadline, self._clock)
                    result.final_url = target.url
                    result.hops.append(RedirectHop(target.url, response.status, addresses[0],
                                                  f'ipv{ipaddress.ip_address(addresses[0]).version}'))
                    self._completed(result, 'http')
                    location = response.getheader('Location')
                    if response.status in (301, 302, 303, 307, 308):
                        if not location or redirect_count == MAX_REDIRECTS:
                            result.limitations.append('inspection_failed')
                            break
                        # Validate raw Location before urljoin strips controls.
                        if ambiguous_url_text(location):
                            raise DestinationBlocked()
                        target = canonical_target(urljoin(target.url, location))
                        continue
                    result.content_type = (response.getheader('Content-Type', '').split(';')[0].strip().lower() or None)
                    encoding = response.getheader('Content-Encoding', 'identity').strip().lower()
                    if result.content_type not in ('text/html', 'application/xhtml+xml') or encoding not in ('', 'identity'):
                        result.limitations.append('inspection_failed')
                        break
                    body = bytearray()
                    while True:
                        connection.sock.settimeout(_remaining(deadline, self._clock))
                        chunk = response.read1(min(16384, MAX_BODY_BYTES + 1 - len(body)))
                        _remaining(deadline, self._clock)
                        if not chunk:
                            if not body or getattr(response, 'length', None) not in (0, None):
                                result.limitations.append('inspection_failed')
                            else:
                                self._completed(result, 'html')
                            break
                        available = MAX_BODY_BYTES - len(body)
                        body.extend(chunk[:available])
                        if len(chunk) > available:
                            result.limitations.append('body_limit')
                            break
                    # utf-8 replacement can expand invalid bytes; ignore avoids
                    # exceeding the retained byte cap when re-encoding the text.
                    result.html = body.decode('utf-8', errors='ignore')
                    break
                finally:
                    if response is not None:
                        response.close()
                    if connection is not None:
                        connection.close()
        except DestinationBlocked:
            result.limitations.append('destination_blocked')
        except ssl.SSLCertVerificationError:
            result.tls = CertificateAnalysis(None, None, None, None, None, False, 'certificate_mismatch')
            result.limitations.append('certificate_mismatch')
        except TimeoutError:
            result.limitations.append('deadline_exceeded')
        except Exception:
            # Never include exception messages: libraries may embed secret URLs.
            result.limitations.append('deadline_exceeded' if self._clock() >= deadline else 'inspection_failed')
        finally:
            if acquired:
                _INSPECTION_GUARD.release()
        return result

    @staticmethod
    def _completed(result, check):
        if check not in result.completed_checks:
            result.completed_checks.append(check)
