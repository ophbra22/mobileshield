"""Hermetic transport checks with fake public observations and byte streams."""
from concurrent.futures import ThreadPoolExecutor
import io
import socket
import ssl
import threading
import time

import pytest

from app.detection import safe_transport as transport
from tests.test_network_policy import FORBIDDEN


class Response:
    def __init__(self, status=200, headers=None, body=b'<html>ok</html>'):
        self.status = status
        self.headers = headers if headers is not None else {'Content-Type': 'text/html'}
        self.body = io.BytesIO(body)
        self.closed = False
        self.retained = 0

    def getheader(self, name, default=None):
        return self.headers.get(name, default)

    def read1(self, size):
        data = self.body.read(size)
        self.retained += len(data)
        return data

    def close(self):
        self.closed = True


class Connection:
    def __init__(self, response):
        self.response = response
        self.closed = False
        self.sock = self
        self.requests = []

    def connect(self):
        pass

    def getpeercert(self):
        return {'notBefore': 'Jan  1 00:00:00 2020 GMT', 'notAfter': 'Jan  1 00:00:00 2030 GMT'}

    def settimeout(self, timeout):
        assert 0 < timeout <= 20

    def request(self, method, path, headers):
        self.requests.append((method, path, headers))

    def getresponse(self):
        return self.response

    def close(self):
        self.closed = True


class Harness:
    def __init__(self, responses=None, resolver=None, clock=time.monotonic):
        self.responses = list(responses or [Response()])
        self.connection_attempts = []
        self.connections = []
        self.resolved = []
        def resolve(target, *, deadline):
            self.resolved.append(target.hostname)
            return resolver(target, deadline=deadline) if resolver else ('8.8.8.8',)
        def connect(target, address, **kwargs):
            self.connection_attempts.append((target, address))
            conn = Connection(self.responses.pop(0))
            self.connections.append(conn)
            return conn
        self.client = transport.SafeTransport(resolver=resolve, connector=connect, clock=clock)

    def inspect(self, url='https://example.com/', deadline=None):
        return self.client.inspect(url, deadline=deadline or time.monotonic() + 20)


@pytest.mark.parametrize('url', FORBIDDEN)
def test_forbidden_targets_never_connect(url):
    h = Harness()
    result = h.inspect(url)
    assert h.connection_attempts == []
    assert result.limitations == ['destination_blocked']


def test_mixed_dns_answers_never_connect():
    h = Harness(resolver=lambda *args, **kwargs: ('8.8.8.8', '127.0.0.1'))
    assert h.inspect().limitations == ['destination_blocked']
    assert h.connection_attempts == []


def test_redirect_to_private_never_connects_to_private():
    h = Harness([Response(302, {'Location': 'http://169.254.169.254/latest/'})])
    result = h.inspect()
    assert result.limitations == ['destination_blocked']
    assert len(h.connection_attempts) == 1
    assert all(c.closed and c.response.closed for c in h.connections)


def test_public_https_redirect_succeeds_and_preserves_host():
    h = Harness([Response(302, {'Location': 'https://other.example.com/landing'}), Response()])
    result = h.inspect('https://example.com/?token=private')
    assert result.final_url == 'https://other.example.com/landing'
    assert len(result.hops) == 2 and result.html == '<html>ok</html>'
    assert result.tls.hostname_matches and result.limitations == []
    assert h.connections[0].requests == [('GET', '/?token=private', {
        'Host': 'example.com', 'Accept-Encoding': 'identity', 'Connection': 'close',
        'User-Agent': 'MobileShield/1.0'})]
    assert all(c.closed and c.response.closed for c in h.connections)


def test_same_host_redirect_rebinding_is_revalidated():
    calls = iter([('8.8.8.8',), ('10.0.0.1',)])
    h = Harness([Response(302, {'Location': '/next'})], resolver=lambda *a, **k: next(calls))
    assert h.inspect().limitations == ['destination_blocked']
    assert len(h.connection_attempts) == 1


def test_redirects_bounded_at_five():
    h = Harness([Response(302, {'Location': f'/hop{i}'}) for i in range(10)])
    result = h.inspect()
    assert len(h.connection_attempts) == 6
    assert len(result.hops) - 1 <= 5
    assert 'inspection_failed' in result.limitations


def test_body_capped_and_connection_closed():
    response = Response(body=b'x' * (256 * 1024 + 100))
    h = Harness([response])
    result = h.inspect()
    assert len(result.html.encode()) <= 256 * 1024
    assert 'body_limit' in result.limitations
    assert response.retained <= 256 * 1024 + 1
    assert response.closed and h.connections[0].closed


def test_unsupported_compression_skips_body():
    response = Response(headers={'Content-Type': 'text/html', 'Content-Encoding': 'gzip'})
    h = Harness([response])
    result = h.inspect()
    assert result.html is None and result.limitations == ['inspection_failed']
    assert response.retained == 0 and response.closed


def test_missing_html_is_a_limitation():
    h = Harness([Response(headers={'Content-Type': 'application/pdf'})])
    result = h.inspect()
    assert result.html is None and result.limitations == ['inspection_failed']


def test_timeout_exception_never_exposes_requested_url():
    def fail(*args, **kwargs):
        raise TimeoutError('https://example.com/?token=private')
    h = Harness(resolver=fail)
    result = h.inspect('https://example.com/?token=private')
    assert result.limitations == ['deadline_exceeded']
    assert 'token' not in repr(result)


def test_expired_deadline_does_not_connect():
    h = Harness()
    assert h.inspect(deadline=time.monotonic() - 1).limitations == ['deadline_exceeded']
    assert h.connection_attempts == []


def test_process_wide_two_inspection_limit_and_immediate_refusal():
    entered = threading.Event()
    release = threading.Event()
    lock = threading.Lock()
    active = peak = 0
    def resolver(*args, **kwargs):
        nonlocal active, peak
        with lock:
            active += 1
            peak = max(peak, active)
            if active == 2:
                entered.set()
        release.wait(2)
        with lock:
            active -= 1
        return ('8.8.8.8',)
    with ThreadPoolExecutor(max_workers=3) as pool:
        jobs = [pool.submit(Harness(resolver=resolver).inspect) for _ in range(2)]
        assert entered.wait(1)
        third = Harness()
        started = time.monotonic()
        with pytest.raises(transport.InspectionBusy):
            third.inspect(deadline=started + 20)
        assert time.monotonic() - started < .3
        assert third.connection_attempts == []
        assert third.resolved == []
        release.set()
        assert all(job.result().html for job in jobs)
    assert peak == 2
    assert Harness().inspect().html  # refusal and completed work both release resources


def test_pinned_socket_correct_sni_and_tls_verification(monkeypatch):
    addresses, hostnames, contexts, sockets = [], [], [], []
    class FakeSocket:
        def __init__(self, *args):
            self.closed = False
            sockets.append(self)
        def settimeout(self, value):
            assert 0 < value <= 20
        def connect(self, address):
            addresses.append(address)
        def sendall(self, data):
            assert b'Host: example.com' in data
            assert b'Accept-Encoding: identity' in data
        def makefile(self, *args):
            return io.BytesIO(b'HTTP/1.1 200 OK\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nok')
        def getpeercert(self):
            return {}
        def do_handshake(self):
            pass
        def shutdown(self, how):
            pass
        def close(self):
            self.closed = True
    def wrap(context, sock, *, server_hostname, do_handshake_on_connect):
        contexts.append(context)
        hostnames.append(server_hostname)
        assert do_handshake_on_connect is False
        return sock
    monkeypatch.setattr(socket, 'socket', FakeSocket)
    monkeypatch.setattr(ssl.SSLContext, 'wrap_socket', wrap)
    client = transport.SafeTransport(resolver=lambda *a, **k: ('8.8.8.8',))
    result = client.inspect('https://example.com/', deadline=time.monotonic() + 2)
    assert result.html == 'ok' and result.limitations == []
    assert addresses == [('8.8.8.8', 443)] and hostnames == ['example.com']
    assert contexts[0].check_hostname and contexts[0].verify_mode == ssl.CERT_REQUIRED
    assert all(s.closed for s in sockets)


def test_bad_tls_certificate_is_reported_and_connection_closed():
    h = Harness()
    original = h.client._connector
    def connector(*args, **kwargs):
        conn = original(*args, **kwargs)
        def fail():
            raise ssl.SSLCertVerificationError('secret URL certificate error')
        conn.connect = fail
        return conn
    h.client._connector = connector
    result = h.inspect()
    assert result.limitations == ['certificate_mismatch']
    assert result.tls.hostname_matches is None  # Not every verification error is a hostname mismatch.
    assert result.tls.valid_now is None
    assert h.connections[0].closed


@pytest.mark.parametrize('stall', [None, 'headers', 'body'])
def test_connection_close_response_keeps_deadline_until_body_closed(monkeypatch, stall):
    sockets = []
    class DeadlineSocket:
        def __init__(self, *args):
            self.stopped = threading.Event()
            self.closed = False
            sockets.append(self)
        def settimeout(self, value):
            pass
        def connect(self, address):
            assert address == ('8.8.8.8', 80)
        def sendall(self, data):
            pass
        def makefile(self, *args):
            sock = self
            class Stream(io.BytesIO):
                def readline(self, *args):
                    if stall == 'headers':
                        assert sock.stopped.wait(.7), 'watchdog failed to interrupt headers'
                        return b''
                    return super().readline(*args)
                def read1(self, size):
                    if stall == 'body':
                        assert sock.stopped.wait(.7), 'watchdog failed to interrupt body'
                        return b''
                    return super().read1(size)
            return Stream(b'HTTP/1.1 200 OK\r\nConnection: close\r\nContent-Type: text/html\r\nContent-Length: 2\r\n\r\nok')
        def shutdown(self, how):
            self.stopped.set()
        def close(self):
            self.closed = True
    monkeypatch.setattr(socket, 'socket', DeadlineSocket)
    client = transport.SafeTransport(resolver=lambda *a, **k: ('8.8.8.8',))
    started = time.monotonic()
    result = client.inspect('http://example.com/', deadline=started + .1)
    assert time.monotonic() - started < .5
    assert sockets[0].closed
    if stall:
        assert result.limitations == ['deadline_exceeded']
        assert result.html is None
        assert sockets[0].stopped.is_set()
    else:
        assert result.html == 'ok' and result.limitations == []


def test_one_deadline_across_redirects_and_maximum_twenty_seconds():
    now = [100.0]
    deadlines = []
    def resolver(target, *, deadline):
        deadlines.append(deadline)
        now[0] += 11
        return ('8.8.8.8',)
    h = Harness([Response(302, {'Location': '/next'}), Response()],
                resolver=resolver, clock=lambda: now[0])
    result = h.inspect(deadline=1000)
    assert deadlines == [120, 120]
    assert result.limitations == ['deadline_exceeded']
    assert len(h.connection_attempts) == 1


@pytest.mark.parametrize('body,declared_length', [(b'', 0), (b'<html>', 100)])
def test_empty_or_truncated_html_is_incomplete(body, declared_length):
    response = Response(body=body)
    response.length = declared_length
    result = Harness([response]).inspect()
    assert 'inspection_failed' in result.limitations
    assert 'html' not in result.completed_checks
