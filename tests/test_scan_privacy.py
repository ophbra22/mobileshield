"""Privacy regression tests use only locally constructed synthetic records."""
import asyncio
import logging
from unittest.mock import Mock

import pytest


@pytest.mark.parametrize('path', ['/v1/scans', '/v1/scans/1', '/v1/scans/1/report.pdf'])
def test_history_gone_without_database_dependency(client, path):
    from app.db.deps import get_db
    from app.main import app
    def forbidden_db():
        pytest.fail('Retired history accessed database')
    app.dependency_overrides[get_db] = forbidden_db
    result = client.get(path)
    assert result.status_code == 410
    assert result.headers['cache-control'] == 'no-store'


def test_scans_never_request_a_database_session(client):
    from app.db.deps import get_db
    from app.main import app
    def forbidden_db():
        pytest.fail('Scan route requested a database session')
    app.dependency_overrides[get_db] = forbidden_db
    assert client.post('/v1/analyze-message', json={'text': 'hello'}).status_code == 200
    assert client.post('/v1/analyze', json={'url': 'https://example.com'}).status_code == 200
    for path in ('/v1/scans', '/v1/scans/1', '/v1/scans/1/report.pdf'):
        assert client.get(path).status_code == 410


def test_limiter_expires_and_caps_identity_memory():
    from app.scan_limits import ScanRateLimiter
    clock = Mock(return_value=0)
    limiter = ScanRateLimiter(limit=1, clock=clock)
    for i in range(10000):
        assert limiter.allow(str(i))
    # A full table evicts the oldest window instead of locking out new clients.
    assert limiter.allow('overflow')
    assert len(limiter._identities) == 10000
    assert '0' not in limiter._identities and 'overflow' in limiter._identities
    clock.return_value = 61
    assert limiter.allow('fresh')
    assert len(limiter._identities) == 1


def test_streamed_body_cap_before_parser(client):
    from app.main import app
    chunks = [b'x' * 65536, b'x' * 65536, b'PRIVATE_SENTINEL']
    sent = []
    async def receive():
        part = chunks.pop(0)
        return {'type': 'http.request', 'body': part, 'more_body': bool(chunks)}
    async def send(message):
        sent.append(message)
    scope = {'type': 'http', 'asgi': {'version': '3.0'}, 'http_version': '1.1',
             'method': 'POST', 'scheme': 'http', 'path': '/v1/analyze-message',
             'raw_path': b'/v1/analyze-message', 'query_string': b'', 'root_path': '',
             'headers': [(b'content-type', b'application/json')], 'client': ('synthetic', 123),
             'server': ('testserver', 80)}
    asyncio.run(app(scope, receive, send))
    assert sent[0]['status'] == 413
    assert b'PRIVATE_SENTINEL' not in sent[-1]['body']


def test_uvicorn_managed_logs_do_not_leak(client, caplog):
    with caplog.at_level(logging.INFO):
        logging.getLogger('uvicorn.access').info('PRIVATE_SENTINEL /secret?token=PRIVATE_SENTINEL')
        try:
            raise RuntimeError('PRIVATE_SENTINEL')
        except RuntimeError:
            logging.getLogger('uvicorn.error').exception('Exception in ASGI application PRIVATE_SENTINEL')
        logging.getLogger('uvicorn.error').warning('Invalid HTTP request received: %s', 'PRIVATE_SENTINEL')
        client.get('/private/PRIVATE_SENTINEL?token=PRIVATE_SENTINEL')
    managed = [r for r in caplog.records if r.name in {'uvicorn.access', 'uvicorn.error', 'mobileshield.requests'}]
    assert 'PRIVATE_SENTINEL' not in str([(r.getMessage(), r.exc_text, r.stack_info) for r in managed])
    assert any('<server-error>' in r.getMessage() for r in managed)


@pytest.mark.parametrize('exit_mode', ['response', 'exception', 'disconnect', 'cancel'])
@pytest.mark.parametrize('path', ['/v1/analyze-message', '/v1/analyze-message/', '/v1/analyze/', '/unmatched'])
def test_request_work_overflow_and_cleanup(exit_mode, path):
    from types import SimpleNamespace

    from app.scan_limits import PrivateRequestMiddleware, RequestWorkAdmission, ScanRateLimiter
    admission = RequestWorkAdmission()
    entered = 0
    ready = asyncio.Event()
    release = asyncio.Event()
    responses = []
    async def downstream(scope, receive, send):
        if exit_mode == 'exception':
            raise RuntimeError('PRIVATE_SENTINEL')
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'{}'})
    middleware = PrivateRequestMiddleware(downstream)
    state = SimpleNamespace(scan_limiter=ScanRateLimiter(100), scan_work=admission)
    async def receive():
        nonlocal entered
        entered += 1
        if entered == 32:
            ready.set()
        await release.wait()
        return {'type': 'http.disconnect'} if exit_mode == 'disconnect' else {'type': 'http.request', 'body': b'{}'}
    async def send(message):
        responses.append(message)
    def scope():
        return {'type': 'http', 'method': 'POST', 'path': path, 'headers': [],
                'app': SimpleNamespace(state=state), 'client': ('synthetic', 123)}
    async def scenario():
        tasks = [asyncio.create_task(middleware(scope(), receive, send)) for _ in range(32)]
        await asyncio.wait_for(ready.wait(), 1)
        assert admission._active == 32
        await middleware(scope(), receive, send)
        assert responses[0]['status'] == 503
        assert entered == 32  # overflow rejected before reading or scheduling work
        if exit_mode == 'cancel':
            for task in tasks:
                task.cancel()
        else:
            release.set()
        await asyncio.gather(*tasks, return_exceptions=True)
        assert admission._active == 0
        assert admission.acquire()
        admission.release()
    asyncio.run(scenario())


def test_idle_identity_expiry_does_not_require_another_scan():
    from app.scan_limits import ScanRateLimiter
    clock = Mock(return_value=0)
    limiter = ScanRateLimiter(60, clock=clock)
    assert limiter.allow('synthetic-client')
    clock.return_value = 60
    limiter.expire()
    assert limiter._identities == {}


def test_lifespan_runs_and_stops_idle_cleanup(monkeypatch):
    import threading

    from fastapi.testclient import TestClient

    import app.main as main
    from app.scan_limits import ScanRateLimiter
    initialize = Mock()
    monkeypatch.setattr(main, 'initialize_database', initialize)
    clock = Mock(return_value=0)
    limiter = ScanRateLimiter(60, clock=clock)
    monkeypatch.setattr(main.app.state, 'scan_limiter', limiter)
    expired = threading.Event()
    original_expire = limiter.expire
    def expire():
        original_expire()
        expired.set()
    monkeypatch.setattr(limiter, 'expire', expire)
    with TestClient(main.app):
        task = main.app.state.scan_cleanup_task
        assert not task.done()
        assert limiter.allow('idle-synthetic-client')
        clock.return_value = 60
        assert expired.wait(2), 'Idle cleanup did not run without another HTTP scan'
        assert limiter._identities == {}
    initialize.assert_called_once_with()
    assert task.done()


def test_ipv6_clients_share_a_limit_per_64():
    from app.scan_limits import client_identity
    assert client_identity('2001:db8:1:2::1') == client_identity('2001:db8:1:2:ffff::9') == '2001:db8:1:2::/64'
    assert client_identity('2001:db8:1:3::1') != client_identity('2001:db8:1:2::1')
    assert client_identity('203.0.113.7') == '203.0.113.7'
    assert client_identity('::ffff:203.0.113.7') == '203.0.113.7'
    assert client_identity(None) == '<unknown>'


def test_identity_flood_cannot_lock_out_other_clients():
    from app.scan_limits import ScanRateLimiter
    limiter = ScanRateLimiter(limit=5, clock=Mock(return_value=0), max_identities=100)
    for i in range(1000):
        limiter.allow(f'attacker-{i}')
    assert limiter.allow('legitimate-user')


def test_uvicorn_lifecycle_messages_are_not_reported_as_errors(caplog):
    from app.scan_limits import configure_private_server_logging
    configure_private_server_logging()
    with caplog.at_level(logging.INFO, logger='uvicorn.error'):
        logging.getLogger('uvicorn.error').info('Started server process [%d]', 4242)
        logging.getLogger('uvicorn.error').info('Uvicorn running on %s://%s:%d (Press CTRL+C to quit)',
                                                'http', '127.0.0.1', 8000)
    messages = [r.getMessage() for r in caplog.records if r.name == 'uvicorn.error']
    assert messages == ['Started server process [4242]',
                        'Uvicorn running on http://127.0.0.1:8000 (Press CTRL+C to quit)']
