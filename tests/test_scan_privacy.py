"""Privacy regression tests use only locally constructed synthetic records."""
import asyncio
import logging
from unittest.mock import Mock

import pytest
from sqlalchemy import create_engine, select
from sqlalchemy.orm import Session
from sqlalchemy.pool import StaticPool

from tests.test_message_api import client


@pytest.mark.parametrize('path', ['/v1/scans', '/v1/scans/1', '/v1/scans/1/report.pdf'])
def test_history_gone_without_database_dependency(client, path):
    from app.main import app
    from app.db.deps import get_db
    def forbidden_db():
        pytest.fail('Retired history accessed database')
    app.dependency_overrides[get_db] = forbidden_db
    result = client.get(path)
    assert result.status_code == 410
    assert result.headers['cache-control'] == 'no-store'


def test_synthetic_history_unchanged_and_no_new_writes(client):
    from app.main import app
    from app.db.database import Base
    from app.db.deps import get_db
    from app.db.models import Scan
    engine = create_engine('sqlite://', poolclass=StaticPool)
    Base.metadata.create_all(engine)
    with Session(engine) as db:
        db.add(Scan(normalized_url='https://synthetic.example/private', domain='synthetic.example',
                    risk_score=7, verdict='legacy', confidence='legacy', reasons=['synthetic'], signals={'synthetic': True}))
        db.commit()
        before = [dict(row) for row in db.execute(select(Scan.__table__)).mappings()]
        def forbidden_db():
            pytest.fail('Scan route requested a database session')
        app.dependency_overrides[get_db] = forbidden_db
        assert client.post('/v1/analyze-message', json={'text': 'hello'}).status_code == 200
        assert client.post('/v1/analyze', json={'url': 'https://example.com'}).status_code == 200
        for path in ('/v1/scans', '/v1/scans/1', '/v1/scans/1/report.pdf'):
            assert client.get(path).status_code == 410
        after = [dict(row) for row in db.execute(select(Scan.__table__)).mappings()]
        assert before == after


def test_limiter_expires_and_caps_identity_memory():
    from app.scan_limits import ScanRateLimiter
    clock = Mock(return_value=0)
    limiter = ScanRateLimiter(limit=1, clock=clock)
    for i in range(10000):
        assert limiter.allow(str(i))
    assert not limiter.allow('overflow')
    assert len(limiter._identities) == 10000
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
def test_request_work_overflow_and_cleanup(exit_mode):
    from types import SimpleNamespace
    from app.scan_limits import PrivateRequestMiddleware, ScanRateLimiter, RequestWorkAdmission
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
        return {'type': 'http', 'method': 'POST', 'path': '/v1/analyze-message', 'headers': [],
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
    import app.main as main
    from app.scan_limits import ScanRateLimiter
    from fastapi.testclient import TestClient
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
