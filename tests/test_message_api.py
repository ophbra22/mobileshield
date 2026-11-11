"""Real ASGI boundary tests; no database or destination network required."""

import pytest


def test_new_and_legacy_routes_share_stateless_default(client):
    result = client.post('/v1/analyze-message', json={'text': 'hello https://example.com'})
    assert result.status_code == 200
    assert result.json()['schema_version'] == 1
    legacy = client.post('/v1/analyze', json={'url': 'https://example.com'})
    assert legacy.status_code == 200
    assert legacy.json()['scan_id'] is None
    assert legacy.json()['status'] == 'unknown'
    assert legacy.json()['verdict'] == 'unknown'
    assert client.transport_spy.inspect.call_count == 0
    for response in (result, legacy):
        assert response.headers['cache-control'] == 'no-store'


@pytest.mark.parametrize('payload', [{'text': 'PRIVATE_SENTINEL', 'inspect_links': 'PRIVATE_SENTINEL'},
                                    {'text': 'hello', 'PRIVATE_SENTINEL': 'PRIVATE_SENTINEL'},
                                    {'text': 'PRIVATE_SENTINEL' * 1000}])
def test_422_redacts_validation_input(client, payload, caplog):
    result = client.post('/v1/analyze-message', json=payload)
    assert result.status_code == 422
    assert 'PRIVATE_SENTINEL' not in result.text + caplog.text
    assert 'input' not in result.text
    assert result.headers['cache-control'] == 'no-store'


def test_malformed_json_is_redacted(client):
    result = client.post('/v1/analyze-message', content='{"PRIVATE_SENTINEL":',
                         headers={'content-type': 'application/json'})
    assert result.status_code == 422
    assert 'PRIVATE_SENTINEL' not in result.text


def test_body_limit_413(client):
    result = client.post('/v1/analyze-message', content=b'x' * (128 * 1024 + 1))
    assert result.status_code == 413
    assert result.headers['cache-control'] == 'no-store'


def test_rate_limit_429_ignores_forwarded_identity(client):
    import app.main as main
    from app.scan_limits import ScanRateLimiter
    main.app.state.scan_limiter = ScanRateLimiter(limit=1)
    assert client.post('/v1/analyze-message', json={'text': 'hello'}).status_code == 200
    result = client.post('/v1/analyze-message', json={'text': 'hello'}, headers={'x-forwarded-for': '8.8.8.8'})
    assert result.status_code == 429
    assert result.headers['cache-control'] == 'no-store'


def test_unexpected_backend_failure_503_is_private(client, monkeypatch, caplog):
    import app.routers.analyze as router
    def fail(*args, **kwargs):
        raise RuntimeError('PRIVATE_SENTINEL')
    monkeypatch.setattr(router, 'analyze_message', fail)
    result = client.post('/v1/analyze-message?token=PRIVATE_SENTINEL', json={'text': 'hello'},
                         headers={'x-request-id': 'PRIVATE_SENTINEL'})
    assert result.status_code == 503
    assert 'PRIVATE_SENTINEL' not in result.text + str(result.headers) + caplog.text
    assert result.headers['cache-control'] == 'no-store'


def test_too_many_links_is_422(client):
    result = client.post('/v1/analyze-message', json={'text': ' '.join(f'https://host{i}.example' for i in range(11))})
    assert result.status_code == 422


def test_exhausted_shared_slots_return_503_without_network(client):
    from app.detection import safe_transport
    from app.main import app
    from app.routers.analyze import get_scan_transport
    app.dependency_overrides[get_scan_transport] = lambda: safe_transport.SafeTransport()
    assert safe_transport._INSPECTION_GUARD.acquire(blocking=False)
    assert safe_transport._INSPECTION_GUARD.acquire(blocking=False)
    try:
        result = client.post('/v1/analyze-message', json={'text': 'https://example.com', 'inspect_links': True})
    finally:
        safe_transport._INSPECTION_GUARD.release()
        safe_transport._INSPECTION_GUARD.release()
    assert result.status_code == 503
    assert result.headers['cache-control'] == 'no-store'


def test_http_exception_detail_and_headers_are_sanitized(client, monkeypatch, caplog):
    from fastapi import HTTPException

    import app.routers.analyze as router
    def fail(*args, **kwargs):
        raise HTTPException(503, detail='PRIVATE_SENTINEL', headers={'X-Private': 'PRIVATE_SENTINEL'})
    monkeypatch.setattr(router, 'analyze_message', fail)
    result = client.post('/v1/analyze-message', json={'text': 'hello'})
    assert result.status_code == 503
    assert 'PRIVATE_SENTINEL' not in result.text + str(result.headers) + caplog.text
    assert result.headers['cache-control'] == 'no-store'


def test_response_validation_error_is_not_safe(client, monkeypatch):
    import app.routers.analyze as router
    monkeypatch.setattr(router, 'analyze_message', lambda *a, **k: {'assessment': 'safe PRIVATE_SENTINEL'})
    result = client.post('/v1/analyze-message', json={'text': 'hello'})
    assert result.status_code == 503
    assert 'PRIVATE_SENTINEL' not in result.text


def test_server_request_id_is_generated_and_correlated(client, caplog):
    import logging
    with caplog.at_level(logging.INFO, logger='mobileshield.requests'):
        result = client.post('/v1/analyze-message', json={'text': 'PRIVATE_SENTINEL'},
                             headers={'X-Request-ID': 'PRIVATE_SENTINEL'})
    request_id = result.headers['x-request-id']
    assert result.json()['request_id'] == request_id
    assert len(request_id) == 32
    assert request_id in caplog.text
    assert 'PRIVATE_SENTINEL' not in caplog.text
    record = next(record for record in caplog.records if record.name == 'mobileshield.requests')
    assert record.getMessage().startswith('route=/v1/analyze-message status=200 duration_ms=')


def test_early_error_is_readable_to_allowed_web_origin(client):
    result = client.post('/v1/analyze-message', content=b'x' * (128 * 1024 + 1),
                         headers={'origin': 'http://localhost:3000'})
    assert result.status_code == 413
    assert result.headers['access-control-allow-origin'] == 'http://localhost:3000'
    assert result.headers['cache-control'] == 'no-store'
