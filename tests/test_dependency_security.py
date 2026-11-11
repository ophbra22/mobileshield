"""Synthetic, network-free regressions for the bounded dependency remediation."""
import logging
from types import SimpleNamespace
from unittest.mock import Mock

import pytest
import jwt
from jwt import ExpiredSignatureError, InvalidAlgorithmError, InvalidTokenError

from tests.test_message_api import client


@pytest.mark.parametrize('host', ['testserver/docs?PRIVATE_HOST=', 'testserver/docs#PRIVATE_HOST='])
@pytest.mark.parametrize('path,status', [('/health', 200), ('/missing', 404), ('/v1/scans/7/report.pdf', 410)])
def test_json_csp_uses_routed_path_not_host(client, caplog, host, path, status):
    with caplog.at_level(logging.INFO, logger='mobileshield.requests'):
        response = client.get(path, headers={'host': host})
    assert response.status_code == status
    assert response.headers['content-security-policy'] == "default-src 'none'; frame-ancestors 'none'"
    assert response.headers['cache-control'] == 'no-store'
    assert 'PRIVATE_HOST' not in response.text + str(response.headers)
    managed = [r.getMessage() for r in caplog.records if r.name == 'mobileshield.requests']
    assert 'PRIVATE_HOST' not in str(managed)
    if status != 200:
        assert response.json()['request_id'] == response.headers['x-request-id']


@pytest.mark.parametrize('path', ['/docs', '/redoc', '/openapi.json', '/docs/oauth2-redirect'])
@pytest.mark.parametrize('host', ['testserver', 'testserver/private?PRIVATE_HOST='])
def test_actual_docs_keep_documentation_csp(client, path, host):
    response = client.get(path, headers={'host': host})
    assert response.status_code == 200
    assert "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net" in response.headers['content-security-policy']
    assert response.headers['cache-control'] == 'no-store'


def test_malformed_host_cannot_bypass_scan_admission_or_enable_network(client, monkeypatch):
    import requests
    from app.main import app
    from app.scan_limits import ScanRateLimiter
    request = Mock(side_effect=AssertionError('Unexpected Requests call'))
    monkeypatch.setattr(requests.sessions.Session, 'request', request)
    app.state.scan_limiter = ScanRateLimiter(limit=1)
    headers = {'host': 'testserver/docs?PRIVATE_HOST='}
    result = client.post('/v1/analyze-message', json={'text': 'hello https://example.com'}, headers=headers)
    assert result.status_code == 200
    assert result.headers['content-security-policy'] == "default-src 'none'; frame-ancestors 'none'"
    denied = client.post('/v1/analyze-message', json={'text': 'hello'}, headers=headers)
    assert denied.status_code == 429
    assert denied.json()['detail'] == 'rate_limit_exceeded'
    assert denied.headers['cache-control'] == 'no-store'
    request.assert_not_called()
    client.transport_spy.inspect.assert_not_called()


@pytest.fixture
def synthetic_jwt(monkeypatch):
    from app import security
    monkeypatch.setattr(security, 'settings', SimpleNamespace(
        jwt_secret='synthetic-test-secret-never-used-for-real-auth', jwt_expires_minutes=120))
    return security


def test_hs256_roundtrip_preserves_claims_and_input(synthetic_jwt):
    payload = {'sub': 'synthetic-user', 'purpose': 'compatibility'}
    token = synthetic_jwt.create_jwt(payload)
    assert jwt.get_unverified_header(token)['alg'] == 'HS256'
    decoded = synthetic_jwt.decode_jwt(token)
    assert {k: decoded[k] for k in payload} == payload
    assert isinstance(decoded['exp'], int)
    assert 'exp' not in payload


def test_hs256_expiry_is_enforced(synthetic_jwt):
    token = jwt.encode({'sub': 'synthetic-user', 'exp': 1}, synthetic_jwt.settings.jwt_secret, algorithm='HS256')
    with pytest.raises(ExpiredSignatureError):
        synthetic_jwt.decode_jwt(token)


def test_hs256_wrong_key_is_rejected(synthetic_jwt):
    token = jwt.encode({'sub': 'synthetic-user'}, 'different-synthetic-secret', algorithm='HS256')
    with pytest.raises(InvalidTokenError):
        synthetic_jwt.decode_jwt(token)


@pytest.mark.parametrize('algorithm', ['HS384', 'HS512'])
def test_nonconfigured_algorithm_is_rejected(synthetic_jwt, algorithm):
    token = jwt.encode({'sub': 'synthetic-user'}, synthetic_jwt.settings.jwt_secret, algorithm=algorithm)
    with pytest.raises(InvalidAlgorithmError):
        synthetic_jwt.decode_jwt(token)


def test_token_without_expiry_is_rejected(synthetic_jwt):
    token = jwt.encode({'sub': 'synthetic-user'}, synthetic_jwt.settings.jwt_secret, algorithm='HS256')
    with pytest.raises(InvalidTokenError):
        synthetic_jwt.decode_jwt(token)


def test_password_hash_roundtrip():
    from app.security import hash_password, verify_password
    hashed = hash_password('correct horse battery')
    assert verify_password('correct horse battery', hashed)
    assert not verify_password('wrong password!', hashed)
    assert not verify_password('correct horse battery', 'not-a-bcrypt-hash')
