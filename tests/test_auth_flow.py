"""Availability assertions only: auth routes are currently disabled.

These are not authentication-flow coverage and do not exercise a live database.
"""
import pytest
from fastapi.testclient import TestClient

from app.main import app


@pytest.mark.parametrize('method,path', [
    ('POST', '/v1/auth/register'), ('POST', '/v1/auth/login'),
    ('GET', '/v1/auth/me'), ('GET', '/v1/keys'),
])
def test_disabled_auth_routes_are_unavailable(method, path):
    with TestClient(app, raise_server_exceptions=False) as client:
        response = client.request(method, path)
    assert response.status_code == 404


@pytest.fixture(autouse=True)
def synthetic_startup(monkeypatch):
    monkeypatch.setattr('app.main.initialize_database', lambda: None)
