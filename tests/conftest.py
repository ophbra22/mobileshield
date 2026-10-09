"""Hermetic backend tests: no live databases, allowlists, DNS or HTTP."""

import os
import socket

import pytest
import tldextract

# Set before application imports; never read a developer's live configuration.
os.environ['ALLOWLIST_ENABLED'] = 'false'
os.environ['ALLOWLIST_SOURCES'] = 'local_popular'
os.environ['ALLOWLIST_CACHE_PATH'] = ''
os.environ['DATABASE_URL'] = 'sqlite://'

# Legacy dataset helpers call the module convenience function. Use its bundled
# snapshot too, so recording their baseline does not download a suffix list.
tldextract.extract = tldextract.TLDExtract(
    suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True,
)

_network_attempts = []
_original_connect = socket.socket.connect
_original_connect_ex = socket.socket.connect_ex
_original_sendto = socket.socket.sendto


def _deny_network(*args, **kwargs):
    _network_attempts.append('unexpected network operation')
    raise AssertionError('Unexpected network operation in a hermetic test')


def _connect(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        return _deny_network()
    return _original_connect(sock, address)


def _connect_ex(sock, address):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        return _deny_network()
    return _original_connect_ex(sock, address)


def _sendto(sock, *args, **kwargs):
    if sock.family in (socket.AF_INET, socket.AF_INET6):
        return _deny_network()
    return _original_sendto(sock, *args, **kwargs)


# Guard collection-time imports as well as test execution. Native DB drivers
# cannot bypass this via libpq because the configured test database is SQLite.
socket.socket.connect = _connect
socket.socket.connect_ex = _connect_ex
socket.socket.sendto = _sendto
socket.create_connection = _deny_network
socket.getaddrinfo = _deny_network
socket.gethostbyname = _deny_network
socket.gethostbyname_ex = _deny_network
socket.gethostbyaddr = _deny_network


@pytest.fixture(autouse=True)
def no_unexpected_network():
    yield
    attempts = list(_network_attempts)
    _network_attempts.clear()
    assert not attempts, 'Network attempted even if application code caught the error'
