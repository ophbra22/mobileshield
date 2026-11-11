"""Destination policy regressions; no destination DNS or sockets are used."""
import multiprocessing
import time

import pytest

from app.detection import network_policy as policy

FORBIDDEN = [
    'http://127.0.0.1/', 'http://10.0.0.1/', 'http://172.16.0.1/',
    'http://192.168.1.1/', 'http://169.254.169.254/', 'http://100.64.0.1/',
    'http://224.0.0.1/', 'http://240.0.0.1/', 'http://0.0.0.0/',
    'http://192.0.0.8/', 'http://198.18.0.1/', 'http://192.0.2.1/',
    'http://[::1]/', 'http://[::]/', 'http://[fc00::1]/', 'http://[fe80::1]/',
    'http://[ff02::1]/', 'http://[fec0::1]/', 'http://[2001:db8::1]/',
    'http://[::ffff:127.0.0.1]/', 'http://[::ffff:8.8.8.8]/',
    'http://[64:ff9b::a00:1]/', 'http://[2002:7f00:1::]/',
    'http://2130706433/', 'http://127.1/', 'http://0177.0.0.1/',
    'http://0x7f000001/', 'http://0x7f.0.0.1/',
    'http://localhost/', 'http://foo.localhost/', 'http://printer/',
    'http://printer.local/', 'http://service.internal/', 'http://router.home/',
    'http://user:secret@example.com/', 'http://example.com@127.0.0.1/',
    'http://[fe80::1%25en0]/', 'http://example.com:foo/',
    'http://example.com:/', 'http://example.com:0/', 'http://example.com:443/',
    'https://example.com:80/', 'https://example.com:444/',
    'http://example.com\n/', ' http://example.com/', 'http://example.com/a b',
    'http://example.com\\@127.0.0.1/', 'http://%31%32%37.0.0.1/',
    'file:///etc/passwd', 'ftp://example.com/', '//example.com/',
]


@pytest.mark.parametrize('url', FORBIDDEN)
def test_forbidden_target_rejected(url):
    with pytest.raises(policy.DestinationBlocked, match='^destination_blocked$'):
        policy.canonical_target(url)


def test_canonical_target_and_public_literal():
    target = policy.canonical_target('HTTPS://ExAmPlE.COM.:443/a?q=secret#fragment')
    assert (target.url, target.hostname, target.port, target.path_query) == (
        'https://example.com/a?q=secret', 'example.com', 443, '/a?q=secret')
    assert policy.resolve_public(policy.canonical_target('https://8.8.8.8/'),
                                 deadline=time.monotonic() + 1) == ('8.8.8.8',)
    assert policy.canonical_target('https://[2606:4700:4700::1111]/').hostname == '2606:4700:4700::1111'


def mixed_worker(pipe, hostname, port):
    pipe.send(('ok', ['8.8.8.8', '10.0.0.1']))
    pipe.close()


def stalled_worker(pipe, hostname, port):
    time.sleep(60)


def public_worker(pipe, hostname, port):
    pipe.send(('ok', ['8.8.8.8', '8.8.8.8', '2606:4700:4700::1111']))
    pipe.close()


def test_all_dns_answers_validated(monkeypatch):
    monkeypatch.setattr(policy, '_dns_worker', mixed_worker)
    with pytest.raises(policy.DestinationBlocked):
        policy.resolve_public(policy.canonical_target('https://example.com/'),
                              deadline=time.monotonic() + 3)


def test_public_dns_answers_and_no_workers_left(monkeypatch):
    monkeypatch.setattr(policy, '_dns_worker', public_worker)
    before = {p.pid for p in multiprocessing.active_children()}
    assert policy.resolve_public(policy.canonical_target('https://example.com/'),
                                 deadline=time.monotonic() + 3) == ('8.8.8.8', '2606:4700:4700::1111')
    assert {p.pid for p in multiprocessing.active_children()} == before


def test_stalled_dns_worker_terminated_and_joined(monkeypatch):
    monkeypatch.setattr(policy, '_dns_worker', stalled_worker)
    before = {p.pid for p in multiprocessing.active_children()}
    started = time.monotonic()
    with pytest.raises(TimeoutError, match='^deadline_exceeded$'):
        policy.resolve_public(policy.canonical_target('https://example.com/'),
                              deadline=started + .25)
    assert time.monotonic() - started < .8
    assert {p.pid for p in multiprocessing.active_children()} == before


@pytest.mark.parametrize('url', [
    'http://example.com/\u0085x', 'http://example.com/\u009fx',
    'http://[2606:4700:4700::1111]junk/', 'http://example.com../',
    'http://１２７.０.０.１/',
])
def test_ambiguous_authority_and_unicode_controls_rejected(url):
    with pytest.raises(policy.DestinationBlocked):
        policy.canonical_target(url)


def test_documentation_prefix_missing_from_older_python_registry_is_blocked():
    with pytest.raises(policy.DestinationBlocked):
        policy.canonical_target('https://[3fff::1]/')
