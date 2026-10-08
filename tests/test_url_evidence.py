from pathlib import Path
import os
import subprocess
import sys

import pytest

from app.detection import content_analyzer
from app.detection.models import CertificateAnalysis
from app.detection.safe_transport import UrlObservation
from app.message_parser import parse_message

FIXTURE = Path(__file__).parent / 'fixtures' / 'credential-form.html'


def candidate(url='https://paypal-login.attacker.com/login'):
    return parse_message(url).links[0]


def observed(url, html='<html><body>Hello</body></html>', **kwargs):
    return UrlObservation(final_url=url, html=html, content_type='text/html',
                          tls=CertificateAnalysis(None, None, None, None, True, True),
                          completed_checks=['tls', 'http', 'html'], **kwargs)


def analyze(candidate_, observation):
    from app.detection.engine import analyze_url_candidate
    return analyze_url_candidate(candidate_, observation)


def test_real_input_elements_set_both_flags():
    content = content_analyzer.analyze_html(FIXTURE.read_text())
    assert content.has_form is True
    assert content.credential_form is True
    assert content.payment_form is True


def test_unfetched_form_checks_are_unknown():
    content = content_analyzer.analyze_content(None, None)
    assert content.fetched is False
    assert content.has_form is None
    assert content.credential_form is None
    assert content.payment_form is None


def test_valid_tls_preserves_brand_and_credentials():
    link = candidate()
    result = analyze(link, observed(link.canonical_url, FIXTURE.read_text()))
    assert result.assessment == 'phishing'
    assert {'brand_destination_mismatch', 'credential_form', 'payment_form'} <= {r.code for r in result.reasons}


def test_missing_html_is_limitation_not_observed_absence():
    link = candidate('https://example.com')
    result = analyze(link, UrlObservation(final_url=link.canonical_url, completed_checks=['http']))
    assert 'inspection_failed' in result.limitations
    assert result.assessment == 'unknown'
    assert not {'credential_form', 'payment_form'} & {r.code for r in result.reasons}


def test_timeout_is_not_certificate_mismatch():
    result = analyze(candidate('https://example.com'), UrlObservation(limitations=['deadline_exceeded']))
    assert result.assessment == 'unknown'
    assert result.inspection_status == 'failed'
    assert result.limitations == ['deadline_exceeded']
    assert 'certificate_mismatch' not in {r.code for r in result.reasons}


def test_verified_certificate_failure_is_evidence():
    result = analyze(candidate('https://example.com'), UrlObservation(
        tls=CertificateAnalysis(None, None, None, None, None, False, 'certificate_mismatch'),
        limitations=['certificate_mismatch']))
    assert result.assessment == 'suspicious'
    assert 'certificate_mismatch' in {r.code for r in result.reasons}


def test_local_blocklist_is_limited_local_warning():
    result = analyze(candidate('https://evil.com'), None)
    assert result.assessment == 'suspicious'
    reason = next(r for r in result.reasons if r.code == 'local_blocklist_hit')
    assert reason.source == 'url'
    assert reason.strength == 'medium'
    assert reason.params == {'display_host': 'evil.com'}
    assert result.limitations == ['inspection_disabled']


@pytest.mark.parametrize('url', ['https://שלום.com', 'https://xn--9dbne9b.com'])
def test_hebrew_idn_alone_is_not_phishing(url):
    link = candidate(url)
    result = analyze(link, observed(link.canonical_url))
    assert result.assessment == 'no_clear_signs'
    assert result.reasons == []


def test_static_mode_is_offline_and_honest():
    result = analyze(candidate('https://example.com'), None)
    assert result.assessment == 'unknown'
    assert result.inspection_status == 'not_requested'
    assert result.limitations == ['inspection_disabled']


def test_redirect_final_and_initial_evidence_both_survive():
    link = candidate('https://paypal-login.attacker.com')
    result = analyze(link, observed('https://google.com'))
    assert result.assessment == 'suspicious'
    assert 'brand_destination_mismatch' in {r.code for r in result.reasons}


def test_blocked_private_address_is_unassessable():
    result = analyze(candidate('http://192.168.1.10/login'), UrlObservation(limitations=['destination_blocked']))
    assert result.assessment == 'unknown'
    assert result.inspection_status == 'blocked'
    assert result.limitations == ['destination_blocked']


def test_truncated_body_preserves_positive_evidence_with_limitation():
    link = candidate()
    observation = observed(link.canonical_url, FIXTURE.read_text(), limitations=['body_limit'])
    observation.completed_checks.remove('html')
    result = analyze(link, observation)
    assert result.assessment == 'phishing'
    assert result.inspection_status == 'failed'
    assert result.limitations == ['body_limit']


def test_no_brand_word_is_not_brand_impersonation():
    result = analyze(candidate('https://tracking.newbrand.click'), None)
    assert not {'brand_destination_mismatch', 'lookalike_host'} & {r.code for r in result.reasons}


def test_ordinary_production_import_and_domain_helpers_are_offline():
    script = '''
import socket, threading
attempts = []
def deny(*a, **k):
    attempts.append('network')
    raise AssertionError('network denied')
socket.getaddrinfo = socket.create_connection = deny
socket.socket.connect = socket.socket.connect_ex = socket.socket.sendto = deny
import requests
requests.sessions.Session.request = deny
from app.detection.engine import run_detection
from app.detection.domain_analyzer import analyze_domain
from app.detection.url_normalizer import normalize_url
from app.brand import analyze_brand
from app.reputation import get_allowlist
analyze_domain(normalize_url('https://example.com'), 'https://example.com')
analyze_brand('example.com')
get_allowlist()
for thread in threading.enumerate():
    if thread is not threading.current_thread():
        thread.join(timeout=1)
assert not attempts, attempts
'''
    env = {**os.environ, 'ALLOWLIST_ENABLED': 'true',
           'ALLOWLIST_SOURCES': 'https://allowlist.example/list', 'ALLOWLIST_CACHE_PATH': ''}
    result = subprocess.run([sys.executable, '-c', script], env=env, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr


def test_short_domain_is_not_a_substring_brand_lookalike():
    result = analyze(candidate('https://t.ly/abc'), None)
    assert not {'brand_destination_mismatch', 'lookalike_host'} & {r.code for r in result.reasons}


def test_trusted_root_does_not_cancel_other_brand_and_credential_evidence():
    link = candidate('https://paypal.google.com')
    result = analyze(link, observed(link.canonical_url, FIXTURE.read_text()))
    assert result.assessment == 'phishing'
    assert {'brand_destination_mismatch', 'credential_form'} <= {r.code for r in result.reasons}


def test_real_brand_claim_on_neutral_host_is_preserved():
    link = candidate('https://attacker.com')
    result = analyze(link, observed(link.canonical_url,
        '<title>PayPal sign in</title><form><input type="password"></form>'))
    assert result.assessment == 'phishing'
    assert {'brand_destination_mismatch', 'credential_form'} <= {r.code for r in result.reasons}


def test_form_attribute_associates_inputs_outside_form():
    content = content_analyzer.analyze_html('<input type="password" form="login"><form id="login"></form>')
    assert content.credential_form is True
    assert content.payment_form is False


def test_partial_html_retains_unknown_for_unseen_forms():
    content = content_analyzer.analyze_content(UrlObservation(html='<html><p>Hello', limitations=['body_limit']))
    assert content.fetched is False
    assert content.has_form is None
    assert content.credential_form is None
    assert content.payment_form is None


def test_legacy_private_input_never_reaches_injected_transport():
    from app.detection.engine import run_detection
    def forbidden(*args, **kwargs):
        pytest.fail('private input reached transport')
    result = run_detection('http://192.168.1.10/login', object(), resolver=forbidden)
    assert result.status == 'unknown'
    assert result.signals['limitations'] == ['destination_blocked']


def test_legacy_scan_uses_one_observation_and_no_database():
    from app.detection.engine import run_detection
    link = candidate('https://example.com')
    calls = []
    def inspector(url, *, deadline):
        calls.append(url)
        return observed(url)
    class NoDatabase:
        def __getattr__(self, name):
            pytest.fail('legacy analysis touched database')
    result = run_detection(link.raw, NoDatabase(), resolver=inspector)
    assert calls == [link.canonical_url]
    assert result.reputation == 'unknown'
    assert result.signals['content']['credential_form'] is False


def test_discount_cannot_suppress_strong_scoring_evidence():
    from app.detection.engine import run_detection
    result = run_detection('https://paypal.google.com/login', object(),
        resolver=lambda url, deadline: observed(url, FIXTURE.read_text()))
    assert result.status == 'phishing'
    assert 'brand_impersonation' in result.signals['strong_signals']
    assert 'allowlist_discount' not in {c['key'] for c in result.breakdown}


@pytest.mark.parametrize('url', ['http://[::1]/login', 'https://[fd00::1]/'])
def test_legacy_private_ipv6_is_blocked_and_unassessable(url):
    from app.detection.engine import run_detection
    result = run_detection(url, object(), resolver=lambda *a, **k: pytest.fail('private IPv6 reached transport'))
    assert result.status == 'unknown'
    assert result.signals['limitations'] == ['destination_blocked']
    assert result.normalized_url == candidate(url).canonical_url


def test_non_html_observation_preserves_content_type_without_absence_claim():
    content = content_analyzer.analyze_content(UrlObservation(content_type='application/octet-stream',
        completed_checks=['http'], limitations=['inspection_failed']))
    assert content.content_type == 'application/octet-stream'
    assert content.credential_form is None


def test_certificate_failure_after_redirect_does_not_blame_previous_response_host():
    link = candidate('https://example.com')
    result = analyze(link, UrlObservation(final_url=link.canonical_url,
        tls=CertificateAnalysis(None, None, None, None, None, False, 'certificate_mismatch'),
        completed_checks=['http'], limitations=['certificate_mismatch']))
    reason = next(r for r in result.reasons if r.code == 'certificate_mismatch')
    assert reason.params == {}


def test_intermediate_redirect_evidence_survives_normal_final_destination():
    from app.detection.models import RedirectHop
    link = candidate('https://example.com')
    observation = observed('https://google.com')
    observation.hops = [RedirectHop(link.canonical_url, 302, '1.1.1.1', 'ipv4'),
        RedirectHop('https://paypal-login.attacker.com', 302, '1.1.1.1', 'ipv4'),
        RedirectHop('https://google.com', 200, '1.1.1.1', 'ipv4')]
    result = analyze(link, observation)
    assert result.assessment == 'suspicious'
    assert any(r.code == 'brand_destination_mismatch' and r.source == 'inspection' for r in result.reasons)


def test_actual_negative_form_observation_requires_completed_html():
    link = candidate('https://example.com')
    result = analyze(link, observed(link.canonical_url))
    assert result.assessment == 'no_clear_signs'
    assert result.inspection_status == 'completed'
    assert result.limitations == []


def test_invalid_candidate_and_raw_observation_errors_never_leak():
    invalid = candidate('https://user:secret@example.com')
    result = analyze(invalid, None)
    assert result.assessment == 'unknown'
    assert result.inspection_status == 'skipped'
    assert result.limitations == ['invalid_link']
    link = candidate('https://example.com')
    failed = analyze(link, UrlObservation(limitations=['oops token=PRIVATE_SECRET']))
    assert failed.limitations == ['inspection_failed']
    assert 'PRIVATE_SECRET' not in failed.model_dump_json()
