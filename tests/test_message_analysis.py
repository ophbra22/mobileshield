"""Synthetic message evidence and bounded orchestration tests."""
from unittest.mock import Mock

import pytest

from app.message_models import MessageRequest, MessageResponse
from app.detection.safe_transport import UrlObservation


def run(text, inspect=False, transport=None):
    from app.analysis import analyze_message
    return analyze_message(MessageRequest(text=text, inspect_links=inspect),
                           request_id='server-id', transport=transport or Mock())


@pytest.mark.parametrize('text', ['Hello, see you tomorrow', 'שלום נתראה מחר',
                                  'See https://example.com and https://example.org'])
def test_static_contract_and_zero_outbound_calls(text):
    transport = Mock()
    result = run(text, transport=transport)
    MessageResponse.model_validate(result.model_dump())
    assert transport.inspect.call_count == 0
    assert result.request_id == 'server-id'
    if result.links:
        assert result.assessment == 'no_clear_signs'
        assert result.analysis_status == 'complete'
        assert 'inspection_disabled' in result.limitations
    else:
        assert result.assessment == 'no_clear_signs'
        assert result.analysis_status == 'complete'


@pytest.mark.parametrize('text', ['Send me your OTP now https://apple.com',
                                  'שלח לי את הסיסמה שלך עכשיו https://apple.com'])
def test_secret_request_survives_official_link(text):
    result = run(text)
    assert result.assessment in ('suspicious', 'phishing')
    assert 'credential_request' in [r.code for r in result.reasons]
    assert 'do_not_share_secrets' in result.recommended_actions


@pytest.mark.parametrize('text', ['OTP', 'password', 'urgent', 'Do not share your OTP',
                                  "Never send your password", 'אל תשתף את הסיסמה שלך'])
def test_keyword_or_prevention_advice_is_not_a_secret_request(text):
    result = run(text)
    assert result.assessment != 'phishing'
    assert 'credential_request' not in [r.code for r in result.reasons]


def test_context_combination_required_for_phishing():
    assert run('Please send me your password').assessment == 'suspicious'
    assert run('Send me your password now or your account will be suspended').assessment == 'phishing'


def test_unsupported_without_evidence_is_unknown():
    result = run('请今天联系我')
    assert result.assessment == 'unknown'
    assert result.analysis_status == 'unavailable'
    assert 'unsupported_text' in result.limitations


def test_phishing_link_not_averaged_away_by_failure():
    transport = Mock()
    from tests.test_url_evidence import observed, FIXTURE
    transport.inspect.side_effect = [observed('https://paypal-login.attacker.com', FIXTURE.read_text()),
                                     UrlObservation(limitations=['deadline_exceeded'])]
    result = run('See https://paypal-login.attacker.com and https://example.org', True, transport)
    assert result.assessment == 'phishing'
    assert result.analysis_status == 'partial'


def test_inspection_exception_is_sanitized_and_unknown():
    transport = Mock()
    transport.inspect.side_effect = RuntimeError('PRIVATE_SENTINEL')
    result = run('https://example.com', True, transport)
    assert result.assessment == 'unknown'
    assert 'PRIVATE_SENTINEL' not in result.model_dump_json()


def test_deadline_skips_later_links(monkeypatch):
    import app.analysis as service
    clock = Mock(side_effect=[0, 0, 21])
    monkeypatch.setattr(service.time, 'monotonic', clock)
    transport = Mock(inspect=Mock(return_value=UrlObservation(limitations=['deadline_exceeded'])))
    result = run('https://example.com https://example.org', True, transport)
    assert transport.inspect.call_count == 1
    assert result.links[1].inspection_status == 'skipped'
    assert 'deadline_exceeded' in result.links[1].limitations


@pytest.mark.parametrize('brand,url', [('Outlook', 'https://outlook.com'), ('Office', 'https://office.com'),
                                     ('iCloud', 'https://icloud.com'), ('Hapoalim', 'https://poalim.biz')])
def test_message_brand_family_official_domains(brand, url):
    result = run(f'{brand}: please check your account at {url}')
    assert 'brand_destination_mismatch' not in [r.code for r in result.reasons]


def test_specific_brand_claim_plus_other_host_is_evidence():
    result = run('Microsoft: verify your account at https://unrelated.example')
    assert 'brand_destination_mismatch' in [r.code for r in result.reasons]
    assert run('Your bank: https://unrelated.example').assessment == 'no_clear_signs'


def test_busy_first_link_retains_observed_message_risk():
    from app.detection.safe_transport import InspectionBusy
    transport = Mock(inspect=Mock(side_effect=InspectionBusy()))
    result = run('Send me your OTP now https://apple.com', True, transport)
    assert result.assessment == 'suspicious'
    assert result.analysis_status == 'partial'
    assert result.links[0].inspection_status == 'skipped'


def test_busy_first_link_retains_static_url_warning():
    from app.detection.safe_transport import InspectionBusy
    transport = Mock(inspect=Mock(side_effect=InspectionBusy()))
    result = run('https://evil.com', True, transport)
    assert result.assessment == 'suspicious'
    assert result.analysis_status == 'partial'


def test_busy_later_link_preserves_finished_evidence():
    from app.detection.safe_transport import InspectionBusy
    from tests.test_url_evidence import observed, FIXTURE
    transport = Mock(inspect=Mock(side_effect=[observed('https://paypal-login.attacker.com', FIXTURE.read_text()), InspectionBusy()]))
    result = run('https://paypal-login.attacker.com https://example.com', True, transport)
    assert result.assessment == 'phishing'
    assert result.analysis_status == 'partial'
    assert result.links[1].inspection_status == 'skipped'


def test_malformed_backend_observation_never_safe():
    result = run('https://example.com', True, Mock(inspect=Mock(return_value={'html': 'ok'})))
    assert result.assessment == 'unknown'
    assert result.links[0].inspection_status == 'failed'


import json
from pathlib import Path
_CORPUS = json.loads((Path(__file__).parent / 'fixtures/messages.json').read_text())


@pytest.mark.parametrize('case', _CORPUS, ids=lambda case: case['id'])
def test_fixed_message_corpus(case):
    result = run(case['text'])
    assert result.assessment == case['expected_assessment']


def test_completed_inspection_can_return_no_clear_signs():
    from tests.test_url_evidence import observed
    result = run('Read https://example.com', True,
                 Mock(inspect=Mock(return_value=observed('https://example.com'))))
    assert result.assessment == 'no_clear_signs'
    assert result.analysis_status == 'complete'


def test_negated_clause_does_not_suppress_later_secret_request():
    assert run('Do not share your password with strangers, but send me your OTP.').assessment == 'suspicious'


def test_no_clear_signs_not_allowed_when_link_results_missing():
    from app.detection.message_analyzer import assess_message
    from app.message_parser import parse_message
    result = assess_message(parse_message('Read https://example.com'), [])
    assert result.assessment == 'unknown'
    assert 'inspection_failed' in result.limitations


def test_static_completion_is_distinct_from_requested_inspection_failure():
    text = 'Read https://example.com for details'
    static = run(text)
    assert static.assessment == 'no_clear_signs'
    assert static.analysis_status == 'complete'
    assert static.links[0].assessment == 'unknown'
    assert static.links[0].inspection_status == 'not_requested'
    assert static.limitations == ['inspection_disabled']
    assert 'consider_link_inspection' in static.recommended_actions
    deep = run(text, True, Mock(inspect=Mock(return_value=UrlObservation(limitations=['inspection_failed']))))
    assert deep.assessment == 'unknown'
    assert deep.analysis_status == 'partial'


@pytest.mark.parametrize('text', ['Read ftp://example.com', '你好 https://example.com',
                                  'Read https://example.com:8080', 'Read https://127.0.0.1'])
def test_other_missing_or_blocked_checks_prevent_static_reassurance(text):
    assert run(text).assessment == 'unknown'
