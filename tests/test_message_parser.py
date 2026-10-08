import json
import subprocess
import sys
from pathlib import Path

import pytest

from app.message_models import (
    AssessmentSummary, LinkResult, MessageRequest, MessageResponse, Reason,
)
from app.message_parser import parse_message
from app.detection.url_normalizer import extract_domain, split_domain


def test_plain_hebrew_preserves_complete_input():
    text = '  שלום, נדבר מחר\n🙂  '
    parsed = parse_message(text)
    assert parsed.text == text
    assert parsed.links == []
    assert parsed.supported_text


@pytest.mark.parametrize('text', ['🙂' * 10_000, 'a\u0301' * 5_000])
def test_codepoint_limit_accepts_exact_boundary(text):
    assert MessageRequest(text=text).text == text
    assert parse_message(text).text == text


@pytest.mark.parametrize('text', ['🙂' * 10_001, 'a\u0301' * 5_000 + 'a', '   ', '', '\t\n'])
def test_invalid_text_rejected_by_both_interfaces(text):
    with pytest.raises(ValueError):
        MessageRequest(text=text)
    with pytest.raises(ValueError):
        parse_message(text)


@pytest.mark.parametrize('value', [0, 1, 'true', 'false', None])
def test_request_boolean_is_strict(value):
    with pytest.raises(ValueError):
        MessageRequest(text='hello', inspect_links=value)


def test_request_forbids_unknown_fields_and_non_string_text():
    assert MessageRequest(text='hello').inspect_links is False
    assert MessageRequest(text='hello', inspect_links=True).inspect_links is True
    with pytest.raises(ValueError):
        MessageRequest(text='hello', url='https://example.com')
    with pytest.raises(ValueError):
        MessageRequest(text=123)


@pytest.mark.parametrize(('text', 'urls'), [
    ('See example.com/a, https://example.com/a.', ['https://example.com/a']),
    ('https://a.example/a https://b.example/b', ['https://a.example/a', 'https://b.example/b']),
    ('See (https://example.com/wiki/a_(b)).', ['https://example.com/wiki/a_(b)']),
    ('ראו https://example.com/a, ואחר כך example.org״', ['https://example.com/a', 'https://example.org/']),
    ('HTTPS://EXAMPLE.COM:443/a#part https://example.com/a', ['https://example.com/a']),
    ('https://example.com/a;b?x=1&y=2', ['https://example.com/a;b?x=1&y=2']),
    ('https://שלום.com/בית', ['https://xn--9dbne9b.com/%D7%91%D7%99%D7%AA']),
    ('שלום.com', ['https://xn--9dbne9b.com/']),
    ('https://[2001:db8::1]/', ['https://[2001:db8::1]/']),
])
def test_named_url_normalization_cases(text, urls):
    parsed = parse_message(text)
    assert [link.canonical_url for link in parsed.links] == urls
    assert all(link.parse_error is None for link in parsed.links)
    assert [link.link_id for link in parsed.links] == [f'link_{i}' for i in range(1, len(urls) + 1)]
    assert parsed.text == text


@pytest.mark.parametrize('text', ['me@example.com', 'first.last+tag@example.com', 'user@sub.example.org', 'hello world', 'not.a.real.suffix', 'version 1.2.3'])
def test_email_and_prose_are_not_links(text):
    assert parse_message(text).links == []


@pytest.mark.parametrize(('text', 'error'), [
    ('ftp://example.com/a', 'unsupported_scheme'),
    ('mailto:me@example.com', 'unsupported_scheme'),
    ('javascript:alert(1)', 'unsupported_scheme'),
    ('https://', 'invalid_url'),
    ('https:///example.com', 'invalid_url'),
    ('https://user:secret@example.com', 'ambiguous_url'),
    ('https://example.com:8080', 'invalid_port'),
    ('http://example.com:443', 'invalid_port'),
    ('https://exa\u200bmple.com', 'ambiguous_url'),
    ('https://exam\u202eple.com', 'ambiguous_url'),
    ('https://example.com/%zz', 'invalid_url'),
])
def test_malformed_unsupported_and_ambiguous_links_stay_visible(text, error):
    link, = parse_message(text).links
    assert link.raw == text
    assert link.canonical_url is None
    assert link.parse_error == error


def test_idn_has_no_implicit_spoof_classification():
    link, = parse_message('https://שלום.com').links
    assert link.display_host == 'שלום.com'
    assert link.parse_error is None


def test_analysis_copy_removes_controls_without_rewriting_original_links():
    text = 'שלום\u200b  now\u202e https://exa\u200bmple.com'
    parsed = parse_message(text)
    assert parsed.text == text
    assert parsed.normalized_text == 'שלום now https://example.com'
    assert parsed.links[0].canonical_url is None


@pytest.mark.parametrize(('text', 'supported'), [('שלום hello', True), ('hello 🙂', True), ('🙂 123 !!!', False), ('你好', False), ('Привет https://example.com', False), ('https://example.com', False)])
def test_text_language_coverage(text, supported):
    assert parse_message(text).supported_text is supported


def test_distinct_link_limit_rejects_not_truncates():
    assert len(parse_message(' '.join(f'https://a{i}.example' for i in range(10))).links) == 10
    with pytest.raises(ValueError):
        parse_message(' '.join(f'https://a{i}.example' for i in range(11)))
    assert len(parse_message(' '.join(['example.com'] * 11)).links) == 1


@pytest.mark.parametrize(('text', 'url', 'error'), [
    ('example.com:443/a', 'https://example.com/a', None),
    ('https:example.com', None, 'invalid_url'),
    ('http:/example.com', None, 'invalid_url'),
    ('ht\u200btps://example.com', None, 'ambiguous_url'),
    ("See 'https://example.com/a'.", 'https://example.com/a', None),
])
def test_scheme_and_quotation_boundaries(text, url, error):
    link, = parse_message(text).links
    assert link.canonical_url == url
    assert link.parse_error == error


def test_offline_private_suffix_extraction():
    assert extract_domain('a.github.io') == 'a.github.io'
    assert split_domain('a.b.co.il').suffix == 'co.il'


def test_parser_import_does_not_initialize_analyzers():
    result = subprocess.run([sys.executable, '-c', "import sys; import app.message_parser; assert 'app.detection.engine' not in sys.modules; assert 'app.reputation' not in sys.modules"], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


def make_reason(**overrides):
    fields = dict(code='lookalike_host', strength='medium', source='url', link_id='link_1', params={'brand': 'paypal', 'display_host': 'paypa1.example', 'expected_host': 'paypal.com'})
    fields.update(overrides)
    return Reason(**fields)


def test_safe_reason_registry_accepts_hostnames_and_ips():
    assert make_reason().params['brand'] == 'paypal'
    assert make_reason(code='destination_blocked', params={'display_host': '2001:db8::1'}).params
    assert make_reason(code='credential_request', source='message', params={}).params == {}


@pytest.mark.parametrize('params', [{'secret': '123456'}, {'brand': 'arbitrary copied text'}, {'display_host': 'https://example.com/token'}, {'display_host': 'user@example.com'}, {'display_host': 'example.com:443'}, {'display_host': 'exam\u200bple.com'}, {'display_host': 'a' * 257}, {'display_host': 'fe80::1%secret'}])
def test_reason_rejects_unsafe_facts(params):
    with pytest.raises(ValueError):
        make_reason(params=params)


def test_reason_rejects_unknown_code_and_message_facts():
    with pytest.raises(ValueError):
        make_reason(code='unknown_code', params={})
    with pytest.raises(ValueError):
        make_reason(code='credential_request', params={'display_host': 'example.com'})


def test_response_bounds_and_literal_contract():
    summary = dict(assessment='suspicious', analysis_status='partial', reasons=[make_reason()], recommended_actions=['verify_independently'], limitations=['inspection_disabled'])
    response = MessageResponse(**summary, schema_version=1, links=[], request_id='test-request')
    assert response.model_dump()['schema_version'] == 1
    assert AssessmentSummary(**summary).assessment == 'suspicious'
    with pytest.raises(ValueError):
        MessageResponse(**summary, schema_version=2, links=[], request_id='test-request')
    for overrides in [{'reasons': [make_reason()] * 33}, {'limitations': ['raw exception token=secret']}, {'assessment': 'benign'}]:
        with pytest.raises(ValueError):
            AssessmentSummary(**(summary | overrides))
    with pytest.raises(ValueError):
        LinkResult(link_id='link_1', assessment='unknown', inspection_status='failed', display_host=None, reasons=[make_reason()] * 33, limitations=['inspection_failed'], technical=None)


def test_fixed_synthetic_corpus():
    corpus = json.loads((Path(__file__).parent / 'fixtures/messages.json').read_text())
    assert len(corpus) >= 60
    for language in ['he', 'en']:
        cases = [case for case in corpus if case['language'] == language]
        assert len(cases) >= 30
        assert {case['expected_assessment'] for case in cases} >= {'no_clear_signs', 'suspicious', 'unknown'}
    for case in corpus:
        parsed = parse_message(case['text'])
        assert len(parsed.links) == case['expected_link_count'], case['id']
        assert parsed.supported_text is case['expected_supported_text'], case['id']
        assert parsed.text == case['text']
