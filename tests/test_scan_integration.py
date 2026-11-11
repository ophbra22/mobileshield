"""Real ASGI serialization, fixed synthetic corpus and client parser integration."""
import json
import subprocess
from pathlib import Path
from typing import get_args

import pytest

from app.message_models import ActionCode, AnalysisStatus, Assessment, MessageResponse

ROOT = Path(__file__).resolve().parents[1]
CORPUS = json.loads((ROOT / 'tests/fixtures/messages.json').read_text())


def frontend_roundtrip(responses):
    # Execute the actual TypeScript runtime parser, without a browser or network.
    script = r'''
const fs = require('fs');
const ts = require('typescript');
const source = fs.readFileSync('lib/analysis.ts', 'utf8');
const compiled = ts.transpileModule(source, {compilerOptions: {module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020}}).outputText;
const parser = {exports: {}};
new Function('module', 'exports', compiled)(parser, parser.exports);
const values = JSON.parse(fs.readFileSync(0, 'utf8'));
process.stdout.write(JSON.stringify(values.map(parser.exports.parseAnalysisResponse)));
'''
    completed = subprocess.run(['node', '-e', script], cwd=ROOT / 'mobileshield-web',
                               input=json.dumps(responses), text=True, capture_output=True, check=True)
    assert json.loads(completed.stdout) == responses


def test_fixed_corpus_through_endpoint_and_actual_frontend_parser(client):
    assert len(CORPUS) == 60
    values = []
    for case in CORPUS:
        response = client.post('/v1/analyze-message', json={'text': case['text']})
        assert response.status_code == 200, case['id']
        value = response.json()
        assert value['assessment'] == case['expected_assessment'], case['id']
        assert len(value['links']) == case['expected_link_count'], case['id']
        assert response.headers['cache-control'] == 'no-store'
        values.append(value)
    assert client.transport_spy.inspect.call_count == 0
    frontend_roundtrip(values)


@pytest.mark.parametrize('text', [
    'Envoyez-moi votre mot de passe immédiatement.',
    'Envíame tu contraseña y el código de verificación ahora.',
    'Senden Sie mir sofort Ihr Passwort.',
    'Envoyez moi votre mot de passe.',
    'שלום Senden Sie mir Ihr Passwort.',
    'Hello, veuillez transmettre vos identifiants.',
    'Aurelia discusses photosynthesis.',
])
def test_uncovered_latin_prose_cannot_be_complete_or_no_clear(client, text):
    response = client.post('/v1/analyze-message', json={'text': text})
    assert response.status_code == 200
    result = response.json()
    assert result['assessment'] == 'unknown'
    assert result['analysis_status'] == 'unavailable'
    assert 'unsupported_text' in result['limitations']
    frontend_roundtrip([result])


@pytest.mark.parametrize('delivery', ['by email', 'via email'])
def test_fronted_secret_request_delivery_preposition(client, delivery):
    result = client.post('/v1/analyze-message', json={
        'text': f'Do not send the agenda, your password, please send that {delivery}.'}).json()
    assert result['assessment'] == 'suspicious'
    assert result['analysis_status'] == 'complete'
    assert 'credential_request' in [r['code'] for r in result['reasons']]
    assert 'do_not_share_secrets' in result['recommended_actions']


@pytest.mark.parametrize('text', [
    'Send your password. Veuillez transmettre vos identifiants.',
    'שלום Envoyez moi votre mot de passe. Send your OTP.',
])
def test_independent_positive_evidence_survives_limited_coverage(client, text):
    result = client.post('/v1/analyze-message', json={'text': text}).json()
    assert result['assessment'] == 'suspicious'
    assert result['analysis_status'] == 'partial'
    assert 'unsupported_text' in result['limitations']
    assert 'credential_request' in [r['code'] for r in result['reasons']]
    assert 'do_not_share_secrets' in result['recommended_actions']
    frontend_roundtrip([result])


def test_all_contract_enums_survive_endpoint_serialization(client, monkeypatch):
    import app.routers.analyze as router
    from app.message_models import MAX_REASONS, REASON_PARAM_KEYS, LinkResult, Reason
    values = []
    # Controlled valid production response models exercise every accepted enum
    # through FastAPI response validation/serialization and the real TS parser.
    reason_codes = list(REASON_PARAM_KEYS)
    for offset in range(0, len(reason_codes), MAX_REASONS):
        batch = reason_codes[offset:offset + MAX_REASONS]
        for assessment in get_args(Assessment):
            for status in get_args(AnalysisStatus):
                response = MessageResponse(assessment=assessment, analysis_status=status,
                                           recommended_actions=list(get_args(ActionCode)), request_id='fixture',
                                           reasons=[Reason(code=c, strength=strength, source=source)
                                                    for c in batch
                                                    for strength, source in [('info', 'message')]],
                                           links=[LinkResult(link_id=f'link_{i}', assessment=assessment,
                                                             inspection_status=inspection,
                                                             reasons=[Reason(code='credential_request', strength=strength, source=source)])
                                                  for i, (inspection, strength, source) in enumerate([
                                                      ('not_requested', 'info', 'message'), ('completed', 'medium', 'url'),
                                                      ('blocked', 'strong', 'inspection'), ('failed', 'info', 'url'),
                                                      ('skipped', 'medium', 'inspection')], 1)])
                monkeypatch.setattr(router, 'analyze_message', lambda *a, _result=response, **k: _result)
                result = client.post('/v1/analyze-message', json={'text': 'hello'})
                assert result.status_code == 200
                values.append(result.json())
    assert {reason['code'] for value in values for reason in value['reasons']} == set(REASON_PARAM_KEYS)
    frontend_roundtrip(values)


def test_fixture_transport_partial_failures_keep_observed_warning(client):
    from app.main import app
    from app.routers.analyze import get_scan_transport
    from tests.fixture_server import FixtureTransport
    app.dependency_overrides[get_scan_transport] = FixtureTransport
    result = client.post('/v1/analyze-message', json={
        'text': 'Send your password https://paypal-login.attacker.example https://failed.example https://busy.example https://example.org',
        'inspect_links': True}).json()
    assert result['assessment'] == 'phishing'
    assert result['analysis_status'] == 'partial'
    assert [link['inspection_status'] for link in result['links']] == ['completed', 'failed', 'skipped', 'skipped']
    assert 'retry_later' in result['recommended_actions']
    frontend_roundtrip([result])


def test_fixture_unknown_destinations_fail_without_socket_or_dns():
    from tests.fixture_server import FixtureTransport
    # tests/conftest.py detects network attempts even if swallowed by the code.
    result = FixtureTransport().inspect('https://arbitrary.example/private?token=SYNTHETIC', deadline=0)
    assert result.limitations == ['inspection_failed']
    assert result.final_url is None


def test_supported_english_prose_is_not_confused_by_url_lexemes(client):
    result = client.post('/v1/analyze-message', json={
        'text': 'Hello, please review https://arbitrary.example/unbekannt?term=contraseña'}).json()
    assert result['analysis_status'] == 'complete'
    assert 'unsupported_text' not in result['limitations']


def test_positive_url_evidence_survives_uncovered_text(client):
    result = client.post('/v1/analyze-message', json={
        'text': 'Envoyez moi votre mot de passe https://phishingsite.com'}).json()
    assert result['assessment'] == 'suspicious'
    assert result['analysis_status'] == 'partial'
    assert 'unsupported_text' in result['limitations']
    assert 'local_blocklist_hit' in [r['code'] for r in result['reasons']]
    frontend_roundtrip([result])
