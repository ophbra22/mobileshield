"""Legacy browser negotiation and executable old/new client contract checks."""
import json
import re
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest

ROOT = Path(__file__).resolve().parents[1]
ORIGIN = 'http://localhost:3000'
VERSION = 'X-MobileShield-Response-Version'
URLS = [
    'https://paypal-login.attacker.example/PRIVATE_SENTINEL',
    'https://unknown.example/PRIVATE_SENTINEL',
    'https://example.com/PRIVATE_SENTINEL',
]


@pytest.mark.parametrize('url', URLS)
@pytest.mark.parametrize('version', [None, '', '0', '2', 'garbage_PRIVATE_SENTINEL', '1, 2'])
@pytest.mark.parametrize('inspect_links', [False, True])
def test_unsupported_browser_stops_before_analysis(client, monkeypatch, caplog, url, version, inspect_links):
    import app.routers.analyze as router
    analysis = Mock(wraps=router.analyze_message)
    monkeypatch.setattr(router, 'analyze_message', analysis)
    headers = {'Origin': ORIGIN, 'X-Request-ID': 'PRIVATE_SENTINEL'}
    if version is not None:
        headers[VERSION] = version
    response = client.post('/v1/analyze', json={'url': url, 'inspect_links': inspect_links}, headers=headers)
    assert response.status_code == 409
    body = response.json()
    assert set(body) == {'detail', 'message', 'request_id'}
    assert body['detail'] == 'client_upgrade_required'
    assert 'refresh' in body['message'].lower() and 'update' in body['message'].lower()
    assert re.fullmatch(r'[0-9a-f]{32}', body['request_id'])
    assert response.headers['x-request-id'] == body['request_id']
    assert response.headers['cache-control'] == 'no-store'
    assert response.headers['access-control-allow-origin'] == ORIGIN
    assert 'PRIVATE_SENTINEL' not in response.text + str(response.headers) + caplog.text
    analysis.assert_not_called()
    client.transport_spy.inspect.assert_not_called()


@pytest.mark.parametrize('origin', ['', 'null', 'https://unlisted.example'])
def test_every_present_origin_requires_negotiation_without_expanding_cors(client, origin):
    response = client.post('/v1/analyze', json={'url': URLS[0]}, headers={'Origin': origin})
    assert response.status_code == 409
    assert 'access-control-allow-origin' not in response.headers
    client.transport_spy.inspect.assert_not_called()


def test_duplicate_versions_are_not_an_explicit_supported_version(client):
    response = client.post('/v1/analyze', json={'url': URLS[0]},
                           headers=[('Origin', ORIGIN), (VERSION, '1'), (VERSION, '2')])
    assert response.status_code == 409


@pytest.mark.parametrize('headers', [
    {'Origin': ORIGIN, VERSION: '1'}, {}, {VERSION: '2'},
])
@pytest.mark.parametrize('url,inspect_links,verdict,assessment', [
    ('https://paypal-login.attacker.example', True, 'phishing', 'phishing'),
    ('https://phishingsite.com', False, 'suspicious', 'suspicious'),
    ('https://example.com', True, 'legitimate', 'no_clear_signs'),
    ('https://example.com', False, 'unknown', 'unknown'),
])
def test_compatible_browser_and_originless_api_keep_canonical_results(
        client, headers, url, inspect_links, verdict, assessment):
    from app.detection.models import CertificateAnalysis
    from app.detection.safe_transport import UrlObservation
    client.transport_spy.inspect.return_value = UrlObservation(
        final_url=url, html='<input type="password">' if 'attacker' in url else '<p>Ordinary page</p>',
        content_type='text/html',
        tls=CertificateAnalysis('Synthetic fixture', None, '2026', '2027', True, True),
        completed_checks=['http', 'html', 'tls'],
    )
    response = client.post('/v1/analyze', json={'url': url, 'inspect_links': inspect_links}, headers=headers)
    assert response.status_code == 200
    body = response.json()
    assert body['verdict'] == body['status'] == verdict
    assert body['assessment'] == assessment
    assert body['scan_id'] is None
    assert body['schema_version'] == 1
    assert response.headers['cache-control'] == 'no-store'
    assert client.transport_spy.inspect.call_count == int(inspect_links)


@pytest.mark.parametrize('version', [None, '', '2'])
def test_new_message_endpoint_needs_no_legacy_version(client, version):
    headers = {'Origin': ORIGIN}
    if version is not None:
        headers[VERSION] = version
    response = client.post('/v1/analyze-message', json={'text': 'Send your password'}, headers=headers)
    assert response.status_code == 200
    assert response.json()['assessment'] == 'suspicious'
    assert response.headers['access-control-allow-origin'] == ORIGIN


def test_negotiation_retains_existing_body_rate_and_work_limits(client):
    from app.main import app
    from app.scan_limits import ScanRateLimiter
    headers = {'Origin': ORIGIN}
    oversized = client.post('/v1/analyze', content=b'x' * (128 * 1024 + 1), headers=headers)
    assert oversized.status_code == 413
    app.state.scan_limiter = ScanRateLimiter(limit=0)
    limited = client.post('/v1/analyze', json={'url': URLS[0]}, headers=headers)
    assert limited.status_code == 429
    app.state.scan_limiter = ScanRateLimiter(limit=60)
    acquired = 0
    try:
        while app.state.scan_work.acquire():
            acquired += 1
        busy = client.post('/v1/analyze', json={'url': URLS[0]}, headers=headers)
        assert busy.status_code == 503
    finally:
        for _ in range(acquired):
            app.state.scan_work.release()
    recovered = client.post('/v1/analyze', json={'url': URLS[0]}, headers=headers)
    assert recovered.status_code == 409
    for response in (oversized, limited, busy, recovered):
        assert response.headers['cache-control'] == 'no-store'
        assert response.headers['access-control-allow-origin'] == ORIGIN
    client.transport_spy.inspect.assert_not_called()


def test_version_header_preflight_uses_existing_cors_policy(client):
    response = client.options('/v1/analyze', headers={
        'Origin': ORIGIN, 'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': f'content-type,{VERSION.lower()}',
    })
    assert response.status_code == 200
    assert response.headers['access-control-allow-origin'] == ORIGIN
    assert VERSION.lower() in response.headers['access-control-allow-headers']
    denied = client.options('/v1/analyze', headers={
        'Origin': 'https://unlisted.example', 'Access-Control-Request-Method': 'POST',
        'Access-Control-Request-Headers': VERSION.lower(),
    })
    assert denied.status_code == 400
    assert 'access-control-allow-origin' not in denied.headers


def test_exact_baseline_client_rejects_real_upgrade_responses_before_mapping(client):
    responses = [client.post('/v1/analyze', json={'url': url}, headers={'Origin': ORIGIN}) for url in URLS]
    script = (ROOT / 'tests/fixtures/baseline-client/check-rejection.cjs').read_text()
    result = subprocess.run(['node', '-e', script], cwd=ROOT / 'mobileshield-web',
                            input=json.dumps([{'status': r.status_code, 'body': r.json()} for r in responses]),
                            text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
    assert json.loads(result.stdout) == {
        'upgrade_rejections': 3, 'result_mappings': 0, 'json_reads': 0,
        'baseline_positive_controls': ['BENIGN', 'BENIGN'],
    }


def test_current_client_fails_closed_on_old_endpoint_404_and_accepts_new_server(client):
    response = client.post('/v1/analyze-message', json={'text': 'Hello, see you tomorrow.'},
                           headers={'Origin': ORIGIN})
    assert response.status_code == 200
    script = r'''
const assert = require('node:assert/strict');
const fs = require('node:fs');
const ts = require('typescript');
function load(path, dependencies = {}) {
  const compiled = ts.transpileModule(fs.readFileSync(path, 'utf8'), {compilerOptions: {
    module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2020,
  }}).outputText;
  const mod = {exports: {}};
  new Function('module', 'exports', 'require', compiled)(mod, mod.exports, name => {
    assert.ok(name in dependencies, 'Unexpected dependency');
    return dependencies[name];
  });
  return mod.exports;
}
const analysis = load('lib/analysis.ts');
const api = load('lib/api.ts', {'./analysis': analysis});
const currentResponse = JSON.parse(fs.readFileSync(0, 'utf8'));
(async () => {
  let fetches = 0;
  global.fetch = async (url, init) => {
    fetches++;
    assert.ok(url.endsWith('/v1/analyze-message'));
    assert.equal(init.headers['X-MobileShield-Response-Version'], undefined);
    // Controlled old-server missing-route response; no old server is started.
    return new Response('{"detail":"Not Found"}', {status: 404});
  };
  await assert.rejects(api.analyzeMessage({text: 'Hello', inspect_links: false}, new AbortController().signal),
    error => error instanceof analysis.AnalysisError && error.code === 'request_failed');
  global.fetch = async () => {
    fetches++;
    return new Response(JSON.stringify(currentResponse), {
      status: 200, headers: {'Content-Type': 'application/json'},
    });
  };
  const result = await api.analyzeMessage({text: 'Hello', inspect_links: false}, new AbortController().signal);
  assert.deepEqual(result, currentResponse);
  assert.equal(result.assessment, 'no_clear_signs');
  assert.equal(fetches, 2);
})().catch(error => { console.error(error); process.exitCode = 1; });
'''
    result = subprocess.run(['node', '-e', script], cwd=ROOT / 'mobileshield-web',
                            input=json.dumps(response.json()), text=True, capture_output=True)
    assert result.returncode == 0, result.stdout + result.stderr
