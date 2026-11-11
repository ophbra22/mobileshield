"""End-to-end regression cases through the real ASGI app; all destinations and bodies are synthetic."""
import asyncio
import json
from types import SimpleNamespace

import pytest

from app.detection.content_analyzer import analyze_content
from app.detection.safe_transport import UrlObservation
from tests.test_safe_transport import Harness, Response
from tests.test_scan_integration import frontend_roundtrip


def deep_result(client, harness, url='https://example.com/'):
    from app.main import app
    from app.routers.analyze import get_scan_transport
    app.dependency_overrides[get_scan_transport] = lambda: harness.client
    response = client.post('/v1/analyze-message', json={
        'text': f'Read {url}', 'inspect_links': True})
    assert response.status_code == 200
    assert response.headers['cache-control'] == 'no-store'
    result = response.json()
    frontend_roundtrip([result])
    return result


@pytest.mark.parametrize('text,warning', [
    ('שלח לי שם וסיסמה', True),
    ('שלח לי שם והסיסמה', True),
    ('שלח לי את הסיסמה', True),
    ('שתפו שם וסיסמאות', True),
    ('מסרו שם וקודי אימות', True),
    ('שלחו שם וקוד חד פעמי', True),
    ('אל תשלח לי שם וסיסמה', False),
    ('אין לשלוח שם והסיסמה', False),
    ('לא למסור שם וקודי אימות', False),
    ('אל תשתפו שם וסיסמאות', False),
    ('אל תשלח שם וסיסמה אבל מסור שם וקוד אימות', True),
    ('שלח לי שם וסיסמהבדיקה', False),
    ('שלח לי שם טסיסמה', False),
    ('Send me your passwords now.', True),
    ('Share your passcodes and verification codes.', True),
    ('Do not send your passwords.', False),
    ('Never share your passcodes or verification codes.', False),
    ('שלחו לי את הסיסמה עכשיו', True),
    ('נא לשלוח לי את הסיסמה עכשיו', True),
    ('שתפו את הסיסמאות שלכם', True),
    ('יש למסור את קודי האימות', True),
    ('אל תשלחו לי את הסיסמה שלכם', False),
    ('אין לשלוח את הסיסמה', False),
    ('לא למסור קודי אימות', False),
    ('אל תשתפו את הסיסמאות שלכם', False),
    ('אל תשלחו את הסיסמה אבל מסרו לי את קוד האימות', True),
])
def test_common_secret_morphology_through_client(client, text, warning):
    response = client.post('/v1/analyze-message', json={'text': text})
    result = response.json()
    assert result['assessment'] == ('suspicious' if warning else 'no_clear_signs')
    assert result['analysis_status'] == 'complete'
    assert ('credential_request' in {r['code'] for r in result['reasons']}) is warning
    client.transport_spy.inspect.assert_not_called()
    frontend_roundtrip([result])


@pytest.mark.parametrize('status', [200, 201, 403, 404, 429, 500, 503])
@pytest.mark.parametrize('warning', [False, True])
def test_http_status_keeps_evidence_without_claiming_error_body_complete(client, status, warning):
    body = b'<input type="password">' if warning else b'<html>Hello</html>'
    harness = Harness([Response(status=status, body=body)])
    result = deep_result(client, harness)
    success = 200 <= status < 300
    assert result['assessment'] == ('suspicious' if warning else 'no_clear_signs' if success else 'unknown')
    assert result['analysis_status'] == ('complete' if success else 'partial')
    assert result['links'][0]['inspection_status'] == ('completed' if success else 'failed')
    assert ('inspection_failed' in result['limitations']) is not success
    assert ('credential_form' in {r['code'] for r in result['reasons']}) is warning
    assert all(c.closed and c.response.closed for c in harness.connections)


@pytest.mark.parametrize('html,code', [
    ('<input type="password"><button>Sign in</button>', 'credential_form'),
    ('<input autocomplete="one-time-code">', 'credential_form'),
    ('<input type="text" autocomplete="cc-number"><button>Pay</button>', 'payment_form'),
    ('<input name="cardnumber">', 'payment_form'),
    ('<input type="email" name="email"><input name="search">', None),
    ('<input type="hidden" name="password"><input type="hidden" name="card">', None),
])
def test_standalone_fields_are_observed_independently_of_forms(client, html, code):
    result = deep_result(client, Harness([Response(body=html.encode())]))
    assert result['assessment'] == ('suspicious' if code else 'no_clear_signs')
    assert {r['code'] for r in result['reasons']} == ({code} if code else set())
    observation = UrlObservation(html=html, completed_checks=['html'])
    assert analyze_content(observation).has_form is False


@pytest.mark.parametrize('failure', ['timeout', 'error', 'budget'])
@pytest.mark.parametrize('warning', [False, True])
def test_partial_body_survives_late_read_failure(client, failure, warning):
    clock = [0.0]
    prefix = (b'<title>PayPal sign in</title><form><input type="password"></form>'
              if warning else b'<html>Hello</html>')
    class PartialResponse(Response):
        def read1(self, size):
            if not self.retained:
                self.retained += len(prefix)
                return prefix
            if failure == 'budget':
                clock[0] = 21
                return b'last chunk'
            if failure == 'timeout':
                raise TimeoutError('PRIVATE_SENTINEL')
            raise OSError('PRIVATE_SENTINEL')
    harness = Harness([PartialResponse()], clock=lambda: clock[0])
    observations = []
    inspect = harness.client.inspect
    def capture(*args, **kwargs):
        observation = inspect(*args, **kwargs)
        observations.append(observation)
        return observation
    harness.client.inspect = capture
    result = deep_result(client, harness)
    assert observations[0].html.startswith(prefix.decode())
    assert len(observations[0].html.encode()) <= 256 * 1024
    assert 'html' not in observations[0].completed_checks
    content = analyze_content(observations[0])
    assert content.fetched is False
    assert content.credential_form is (True if warning else None)
    assert result['assessment'] == ('phishing' if warning else 'unknown')
    assert result['analysis_status'] == 'partial'
    assert result['links'][0]['inspection_status'] == 'failed'
    assert ('deadline_exceeded' if failure != 'error' else 'inspection_failed') in result['limitations']
    assert {r['code'] for r in result['reasons']} == (
        {'credential_form', 'brand_destination_mismatch'} if warning else set())
    assert 'PRIVATE_SENTINEL' not in json.dumps(result)
    assert len(harness.connection_attempts) == 1
    assert all(c.closed and c.response.closed for c in harness.connections)
    assert Harness().inspect().html  # The shared guard was released.


@pytest.mark.parametrize('url', [
    'https://example.com../private', 'https://example.com:/private',
    'https://example.com..:443/private', 'https://[2606:4700:4700::1111]junk/private',
])
def test_raw_malformed_authority_never_reaches_transport(client, url):
    harness = Harness()
    result = deep_result(client, harness, url)
    assert result['assessment'] == 'unknown'
    assert result['analysis_status'] == 'partial'
    assert result['links'][0]['inspection_status'] == 'skipped'
    assert result['links'][0]['limitations'] == ['invalid_link']
    assert harness.resolved == harness.connection_attempts == []


@pytest.mark.parametrize('url', [
    'https://example.com./private', 'https://example.com:443/private',
    'http://example.com:80/private', 'https://דוגמה.com/private',
    '(https://example.com/private).',
])
def test_valid_authority_and_prose_punctuation_still_inspected(client, url):
    harness = Harness()
    result = deep_result(client, harness, url)
    assert result['assessment'] == 'no_clear_signs'
    assert result['analysis_status'] == 'complete'
    assert len(harness.connection_attempts) == 1


@pytest.mark.parametrize('dribble', [False, True])
def test_body_deadline_expires_all_work_slots_and_is_private(monkeypatch, caplog, dribble):
    import app.scan_limits as limits
    # Short injected test budget; production remains a hard ten seconds.
    monkeypatch.setattr(limits, 'MAX_BODY_READ_SECONDS', .04, raising=False)
    admission = limits.RequestWorkAdmission()
    state = SimpleNamespace(scan_limiter=limits.ScanRateLimiter(100), scan_work=admission)
    entered = 0
    ready = asyncio.Event()
    responses = []
    async def downstream(scope, receive, send):
        assert (await receive())['body'] == b'{}'
        await send({'type': 'http.response.start', 'status': 200, 'headers': []})
        await send({'type': 'http.response.body', 'body': b'{}'})
    middleware = limits.PrivateRequestMiddleware(downstream, cors_origins=['https://ui.example'])
    def scope():
        return {'type': 'http', 'method': 'POST', 'path': '/unmatched/PRIVATE_SENTINEL',
                'headers': [(b'origin', b'https://ui.example'), (b'x-request-id', b'PRIVATE_SENTINEL')],
                'app': SimpleNamespace(state=state), 'client': ('synthetic', 123)}
    async def receive():
        nonlocal entered
        entered += 1
        if entered >= 32:
            ready.set()
        if dribble:
            await asyncio.sleep(.005)
            return {'type': 'http.request', 'body': b'PRIVATE_SENTINEL', 'more_body': True}
        await asyncio.Event().wait()
    async def send(message):
        responses.append(message)
    async def scenario():
        tasks = [asyncio.create_task(middleware(scope(), receive, send)) for _ in range(32)]
        try:
            await asyncio.wait_for(ready.wait(), .5)
            assert admission._active == 32
            await middleware(scope(), receive, send)
            assert responses[0]['status'] == 503
            responses.clear()
            await asyncio.wait_for(asyncio.gather(*tasks), .5)
            starts = [m for m in responses if m['type'] == 'http.response.start']
            bodies = [json.loads(m['body']) for m in responses if m['type'] == 'http.response.body']
            assert len(starts) == len(bodies) == 32
            assert all(m['status'] == 408 for m in starts)
            for start, body in zip(starts, bodies):
                headers = dict(start['headers'])
                assert headers[b'cache-control'] == b'no-store'
                assert headers[b'access-control-allow-origin'] == b'https://ui.example'
                assert body == {'detail': 'request_timeout', 'request_id': headers[b'x-request-id'].decode()}
            assert 'PRIVATE_SENTINEL' not in repr(responses) + caplog.text
            assert admission._active == 0
            async def complete():
                return {'type': 'http.request', 'body': b'{}'}
            responses.clear()
            await middleware(scope(), complete, send)
            assert responses[0]['status'] == 200
            assert admission._active == 0
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
    asyncio.run(scenario())


@pytest.mark.parametrize('assessment,status,expected', [
    ('no_clear_signs', 'complete', 'legitimate'),
    ('unknown', 'partial', 'unknown'), ('unknown', 'unavailable', 'unknown'),
    ('suspicious', 'complete', 'suspicious'), ('phishing', 'partial', 'phishing'),
])
def test_legacy_adapter_keeps_documented_alias_and_canonical_assessment(client, monkeypatch, assessment, status, expected):
    import app.routers.analyze as router
    from app.db.deps import get_db
    from app.main import app
    from app.message_models import MessageResponse
    app.dependency_overrides[get_db] = lambda: pytest.fail('Legacy scan accessed database')
    monkeypatch.setattr(router, 'analyze_message', lambda *a, **k: MessageResponse(
        assessment=assessment, analysis_status=status, request_id=k['request_id']))
    response = client.post('/v1/analyze', json={'url': 'https://example.com'})
    assert response.status_code == 200
    result = response.json()
    assert result['status'] == result['verdict'] == expected
    assert result['assessment'] == assessment
    assert result['analysis_status'] == status
    assert result['scan_id'] is None
    assert response.headers['cache-control'] == 'no-store'


def test_redirect_through_blocklisted_hop_keeps_its_evidence():
    from app.detection.engine import analyze_url_candidate
    from app.detection.models import RedirectHop
    from tests.test_url_evidence import candidate, observed
    observation = observed('https://google.com/', hops=[
        RedirectHop('https://evil.com/', 302, '8.8.8.8', 'ipv4'),
        RedirectHop('https://google.com/', 200, '8.8.8.8', 'ipv4'),
    ])
    result = analyze_url_candidate(candidate('https://evil.com/'), observation)
    assert result.assessment == 'suspicious'
    assert 'local_blocklist_hit' in {reason.code for reason in result.reasons}


def test_successful_real_legacy_inspection_maps_only_legacy_fields(client):
    from app.main import app
    from app.routers.analyze import get_scan_transport
    harness = Harness()
    app.dependency_overrides[get_scan_transport] = lambda: harness.client
    response = client.post('/v1/analyze', json={'url': 'https://example.com', 'inspect_links': True})
    assert response.status_code == 200
    result = response.json()
    assert result['assessment'] == 'no_clear_signs'
    assert result['analysis_status'] == 'complete'
    assert result['status'] == result['verdict'] == 'legitimate'
    assert result['scan_id'] is None
    assert response.headers['cache-control'] == 'no-store'
