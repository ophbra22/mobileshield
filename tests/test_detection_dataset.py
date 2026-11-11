import pytest

from app.analysis import analyze_message
from app.detection.models import CertificateAnalysis, RedirectHop
from app.detection.safe_transport import UrlObservation
from app.message_models import MessageRequest


def _resolver_for(final_url: str | None = None):
    def _inner(url, *, deadline):
        final = final_url or url
        hops = [RedirectHop(url, 302 if final_url else 200, '1.1.1.1', 'ipv4')]
        if final_url:
            hops.append(RedirectHop(final, 200, '1.1.1.1', 'ipv4'))
        fields = ''
        if any(token in final.lower() for token in ['login', 'verify', 'reset', 'password']):
            fields += '<input type="password" name="password">'
        if 'payment' in final.lower():
            fields += '<input name="card_number">'
        html = '<html><body>' + ('<form>' + fields + '</form>' if fields else 'Hello') + '</body></html>'
        return UrlObservation(
            final_url=final, hops=hops,
            tls=CertificateAnalysis('Test CA', None, '2024', '2026', True, True) if final.startswith('https:') else None,
            html=html, content_type='text/html',
            completed_checks=['http', 'html'] + (['tls'] if final.startswith('https:') else []),
        )
    return _inner


DATASET = [
    # Legitimate
    ('https://google.com', 'legitimate', _resolver_for()),
    ('https://accounts.google.com', 'legitimate', _resolver_for()),
    ('https://apple.com', 'legitimate', _resolver_for()),
    ('https://support.microsoft.com', 'legitimate', _resolver_for()),
    ('https://facebook.com', 'legitimate', _resolver_for()),
    ('https://www.binance.com', 'legitimate', _resolver_for()),
    # Recognized brand aliases and banking roots must retain their original identity.
    ('https://outlook.com', 'legitimate', _resolver_for()),
    ('https://office.com', 'legitimate', _resolver_for()),
    ('https://icloud.com', 'legitimate', _resolver_for()),
    ('https://bankhapoalim.co.il', 'legitimate', _resolver_for()),
    ('https://www.mizrahi-tefahot.co.il', 'legitimate', _resolver_for()),
    ('https://www.fibi.co.il', 'legitimate', _resolver_for()),
    ('https://discountbank.co.il', 'legitimate', _resolver_for()),
    # Marketing tracker redirect -> should stay legitimate
    ('https://w.ems.to/iRIA1SC', 'legitimate', _resolver_for(final_url='https://www.maniajeans.co.il')),
    # A shortener is judged by where it lands, not by being a shortener.
    ('http://t.ly/abc', 'legitimate', _resolver_for(final_url='https://apple.com')),
    # No invented brand match from an unfamiliar name.
    ('https://tracking.newbrand.click/u/123', 'legitimate', _resolver_for()),
    ('https://neutral-redirect.xyz/login', 'suspicious', _resolver_for()),
    # Phishing
    ('https://goog1e-login-check.com', 'phishing', _resolver_for()),
    ('https://paypa1-security-login.net', 'phishing', _resolver_for()),
    ('http://192.168.1.10/login', 'unknown', _resolver_for()),
    ('https://amazon.com.security-check-user-login.co', 'phishing', _resolver_for()),
    # A credential form plus lexical hints lacks independent strong evidence.
    ('https://verify-account-alert.example.xyz/login', 'suspicious', _resolver_for()),
    ('https://microsoft-password-reset-confirm.biz', 'phishing', _resolver_for()),
]


ASSESSMENT = {'legitimate': 'no_clear_signs', 'suspicious': 'suspicious', 'phishing': 'phishing', 'unknown': 'unknown'}


class _Transport:
    """Serves synthetic observations; private destinations never reach it."""

    def __init__(self, resolver):
        self._resolver = resolver
        self.calls = []

    def inspect(self, url, *, deadline):
        self.calls.append(url)
        return self._resolver(url, deadline=deadline)


@pytest.mark.parametrize('url,expected,resolver', DATASET)
def test_detection_dataset(url, expected, resolver):
    """Labelled URLs through the production message pipeline with link inspection."""
    transport = _Transport(resolver)
    result = analyze_message(MessageRequest(text=url, inspect_links=True), request_id='dataset', transport=transport)
    assert result.assessment == ASSESSMENT[expected]
    if expected in {'suspicious', 'phishing'}:
        assert result.reasons, f'Expected reasons for {url}'
    if expected == 'legitimate':
        assert result.analysis_status == 'complete'
        assert result.reasons == []
    if expected == 'unknown':
        link = result.links[0]
        assert link.inspection_status == 'blocked'
        assert link.limitations == ['destination_blocked']
        assert transport.calls == []
