import pytest

from app.analysis import analyze_url
from app.detection.models import CertificateAnalysis, RedirectHop
from app.detection.safe_transport import UrlObservation


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
    # Marketing tracker redirect -> should stay legitimate
    ('https://w.ems.to/iRIA1SC', 'legitimate', _resolver_for(final_url='https://www.maniajeans.co.il')),
    # Suspicious
    ('http://t.ly/abc', 'suspicious', _resolver_for(final_url='https://apple.com')),
    # No invented brand match or RDAP age; the remaining 22 points are below the warning threshold.
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


class DummySession:
    """Minimal stub for SQLAlchemy session in tests."""

    def __getattr__(self, name):
        def _noop(*args, **kwargs):
            return None

        return _noop


@pytest.mark.parametrize('url,expected,resolver', DATASET)
def test_detection_dataset(url, expected, resolver):
    res = analyze_url(url, DummySession(), resolver=resolver)
    assert res.status == expected
    assert 0 <= res.risk_score <= 100
    if expected not in {'legitimate', 'unknown'}:
        assert res.reasons, f"Expected reasons for {url}"
        assert res.confidence in {'medium', 'high', 'low'}
    if expected == 'phishing':
        assert res.risk_score >= 60
    if expected == 'legitimate':
        assert res.risk_score <= 25

    if expected == 'unknown':
        assert res.signals['inspection_status'] == 'blocked'
        assert res.signals['limitations'] == ['destination_blocked']
        assert res.signals['content']['credential_form'] is None
        assert res.risk_score == 0
