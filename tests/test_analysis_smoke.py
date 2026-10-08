from types import SimpleNamespace

from app.analysis import analyze_url
from app.detection.models import CertificateAnalysis, RedirectHop
from app.detection.safe_transport import UrlObservation


def _resolver(url, *, deadline):
    return UrlObservation(
        final_url=url, hops=[RedirectHop(url, 200, '1.1.1.1', 'ipv4')],
        tls=CertificateAnalysis(None, None, None, None, True, True),
        html='<html><body>Hello</body></html>', content_type='text/html',
        completed_checks=['tls', 'http', 'html'],
    )


def test_analyze_smoke():
    res = analyze_url('https://example.com', SimpleNamespace(), resolver=_resolver)
    assert res.normalized_url
    assert res.status == 'legitimate'
    assert res.reputation == 'unknown'
    assert res.signals['inspection_status'] == 'completed'
    assert res.signals['limitations'] == []
    assert res.signals.get('redirect') is not None
    assert res.breakdown is not None
