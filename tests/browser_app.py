"""Loopback-only synthetic browser fixture; never shipped in the production image.

Run from repository root with the documented fixture-only environment. The app
is the production app, with ONLY database initialization and scan transport
substituted. HTTP destinations are never contacted, including unknown hosts.
"""
import time
from urllib.parse import urlsplit

import app.main as main
from app.detection.models import CertificateAnalysis, RedirectHop
from app.detection.safe_transport import InspectionBusy, UrlObservation
from app.routers.analyze import get_scan_transport


class FixtureTransport:
    def inspect(self, url, *, deadline):
        host = urlsplit(url).hostname
        if host == 'slow.example':
            time.sleep(min(4, max(0, deadline - time.monotonic())))
        if host == 'busy.example':
            raise InspectionBusy()
        if host == 'failed.example':
            return UrlObservation(limitations=['inspection_failed'])
        if host == 'deadline.example':
            return UrlObservation(limitations=['deadline_exceeded'])
        if host not in {'example.com', 'example.org', 'slow.example', 'paypal-login.attacker.example'}:
            return UrlObservation(limitations=['inspection_failed'])
        html = '<html><body>Ordinary synthetic page</body></html>'
        if host == 'paypal-login.attacker.example':
            html = '<html><body><form><input type="password"></form></body></html>'
        return UrlObservation(
            final_url=url, html=html, content_type='text/html',
            hops=[RedirectHop(url, 200, '1.1.1.1', 'ipv4')],
            tls=CertificateAnalysis('Synthetic fixture', None, '2026', '2027', True, True),
            completed_checks=['http', 'html', 'tls'],
        )


main.initialize_database = lambda: None
app = main.app
app.dependency_overrides[get_scan_transport] = FixtureTransport
