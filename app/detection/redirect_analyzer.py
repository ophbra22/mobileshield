"""Pure compatibility view of the guarded transport's received response chain."""
from __future__ import annotations
from typing import TYPE_CHECKING
from urllib.parse import urlsplit
from app.detection.config import DEFAULT_CONFIG
from app.detection.models import RedirectResult, URLParts
from app.detection.url_normalizer import extract_domain

if TYPE_CHECKING:
    from app.detection.safe_transport import UrlObservation


def follow_redirects(observation: UrlObservation, parts: URLParts, config=DEFAULT_CONFIG) -> RedirectResult:
    final_url = observation.final_url or parts.normalized_url
    final_domain = extract_domain(urlsplit(final_url).hostname or '')
    last = observation.hops[-1] if observation.hops else None
    limitation = observation.limitations[0] if observation.limitations else None
    return RedirectResult(
        final_url=final_url, final_status=last.status if last else None,
        redirect_hops=max(0, len(observation.hops) - 1), chain=list(observation.hops),
        domain_changed=parts.registrable_domain != final_domain,
        used_shortener=parts.registrable_domain in config.shortener_domains,
        error=limitation, ssrf_blocked='destination_blocked' in observation.limitations,
        ssrf_reason='destination_blocked' if 'destination_blocked' in observation.limitations else None,
        content_type=observation.content_type, dns_ip=last.ip if last else None,
        dns_ip_version=last.ip_version if last else None,
    )
