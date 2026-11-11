from __future__ import annotations

from app.brand import analyze_brand, detect_brand_impersonation, impersonated_brands, path_impersonated_brands
from app.detection.models import BrandAnalysis, URLParts


def analyze_brand_signals(parts: URLParts) -> BrandAnalysis:
    """Hostname/path brand evidence from the shared brand registry."""
    hostname = parts.hostname
    impersonation = detect_brand_impersonation(hostname, parts.registrable_domain)
    impersonated = list(dict.fromkeys(impersonated_brands(hostname) + path_impersonated_brands(hostname, parts.path)))
    lookalike = analyze_brand(hostname)
    return BrandAnalysis(
        impersonates_brand=bool(impersonated or lookalike),
        brand=lookalike.brand if lookalike else (impersonated[0] if impersonated else None),
        lookalike_score=lookalike.score if lookalike else None,
        method=lookalike.method if lookalike else None,
        brand_keyword_hits=impersonation['brands_found'],
        brand_in_subdomain=impersonation['is_brand_in_subdomain'],
    )
