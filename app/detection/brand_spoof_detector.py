from __future__ import annotations

from app.brand import (analyze_brand, detect_brand_impersonation, detect_typosquat, impersonated_brands,
                       is_official_domain, path_impersonated_brands)
from app.detection.config import DEFAULT_CONFIG
from app.detection.models import BrandAnalysis, URLParts


def analyze_brand_signals(parts: URLParts, config=DEFAULT_CONFIG) -> BrandAnalysis:
    """Hostname/path brand evidence from the shared brand registry."""
    hostname = parts.hostname
    registrable = parts.registrable_domain

    impersonation = detect_brand_impersonation(hostname, registrable)
    impersonated = list(dict.fromkeys(impersonated_brands(hostname) + path_impersonated_brands(hostname, parts.path)))
    lookalike = analyze_brand(hostname)
    typosquat_target, typosquat_distance, _ = detect_typosquat(registrable)

    return BrandAnalysis(
        impersonates_brand=bool(impersonated or lookalike),
        brand=lookalike.brand if lookalike else (impersonated[0] if impersonated else None),
        lookalike_score=lookalike.score if lookalike else None,
        method=lookalike.method if lookalike else None,
        typosquat_target=typosquat_target,
        typosquat_distance=typosquat_distance,
        official_domain=is_official_domain(registrable),
        brand_keyword_hits=impersonation['brands_found'],
        brand_in_subdomain=impersonation['is_brand_in_subdomain'],
    )
