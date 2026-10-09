from __future__ import annotations

from app.brand import (GENERIC_BRAND_TERMS, analyze_brand, detect_brand_impersonation,
                       detect_typosquat, is_official_domain, official_domains_for_brand)
from app.detection.config import DEFAULT_CONFIG
from app.detection.models import BrandAnalysis, URLParts


def analyze_brand_signals(parts: URLParts, config=DEFAULT_CONFIG) -> BrandAnalysis:
    hostname = parts.hostname
    registrable = parts.registrable_domain

    brand_keywords = [bk for bk in sorted(config.brand_keywords) if bk not in GENERIC_BRAND_TERMS and (bk in hostname or bk in parts.path.lower())]
    impersonation = detect_brand_impersonation(hostname, registrable)
    brand_in_subdomain = impersonation.get('is_brand_in_subdomain', False)

    lookalike = analyze_brand(registrable)
    typosquat_target, typosquat_distance, _ = detect_typosquat(registrable)
    unrelated_hits = []
    for keyword in brand_keywords:
        official_roots = official_domains_for_brand(keyword)
        official_roots |= {root for root in config.trusted_roots if keyword in root.split('.')[0]}
        if not any(root and is_official_domain(registrable, root) for root in official_roots):
            unrelated_hits.append(keyword)
    brand = lookalike.brand if lookalike else (unrelated_hits[0] if unrelated_hits else None)

    return BrandAnalysis(
        impersonates_brand=bool(impersonation.get('is_registered_domain_suspicious')) or bool(lookalike) or bool(unrelated_hits),
        brand=brand,
        lookalike_score=lookalike.score if lookalike else None,
        method=lookalike.method if lookalike else None,
        typosquat_target=typosquat_target,
        typosquat_distance=typosquat_distance,
        official_domain=is_official_domain(registrable),
        brand_keyword_hits=brand_keywords,
        brand_in_subdomain=brand_in_subdomain,
    )
