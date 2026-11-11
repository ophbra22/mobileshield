from __future__ import annotations

from urllib.parse import urlsplit

from app.brand import claimed_brands, is_official_domain, official_domains_for_brand
from app.detection.brand_spoof_detector import analyze_brand_signals
from app.detection.certificate_analyzer import fetch_certificate
from app.detection.classifier import classify_evidence
from app.detection.content_analyzer import analyze_content
from app.detection.domain_analyzer import analyze_domain
from app.detection.safe_transport import UrlObservation
from app.detection.url_normalizer import normalize_url
from app.message_models import REASON_PARAM_KEYS, LinkCandidate, LinkResult, LinkTechnical, Reason
from app.reputation import BLOCKLISTED_DOMAINS


def collect_url_evidence(candidate: LinkCandidate, observation: UrlObservation | None) -> list[Reason]:
    """Collect safe, positive facts only; an unavailable check is never negative proof."""
    reasons: list[Reason] = []
    seen: set[tuple[str, str]] = set()

    def add(code, strength, source, host=None):
        identity = (code, host or '')
        if identity in seen:
            return
        seen.add(identity)
        params = {'display_host': host} if host and len(host) <= 256 else {}
        reasons.append(Reason(code=code, strength=strength, source=source,
                              link_id=candidate.link_id, params=params))

    if candidate.parse_error or candidate.canonical_url is None:
        add('invalid_link', 'info', 'url')
        return reasons
    urls = [(candidate.canonical_url, 'url')]
    if observation:
        observed_urls = [hop.url for hop in observation.hops]
        if observation.final_url:
            observed_urls.append(observation.final_url)
        urls.extend((url, 'inspection') for url in dict.fromkeys(observed_urls)
                    if url != candidate.canonical_url)
    for url, source in urls:
        parts = normalize_url(url)
        brand = analyze_brand_signals(parts)
        domain = analyze_domain(parts, url)
        if brand.impersonates_brand:
            add('brand_destination_mismatch', 'strong', source, parts.hostname)
        if brand.lookalike_score:
            add('lookalike_host', 'strong', source, parts.hostname)
        if domain.obfuscated or domain.excessive_subdomains or domain.hyphen_count >= 3:
            add('suspicious_obfuscation', 'medium', source, parts.hostname)
        if parts.registrable_domain in BLOCKLISTED_DOMAINS:
            add('local_blocklist_hit', 'medium', source, parts.hostname)
    if observation:
        final = normalize_url(observation.final_url or candidate.canonical_url)
        content = analyze_content(observation)
        if content.credential_form:
            add('credential_form', 'strong', 'inspection', final.hostname)
        if content.payment_form:
            add('payment_form', 'strong', 'inspection', final.hostname)
        # A real page claim can reveal impersonation even on a neutral hostname.
        for brand in sorted(claimed_brands(content.brand_claim or '')):
            official = official_domains_for_brand(brand)
            if not any(root and is_official_domain(final.hostname, root) for root in official):
                add('brand_destination_mismatch', 'strong', 'inspection', final.hostname)
        tls = fetch_certificate(observation)
        if tls.hostname_matches is False or tls.valid_now is False or 'certificate_mismatch' in observation.limitations:
            # A failure may belong to a redirect target with no response yet.
            # final_url identifies the last received response, not that target.
            add('certificate_mismatch', 'strong', 'inspection')
    return reasons[:32]


def analyze_url_candidate(candidate: LinkCandidate, observation: UrlObservation | None) -> LinkResult:
    """Pure evidence and uncertainty projection; callers choose whether to inspect."""
    reasons = collect_url_evidence(candidate, observation)
    if candidate.parse_error or candidate.canonical_url is None:
        status, limitations = 'skipped', ['invalid_link']
    elif observation is None:
        status, limitations = 'not_requested', ['inspection_disabled']
    else:
        limitations = list(dict.fromkeys(
            code if code in REASON_PARAM_KEYS else 'inspection_failed' for code in observation.limitations
        ))
        complete = ('http' in observation.completed_checks and 'html' in observation.completed_checks
                    and bool(observation.html) and analyze_content(observation).fetched)
        final_scheme = urlsplit(observation.final_url or candidate.canonical_url).scheme
        tls = fetch_certificate(observation)
        if final_scheme == 'https':
            complete = complete and tls.valid_now is True and tls.hostname_matches is True
        if not complete and not limitations:
            limitations.append('inspection_failed')
        status = ('blocked' if 'destination_blocked' in limitations else
                  'failed' if limitations else 'completed')
    assessment = classify_evidence(reasons, inspection_complete=status == 'completed')
    return LinkResult(
        link_id=candidate.link_id, assessment=assessment, inspection_status=status,
        display_host=candidate.display_host, reasons=reasons, limitations=limitations,
        technical=LinkTechnical(normalized_url=candidate.canonical_url,
                                final_url=observation.final_url if observation else None),
    )
