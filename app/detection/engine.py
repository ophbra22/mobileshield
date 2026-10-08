from __future__ import annotations

import time
from urllib.parse import urlsplit

from sqlalchemy.orm import Session

from app.detection.brand_spoof_detector import analyze_brand_signals
from app.detection.certificate_analyzer import fetch_certificate
from app.detection.classifier import classify, classify_evidence
from app.detection.config import DEFAULT_CONFIG, DetectionConfig
from app.detection.content_analyzer import analyze_content
from app.detection.domain_analyzer import analyze_domain
from app.detection.models import DetectionResult, ScoreComponent, TechnicalDetails
from app.detection.redirect_analyzer import follow_redirects
from app.detection.risk_scorer import score_risk
from app.detection.server_analyzer import analyze_server
from app.detection.url_normalizer import normalize_url
from app.detection.explanation_builder import build_reasons
from app.reputation import BLOCKLISTED_DOMAINS, get_or_compute_domain_reputation
from app.brand import BRAND_ALLOWLIST_DOMAINS, BRAND_KEYWORDS, PROTECTED_BRANDS, is_official_domain
from app.detection.network_policy import canonical_target, DestinationBlocked
from app.detection.safe_transport import SafeTransport, UrlObservation
from app.message_models import LinkCandidate, LinkResult, LinkTechnical, Reason, REASON_PARAM_KEYS
from app.message_parser import parse_message


def run_detection(raw_url: str, db: Session, resolver=None, config: DetectionConfig = DEFAULT_CONFIG) -> DetectionResult:
    # Legacy callers also use the one guarded transport; no secondary requests.
    parsed = parse_message(raw_url)
    if len(parsed.links) != 1 or parsed.links[0].canonical_url is None:
        raise ValueError('invalid_link')
    candidate = parsed.links[0]
    initial_parts = normalize_url(candidate.canonical_url)
    # Keep the parser-authorized authority, including IPv6 brackets.
    initial_parts.normalized_url = candidate.canonical_url
    try:
        target = canonical_target(candidate.canonical_url)
    except DestinationBlocked:
        observation = UrlObservation(limitations=['destination_blocked'])
    else:
        inspector = resolver if callable(resolver) else SafeTransport().inspect
        observation = inspector(target.url, deadline=time.monotonic() + 20)
    redirect_result = follow_redirects(observation, initial_parts, config=config)
    final_parts = normalize_url(redirect_result.final_url)

    # Domain analysis on final destination
    domain_analysis = analyze_domain(final_parts, raw_url, config=config)

    # Reputation
    rep_cache, rep_signals, rep_score_hint, rep_reasons = get_or_compute_domain_reputation(db, final_parts.registrable_domain)
    reputation = rep_cache.reputation

    # TLS / certificate
    certificate = fetch_certificate(observation)

    # Server info
    server = analyze_server(redirect_result.dns_ip, redirect_result.dns_ip_version)

    # Content analysis (best-effort)
    content = analyze_content(observation)

    # Brand spoofing
    brand = analyze_brand_signals(final_parts, config=config)

    # Risk scoring
    score_result = score_risk(
        parts=final_parts,
        redirect=redirect_result,
        domain=domain_analysis,
        reputation=_to_reputation(rep_cache, rep_signals, rep_score_hint, rep_reasons),
        tls=certificate,
        content=content,
        brand=brand,
        server=server,
        config=config,
    )

    link_result = analyze_url_candidate(candidate, observation)
    # Preserve evidence from the initial URL and actual content even when a
    # trusted final root would otherwise prevent legacy scoring components.
    evidence_keys = {
        'brand_destination_mismatch': 'brand_impersonation', 'lookalike_host': 'lookalike',
        'credential_form': 'credential_form_untrusted', 'payment_form': 'payment_form',
        'certificate_mismatch': 'cert_mismatch',
    }
    existing_keys = {component.key for component in score_result.components}
    for reason in link_result.reasons:
        key = evidence_keys.get(reason.code)
        weight = config.weights.get(key) if key else None
        if weight and key not in existing_keys:
            score_result.add(ScoreComponent(key, weight.points, weight.level, weight.description))
            existing_keys.add(key)
    if score_result.strong:
        score_result.components = [c for c in score_result.components if c.points >= 0]
    score_result.total = max(0, min(sum(c.points for c in score_result.components), 100))
    status, confidence = classify(score_result, config=config)
    if link_result.assessment == 'phishing':
        status, confidence = 'phishing', 'high'
    elif status == 'legitimate' and link_result.assessment == 'suspicious':
        status, confidence = 'suspicious', 'medium'
    elif status == 'legitimate' and link_result.assessment == 'unknown':
        status, confidence = 'unknown', 'low'
    if link_result.inspection_status == 'blocked' and not link_result.reasons:
        status, confidence = 'unknown', 'low'
        score_result.total = 0

    reasons = build_reasons(score_result.components)

    technical_details = TechnicalDetails(
        submitted_url=raw_url,
        normalized_url=initial_parts.normalized_url,
        final_url=redirect_result.final_url,
        redirect_count=redirect_result.redirect_hops,
        ip_address=redirect_result.dns_ip,
        geo=server.geo,
        domain_age_days=rep_signals.get('domain_age_days'),
        first_seen=None,
        certificate_issuer=certificate.issuer,
        certificate_valid_from=certificate.valid_from,
        certificate_valid_to=certificate.valid_to,
        hostname_match=certificate.hostname_matches,
    )

    signals = {
        'url': {
            'submitted': raw_url,
            'normalized': initial_parts.normalized_url,
            'final': redirect_result.final_url,
            'hostname': final_parts.hostname,
            'registrable_domain': final_parts.registrable_domain,
            'tld': final_parts.tld,
        },
        'redirect_hops': redirect_result.redirect_hops,
        'redirect': {
            'hops': redirect_result.redirect_hops,
            'chain': [hop.__dict__ for hop in redirect_result.chain],
            'domain_changed': redirect_result.domain_changed,
            'used_shortener': redirect_result.used_shortener,
            'error': redirect_result.error,
            'final_status': redirect_result.final_status,
            'content_type': redirect_result.content_type,
        },
        'domain': domain_analysis.__dict__,
        'reputation': {
            'reputation': reputation,
            'score_hint': rep_score_hint,
            'signals': rep_signals,
            'reasons': rep_reasons,
        },
        'certificate': certificate.__dict__,
        'content': content.__dict__,
        'brand': brand.__dict__,
        'server': server.__dict__,
        'inspection_status': link_result.inspection_status,
        'limitations': link_result.limitations,
        'url_evidence': [reason.model_dump() for reason in link_result.reasons],
        'strong_signals': list(set(score_result.strong)),
        'medium_signals': list(set(score_result.medium)),
        'weak_signals': list(set(score_result.low)),
    }

    # Map to required structured output
    verdict = status
    risk_score = min(max(score_result.total, 0), 100)
    if verdict == 'phishing':
        risk_score = max(risk_score, config.thresholds.suspicious_max + 1)
    if verdict == 'legitimate':
        risk_score = min(risk_score, config.thresholds.legitimate_max)

    breakdown = [c.__dict__ for c in score_result.components]

    return DetectionResult(
        status=status,
        score=risk_score,
        risk_score=risk_score,
        confidence=confidence,
        reasons=reasons,
        breakdown=breakdown,
        technical_details=technical_details,
        signals=signals,
        normalized_url=initial_parts.normalized_url,
        domain=final_parts.registrable_domain,
        final_url=redirect_result.final_url,
        resolved_domain=final_parts.registrable_domain,
        redirect_hops=redirect_result.redirect_hops,
        verdict=verdict,
        risk_reasons=reasons,
        reputation=reputation,
        is_shortener=redirect_result.used_shortener,
    )


def _to_reputation(cache, signals, score_hint, reasons):
    from app.detection.models import ReputationAnalysis

    return ReputationAnalysis(
        reputation=cache.reputation if cache else 'unknown',
        score_hint=score_hint or 0,
        reasons=reasons or [],
        signals=signals or {},
        domain_age_days=signals.get('domain_age_days'),
        first_seen=None,
    )


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
        title = content.brand_claim or ''
        for brand in sorted(set(BRAND_KEYWORDS) | set(PROTECTED_BRANDS)):
            if brand not in title:
                continue
            official = BRAND_ALLOWLIST_DOMAINS.get(brand, set()) | {PROTECTED_BRANDS.get(brand, '')}
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
