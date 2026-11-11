from __future__ import annotations

import time

from app.detection.engine import analyze_url_candidate
from app.detection.message_analyzer import assess_message
from app.detection.network_policy import DestinationBlocked, canonical_target
from app.detection.safe_transport import MAX_INSPECTION_SECONDS, InspectionBusy, SafeTransport, UrlObservation
from app.message_models import MessageRequest, MessageResponse
from app.message_parser import parse_message


class InvalidMessage(ValueError):
    """Safe boundary marker; never expose parser exception text."""


class AnalysisUnavailable(Exception):
    """Inspection could not begin and no observed warning is available."""


def analyze_message(payload: MessageRequest, *, request_id: str, transport: SafeTransport) -> MessageResponse:
    try:
        parsed = parse_message(payload.text)
    except ValueError:
        raise InvalidMessage('invalid_message') from None
    deadline = time.monotonic() + MAX_INSPECTION_SECONDS
    links = []
    capacity_exhausted = False
    static_links = []
    for candidate in parsed.links:
        observation = None
        if candidate.canonical_url:
            try:
                canonical_target(candidate.canonical_url)  # pure, never DNS
            except DestinationBlocked:
                observation = UrlObservation(limitations=['destination_blocked'])
        static_links.append(analyze_url_candidate(candidate, observation))
    static_warning = assess_message(parsed, static_links).assessment in ('phishing', 'suspicious')
    for candidate, static_result in zip(parsed.links, static_links):
        if not payload.inspect_links or static_result.inspection_status in ('blocked', 'skipped'):
            links.append(static_result)
            continue
        observation = None
        skipped = False
        if payload.inspect_links and candidate.canonical_url:
            if capacity_exhausted:
                observation = UrlObservation(limitations=['inspection_failed'])
                skipped = True
            elif time.monotonic() >= deadline:
                observation = UrlObservation(limitations=['deadline_exceeded'])
                skipped = True
            else:
                try:
                    observation = transport.inspect(candidate.canonical_url, deadline=deadline)
                    if not isinstance(observation, UrlObservation):
                        observation = UrlObservation(limitations=['inspection_failed'])
                except InspectionBusy:
                    if not links and not static_warning:
                        raise AnalysisUnavailable() from None
                    capacity_exhausted = True
                    observation = UrlObservation(limitations=['inspection_failed'])
                    skipped = True
                except Exception:
                    observation = UrlObservation(limitations=['inspection_failed'])
        result = analyze_url_candidate(candidate, observation)
        if skipped:
            result.inspection_status = 'skipped'
        links.append(result)
    summary = assess_message(parsed, links)
    return MessageResponse(**summary.model_dump(), links=links, request_id=request_id)


def to_legacy_response(result: MessageResponse, raw_url: str) -> dict:
    link = result.links[0] if result.links else None
    technical = link.technical if link else None
    legacy_assessment = ('legitimate' if result.assessment == 'no_clear_signs'
                         and result.analysis_status == 'complete' else result.assessment)
    return {
        **result.model_dump(), 'scan_id': None,
        'status': legacy_assessment, 'verdict': legacy_assessment,
        'normalized_url': technical.normalized_url if technical else None,
        'final_url': technical.final_url if technical else None,
        'resolved_url': technical.final_url if technical else None,
        'domain': link.display_host if link else None,
        'input_domain': link.display_host if link else None,
        'resolved_domain': link.display_host if link else None,
        'risk_reasons': [reason.code for reason in result.reasons],
    }
