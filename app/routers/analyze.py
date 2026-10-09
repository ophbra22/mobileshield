"""Ephemeral scan endpoints; deliberately no database dependency."""
from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import Field

from app.analysis import AnalysisUnavailable, InvalidMessage, analyze_message, to_legacy_response
from app.detection.safe_transport import SafeTransport
from app.message_models import ContractModel, MessageRequest, MessageResponse

router = APIRouter()
_TRANSPORT = SafeTransport()


def get_scan_transport() -> SafeTransport:
    return _TRANSPORT


class AnalyzeRequest(ContractModel):
    url: str = Field(min_length=3, max_length=2048, pattern=r'^https?://.+')
    inspect_links: bool = False


def _analyze(payload, request, transport):
    try:
        return analyze_message(payload, request_id=request.state.request_id, transport=transport)
    except AnalysisUnavailable:
        raise HTTPException(503, detail='analysis_unavailable') from None
    except InvalidMessage:
        raise HTTPException(422, detail='invalid_message') from None


@router.post('/v1/analyze-message', response_model=MessageResponse)
def message(payload: MessageRequest, request: Request, transport: SafeTransport = Depends(get_scan_transport)):
    return _analyze(payload, request, transport)


@router.post('/v1/analyze')
def legacy(payload: AnalyzeRequest, request: Request, transport: SafeTransport = Depends(get_scan_transport)):
    # Old browser bundles mistake unfamiliar verdicts for benign. This is
    # response-contract negotiation, not authentication or an Origin trust rule.
    if 'origin' in request.headers and request.headers.getlist('x-mobileshield-response-version') != ['1']:
        raise HTTPException(409, detail='client_upgrade_required')
    result = _analyze(MessageRequest(text=payload.url, inspect_links=payload.inspect_links), request, transport)
    return to_legacy_response(result, payload.url)


@router.get('/v1/scans')
@router.get('/v1/scans/{scan_id}')
@router.get('/v1/scans/{scan_id}/report.pdf')
def retired_history():
    raise HTTPException(410, detail='scan_history_unavailable')
