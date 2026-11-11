"""Bounded, stateless message-analysis contracts (request memory only)."""

from __future__ import annotations

import ipaddress
import unicodedata
from typing import Literal

import idna
from pydantic import BaseModel, ConfigDict, Field, StrictBool, field_validator, model_validator

from app.brand import KNOWN_BRAND_IDS as KNOWN_BRANDS

MAX_TEXT_CODEPOINTS = 10_000
MAX_LINKS = 10
MAX_REASONS = 32

Assessment = Literal['phishing', 'suspicious', 'no_clear_signs', 'unknown']
AnalysisStatus = Literal['complete', 'partial', 'unavailable']
ActionCode = Literal['avoid_interaction', 'verify_independently', 'do_not_share_secrets', 'consider_link_inspection', 'retry_later']
ReasonCode = Literal[
    'credential_request', 'payment_request', 'urgency', 'brand_destination_mismatch',
    'lookalike_host', 'suspicious_obfuscation', 'credential_form', 'payment_form',
    'local_blocklist_hit', 'certificate_mismatch', 'unsupported_text', 'invalid_link',
    'inspection_disabled', 'inspection_failed', 'destination_blocked', 'body_limit',
    'deadline_exceeded',
]

# Parameters are deliberately restricted to facts that can be safely localized.
# Never add arbitrary excerpts, exception text, paths, or secret-bearing URLs.
REASON_PARAM_KEYS: dict[str, frozenset[str]] = {
    code: frozenset() for code in ReasonCode.__args__
}
for _code in (
    'suspicious_obfuscation', 'credential_form', 'payment_form', 'local_blocklist_hit',
    'certificate_mismatch', 'invalid_link', 'destination_blocked',
):
    REASON_PARAM_KEYS[_code] = frozenset({'display_host'})
for _code in ('brand_destination_mismatch', 'lookalike_host'):
    REASON_PARAM_KEYS[_code] = frozenset({'display_host', 'expected_host', 'brand'})


def validate_message_text(text: str) -> str:
    """Reject rather than truncate; Python len counts Unicode code points."""
    if not isinstance(text, str) or not text.strip() or len(text) > MAX_TEXT_CODEPOINTS:
        raise ValueError('Text must contain 1 to 10000 Unicode code points and not be whitespace')
    return text


def _safe_host(value: str) -> bool:
    if any(unicodedata.category(c).startswith('C') or c.isspace() for c in value):
        return False
    # A zone identifier is not an IP literal and can contain arbitrary text.
    if '%' in value:
        return False
    try:
        return str(ipaddress.ip_address(value)) == value
    except ValueError:
        pass
    if any(c in value for c in '/:@?#%\\[]') or value != value.lower() or value.endswith('.'):
        return False
    try:
        idna.encode(value, uts46=False, std3_rules=True)
        return True
    except idna.IDNAError:
        return False


class ContractModel(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True)


class MessageRequest(ContractModel):
    text: str = Field(max_length=MAX_TEXT_CODEPOINTS)
    inspect_links: StrictBool = False

    _validate_text = field_validator('text')(validate_message_text)


class Reason(ContractModel):
    code: str
    strength: Literal['info', 'medium', 'strong']
    source: Literal['message', 'url', 'inspection']
    link_id: str | None = None
    params: dict[str, str] = Field(default_factory=dict, max_length=4)

    @model_validator(mode='after')
    def validate_safe_facts(self) -> Reason:
        allowed = REASON_PARAM_KEYS.get(self.code)
        if allowed is None or not self.params.keys() <= allowed:
            raise ValueError('Reason code or parameter keys are not registered')
        for key, value in self.params.items():
            if len(value) > 256:
                raise ValueError('Reason fact exceeds its code-point limit')
            if key == 'brand':
                if value not in KNOWN_BRANDS:
                    raise ValueError('Brand fact must be a known normalized identifier')
            elif not _safe_host(value):
                raise ValueError('Host fact must be a canonical hostname or IP literal')
        return self


class LinkCandidate(ContractModel):
    link_id: str
    raw: str
    canonical_url: str | None
    display_host: str | None
    parse_error: str | None


class ParsedMessage(ContractModel):
    text: str = Field(max_length=MAX_TEXT_CODEPOINTS)
    normalized_text: str
    links: list[LinkCandidate] = Field(max_length=MAX_LINKS)
    supported_text: bool

    _validate_text = field_validator('text')(validate_message_text)


class LinkTechnical(ContractModel):
    normalized_url: str | None = None
    final_url: str | None = None


class LinkResult(ContractModel):
    link_id: str
    assessment: Assessment
    inspection_status: Literal['not_requested', 'completed', 'blocked', 'failed', 'skipped']
    display_host: str | None = None
    reasons: list[Reason] = Field(default_factory=list, max_length=MAX_REASONS)
    limitations: list[ReasonCode] = Field(default_factory=list)
    technical: LinkTechnical | None = None


class AssessmentSummary(ContractModel):
    assessment: Assessment
    analysis_status: AnalysisStatus
    reasons: list[Reason] = Field(default_factory=list, max_length=MAX_REASONS)
    recommended_actions: list[ActionCode] = Field(default_factory=list)
    limitations: list[ReasonCode] = Field(default_factory=list)


class MessageResponse(AssessmentSummary):
    schema_version: Literal[1] = 1
    links: list[LinkResult] = Field(default_factory=list, max_length=MAX_LINKS)
    request_id: str
