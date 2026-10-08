"""Pure contextual message evidence and risk-first coverage aggregation."""
from __future__ import annotations

import re
import unicodedata

from app.brand import BRAND_KEYWORDS, PROTECTED_BRANDS, is_official_domain, official_domains_for_brand
from app.message_models import AssessmentSummary, LinkResult, ParsedMessage, Reason, MAX_REASONS

_REQUEST = re.compile(r"\b(?:send|share|give|enter|provide|confirm|submit|reply|pay|transfer|needs?)\b|(?<!\w)(?:שלח|שלחי|שתף|שתפי|מסור|מסרי|הזן|הזיני|שלמי|שלם|העבר|העבירי|אשר|אשרי|צריך|צריכה)(?!\w)", re.I)
_SECRET = re.compile(r'\b(?:otp|password|passcode|pin|verification code|security code)\b|(?:סיסמ[אה]|קוד (?:ה)?אימות|קוד חד פעמי)', re.I)
_PAYMENT = re.compile(r'\b(?:payment|money|fee|bank details|card details|credit card|card number|cvv)\b|(?:תשלום|כסף|פרטי אשראי|פרטי כרטיס|דמי משלוח|כרטיס האשראי)', re.I)
_NEGATION = re.compile(r"\b(?:do not|don't|never|must not|should not|shouldn't|not to)\b|(?:אל ת|לא ל|אין ל)", re.I)
_URGENCY = re.compile(r'\b(?:now|immediately|urgent(?:ly)?|within \d+ (?:minutes|hours))\b|(?:עכשיו|מיד|דחוף|בדחיפות)', re.I)
_THREAT = re.compile(r'\b(?:account.{0,30}(?:suspend|close|block)|suspended|locked out)\b|(?:החשבון.{0,25}(?:ייסגר|יחסם|ייחסם))', re.I)
_LOGIN = re.compile(r'\b(?:log[ -]?in|sign[ -]?in)\b|(?:היכנס|כניסה)', re.I)


def _prose(parsed: ParsedMessage) -> str:
    text = parsed.text
    for candidate in parsed.links:
        text = text.replace(candidate.raw, ' ')
    return unicodedata.normalize('NFKC', ''.join(
        c for c in text if not unicodedata.category(c).startswith('C') or c.isspace()
    ))


def text_evidence(parsed: ParsedMessage) -> list[Reason]:
    prose = _prose(parsed)
    reasons: list[Reason] = []
    codes: set[str] = set()
    # Negation is clause-local: safety advice cannot suppress a later request.
    for clause in re.split(r'[.!?;\n]|\bbut\b|אבל', prose, flags=re.I):
        if _NEGATION.search(clause) or not _REQUEST.search(clause):
            continue
        if _SECRET.search(clause):
            codes.add('credential_request')
        if _PAYMENT.search(clause):
            codes.add('payment_request')
    if _THREAT.search(prose) and _LOGIN.search(prose) and not _NEGATION.search(prose):
        codes.add('credential_request')
    for link in parsed.links:
        if any(c in link.raw for c in '\u202a\u202b\u202d\u202e\u2066\u2067\u2068') and _LOGIN.search(prose):
            reasons.append(Reason(code='suspicious_obfuscation', strength='medium', source='message', link_id=link.link_id))
    for code in sorted(codes):
        reasons.append(Reason(code=code, strength='strong', source='message'))
    if codes and (_URGENCY.search(prose) or _THREAT.search(prose)):
        reasons.append(Reason(code='urgency', strength='strong' if _THREAT.search(prose) else 'medium', source='message'))
    # Compare explicit named claims using the same brand-family roots as URL
    # evidence. Generic bank vocabulary and brand words inside URLs are not claims.
    for brand in sorted(set(BRAND_KEYWORDS) | set(PROTECTED_BRANDS)):
        roots = official_domains_for_brand(brand)
        if not roots or not re.search(r'(?<!\w)' + re.escape(brand) + r'(?!\w)', prose, re.I):
            continue
        for link in parsed.links:
            if link.display_host and link.canonical_url and not any(
                is_official_domain(link.display_host, root) for root in roots
            ):
                reasons.append(Reason(code='brand_destination_mismatch', strength='strong', source='message',
                                      link_id=link.link_id, params={'brand': brand}))
    return reasons[:MAX_REASONS]


def assess_message(parsed: ParsedMessage, links: list[LinkResult]) -> AssessmentSummary:
    message_reasons = text_evidence(parsed)
    all_reasons = message_reasons + [reason for link in links for reason in link.reasons]
    # Retain highest-risk explanations first if the message reaches the contract cap.
    order = {'strong': 0, 'medium': 1, 'info': 2}
    reasons = sorted(all_reasons, key=lambda reason: order[reason.strength])[:MAX_REASONS]
    message_codes = {reason.code for reason in message_reasons}
    warning = any(reason.strength in ('strong', 'medium') for reason in all_reasons)
    dangerous = any(link.assessment == 'phishing' for link in links)
    solicits = bool(message_codes & {'credential_request', 'payment_request'})
    # Urgency alone adds context, but a request plus an independent destination
    # warning (or an explicit threat tied to secret/payment solicitation) is
    # needed for phishing. Generic login under pressure remains suspicious.
    direct_solicitation = any(_REQUEST.search(clause) and (_SECRET.search(clause) or _PAYMENT.search(clause))
                              and not _NEGATION.search(clause)
                              for clause in re.split(r'[.!?;\n]|\bbut\b|אבל', _prose(parsed), flags=re.I))
    contextual_risk = solicits and direct_solicitation and any(
        reason.code not in {'credential_request', 'payment_request'}
        and (reason.strength == 'strong' or (reason.source != 'message' and reason.strength == 'medium'))
        for reason in all_reasons
    )
    limitations = list(dict.fromkeys(code for link in links for code in link.limitations))
    unsupported = not parsed.supported_text and bool(re.search(r'[^\W\d_]', _prose(parsed), re.UNICODE))
    if unsupported:
        limitations.append('unsupported_text')
    missing = len(links) != len(parsed.links) or {link.link_id for link in links} != {link.link_id for link in parsed.links}
    if missing:
        limitations.append('inspection_failed')
    def coverage_complete(link: LinkResult) -> bool:
        if link.inspection_status == 'not_requested':
            # Static scope can complete without visiting pages. Link-level
            # unknown and the inspection-disabled caveat remain visible.
            return parsed.supported_text and link.limitations == ['inspection_disabled']
        return (link.inspection_status == 'completed' and link.assessment != 'unknown'
                and not link.limitations)

    incomplete = missing or unsupported or any(not coverage_complete(link) for link in links)
    # Symbol-only/unsupported input with no usable evidence is unavailable.
    usable = parsed.supported_text or warning or any(link.inspection_status == 'completed' for link in links)
    if not usable and not links and 'unsupported_text' not in limitations:
        limitations.append('unsupported_text')
        incomplete = True
    assessment = ('phishing' if dangerous or contextual_risk else
                  'suspicious' if warning or any(link.assessment == 'suspicious' for link in links) else
                  'unknown' if incomplete or not usable else 'no_clear_signs')
    status = 'complete' if not incomplete and usable else 'partial' if usable or links else 'unavailable'
    actions = []
    if assessment == 'phishing':
        actions.append('avoid_interaction')
    if assessment in ('phishing', 'suspicious'):
        actions.append('verify_independently')
    if 'credential_request' in message_codes or any(reason.code == 'credential_form' for reason in reasons):
        actions.append('do_not_share_secrets')
    if 'inspection_disabled' in limitations:
        actions.append('consider_link_inspection')
    if any(code in limitations for code in ('inspection_failed', 'deadline_exceeded')):
        actions.append('retry_later')
    return AssessmentSummary(assessment=assessment, analysis_status=status, reasons=reasons,
                             recommended_actions=actions, limitations=list(dict.fromkeys(limitations)))
