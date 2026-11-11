"""Pure contextual message evidence and risk-first coverage aggregation."""
from __future__ import annotations

import re
import unicodedata

from app.brand import claimed_brands, is_official_domain, official_domains_for_brand
from app.message_models import AssessmentSummary, LinkResult, ParsedMessage, Reason, MAX_REASONS

# Bounded request families: imperative gender/number, infinitive and the
# corresponding second-person forms used in prevention statements. All pass
# through the same action-scoped negation logic below.
_HEBREW_REQUESTS = (
    r'שלח(?:י|ו)?|לשלוח|תשלח(?:י|ו)?',
    r'שתף|שתפ(?:י|ו)|לשתף|תשתף|תשתפ(?:י|ו)',
    r'מסור|מסר(?:י|ו)|למסור|תמסור|תמסר(?:י|ו)',
    r'הזן|הזינ(?:י|ו)|להזין|תזין|תזינ(?:י|ו)',
    r'שלם|שלמ(?:י|ו)|לשלם|תשלם|תשלמ(?:י|ו)',
    r'העבר|העברו|העבירי|העבירו|להעביר|תעביר(?:י|ו)?',
    r'אשר(?:י|ו)?|לאשר|תאשר(?:י|ו)?',
    r'צריך|צריכה|צריכים|צריכות',
)
_REQUEST = re.compile(
    r'\b(?:send|share|give|enter|provide|confirm|submit|reply|pay|transfer|needs?)\b|'
    r'(?<!\w)(?:' + '|'.join(_HEBREW_REQUESTS) + r')(?!\w)', re.I,
)
_SECRET = re.compile(
    r'\b(?:otps?|passwords?|passcodes?|pins?|verification codes?|security codes?)\b|'
    r'(?<!\w)ו?(?:ה?סיסמ(?:ה|א|אות|ות)|ה?קוד(?:י|ים)? (?:ה)?אימות|'
    r'ה?קוד(?:ים)? חד פעמי(?:ים)?)(?!\w)', re.I,
)
_PAYMENT = re.compile(r'\b(?:payment|money|fee|bank details|card details|credit card|card number|cvv)\b|(?:תשלום|כסף|פרטי אשראי|פרטי כרטיס|דמי משלוח|כרטיס האשראי)', re.I)
_NEGATED_ACTION_PREFIX = re.compile(
    r"(?:\b(?:do not|don't|never|must not|should not|shouldn't|not to)\s+"
    r"(?:(?:ever|please)\s+)*|(?:אל|לא|אין)\s+)$", re.I,
)
_COORDINATED_ACTION = re.compile(r'\b(?:and|or)\s+$', re.I)
_OBJECT_SEPARATOR = re.compile(r'[,:]')
# Demonstratives need an object boundary: "that you understand" introduces
# a clause and "that agenda" names a new object, rather than referring back.
# A recipient or subordinate adjunct can follow the object ("that to me",
# "that when you arrive"); a bare adverb must end before another clause.
_DEMONSTRATIVE_OBJECT_BOUNDARY = (
    r'(?=\s*(?:$|[,:])|\s+(?:(?:back|over)\s+)?(?:to|with|for|from|by|via)\b|'
    r'\s+(?:when|once|because|if|unless|until|before|after)\b|'
    r'\s+(?:(?:right\s+)?now|please|back|over|here|there|again|today|tomorrow|later|[a-z]+ly)'
    r'\s*(?:$|[,:]))'
)
_OBJECT_REFERENCE = re.compile(
    r'^\s+(?:(?:me|us|him|her|לי|לנו)\s+)?'
    r'(?P<object>it|them|אותו|אותה|אותם|אותן|(?:this|that)'
    + _DEMONSTRATIVE_OBJECT_BOUNDARY + r')(?!\w)', re.I,
)
_ACTION_PRELUDE = re.compile(r'\s*(?:please|בבקשה)?\s*', re.I)
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


def _positive_actions(prose: str, pattern: re.Pattern):
    """Associate negation with its action, not every request in the sentence."""
    for clause in re.split(r'[.!?;\n]|\bbut\b|אבל', prose, flags=re.I):
        actions = list(pattern.finditer(clause))
        previous_negated = False
        for index, action in enumerate(actions):
            prefix = clause[:action.start()]
            negated = bool(_NEGATED_ACTION_PREFIX.search(prefix))
            if previous_negated and _COORDINATED_ACTION.search(prefix):
                negated = True
            previous_negated = negated
            end = actions[index + 1].start() if index + 1 < len(actions) else len(clause)
            if not negated:
                # Conjunctions stay inside object phrases. A later explicit
                # object does not inherit the previous action's comma list.
                start = 0 if index == 0 else action.end()
                if index:
                    previous_end = actions[index - 1].end()
                    separators = list(_OBJECT_SEPARATOR.finditer(clause, previous_end, action.start()))
                    if separators:
                        start = separators[-1].end()
                        reference = _OBJECT_REFERENCE.match(clause[action.end():end])
                        if reference:
                            # A comma before "please give them" ends the object
                            # phrase, not another item in it. Singular references
                            # bind to the nearest phrase; plural references keep
                            # the entire possible fronted list after the previous
                            # action's initial object. Ambiguous list attachment
                            # conservatively retains potential request evidence.
                            if _ACTION_PRELUDE.fullmatch(clause[start:action.start()]):
                                separators.pop()
                            plural = reference.group('object').casefold() in {'them', 'אותם', 'אותן'}
                            boundary = (separators[0] if plural else separators[-1]) if separators else None
                            start = boundary.end() if boundary else previous_end
                yield action, clause[start:end]


def _solicitation_codes(prose: str) -> set[str]:
    codes = set()
    for _, requested in _positive_actions(prose, _REQUEST):
        if _SECRET.search(requested):
            codes.add('credential_request')
        if _PAYMENT.search(requested):
            codes.add('payment_request')
    return codes


def text_evidence(parsed: ParsedMessage) -> list[Reason]:
    prose = _prose(parsed)
    reasons: list[Reason] = []
    codes = _solicitation_codes(prose)
    if _THREAT.search(prose) and any(_positive_actions(prose, _LOGIN)):
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
    for brand in sorted(claimed_brands(prose)):
        roots = official_domains_for_brand(brand)
        if not roots:
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
    direct_solicitation = bool(_solicitation_codes(_prose(parsed)))
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
