"""Pure contextual message evidence and risk-first coverage aggregation."""
from __future__ import annotations

import re
import unicodedata

from app.brand import claimed_brands, is_official_domain, official_domains_for_brand
from app.message_models import MAX_REASONS, AssessmentSummary, LinkResult, ParsedMessage, Reason

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
    # Common in delivery, bank and tax smishing: "יש להסדיר", "עדכנו את פרטי האשראי".
    r'הסדר|הסדיר(?:י|ו)|להסדיר|תסדיר(?:י|ו)?',
    r'עדכן|עדכנ(?:י|ו)|לעדכן|תעדכן|תעדכנ(?:י|ו)',
    r'השלם|השלימ(?:י|ו)|להשלים|תשלים(?:י|ו)?',
    r'אמת|אמת(?:י|ו)|לאמת|תאמת(?:י|ו)?',
    # Gift-card and "buy this for me" requests.
    r'קנה|קנ(?:י|ו)|לקנות|תקנה|תקנ(?:י|ו)|רכוש|לרכוש',
)
_REQUEST = re.compile(
    r'\b(?:send|share|give|enter|provide|confirm|submit|reply|pay|transfer|needs?|settle|update|verify|buy|purchase|forward)\b|'
    r'(?<!\w)(?:' + '|'.join(_HEBREW_REQUESTS) + r')(?!\w)', re.I,
)
_SECRET = re.compile(
    r'\b(?:otps?|passwords?|passcodes?|pins?|verification codes?|security codes?|login codes?|'
    r'\d[- ]digit codes?|codes? (?:we|i) (?:just )?sent)\b|'
    r'(?<!\w)ו?(?:ה?סיסמ(?:ה|א|אות|ות)|ה?קוד(?:י|ים)? (?:ה)?(?:אימות|אישור|כניסה|אבטחה)|'
    r'ה?קוד(?:ים)? חד פעמי(?:ים)?|קוד בן \d+ ספרות|ה?קוד ש(?:קיבלת|קבלת|נשלח|שלחתי|שלחנו)\w*)(?!\w)', re.I,
)
_PAYMENT = re.compile(
    r'\b(?:payment|money|fees?|bank details|card details|credit card|card number|cvv|customs|fine|'
    r'outstanding balance|billing details|payment method|gift cards?|wire transfer|bitcoin|btc|toll)\b|'
    r'(?:תשלום|כסף|פרטי אשראי|פרטי כרטיס|פרטי האשראי|פרטי הכרטיס|דמי משלוח|דמי מכס|מכס|דמי שחרור|'
    r'כרטיס האשראי|אמצעי תשלום|קנס|חוב|שקל|ש"ח|ש״ח|₪|בביט|בפייבוקס|העברה בנקאית|פרטי חשבון|'
    r'כרטיס(?:י)? מתנה|גיפט קארד)', re.I)
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
_URGENCY = re.compile(
    r'\b(?:now|immediately|urgent(?:ly)?|within \d+ (?:minutes|hours)|today|by midnight|or (?:your|the) '
    r'(?:account|parcel|package))\b|'
    r'(?:עכשיו|מיד|דחוף|בדחיפות|עד היום|בחצות|היום בלבד|תוך \d+ (?:שעות|דקות)|אחרת)', re.I)
# Plain money, as opposed to card, bank or billing details and official charges.
_PERSONAL_MONEY = re.compile(r'\b(?:money|gift cards?|bitcoin|btc)\b|(?:כסף|שקל|ש"ח|ש״ח|₪|בביט|בפייבוקס|כרטיס(?:י)? מתנה|גיפט קארד)', re.I)
# Official domains whose links lead to whoever created them, not to the organization.
_PERSONAL_LINK_HOSTS = frozenset({'wa.me', 't.me', 'paypal.me'})
# Explicit pressure. "today"/"now" alone are ordinary between people who know each other.
_PRESSURE = re.compile(
    r'\b(?:immediately|urgent(?:ly)?|asap|right now|within \d+ (?:minutes|hours))\b|'
    r'(?:מיד|דחוף|בדחיפות|בהקדם|תוך \d+ (?:שעות|דקות))', re.I)
# Scenarios that scam messages reuse, each tied to a call to follow a link.
_SCENARIOS = re.compile(
    # Delivery that failed or is being held.
    r'(?:חבילה|חבילת|משלוח|הזמנה)\S*.{0,40}(?:לא נמסר|ממתינ|מעוכב|עוכב|נכשל|הוחזר)|'
    r'\b(?:package|parcel|delivery|shipment|order)\b.{0,40}\b(?:could not be delivered|not delivered|undeliverable|'
    r'on hold|is being held|failed|is waiting)\b|'
    # Prizes, refunds and grants nobody applied for.
    r'זכית|זכיתם|\byou(?: have|\'ve)? (?:won|been selected)\b|\bclaim your (?:prize|reward|refund)\b|'
    r'מגיע(?:ה)? לך (?:החזר|מענק|זיכוי|פיצוי)|החזר מס|זכאות\S* ל(?:מענק|החזר)|\btax refund\b|'
    r'לקבלת (?:הכסף|ההחזר|המענק|הפרס)|'
    # Blocked card or account.
    r'(?:כרטיס|חשבונ?)\S*.{0,20}(?:נחסם|הושעה|הוגבל|יושעה|ייחסם|יחסם)|פעילות חריגה|'
    r'\b(?:account|card|subscription)\b.{0,30}\b(?:locked|limited|suspended|blocked|expired|on hold)\b|'
    r'\bunusual (?:sign[- ]?in|activity)\b|'
    # Service about to be cut off, and vouchers for people "selected" at random.
    r'(?:קו|חשמל|שירות|מנוי|חשבונ?)\S*.{0,25}(?:ינותק|יבוטל|ייסגר|יופסק)|נבחרת(?:ם)? ל(?:קבל|זכות)|שובר\S* בשווי|'
    r'\bwill be (?:deactivated|disconnected|cancell?ed|deleted|terminated)\b|'
    # Easy money for remote work.
    r'(?:עבודה|עובדים|משרה) מהבית|\bwork from home\b.{0,60}\b(?:per day|daily|a day)\b', re.I)
# "This is my new number" followed by a request is the family-impersonation opener.
_NEW_NUMBER = re.compile(r"\b(?:this is|it'?s|here is) my new (?:number|phone)\b|המספר החדש שלי|מספר חדש שלי", re.I)
_THREAT = re.compile(r'\b(?:account.{0,30}(?:suspend|close|block)|suspended|locked out)\b|(?:החשבון.{0,25}(?:ייסגר|יחסם|ייחסם))', re.I)
_DESTINATION_WARNINGS = frozenset({'brand_destination_mismatch', 'lookalike_host', 'credential_form',
                                  'payment_form', 'certificate_mismatch'})
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
    return set(_solicitations(prose))


def _solicitations(prose: str) -> dict[str, bool]:
    """Requested codes; the value is True when only plain money was requested."""
    codes: dict[str, bool] = {}
    for _, requested in _positive_actions(prose, _REQUEST):
        if _SECRET.search(requested):
            codes['credential_request'] = False
        if _PAYMENT.search(requested):
            plain = not _PAYMENT.search(_PERSONAL_MONEY.sub(' ', requested))
            codes['payment_request'] = codes.get('payment_request', True) and plain
    return codes


def text_evidence(parsed: ParsedMessage) -> list[Reason]:
    prose = _prose(parsed)
    reasons: list[Reason] = []
    codes = _solicitations(prose)
    if _THREAT.search(prose) and any(_positive_actions(prose, _LOGIN)):
        codes['credential_request'] = False
    for link in parsed.links:
        if any(c in link.raw for c in '\u202a\u202b\u202d\u202e\u2066\u2067\u2068') and _LOGIN.search(prose):
            reasons.append(Reason(code='suspicious_obfuscation', strength='medium', source='message', link_id=link.link_id))
    brands = claimed_brands(prose)
    threat = bool(_THREAT.search(prose))
    actionable = False
    for code in sorted(codes):
        strength = 'strong'
        if codes[code] and not (parsed.links or threat or brands):
            # People who know each other ask for money all the time. With no
            # link, threat or named organization it is a warning only under
            # explicit pressure ("urgent", "immediately").
            if not _PRESSURE.search(prose):
                continue
            strength = 'medium'
        actionable = True
        reasons.append(Reason(code=code, strength=strength, source='message'))
    if actionable and (_URGENCY.search(prose) or threat):
        reasons.append(Reason(code='urgency', strength='strong' if threat else 'medium', source='message'))
    # A reused scam scenario matters only when it steers the reader to a link
    # outside the domains of the organizations this registry knows.
    if _SCENARIOS.search(prose) and any(
        link.canonical_url and link.display_host
        and (link.display_host in _PERSONAL_LINK_HOSTS or not is_official_domain(link.display_host))
        for link in parsed.links
    ):
        reasons.append(Reason(code='scam_scenario', strength='medium', source='message'))
    elif _NEW_NUMBER.search(prose) and any(_positive_actions(prose, _REQUEST)):
        reasons.append(Reason(code='scam_scenario', strength='medium', source='message'))
    # Compare explicit named claims using the same brand-family roots as URL
    # evidence. Generic bank vocabulary and brand words inside URLs are not claims.
    for brand in sorted(brands):
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
    # A shortened link only hides its destination. It becomes a warning when the
    # message itself gives a reason to care where the link leads.
    if message_reasons or claimed_brands(_prose(parsed)):
        all_reasons = [reason.model_copy(update={'strength': 'medium'}) if reason.code == 'shortened_link' else reason
                       for reason in all_reasons]
    # Retain highest-risk explanations first if the message reaches the contract cap.
    order = {'strong': 0, 'medium': 1, 'info': 2}
    reasons = sorted(all_reasons, key=lambda reason: order[reason.strength])[:MAX_REASONS]
    message_codes = {reason.code for reason in message_reasons}
    warning = any(reason.strength in ('strong', 'medium') for reason in all_reasons)
    dangerous = any(link.assessment == 'phishing' for link in links)
    solicitation = {'credential_request', 'payment_request'}
    solicits = any(reason.code in solicitation and reason.strength == 'strong' for reason in message_reasons)
    # Urgency alone adds context, but a request plus an independent destination
    # warning (or an explicit threat tied to secret/payment solicitation) is
    # needed for phishing. Generic login under pressure remains suspicious
    # unless the destination itself contradicts the organization named.
    direct_solicitation = bool(_solicitation_codes(_prose(parsed)))
    contextual_risk = solicits and direct_solicitation and any(
        reason.code not in solicitation
        and (reason.strength == 'strong' or (reason.source != 'message' and reason.strength == 'medium'))
        for reason in all_reasons
    )
    destination_contradiction = solicits and any(
        reason.strength == 'strong' and reason.code in _DESTINATION_WARNINGS for reason in all_reasons
    )
    contextual_risk = contextual_risk or destination_contradiction
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
            # A shortened link is the exception: nothing about its destination was seen.
            return (parsed.supported_text and link.limitations == ['inspection_disabled']
                    and not any(reason.code == 'shortened_link' for reason in link.reasons))
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
