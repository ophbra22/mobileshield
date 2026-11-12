"""Brand registry: official domains, explicit name claims and hostname evidence.

A single registry drives three checks so they stay consistent:

* ``claimed_brands(text)``: explicit organization claims in message text or a
  page title ("Your PayPal account", "בנק לאומי").
* ``impersonated_brands(hostname)``: brand names used as hostname *tokens* on a
  domain the brand does not own (``paypal-login.example``).
* ``analyze_brand(domain)``: look-alike spellings (``paypa1``, ``rnicrosoft``).

Matching is token based, never substring based: ``purchase.com`` does not
contain the token ``chase`` and ``applebees.com`` is not ``apple``. Brand names
that are also ordinary words (apple, office, discount…) are marked ambiguous and
need extra context: a qualifier in text ("Microsoft Office", "Discount Bank")
or an account/login token in a hostname (``office365-login.example``).
"""
from __future__ import annotations

import re
import unicodedata
from dataclasses import dataclass
from typing import Optional

from app.detection.url_normalizer import split_domain


@dataclass(frozen=True)
class Brand:
    roots: frozenset[str]
    """Registrable domains owned by the brand (subdomains are included)."""
    claim: str
    """Regex (case-insensitive) for an explicit claim in text."""
    host_tokens: frozenset[str] = frozenset()
    """Hostname tokens that name the brand."""
    ambiguous: bool = False
    """Token is also a common word; hostnames need an account/login token too."""


def _brand(roots, claim, tokens=(), ambiguous=False) -> Brand:
    return Brand(frozenset(roots), claim, frozenset(tokens), ambiguous)


_MS_ROOTS = ('microsoft.com', 'office.com', 'live.com', 'outlook.com', 'microsoftonline.com', 'office365.com')
_APPLE_ROOTS = ('apple.com', 'icloud.com')
_SIGN_IN = r'(?:sign[\s-]?in|log[\s-]?in|account|password|התחברות|כניסה|חשבון)'

BRANDS: dict[str, Brand] = {
    # Global brands
    'paypal': _brand({'paypal.com', 'paypal.me'}, r'pay\s?pal|פייפאל|פייפל', {'paypal'}),
    'google': _brand({'google.com', 'google.co.il', 'youtube.com', 'gmail.com'}, r'google|gmail|גוגל|ג׳ימייל', {'google', 'gmail'}),
    'microsoft': _brand(_MS_ROOTS, r'microsoft|מיקרוסופט', {'microsoft'}),
    'office': _brand(_MS_ROOTS, r'(?:microsoft|ms)\s+office|office\s*365|office\s+' + _SIGN_IN + r'|אופיס\s*365',
                     {'office', 'office365'}, ambiguous=True),
    'outlook': _brand(_MS_ROOTS, r'outlook(?:\.com)?\s+' + _SIGN_IN + r'|outlook\s+(?:mail|web)|hotmail|אאוטלוק',
                      {'outlook', 'hotmail'}, ambiguous=True),
    'apple': _brand(_APPLE_ROOTS, r'apple\s+(?:id|pay|store|support|' + _SIGN_IN + r')|חשבון\s+אפל|אפל\s+(?:איי\s?די|פיי)',
                    {'apple'}, ambiguous=True),
    'appleid': _brand(_APPLE_ROOTS, r'apple\s?id|appleid', {'appleid'}),
    'icloud': _brand(_APPLE_ROOTS, r'i\s?cloud|אייקלאוד', {'icloud'}),
    'whatsapp': _brand({'whatsapp.com', 'whatsapp.net', 'wa.me'}, r'whats\s?app|וואטסאפ|ווטסאפ|וואצאפ', {'whatsapp'}),
    'telegram': _brand({'telegram.org', 't.me'}, r'telegram|טלגרם', {'telegram'}),
    'amazon': _brand({'amazon.com', 'amazon.co.uk', 'amazon.de', 'amazon.fr', 'amazon.it', 'amazon.es', 'amazon.ca',
                      'amazon.com.au', 'amazon.co.jp', 'amazon.in'}, r'amazon|אמזון', {'amazon'}, ambiguous=True),
    'facebook': _brand({'facebook.com', 'fb.com', 'messenger.com'}, r'facebook|פייסבוק', {'facebook'}),
    'instagram': _brand({'instagram.com'}, r'instagram|אינסטגרם', {'instagram'}),
    'meta': _brand({'meta.com', 'facebook.com', 'instagram.com', 'whatsapp.com'},
                   r'meta\s+(?:business|support|verified|account)|מטא\s+(?:ביזנס|תמיכה)', {'meta'}, ambiguous=True),
    'binance': _brand({'binance.com'}, r'binance|ביננס|בייננס', {'binance'}),
    'visa': _brand({'visa.com'}, r'visa\s+(?:card|credit|debit)|כרטיס\s+ויזה', {'visa'}, ambiguous=True),
    'mastercard': _brand({'mastercard.com'}, r'master\s?card|מאסטרקארד', {'mastercard'}),
    'amex': _brand({'americanexpress.com'}, r'amex|american\s+express|אמריקן\s+אקספרס', {'amex', 'americanexpress'}),
    'chase': _brand({'chase.com'}, r'chase\s+(?:bank|online|' + _SIGN_IN + r')|jp\s?morgan\s+chase', {'chase'}, ambiguous=True),
    'bankofamerica': _brand({'bankofamerica.com', 'bofa.com'}, r'bank\s+of\s+america', {'bankofamerica', 'bofa'}),
    'wellsfargo': _brand({'wellsfargo.com'}, r'wells\s?fargo', {'wellsfargo'}),
    'citibank': _brand({'citi.com', 'citibank.com'}, r'citi\s?bank', {'citibank'}),
    'hsbc': _brand({'hsbc.com', 'hsbc.co.uk', 'hsbcnet.com'}, r'hsbc', {'hsbc'}),
    'capitalone': _brand({'capitalone.com'}, r'capital\s?one', {'capitalone'}),
    'stripe': _brand({'stripe.com'}, r'stripe\s+(?:payments?|dashboard|support|' + _SIGN_IN + r')', {'stripe'}, ambiguous=True),
    'cashapp': _brand({'cash.app'}, r'cash\s?app', {'cashapp'}),
    'venmo': _brand({'venmo.com'}, r'venmo', {'venmo'}),
    # Israeli banks, fintech and services
    'leumi': _brand({'leumi.co.il'}, r'(?:bank\s+)?leumi|בנק\s+לאומי|לאומי\s+(?:דיגיטל|קארד)', {'leumi'}),
    'hapoalim': _brand({'bankhapoalim.co.il', 'poalim.biz'}, r'hapoalim|בנק\s+הפועלים', {'hapoalim', 'poalim'}),
    'discount': _brand({'discountbank.co.il'}, r'discount\s+bank|bank\s+discount|בנק\s+דיסקונט',
                       {'discount', 'discountbank'}, ambiguous=True),
    'mizrahi': _brand({'mizrahi-tefahot.co.il'}, r'mizrahi(?:[\s-]+tefahot)?\s+bank|bank\s+mizrahi|mizrahi[\s-]+tefahot|'
                      r'מזרחי[\s-]*טפחות|בנק\s+מזרחי', {'mizrahi', 'tefahot'}, ambiguous=True),
    'beinleumi': _brand({'fibi.co.il'}, r'beinleumi|first\s+international\s+bank|בנק\s+הבינלאומי', {'beinleumi', 'fibi'}),
    'onezero': _brand({'onezerobank.com'}, r'one\s?zero\s+bank|onezero|וואן\s?זירו', {'onezero', 'onezerobank'}),
    'pepper': _brand({'pepper.co.il'}, r'pepper\s+(?:bank|pay|invest)|בנק\s+פפר|פפר\s+פיי', {'pepper'}, ambiguous=True),
    'israelpost': _brand({'israelpost.co.il'}, r'israel\s+post|דואר\s+ישראל', {'israelpost'}),
    # Israeli cards, payment apps, utilities and government services that scams commonly name.
    'cal': _brand({'cal-online.co.il'}, r'ויזה\s+כאל|חברת\s+כאל|כרטיס\s+כאל|לקוחות\s+כאל|כאל\s*[:\-–]|cal[\s-]?online', {'calonline'}),
    'max': _brand({'max.co.il'}, r'max\s+(?:it|card|finance)|כרטיס\s+מקס|מקס\s+(?:איט|פיננסים)|לאומי\s+קארד', {'max'}, ambiguous=True),
    'isracard': _brand({'isracard.co.il'}, r'isracard|ישראכרט', {'isracard'}),
    'bit': _brand({'bitpay.co.il'}, r'אפליקציית\s+ביט|(?:העברה|תשלום|כסף)\s+ב?ביט|bit\s+app'),
    'paybox': _brand({'payboxapp.com'}, r'pay\s?box|פייבוקס', {'paybox'}),
    'kvish': _brand({'kvish6.co.il'}, r'כביש\s*6|כביש\s+שש|kvish\s*6', {'kvish'}),
    'bituachleumi': _brand({'btl.gov.il', 'gov.il'}, r'ביטוח\s+לאומי|bituach\s+leumi', {'bituachleumi', 'btl'}),
    'taxauthority': _brand({'gov.il'}, r'רשות\s+המי?סים|מס\s+הכנסה|israel\s+tax\s+authority', {'taxes'}, ambiguous=True),
    'iec': _brand({'iec.co.il'}, r'חברת\s+החשמל', {'iec'}),
    'bezeq': _brand({'bezeq.co.il'}, r'bezeq|חברת\s+בזק|חשבון\s+בזק|בזק\s+בינלאומי', {'bezeq'}),
    'cellcom': _brand({'cellcom.co.il'}, r'cellcom|סלקום', {'cellcom'}),
    'pelephone': _brand({'pelephone.co.il'}, r'pelephone|פלאפון', {'pelephone'}),
    'hot': _brand({'hot.net.il', 'hotmobile.co.il'}, r'hot\s+mobile|הוט\s+מובייל|חברת\s+הוט', {'hotmobile'}),
    'coinbase': _brand({'coinbase.com'}, r'coinbase', {'coinbase'}),
    'partner': _brand({'partner.co.il'}, r'partner\s+(?:communications|israel)|חברת\s+פרטנר|פרטנר\s+תקשורת', {'partner'}, ambiguous=True),
    # Global services frequently used as delivery and subscription lures.
    'netflix': _brand({'netflix.com'}, r'netflix|נטפליקס', {'netflix'}),
    'usps': _brand({'usps.com'}, r'usps|u\.s\.\s+postal\s+service', {'usps'}),
    'dhl': _brand({'dhl.com'}, r'dhl', {'dhl'}),
    'fedex': _brand({'fedex.com'}, r'fed\s?ex|פדקס', {'fedex'}),
}

# 'bank' is a generic word, never a specific organization claim.
GENERIC_BRAND_TERMS = frozenset({'bank'})
KNOWN_BRAND_IDS = frozenset(BRANDS) | GENERIC_BRAND_TERMS

# Hostname tokens that make an ambiguous brand token suspicious, and suffixes or
# prefixes commonly glued to a brand name ("paypalsecure", "myleumi").
_RISK_TOKENS = frozenset({
    'login', 'logon', 'signin', 'secure', 'security', 'verify', 'verification', 'account', 'accounts',
    'update', 'support', 'auth', 'id', 'wallet', 'billing', 'alert', 'confirm', 'recovery', 'unlock',
    'password', 'banking', 'customer', 'service', 'portal', 'helpdesk', 'payment', 'refund', 'delivery',
})
_AFFIXES = _RISK_TOKENS | frozenset({'online', 'help', 'pay', 'app', 'mail', 'web', 'bank', 'my', 'official', 'center', 'user'})

_HEBREW_PREFIX = '[ובלמשהכ]{0,2}'
_CLAIM_PATTERNS = {
    brand_id: re.compile(r'(?<![^\W_])' + _HEBREW_PREFIX + r'(?:' + brand.claim + r')(?![^\W_])', re.IGNORECASE)
    for brand_id, brand in BRANDS.items()
}


def official_domains_for_brand(brand: str) -> set[str]:
    """Registrable domains owned by a brand; generic terms have none."""
    entry = BRANDS.get(brand)
    return set(entry.roots) if entry else set()


def is_official_domain(domain: str, official: str | None = None) -> bool:
    """True if ``domain`` equals or is a subdomain of an official brand root."""
    if not domain:
        return False
    domain = domain.lower().rstrip('.')
    roots = [official.lower()] if official else {root for brand in BRANDS.values() for root in brand.roots}
    return any(domain == root or domain.endswith('.' + root) for root in roots)


def _owned_by(hostname: str, brand_id: str) -> bool:
    return any(is_official_domain(hostname, root) for root in BRANDS[brand_id].roots)


def claimed_brands(text: str) -> set[str]:
    """Brand IDs explicitly named in prose or a page title."""
    if not text:
        return set()
    return {brand_id for brand_id, pattern in _CLAIM_PATTERNS.items() if pattern.search(text)}


def _host_tokens(hostname: str) -> list[str]:
    """Alphabetic tokens of the host, excluding its public suffix."""
    host = hostname.lower().rstrip('.')
    suffix = split_domain(host).suffix
    if suffix and host.endswith('.' + suffix):
        host = host[: -len(suffix) - 1]
    return [token for token in re.split(r'[^a-z]+', host) if token]


def _tokens_name_brand(tokens: list[str], brand: Brand) -> bool:
    risky_context = any(token in _RISK_TOKENS for token in tokens)
    for token in tokens:
        for name in brand.host_tokens:
            if token == name:
                if not brand.ambiguous or risky_context:
                    return True
            elif token.startswith(name) and token[len(name):] in _AFFIXES:
                return True
            elif token.endswith(name) and token[: -len(name)] in _AFFIXES:
                return True
    return False


def host_brand_mentions(hostname: str) -> list[str]:
    """Brand IDs named by hostname tokens, whether or not the host is official."""
    tokens = _host_tokens(hostname)
    return [brand_id for brand_id, brand in BRANDS.items() if _tokens_name_brand(tokens, brand)]


def impersonated_brands(hostname: str) -> list[str]:
    """Brands named in a hostname that the brand does not own."""
    return [brand_id for brand_id in host_brand_mentions(hostname) if not _owned_by(hostname, brand_id)]


def path_impersonated_brands(hostname: str, path: str) -> list[str]:
    """Brand tokens in a URL path plus an account/login token, off the brand's domains."""
    tokens = [token for token in re.split(r'[^a-z]+', path.lower()) if token]
    if not any(token in _RISK_TOKENS for token in tokens):
        return []
    return [brand_id for brand_id, brand in BRANDS.items()
            if not brand.ambiguous and _tokens_name_brand(tokens, brand) and not _owned_by(hostname, brand_id)]


# Cyrillic and Greek letters that render like Latin ones (``gооgle`` with Cyrillic о).
_CONFUSABLES = str.maketrans({
    'а': 'a', 'в': 'b', 'е': 'e', 'к': 'k', 'м': 'm', 'н': 'h', 'о': 'o', 'р': 'p', 'с': 'c', 'т': 't', 'у': 'y',
    'х': 'x', 'і': 'i', 'ј': 'j', 'ѕ': 's', 'һ': 'h', 'ԁ': 'd', 'ԛ': 'q', 'ԝ': 'w', 'ё': 'e',
    'α': 'a', 'ε': 'e', 'ι': 'i', 'κ': 'k', 'ν': 'v', 'ο': 'o', 'ρ': 'p', 'τ': 't', 'υ': 'u', 'χ': 'x',
    'ı': 'i', 'ɑ': 'a', 'ɡ': 'g',
})


def unicode_host(hostname: str) -> str:
    """Decode punycode labels so look-alike checks see the letters a reader sees."""
    labels = []
    for label in (hostname or '').lower().rstrip('.').split('.'):
        if label.startswith('xn--'):
            try:
                label = label[4:].encode('ascii').decode('punycode')
            except (UnicodeError, ValueError):
                pass
        labels.append(label)
    return '.'.join(labels)


def _latin_skeleton(host: str) -> str:
    """Map confusable letters and accented Latin letters to plain ASCII look-alikes."""
    decomposed = unicodedata.normalize('NFKD', host.translate(_CONFUSABLES))
    return ''.join(c for c in decomposed if not unicodedata.category(c).startswith('M'))


def mixed_script_label(hostname: str) -> bool:
    """A single label mixing Latin with another alphabet is a classic disguise."""
    for label in unicode_host(hostname).split('.'):
        scripts = {unicodedata.name(c, '').split(' ')[0] for c in label if c.isalpha()}
        if 'LATIN' in scripts and len(scripts) > 1:
            return True
    return False


HOMOGLYPH_MAP = {'0': 'o', '1': 'l', 'i': 'l', '3': 'e', '4': 'a', '5': 's', '7': 't', '8': 'b', '@': 'a', '$': 's'}


def _normalize_token(token: str) -> str:
    token = token.lower()
    for src, tgt in HOMOGLYPH_MAP.items():
        token = token.replace(src, tgt)
    return token.replace('rn', 'm').replace('vv', 'w')


def _levenshtein(a: str, b: str) -> int:
    if a == b:
        return 0
    if not a:
        return len(b)
    if not b:
        return len(a)
    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr = [i]
        for j, cb in enumerate(b, 1):
            curr.append(min(prev_row[j] + 1, curr[j - 1] + 1, prev_row[j - 1] + (ca != cb)))
        prev_row = curr
    return prev_row[-1]


def _adjacent_swap(a: str, b: str) -> bool:
    """True if ``a`` is ``b`` with exactly two neighbouring letters swapped."""
    if len(a) != len(b) or a == b:
        return False
    diff = [i for i, (x, y) in enumerate(zip(a, b)) if x != y]
    return len(diff) == 2 and diff[1] == diff[0] + 1 and a[diff[0]] == b[diff[1]] and a[diff[1]] == b[diff[0]]


def _collapse_repeats(value: str) -> str:
    return re.sub(r'(.)\1+', r'\1', value)


# Distinctive names worth look-alike checks; short or ambiguous words are not.
_LOOKALIKE_TARGETS = {
    'paypal': 'paypal', 'google': 'google', 'microsoft': 'microsoft', 'apple': 'apple', 'whatsapp': 'whatsapp',
    'telegram': 'telegram', 'amazon': 'amazon', 'facebook': 'facebook', 'instagram': 'instagram',
    'binance': 'binance', 'icloud': 'icloud', 'leumi': 'leumi', 'hapoalim': 'hapoalim', 'wellsfargo': 'wellsfargo',
}


def _lookalike_method(token: str, target: str) -> str | None:
    if len(token) < 4 or token == target:
        return None
    # Normalize both sides: 'i' and 'l' (or 'rn' and 'm') look alike in either direction.
    normalized, canonical = _normalize_token(token), _normalize_token(target)
    if normalized == canonical:
        return 'homoglyph'
    if len(target) >= 6 and _adjacent_swap(normalized, canonical):
        return 'transposition'
    if len(target) >= 6 and _collapse_repeats(normalized) == _collapse_repeats(canonical):
        return 'levenshtein'
    if len(token) >= 5 and target.startswith(token) and len(target) - len(token) == 1:
        return 'truncation'
    return None


@dataclass
class BrandLookalike:
    brand: str
    score: int
    method: str
    distance: int
    official_domain_matched: bool


def analyze_brand(domain: str) -> Optional[BrandLookalike]:
    """Detect a host token that imitates a brand name (``paypa1``, ``rnicrosoft``, Cyrillic ``gооgle``)."""
    ascii_host = (domain or '').lower().rstrip('.')
    if not ascii_host:
        return None
    visible = unicode_host(ascii_host)
    host = _latin_skeleton(visible)
    disguised = host != visible
    suffix = split_domain(host).suffix
    stem = host[: -len(suffix) - 1] if suffix and host.endswith('.' + suffix) else host
    tokens = [token for token in re.split(r'[.\-_]+', stem) if token]
    score = 35 if disguised or 'xn--' in ascii_host else 25
    if disguised:
        # Foreign or accented letters spelling a brand name exactly are never the brand's own host.
        for brand_id, brand in BRANDS.items():
            names = brand.host_tokens | ({_LOOKALIKE_TARGETS[brand_id]} if brand_id in _LOOKALIKE_TARGETS else set())
            if any(token in names for token in tokens) and not _owned_by(ascii_host, brand_id):
                return BrandLookalike(brand=brand_id, score=score, method='homoglyph', distance=0,
                                      official_domain_matched=False)
    for token in tokens:
        for brand_id, target in _LOOKALIKE_TARGETS.items():
            method = _lookalike_method(token, target)
            if method is None or _owned_by(ascii_host, brand_id):
                continue
            return BrandLookalike(brand=brand_id, score=score, method=method,
                                  distance=_levenshtein(token, target),
                                  official_domain_matched=False)
    return None


def detect_brand_impersonation(hostname: str, registered_domain: str) -> dict:
    """Brand tokens in a hostname whose registrable domain is not the brand's."""
    hostname_l = hostname.lower()
    brands_found = host_brand_mentions(hostname_l)
    suspicious_brands = [brand for brand in brands_found if not _owned_by(hostname_l, brand)]
    subdomain_tokens = [t for t in re.split(r'[^a-z]+', split_domain(hostname_l).subdomain) if t]
    is_brand_in_subdomain = any(_tokens_name_brand(subdomain_tokens, BRANDS[b]) for b in suspicious_brands)
    return {
        'brands_found': brands_found,
        'is_brand_in_subdomain': is_brand_in_subdomain,
        'is_registered_domain_suspicious': bool(suspicious_brands),
    }
