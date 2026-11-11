"""Pure, bounded link extraction from original Hebrew/English message text."""

from __future__ import annotations

import ipaddress
import re
import unicodedata
from urllib.parse import quote, urlsplit, urlunsplit

import idna

from app.detection.network_policy import validate_raw_authority
from app.detection.url_normalizer import split_domain
from app.message_models import MAX_LINKS, LinkCandidate, ParsedMessage, validate_message_text
from app.text_coverage import supported_text

# Match complete explicit candidates before bare domains; do not discover a
# different host inside an unsupported scheme or an email address.
# Python's regex \w excludes Unicode marks. Include the complete Unicode mark
# categories so a match cannot restart inside a decomposed hostname. IDNA then
# validates the entire label, including invalid leading/embedded marks.
_MARKS = ''.join(chr(code) for code in range(0x110000)
                 if unicodedata.category(chr(code)).startswith('M'))
_LABEL = rf'[\w{_MARKS}\-\u200b-\u200f\u202a-\u202e\u2060-\u2069]+'
_CANDIDATES = re.compile(
    rf'(?<![\w{_MARKS}@.+-])(?:[a-z][a-z0-9+.\-\u200b-\u200f\u202a-\u202e\u2060-\u2069]*:[^\s<>"\u05f3\u05f4]+'
    r'|' + _LABEL + r'(?:\.' + _LABEL + r')+(?::[0-9]+)?(?:[/?#][^\s<>"\u05f3\u05f4]*)?)',
    re.IGNORECASE,
)
_TRAILING_PUNCTUATION = '.,;:!?\u05c3\u05f3\u05f4'


def _trim_punctuation(raw: str) -> str:
    while raw:
        if raw[-1] in _TRAILING_PUNCTUATION:
            # The // delimiter of a missing-host URL must remain visible.
            raw = raw[:-1]
        elif raw[-1] in ')]}' and raw.count(raw[-1]) > raw.count({')': '(', ']': '[', '}': '{'}[raw[-1]]):
            raw = raw[:-1]
        else:
            break
    return raw


def _explicit_scheme(raw: str) -> str | None:
    match = re.match(r'^([a-z][a-z0-9+.-]*):', raw, re.IGNORECASE)
    if not match:
        return None
    # A bare domain followed by a numeric port is an authority. Preserve the
    # scheme grammar for every other prefix, including unsupported schemes.
    if '.' in match[1] and re.match(r'[0-9]+(?:[/?#]|$)', raw[match.end():]):
        return None
    return match[1].lower()


def _canonicalize(raw: str) -> tuple[str | None, str | None, str | None]:
    if '\\' in raw or any(unicodedata.category(c).startswith('C') for c in raw):
        return None, None, 'ambiguous_url'
    explicit_scheme = _explicit_scheme(raw)
    if explicit_scheme and explicit_scheme not in {'http', 'https'}:
        return None, None, 'unsupported_scheme'
    if explicit_scheme and not raw.lower().startswith(explicit_scheme + '://'):
        return None, None, 'invalid_url'
    try:
        parts = urlsplit(raw if '://' in raw else 'https://' + raw)
        if not parts.hostname or parts.scheme.lower() not in {'http', 'https'}:
            return None, None, 'invalid_url'
        if parts.username is not None or parts.password is not None:
            return None, None, 'ambiguous_url'
        validate_raw_authority(parts)
        host = parts.hostname.lower().removesuffix('.')
        try:
            host = str(ipaddress.ip_address(host))
            display_host = host
        except ValueError:
            host = idna.encode(unicodedata.normalize('NFC', host), uts46=False, std3_rules=True).decode('ascii')
            display_host = idna.decode(host)
        scheme = parts.scheme.lower()
        if parts.port is not None and parts.port != {'http': 80, 'https': 443}[scheme]:
            return None, display_host, 'invalid_port'
        if re.search(r'%(?![a-f0-9]{2})', raw, re.IGNORECASE):
            return None, display_host, 'invalid_url'
        netloc = '[' + host + ']' if ':' in host else host
        path = quote(parts.path or '/', safe="/%:@!$&'()*+,;=-._~")
        query = quote(parts.query, safe="/%?:@!$&'()*+,;=-._~")
        return urlunsplit((scheme, netloc, path, query, '')), display_host, None
    except (ValueError, idna.IDNAError, UnicodeError):
        return None, None, 'invalid_url'


def parse_message(text: str) -> ParsedMessage:
    """Preserve all original text; no destination I/O or spoof classification."""
    validate_message_text(text)
    normalized = ' '.join(unicodedata.normalize('NFKC', ''.join(
        c for c in text if not unicodedata.category(c).startswith('C') or c.isspace()
    )).split())
    links: list[LinkCandidate] = []
    seen: set[str] = set()
    prose_parts: list[str] = []
    last_end = 0
    for match in _CANDIDATES.finditer(text):
        raw = _trim_punctuation(match[0])
        if match.start() > 0 and text[match.start() - 1] == "'" and raw.endswith("'"):
            raw = _trim_punctuation(raw[:-1])
        explicit = '://' in raw or _explicit_scheme(raw) is not None
        if not explicit:
            # Plain dotted prose is not a link unless its suffix is recognized.
            bare_host = raw.split('/', 1)[0].split('?', 1)[0].split('#', 1)[0].split(':', 1)[0]
            if not split_domain(bare_host).suffix and not bare_host.endswith(('.example', '.test', '.invalid')):
                continue
        prose_parts.append(text[last_end:match.start()])
        last_end = match.end()
        canonical, host, error = _canonicalize(raw)
        identity = canonical or raw
        if identity in seen:
            continue
        seen.add(identity)
        if len(seen) > MAX_LINKS:
            raise ValueError('Message contains more than 10 distinct links')
        links.append(LinkCandidate(
            link_id=f'link_{len(links) + 1}', raw=raw, canonical_url=canonical,
            display_host=host, parse_error=error,
        ))
    prose_parts.append(text[last_end:])
    return ParsedMessage(
        text=text, normalized_text=normalized, links=links,
        supported_text=supported_text(' '.join(prose_parts)),
    )
