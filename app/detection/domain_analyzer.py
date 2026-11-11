from __future__ import annotations

import re
from urllib.parse import urlsplit

from app.detection.models import DomainAnalysis, URLParts
from app.detection.url_normalizer import split_domain

_PERCENT_ESCAPE = re.compile(r'%([0-9a-fA-F]{2})')


def _has_encoded(text: str) -> bool:
    """Detect escapes that hide characters which never need encoding.

    UTF-8 escapes (``%D7%91`` for Hebrew) and encoded separators such as spaces
    are normal in real URLs. Encoding plain letters, digits, dots or ``@``
    (``%70aypal``, ``%2e``, ``%40``) or double encoding (``%25``) only obscures it.
    """
    if '\\x' in text:
        return True
    for match in _PERCENT_ESCAPE.finditer(text):
        value = int(match.group(1), 16)
        if value < 0x80 and (chr(value).isalnum() or chr(value) in '-._~@%'):
            return True
    return False


def _authority_has_at(raw_url: str) -> bool:
    try:
        return '@' in urlsplit(raw_url if '://' in raw_url else 'https://' + raw_url).netloc
    except ValueError:
        return False


def analyze_domain(parts: URLParts, raw_url: str) -> DomainAnalysis:
    """Structural URL facts: hidden characters and unusually deep or hyphenated hosts."""
    hostname = parts.hostname
    extracted = split_domain(hostname)
    subdomain_depth = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    has_at = _authority_has_at(raw_url)
    encoded_chars = _has_encoded(raw_url) or _has_encoded(parts.path) or _has_encoded(parts.query)
    return DomainAnalysis(
        hyphen_count=hostname.replace('xn--', '').count('-'),
        subdomain_depth=subdomain_depth,
        excessive_subdomains=subdomain_depth >= 4,
        has_at=has_at,
        has_encoded_chars=encoded_chars,
        obfuscated=encoded_chars or has_at,
    )
