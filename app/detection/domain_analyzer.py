from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

from app.detection.url_normalizer import split_domain

from app.detection.config import DEFAULT_CONFIG
from app.detection.models import DomainAnalysis, URLParts


def _is_ip_literal(hostname: str) -> bool:
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


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


def analyze_domain(parts: URLParts, raw_url: str, config=DEFAULT_CONFIG) -> DomainAnalysis:
    hostname = parts.hostname
    extracted = split_domain(hostname)
    tld = extracted.suffix.lower()
    subdomain_depth = len(extracted.subdomain.split('.')) if extracted.subdomain else 0
    hyphen_count = hostname.replace('xn--', '').count('-')
    path_lower = parts.path.lower()
    query_lower = parts.query.lower()
    hostname_lower = hostname.lower()
    phishing_keywords = [kw for kw in config.phishing_keywords if kw in path_lower or kw in query_lower or kw in hostname_lower]
    lure_keywords = [kw for kw in config.lure_keywords if kw in path_lower or kw in query_lower or kw in hostname_lower]
    long_path = len(parts.path) > 120
    long_query = len(parts.query) > 180
    has_at = _authority_has_at(raw_url)
    encoded_chars = _has_encoded(raw_url) or _has_encoded(parts.path) or _has_encoded(parts.query)
    suspicious_path = any(ch in parts.path for ch in ['//', '\\']) or encoded_chars
    is_ip_literal = _is_ip_literal(hostname)
    has_punycode = 'xn--' in hostname
    excessive_subdomains = subdomain_depth >= 4
    suspicious_tld = tld in config.suspicious_tlds
    obfuscated = encoded_chars or has_at
    hostname_length = len(hostname)

    trusted = _is_trusted(hostname, config.trusted_roots)

    return DomainAnalysis(
        is_ip_literal=is_ip_literal,
        suspicious_tld=suspicious_tld,
        hyphen_count=hyphen_count,
        subdomain_depth=subdomain_depth,
        excessive_subdomains=excessive_subdomains,
        has_punycode=has_punycode,
        has_at=has_at,
        has_encoded_chars=encoded_chars,
        obfuscated=obfuscated,
        phishing_keywords=phishing_keywords,
        lure_keywords=lure_keywords,
        long_path=long_path,
        long_query=long_query,
        suspicious_path=suspicious_path,
        hostname_length=hostname_length,
        tld=tld,
        trusted=trusted,
    )


def _is_trusted(hostname: str, trusted_roots: set[str]) -> bool:
    host = hostname.lower()
    for root in trusted_roots:
        root_l = root.lower()
        if host == root_l or host.endswith('.' + root_l):
            return True
    return False
