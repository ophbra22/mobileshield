"""Plain data carriers shared by the detection modules."""
from __future__ import annotations

from dataclasses import dataclass
from typing import List, Optional


@dataclass
class URLParts:
    submitted_url: str
    normalized_url: str
    scheme: str
    hostname: str
    registrable_domain: str
    subdomain: str
    path: str
    query: str
    tld: str
    port: Optional[int]


@dataclass
class RedirectHop:
    url: str
    status: Optional[int]
    ip: Optional[str]
    ip_version: Optional[str]


@dataclass
class CertificateAnalysis:
    issuer: Optional[str]
    subject: Optional[str]
    valid_from: Optional[str]
    valid_to: Optional[str]
    valid_now: Optional[bool]
    hostname_matches: Optional[bool]
    error: Optional[str] = None


@dataclass
class ContentAnalysis:
    fetched: bool
    content_type: Optional[str]
    has_form: Optional[bool]
    credential_form: Optional[bool]
    payment_form: Optional[bool]
    brand_claim: Optional[str]
    outbound_domains: List[str]
    outbound_count: int
    outbound_samples: List[str]


@dataclass
class DomainAnalysis:
    hyphen_count: int
    subdomain_depth: int
    excessive_subdomains: bool
    has_at: bool
    has_encoded_chars: bool
    obfuscated: bool


@dataclass
class BrandAnalysis:
    impersonates_brand: bool
    brand: Optional[str]
    lookalike_score: Optional[int]
    method: Optional[str]
    brand_keyword_hits: List[str]
    brand_in_subdomain: bool

