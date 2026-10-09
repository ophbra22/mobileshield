"""Limited local hints only: no RDAP, remote refresh, DNS or cache persistence."""
from __future__ import annotations
from types import SimpleNamespace

BLOCKLISTED_DOMAINS = {'evil.com', 'phishingsite.com', 'malware.test'}
_LOCAL_ALLOWLIST = frozenset({'google.com', 'microsoft.com', 'apple.com', 'paypal.com',
                            'github.com', 'cloudflare.com'})


def get_allowlist() -> set[str]:
    return set(_LOCAL_ALLOWLIST)


def allowlist_hit(domain: str) -> tuple[bool, str | None]:
    hit = domain.lower() in _LOCAL_ALLOWLIST
    return hit, 'local_allowlist' if hit else None


def get_or_compute_domain_reputation(db, domain: str):
    """Legacy return shape, computed in memory; an empty hint is not benign proof."""
    hit = domain.lower() in BLOCKLISTED_DOMAINS
    signals = {'local_blocklist_hit': hit, 'domain_age_days': None}
    reasons = ['Domain matches the limited local blocklist.'] if hit else []
    cache = SimpleNamespace(reputation='suspicious' if hit else 'unknown', score_hint=0,
                            signals=signals, sources={'local_only': True})
    return cache, signals, 0, reasons
