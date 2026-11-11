"""A small local blocklist used as one piece of evidence.

This is intentionally not threat intelligence: there are no remote feeds, DNS
or RDAP lookups, and a domain missing from the list proves nothing.
"""
from __future__ import annotations

BLOCKLISTED_DOMAINS = frozenset({'evil.com', 'phishingsite.com', 'malware.test'})
