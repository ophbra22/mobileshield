"""Small local lists used as individual pieces of evidence.

This is intentionally not threat intelligence: there are no remote feeds, DNS
or RDAP lookups, and a domain missing from a list proves nothing.
"""
from __future__ import annotations

BLOCKLISTED_DOMAINS = frozenset({'evil.com', 'phishingsite.com', 'malware.test'})

# Public link shorteners. A short link hides where it leads until it is followed,
# so it is only evidence while the destination has not been inspected.
LINK_SHORTENERS = frozenset({
    'bit.ly', 'bitly.com', 'tinyurl.com', 't.co', 'goo.gl', 'is.gd', 'v.gd', 'cutt.ly', 'rb.gy', 't.ly', 'ow.ly',
    'buff.ly', 'rebrand.ly', 'shorturl.at', 'tiny.cc', 'did.li', 'bit.do', 's.id', 'shorter.me', 'lnk.bio',
})

# Domain endings that are cheap or free to register and dominate abuse reports.
# Deliberately short: common endings with wide ordinary use (.xyz, .info, .site,
# .click) are left out so an unfamiliar domain is not a warning by itself.
HIGH_ABUSE_SUFFIXES = frozenset({
    'top', 'icu', 'cfd', 'sbs', 'buzz', 'rest', 'win', 'bid', 'loan', 'cyou', 'monster', 'quest',
    'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov',
})
