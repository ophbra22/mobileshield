"""Link-level verdict from collected evidence."""
from __future__ import annotations


def classify_evidence(reasons, *, inspection_complete: bool):
    """Positive evidence survives unavailable checks and trusted-domain hints.

    Two distinct strong signals make a phishing verdict; any medium/strong
    signal is suspicious. Absence of evidence is only "no clear signs" when the
    requested inspection actually completed.
    """
    strong = {reason.code for reason in reasons if reason.strength == 'strong'}
    warning = any(reason.strength in {'medium', 'strong'} for reason in reasons)
    if len(strong) >= 2:
        return 'phishing'
    if warning:
        return 'suspicious'
    return 'no_clear_signs' if inspection_complete else 'unknown'
