"""Certificate evidence from verified transport; never opens its own socket."""
from __future__ import annotations

from typing import TYPE_CHECKING

from app.detection.models import CertificateAnalysis

if TYPE_CHECKING:
    from app.detection.safe_transport import UrlObservation


def fetch_certificate(observation: UrlObservation | None) -> CertificateAnalysis:
    if observation is not None and observation.tls is not None:
        return observation.tls
    return CertificateAnalysis(None, None, None, None, None, None)
