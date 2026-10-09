"""Modular phishing detection engine components."""

from app.detection.config import DEFAULT_CONFIG
from app.detection.models import DetectionResult

__all__ = ['run_detection', 'DEFAULT_CONFIG', 'DetectionResult']


def __getattr__(name):
    if name == 'run_detection':
        from app.detection.engine import run_detection
        return run_detection
    raise AttributeError(f'module {__name__!r} has no attribute {name!r}')
