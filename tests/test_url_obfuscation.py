"""Percent-encoding and '@' only count as obfuscation when they hide something."""
import pytest

from app.detection.domain_analyzer import analyze_domain
from app.detection.url_normalizer import normalize_url


def obfuscated(url: str) -> bool:
    return analyze_domain(normalize_url(url), url).obfuscated


@pytest.mark.parametrize('url', [
    'https://www.ynet.co.il/news/%D7%9E%D7%91%D7%A6%D7%A2',  # Hebrew path (UTF-8)
    'https://example.com/my%20file.pdf',
    'https://example.com/search?q=a%26b%3Dc',
    'https://medium.com/@ophir/my-post',
])
def test_normal_urls_are_not_obfuscated(url):
    assert not obfuscated(url)


@pytest.mark.parametrize('url', [
    'https://example.com/%70aypal',      # encoded letter
    'https://example.com/a%2e%2e/b',     # encoded dots
    'https://example.com/%40evil',       # encoded @
    'https://example.com/%2570aypal',    # double encoding
])
def test_hidden_characters_are_obfuscated(url):
    assert obfuscated(url)


def test_hebrew_link_in_message_is_not_suspicious():
    from tests.test_brand_registry import run
    result = run('קופון הנחה https://www.ynet.co.il/news/article/מבצע')
    assert 'suspicious_obfuscation' not in {reason.code for reason in result.reasons}
