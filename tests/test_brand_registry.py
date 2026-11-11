"""Brand registry: token matching, official domains and claim parity with the web client."""
import re
from pathlib import Path

import pytest

from app.analysis import analyze_message
from app.brand import BRANDS, KNOWN_BRAND_IDS, analyze_brand, claimed_brands, impersonated_brands
from app.message_models import MessageRequest


class _NoTransport:
    def inspect(self, *args, **kwargs):  # pragma: no cover - static checks only
        raise AssertionError('static analysis must not inspect links')


def run(text: str):
    return analyze_message(MessageRequest(text=text), request_id='test', transport=_NoTransport())


def codes(result) -> set[str]:
    return {reason.code for reason in result.reasons}


BRAND_EVIDENCE = {'brand_destination_mismatch', 'lookalike_host'}


@pytest.mark.parametrize('url', [
    # Brand names inside ordinary words are not brand tokens.
    'https://www.purchase.com/', 'https://boardgamegeek.com/', 'https://www.pineapple-recipes.com/',
    'https://www.applebees.com/', 'https://metacritic.com/', 'https://www.discountshoes.com/',
    'https://www.officedepot.com/', 'https://outlookindia.com/', 'https://www.telegraf.com/', 'https://apply.com/',
    # Official domains, including ones that were missing or misspelled.
    'https://www.wellsfargo.com/', 'https://www.hsbcnet.com/', 'https://www.mizrahi-tefahot.co.il/',
    'https://www.fibi.co.il/', 'https://www.onezerobank.com/', 'https://www.israelpost.co.il/',
    'https://www.microsoft.com/', 'https://accounts.google.com/',
])
def test_ordinary_and_official_hosts_have_no_brand_evidence(url):
    assert not codes(run(url)) & BRAND_EVIDENCE


@pytest.mark.parametrize('url,expected', [
    ('https://paypal-login.attacker.com/', 'brand_destination_mismatch'),
    ('https://paypalsecure.com/', 'brand_destination_mismatch'),
    ('https://apple-id-verify.com/', 'brand_destination_mismatch'),
    ('https://office365-login.xyz/', 'brand_destination_mismatch'),
    ('https://evil.com/paypal/login', 'brand_destination_mismatch'),
    ('https://israelpost-delivery.top/pay', 'brand_destination_mismatch'),
    ('https://paypa1-secure.top/verify', 'lookalike_host'),
    ('https://rnicrosoft.com/', 'lookalike_host'),
    ('https://googIe.com/', 'lookalike_host'),
    ('https://mircosoft.com/', 'lookalike_host'),
    ('https://whatsap.com/', 'lookalike_host'),
])
def test_impersonating_hosts_are_flagged(url, expected):
    assert expected in codes(run(url))


def test_misspelled_bank_domain_is_not_treated_as_official():
    # The registry previously trusted 'mizrahitfahot.co.il' instead of the real domain.
    assert 'mizrahitfahot.co.il' not in BRANDS['mizrahi'].roots
    assert 'mizrahi-tefahot.co.il' in BRANDS['mizrahi'].roots
    assert BRANDS['beinleumi'].roots == {'fibi.co.il'}


@pytest.mark.parametrize('text', [
    'Get a 20% discount on shoes today at https://www.amazon.com/deals',
    'Meeting moved, the office is closed. Agenda: https://zoom.us/j/123',
    'Hi, check our new pepper recipe https://www.allrecipes.com/recipe/1',
    'I ate an apple https://example.com/',
    'ביטוח לאומי: https://www.btl.gov.il/',
    'Your visa appointment https://travel.example/',
])
def test_common_words_are_not_brand_claims(text):
    assert 'brand_destination_mismatch' not in codes(run(text))


@pytest.mark.parametrize('text,brand', [
    ('Discount Bank: verify your account', 'discount'),
    ('Your Microsoft Office 365 password expires', 'office'),
    ('Apple ID locked', 'appleid'),
    ('בנק לאומי: החשבון שלך ייחסם', 'leumi'),
    ('הודעה מבנק הפועלים', 'hapoalim'),
    ('דואר ישראל: החבילה שלך מעוכבת', 'israelpost'),
    ('שלחו לנו בוואטסאפ', 'whatsapp'),
    ('PayPal: confirm your details', 'paypal'),
])
def test_explicit_brand_claims_in_english_and_hebrew(text, brand):
    assert brand in claimed_brands(text)


def test_hebrew_smishing_example_is_phishing():
    result = run('דואר ישראל: החבילה שלך מעוכבת, שלם דמי משלוח https://israelpost-delivery.top/pay')
    assert result.assessment == 'phishing'


def test_brand_on_another_brands_domain_is_still_impersonation():
    assert impersonated_brands('paypal.google.com') == ['paypal']


def test_lookalike_ignores_exact_and_unrelated_tokens():
    assert analyze_brand('paypal.com') is None
    assert analyze_brand('pineapple.com') is None
    assert analyze_brand('paypa1.com').brand == 'paypal'


def test_web_client_accepts_every_brand_the_api_can_return():
    source = Path(__file__).resolve().parents[1] / 'mobileshield-web' / 'lib' / 'analysis.ts'
    match = re.search(r'^const brands = \[(.*)\];$', source.read_text(), re.M)
    assert match, 'brand list not found in lib/analysis.ts'
    client_brands = set(re.findall(r"'([a-z]+)'", match.group(1)))
    assert client_brands == set(KNOWN_BRAND_IDS)
