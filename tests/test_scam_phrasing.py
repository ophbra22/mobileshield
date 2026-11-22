"""Common Israeli smishing phrasings (delivery, customs, bank) and their benign look-alikes."""
import pytest

from app.analysis import analyze_message
from app.message_models import MessageRequest


class _NoTransport:
    def inspect(self, *args, **kwargs):  # pragma: no cover - static checks only
        raise AssertionError('static analysis must not inspect links')


def run(text: str):
    return analyze_message(MessageRequest(text=text), request_id='test', transport=_NoTransport())


@pytest.mark.parametrize('text', [
    'דואר ישראל: החבילה שלך מעוכבת במרכז המיון. יש להסדיר דמי משלוח של 7.90 ₪ עד היום בחצות: '
    'https://israelpost-delivery.top/pay',
    'דואר ישראל: הסדירו את התשלום כדי לקבל את החבילה https://israelpost-delivery.top/pay',
    'בנק לאומי: עדכנו את פרטי האשראי שלכם תוך 24 שעות אחרת החשבון ייחסם https://leumi-secure.top',
    'Israel Post: settle the delivery fee today to release your parcel https://israelpost-delivery.top/pay',
])
def test_impersonated_payment_requests_are_phishing(text):
    result = run(text)
    assert result.assessment == 'phishing'
    assert 'payment_request' in {reason.code for reason in result.reasons}


@pytest.mark.parametrize('text', [
    'החבילה שלך ממתינה לשחרור. יש לשלם דמי מכס של 12 ₪ כאן: https://il-customs.top/pay',
    'Your parcel is held at customs. Pay the customs fee now: https://parcel-release.top',
])
def test_unbranded_fee_requests_are_at_least_suspicious(text):
    result = run(text)
    assert result.assessment in {'suspicious', 'phishing'}
    assert 'payment_request' in {reason.code for reason in result.reasons}


@pytest.mark.parametrize('text,code', [
    ('יש להסדיר את החוב היום', 'payment_request'),
    ('אמתו את פרטי הכרטיס בקישור', 'payment_request'),
    ('השלימו את התשלום עד היום', 'payment_request'),
])
def test_new_hebrew_request_verbs(text, code):
    assert code in {reason.code for reason in run(text).reasons}


@pytest.mark.parametrize('text', [
    'החבילה שלכם הגיעה לסניף, אפשר לאסוף אותה עד יום חמישי.',
    'עדכנו אותי מתי אתם מגיעים היום, נתראה בערב',
    'אל תעדכנו את פרטי האשראי בקישורים שמגיעים בהודעה',
    'Please update me when you arrive today',
    'Never verify your card details through a link in a text message',
])
def test_benign_and_negated_messages_stay_clear(text):
    result = run(text)
    assert not {'payment_request', 'credential_request'} & {reason.code for reason in result.reasons}


@pytest.mark.parametrize('text', [
    # The amount is the only payment cue; "7.90" must not split the clause at its decimal point.
    'דואר ישראל: החבילה שלך מעוכבת. יש לשלם 7.90 ש"ח עד היום: https://israelpost-delivery.top/pay',
    'דואר ישראל: החבילה שלך מעוכבת. לשחרור יש לשלם 7.90 ש״ח: https://israelpost-delivery.top/pay',
    'Israel Post: your parcel is on hold. Pay 7.90 ILS today: https://israelpost-delivery.top/pay',
    'Israel Post: your parcel is on hold. Please pay ₪7.90 today: https://israelpost-delivery.top/pay',
    'בנק לאומי: החשבון שלך יחסם. יש להעביר 250 ש"ח עכשיו: https://leumi-secure.xyz',
])
def test_bare_amount_payment_requests_are_phishing(text):
    result = run(text)
    assert result.assessment == 'phishing'
    assert 'payment_request' in {reason.code for reason in result.reasons}


@pytest.mark.parametrize('text', [
    'הפגישה מחר בשעה 10.30, תביא 50 ש"ח לאוכל',
    'המחיר ירד ל-49.90 ₪ בסוף השבוע',
    'אל תשלמו 7.90 ש"ח לאף אחד שמבקש בהודעה',
    "Don't pay 7.90 ILS to anyone who texts you about a parcel",
    'דואר ישראל: החבילה שלך הגיעה לסניף. לפרטים: https://www.israelpost.co.il',
])
def test_amounts_without_a_scam_request_stay_clear(text):
    result = run(text)
    assert 'payment_request' not in {reason.code for reason in result.reasons}
    assert result.assessment != 'phishing'
