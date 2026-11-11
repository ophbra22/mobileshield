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
