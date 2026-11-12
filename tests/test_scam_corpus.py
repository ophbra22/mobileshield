"""Realistic scam and ordinary messages checked without visiting any link.

The scam samples must raise a warning; the ordinary ones must not. Each sample
is a pattern seen in Israeli and English smishing: fees for held parcels, blocked
cards, refunds nobody asked for, look-alike and disguised links, and requests
for codes or money with no link at all.
"""
import pytest

from app.analysis import analyze_message
from app.detection.models import RedirectHop
from app.detection.safe_transport import UrlObservation
from app.message_models import MessageRequest
from app.routers.auth import LoginRequest, RegisterRequest

SCAMS = [
    ('he-post-fee',
     'דואר ישראל: החבילה שלך ממתינה במכס. יש לשלם דמי שחרור בסך 12.90 ש"ח תוך 24 שעות: https://israelpost-delivery.top/pay'),
    ('he-post-nobrand',
     'החבילה שלך לא נמסרה עקב כתובת שגויה. לעדכון הכתובת לחץ כאן: https://il-parcel-track.com/update'),
    ('he-bank-leumi',
     'בנק לאומי: זיהינו פעילות חריגה בחשבונך. החשבון ייחסם תוך 24 שעות. לאימות הפרטים היכנס: https://leumi-secure.co/login'),
    ('he-hapoalim',
     'לקוח יקר, חשבונך בבנק הפועלים הושעה זמנית. לשחרור החשבון יש לאמת את פרטיך בקישור http://bit.ly/3xYzAbc'),
    ('he-kvish6',
     'כביש 6: טרם שולם חוב על נסיעה. למניעת קנס יש להסדיר את התשלום היום: https://kvish6-pay.info/il'),
    ('he-bit',
     'קיבלת העברה של 350 ש"ח באפליקציית ביט. לקבלת הכסף לחץ: https://bit-pay.site/claim'),
    ('he-otp',
     'שלום, זה מהבנק. שלח לי בבקשה את קוד האימות שקיבלת עכשיו ב-SMS כדי שנבטל את העסקה'),
    ('he-whatsapp-code',
     'היי, שלחתי לך בטעות קוד בן 6 ספרות בסמס, אתה יכול להעביר לי אותו? דחוף'),
    ('he-tax',
     'רשות המסים: מגיע לך החזר מס בסך 1,240 ש"ח. למילוי הפרטים לקבלת ההחזר: https://gov-il-refund.com/tax'),
    ('he-netflix',
     'Netflix: התשלום האחרון נכשל. עדכנו את פרטי האשראי כדי להמשיך ליהנות מהשירות: https://netflix-billing-il.com'),
    ('he-cal',
     'כאל: כרטיסך נחסם עקב חשד לשימוש לרעה. להסרת החסימה: https://cal-online-secure.net/unblock'),
    ('he-bituach',
     'ביטוח לאומי: זכאותך למענק אושרה. יש להזין פרטי חשבון בנק לקבלת המענק https://btl-gov.org/grant'),
    ('he-job',
     'שלום! אנחנו מגייסים עובדים מהבית, 800-2000 ש"ח ליום. לפרטים בוואטסאפ: https://wa.me/972500000000'),
    ('en-paypal',
     'PayPal: Your account has been limited. Verify your identity now to avoid suspension: https://paypal-secure-login.com/verify'),
    ('en-paypa1',
     "Your PayPal payment of $499.99 was processed. If this wasn't you, cancel here: https://paypa1.com/cancel"),
    ('en-usps',
     'USPS: Your package could not be delivered due to an incomplete address. Update here: https://usps-redelivery.top/addr'),
    ('en-apple',
     'Apple ID: Your account was locked for security reasons. Sign in to unlock: http://appleid.apple.com.verify-user.info/'),
    ('en-ms',
     'Microsoft account team: unusual sign-in activity. Confirm your password within 24 hours or your account will be closed: https://rnicrosoft-account.com'),
    ('en-bank-ip',
     'Chase Bank alert: suspicious transaction of $920. Log in to review: http://185.23.44.12/chase/login'),
    ('en-otp',
     "Hi, this is your bank's fraud team. Please reply with the verification code we just sent you."),
    ('en-crypto',
     'Congratulations! You won 0.5 BTC. Claim your prize now: https://binance-rewards.xyz/claim'),
    ('en-short',
     'Your Netflix subscription has expired. Renew: https://tinyurl.com/2p9abcd'),
    ('en-at',
     'Amazon: order #112-99 on hold. Update payment method: https://amazon.com@secure-pay.ru/update'),
    ('en-homograph',
     'Google security alert: sign in to review https://gооgle.com/security'),
    ('en-toll',
     'E-ZPass: You have an unpaid toll of $4.15. Pay now to avoid a $50 late fee: https://ezpass-tolls.cc/pay'),
    ('en-boss',
     "Hi, I'm in a meeting and need you to buy 5 Amazon gift cards urgently and send me the codes."),
    ('mixed-leumi',
     'Leumi: יש לאמת את חשבונך. הזן את הסיסמה שלך כאן https://leumi.co.il.verify-id.com'),
]

ORDINARY = [
    ('he-friend',
     'היי מה קורה? נפגשים מחר בשמונה בקפה?'),
    ('he-otp-real',
     'קוד האימות שלך הוא 482913. אין למסור את הקוד לאף אחד.'),
    ('he-leumi-real',
     'בנק לאומי: דף החשבון החודשי שלך זמין לצפייה באתר https://www.leumi.co.il'),
    ('he-post-real',
     'דואר ישראל: החבילה שלך הגיעה לסניף. פרטים: https://israelpost.co.il/itemtrace'),
    ('he-doctor',
     'תזכורת: נקבע לך תור לרופא ביום שלישי בשעה 10:30. לביטול השיבו 2.'),
    ('he-delivery',
     'השליח בדרך אליך ויגיע בין 14:00 ל-16:00.'),
    ('en-friend',
     'Hey, are we still on for dinner tomorrow at 7?'),
    ('en-otp-real',
     'Your verification code is 123456. Do not share this code with anyone.'),
    ('en-paypal-real',
     'You sent a payment of $20.00 to John. View details at https://www.paypal.com/activity'),
    ('en-google-real',
     'Check out this doc: https://docs.google.com/document/d/abc123/edit'),
    ('en-github',
     'The PR is ready for review https://github.com/ophbra22/mobileshield/pull/8'),
    ('en-amazon-real',
     'Your Amazon order has shipped. Track it at https://www.amazon.com/gp/your-account/order-history'),
    ('en-pay-friend',
     'Can you pay me back the 50 shekels for pizza today?'),
    ('he-pay-friend',
     'תעביר לי בבקשה את הכסף על הפיצה היום'),
    ('en-news',
     'Interesting article about phishing: https://www.bbc.com/news/technology-123'),
    ('he-school',
     'הורים יקרים, מחר טיול שנתי. נא לשלם 40 ש"ח דרך אתר בית הספר.'),
]


class _NoTransport:
    def inspect(self, *args, **kwargs):  # pragma: no cover - static checks only
        raise AssertionError('static analysis must not inspect links')


def run(text: str):
    return analyze_message(MessageRequest(text=text), request_id='test', transport=_NoTransport())


def codes(result) -> set[str]:
    return {reason.code for reason in result.reasons}


@pytest.mark.parametrize('name,text', SCAMS, ids=[name for name, _ in SCAMS])
def test_scam_messages_raise_a_warning(name, text):
    result = run(text)
    assert result.assessment in ('phishing', 'suspicious')
    assert result.reasons
    assert 'verify_independently' in result.recommended_actions


@pytest.mark.parametrize('name,text', ORDINARY, ids=[name for name, _ in ORDINARY])
def test_ordinary_messages_stay_clear(name, text):
    result = run(text)
    assert (result.assessment, result.analysis_status) == ('no_clear_signs', 'complete')
    assert result.reasons == []


def test_login_threat_with_mismatched_bank_domain_is_phishing():
    result = run('בנק לאומי: החשבון ייחסם תוך 24 שעות. לאימות הפרטים היכנס: https://leumi-secure.co/login')
    assert result.assessment == 'phishing'
    assert {'brand_destination_mismatch', 'credential_request'} <= codes(result)


@pytest.mark.parametrize('url', ['https://gооgle.com/security', 'https://xn--ggle-55da.com/security',
                                 'https://pаypal.com/', 'https://аpple.com/id'])
def test_cyrillic_lookalike_host_is_phishing_without_a_brand_claim(url):
    result = run('sign in ' + url)
    assert result.assessment == 'phishing'
    assert {'lookalike_host', 'brand_destination_mismatch'} <= codes(result)


@pytest.mark.parametrize('url', ['https://пример.рф/', 'https://דוגמה.co.il/', 'https://münchen.de/'])
def test_ordinary_internationalized_hosts_are_not_lookalikes(url):
    assert not codes(run('see ' + url)) & {'lookalike_host', 'brand_destination_mismatch', 'suspicious_obfuscation'}


def test_public_ip_link_is_suspicious():
    result = run('Log in to review: http://185.23.44.12/login')
    assert result.assessment == 'suspicious'
    assert 'suspicious_obfuscation' in codes(result)


def test_userinfo_disguise_is_suspicious_and_never_echoed():
    result = run('Check this https://amazon.com@secure-pay.ru/update')
    assert result.assessment == 'suspicious'
    assert 'suspicious_obfuscation' in codes(result)
    assert 'secure-pay' not in result.model_dump_json()


def test_bare_shortened_link_is_unknown_not_clear():
    result = run('Check out our new blog post https://bit.ly/3blogpost')
    assert (result.assessment, result.analysis_status) == ('unknown', 'partial')
    assert [(reason.code, reason.strength) for reason in result.reasons] == [('shortened_link', 'info')]
    assert 'consider_link_inspection' in result.recommended_actions


def test_shortened_link_is_a_warning_when_the_message_gives_it_weight():
    result = run('Your parcel is waiting: https://bit.ly/3abcd')
    assert result.assessment == 'suspicious'
    assert {'shortened_link', 'scam_scenario'} <= codes(result)


def test_followed_shortened_link_is_judged_by_where_it_lands():
    class Transport:
        def inspect(self, url, *, deadline):
            hops = [RedirectHop(url, 302, '1.1.1.1', 'ipv4'), RedirectHop('http://example.org/', 200, '1.1.1.1', 'ipv4')]
            return UrlObservation(final_url='http://example.org/', hops=hops, html='<html><body>Hello</body></html>',
                                  content_type='text/html', completed_checks=['http', 'html'])
    result = analyze_message(MessageRequest(text='http://bit.ly/abc', inspect_links=True),
                             request_id='test', transport=Transport())
    assert 'shortened_link' not in codes(result)
    assert result.assessment == 'no_clear_signs'


def test_high_abuse_domain_ending_is_a_warning_only_before_inspection():
    assert 'high_abuse_domain_ending' in codes(run('Update your details: https://my-new-shop.top/'))
    assert 'high_abuse_domain_ending' not in codes(run('Our new site: https://my-new-shop.xyz/'))


@pytest.mark.parametrize('text', [
    'תעביר לי בבקשה את הכסף על הפיצה היום',
    'אפשר להעביר לי 100 שקל בביט על המתנה של דנה?',
    'Can you send me the money for the tickets today?',
])
def test_plain_money_request_between_people_is_not_a_warning(text):
    result = run(text)
    assert result.assessment == 'no_clear_signs'
    assert result.reasons == []


@pytest.mark.parametrize('text', [
    'אמא, הטלפון שלי נשבר. זה המספר החדש שלי. תעבירי לי 2000 שקל בביט דחוף',
    'Hi dad, I dropped my phone, this is my new number. Can you send me 600 urgently?',
    'I need you to buy 5 gift cards urgently and send me the codes.',
])
def test_money_request_under_pressure_or_from_a_new_number_is_suspicious(text):
    assert run(text).assessment == 'suspicious'


@pytest.mark.parametrize('text', ['Please provide your bank details.', 'שלח לי את פרטי האשראי שלך'])
def test_request_for_financial_details_is_always_a_warning(text):
    result = run(text)
    assert result.assessment == 'suspicious'
    assert ('payment_request', 'strong') in {(reason.code, reason.strength) for reason in result.reasons}


@pytest.mark.parametrize('text', [
    'Your account is locked. Sign in at https://www.paypal.com/signin',
    'המשלוח נכשל כי לא הייתם בבית, נגיע שוב מחר בין 10 ל-12.',
    'זכית במקום הראשון בתחרות הכיתתית, כל הכבוד!',
    'I work from home on Thursdays, so let us meet on Wednesday.',
])
def test_scenario_wording_without_an_unknown_link_is_not_a_warning(text):
    assert 'scam_scenario' not in codes(run(text))


@pytest.mark.parametrize('text', [
    'מבזק חדשות: כל הפרטים באתר https://www.example.com/news',
    'התייחס אליו כאל חבר https://www.example.com/',
    'הוא לא הפסיק להביט בתמונה https://www.example.com/',
])
def test_hebrew_words_that_resemble_brand_names_are_not_claims(text):
    assert 'brand_destination_mismatch' not in codes(run(text))


@pytest.mark.parametrize('brand,host', [
    ('cal', 'www.cal-online.co.il'), ('isracard', 'digital.isracard.co.il'), ('kvish', 'www.kvish6.co.il'),
    ('bituachleumi', 'www.btl.gov.il'), ('taxauthority', 'www.gov.il'), ('netflix', 'www.netflix.com'),
])
def test_new_brands_recognize_their_official_hosts(brand, host):
    from app.brand import BRANDS, is_official_domain
    assert any(is_official_domain(host, root) for root in BRANDS[brand].roots)


@pytest.mark.parametrize('model', [RegisterRequest, LoginRequest])
def test_auth_models_enforce_password_length_on_validation(model):
    from pydantic import TypeAdapter, ValidationError
    adapter = TypeAdapter(model)  # the path FastAPI uses for request bodies
    with pytest.raises(ValidationError):
        adapter.validate_python({'email': 'a@example.com', 'password': 'x'})
    with pytest.raises(ValidationError):
        adapter.validate_python({'email': 'a@example.com', 'password': 'x' * 73})
    assert adapter.validate_python({'email': 'a@example.com', 'password': 'long-enough'}).password == 'long-enough'
