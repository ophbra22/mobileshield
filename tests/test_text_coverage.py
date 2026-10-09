"""Independent everyday prose and uncertainty controls; no live destinations."""
from unittest.mock import Mock

import pytest

from app.message_parser import parse_message
from tests.test_message_analysis import run
from tests.test_message_api import client
from tests.test_scan_integration import frontend_roundtrip

ORDINARY = [
    'Hi, our book club meets tomorrow at ten by the library. See you then!',
    'Miriam left the casserole in our refrigerator after rehearsal.',
    'The plumber will replace a washer beneath the kitchen sink.',
    'Could you bring Juniper her binoculars before the birdwatching trip?',
    'Our pottery workshop has moved to the courtyard behind the museum.',
    'I watered the chrysanthemums while you were visiting Edinburgh.',
    'The pediatrician rescheduled our appointment for Wednesday afternoon.',
    'Please put the recyclable packaging beside your blue wheelie bin.',
    'We reviewed the prototype with Anjali and agreed on smaller hinges.',
    'Your sourdough starter is bubbling nicely on the counter.',
    'I’ll collect the repaired saxophone after my shift ends.',
    'Are the marmalade jars still in the cupboard above the oven?',
    'The astronomy society is meeting near the observatory at dusk.',
    'We can discuss Reykjavík and São Paulo after the presentation.',
    'שלום, השארתי את התבשיל של נעמי במקרר אחרי החזרה.',
    'אנחנו נפגשים עם אביגיל ליד המצפה ביום רביעי.',
    'השרברב יחליף את האטם שמתחת לכיור שלנו מחר.',
    'אפשר להביא את המשקפת לטיול הצפרות בשבת?',
    'הסדנה לקרמיקה עברה לחצר שמאחורי המוזיאון.',
    'השקיתי את החרציות בזמן שהייתם בירושלים.',
    'האם הצנצנות עדיין בארון שמעל התנור שלנו?',
    'אני אאסוף את הסקסופון המתוקן אחרי המשמרת.',
    'בבקשה הניחו את האריזות למחזור ליד הפח הכחול.',
    'שָׁלוֹם, אנחנו מחכים לכם ליד הספרייה.',
    'We will meet tomorrow. אנחנו נביא את המחברות שלנו.',
]
UNCERTAIN = [
    '请明天把文件带到办公室', 'Принесите документы завтра утром',
    'يرجى إحضار الأوراق غدا', 'Envoyez moi votre mot de passe.',
    'Senden Sie mir sofort Ihr Passwort.', 'Veuillez transmettre vos identifiants.',
    'Hola necesitamos revisar nuestros documentos mañana.',
    'We will meet tomorrow. Veuillez transmettre vos identifiants.',
    'אנחנו ניפגש מחר. Envoyez moi votre mot de passe.',
    'the.we.you@example.com', 'https://example.com/we/are/in/the/house',
    'Veuillez transmettre vos identifiants https://example.com/hello/the/you',
    'qwerty asdfgh zxcvbn', 'the qwerty is asdfgh',
    'blorf zindle prant fleep', 'xqzv pktr bnnm',
    'hello hello hello hello hello hello', 'aaaaaa bbbbbb cccccc',
    'שדגכ עיחל ךףזס', 'אני ששששש את דדדדד',
    'שלום שלום שלום שלום שלום שלום', 'אבגדהוזחטיכלמנסעפצקרשת',
    'פלרק זנדר קטרפ', 'Abigail', 'מסוק', 'a', 'של', '🙂 123 !!!',
    'Our workshop is tomorrow 你好',
]
SUSPICIOUS = ('Urgent! Your account will be blocked in one hour. Enter your password '
              'and verification code now at https://account-verify.example.com/login '
              'or http://security-update.example.net/confirm .')


@pytest.mark.parametrize('text', ORDINARY)
def test_practical_prose_is_covered(text):
    assert parse_message(text).supported_text
    result = run(text)
    assert (result.assessment, result.analysis_status) == ('no_clear_signs', 'complete')
    assert 'unsupported_text' not in result.limitations


@pytest.mark.parametrize('text', UNCERTAIN)
def test_insufficient_or_unsupported_prose_retains_uncertainty(text):
    assert not parse_message(text).supported_text
    result = run(text)
    assert result.assessment == 'unknown'
    assert result.analysis_status == ('partial' if result.links else 'unavailable')
    if not result.links or text != 'https://example.com/we/are/in/the/house':
        assert 'unsupported_text' in result.limitations


@pytest.mark.parametrize('prefix', ['Hello, ', 'Hello! ', 'שלום, ', 'שלום! '])
@pytest.mark.parametrize('body,supported', [
    ('Our neighbors brought a mandolin to the picnic.', True),
    ('אנחנו נביא את המחברות שלנו מחר.', True),
    ('Veuillez transmettre vos identifiants et documents personnels.', False),
    ('Senden Sie mir Ihre Unterlagen morgen früh.', False),
    ('פלרק זנדר קטרפ ששששש', False),
])
def test_greeting_prefix_cannot_change_substantial_prose_coverage(prefix, body, supported):
    assert parse_message(body).supported_text is supported
    assert parse_message(prefix + body).supported_text is supported


@pytest.mark.parametrize('warning,code', [
    ('Send me your password now.', 'credential_request'),
    ('Please provide your bank details.', 'payment_request'),
    ('שלח לי את הסיסמה שלך עכשיו.', 'credential_request'),
    ('שלם את התשלום עכשיו.', 'payment_request'),
])
@pytest.mark.parametrize('tail', [' Veuillez transmettre vos identifiants.', ' ששששש דדדדד'])
def test_warning_evidence_survives_unsupported_segments(warning, code, tail):
    transport = Mock()
    result = run(warning + tail, transport=transport)
    assert result.assessment in ('suspicious', 'phishing')
    assert result.analysis_status == 'partial'
    assert 'unsupported_text' in result.limitations
    assert code in {reason.code for reason in result.reasons}
    transport.inspect.assert_not_called()


def test_exact_live_cases_through_asgi_and_actual_client_parser(client):
    ordinary = client.post('/v1/analyze-message', json={'text': ORDINARY[0], 'inspect_links': False})
    assert ordinary.status_code == 200
    value = ordinary.json()
    assert (value['assessment'], value['analysis_status']) == ('no_clear_signs', 'complete')
    assert value['links'] == []
    assert 'unsupported_text' not in value['limitations']
    warning = client.post('/v1/analyze-message', json={'text': SUSPICIOUS, 'inspect_links': False})
    assert warning.status_code == 200
    result = warning.json()
    assert result['assessment'] in ('suspicious', 'phishing')
    assert result['analysis_status'] == 'complete'
    assert {'credential_request', 'urgency'} <= {r['code'] for r in result['reasons']}
    assert result['limitations'] == ['inspection_disabled']
    assert [link['display_host'] for link in result['links']] == ['account-verify.example.com', 'security-update.example.net']
    assert all(link['inspection_status'] == 'not_requested' for link in result['links'])
    client.transport_spy.inspect.assert_not_called()
    frontend_roundtrip([value, result])

@pytest.mark.parametrize('text', [
    'Please bring several extra warm woollen blankets tomorrow.',
    'We stored delicate antique hand painted porcelain serving bowls in the cupboard.',
    'Our neighborhood orchestra rehearses unfamiliar contemporary experimental chamber music after lunch.',
])
def test_content_heavy_phrases_bounded_by_structural_context(text):
    assert parse_message(text).supported_text


@pytest.mark.parametrize('text', [
    'We will meet tomorrow veuillez transmettre vos identifiants et documents personnels',
    'Hello our meeting is tomorrow veuillez transmettre vos identifiants et documents personnels',
    'אנחנו ניפגש מחר veuillez transmettre vos identifiants et documents personnels',
])
def test_substantial_unanchored_tail_cannot_borrow_supported_prefix(text):
    assert not parse_message(text).supported_text

@pytest.mark.parametrize('text', [
    'Our compost improves our vegetable patch.',
    'Your violin needs your replacement strings.',
    'The curator catalogued the fragments.',
])
def test_repeated_grammatical_markers_still_supply_structure(text):
    assert parse_message(text).supported_text

@pytest.mark.parametrize('text', [
    'אנחנו כאן ליד הבית שלנו עכשיו פלרק זנדר קטרפ דרנפ צרנפ',
    'We are here at our home now blorf zindle prant fleep drant',
])
def test_long_structural_prefix_cannot_cover_an_unanchored_tail(text):
    assert not parse_message(text).supported_text

@pytest.mark.parametrize('text', [
    'We will meet tomorrow. Veuillez transmettre. Vos identifiants. Et documents.',
    'אנחנו ניפגש מחר. פלרק זנדר. קטרפ דרנפ.',
])
def test_short_fragments_cannot_collectively_hide_substantial_unsupported_text(text):
    assert not parse_message(text).supported_text


def test_a_short_heading_and_name_can_use_substantial_context():
    assert parse_message('Reminder! Juniper. We will bring your notebook tomorrow.').supported_text

# Review I1: inspect repetition before dropping greetings, across punctuation,
# and even when a separate warning provides independent actionable evidence.
REPEATED_PROSE = [
    'hello thanks goodbye ' * 20,
    'the and for ' * 20,
    'אני אתה הוא ' * 20,
    'Hello! Thanks, goodbye. ' * 4,
    'אני; אתה! הוא? ' * 4,
    'we will bring the plates tomorrow ' * 3,
    'we will bring the plates and cups tomorrow while you collect our bowls from your cupboard again ' * 3,
    'hello thanks goodbye ' * 476 + 'hi! ',
]


@pytest.mark.parametrize('text', REPEATED_PROSE)
def test_multiword_cycles_are_uncertain_before_greeting_removal(text):
    assert not parse_message(text).supported_text
    result = run(text)
    assert (result.assessment, result.analysis_status) == ('unknown', 'unavailable')
    assert result.limitations == ['unsupported_text']


def test_repeated_greeting_boundary_is_exactly_ten_thousand_codepoints():
    assert len(REPEATED_PROSE[-1]) == 10_000


@pytest.mark.parametrize('text', REPEATED_PROSE[:-1])
def test_repeated_prose_keeps_warning_but_not_complete_coverage(text):
    transport = Mock()
    result = run(text + ' Send me your password now.', transport=transport)
    assert result.assessment == 'suspicious'
    assert result.analysis_status == 'partial'
    assert {'credential_request', 'urgency'} <= {reason.code for reason in result.reasons}
    assert 'unsupported_text' in result.limitations
    transport.inspect.assert_not_called()


@pytest.mark.parametrize('text', [
    'We will bring plates, we will bring cups, and we will bring napkins.',
    'Our compost improves our garden, and our mulch protects our seedlings.',
    'אני אביא צלחות, אתה תביא כוסות, והוא יביא מפיות.',
])
def test_repeated_grammatical_frames_with_different_content_are_ordinary(text):
    assert parse_message(text).supported_text


# Review I2 plus independent expansions in different everyday domains.
ORDINARY_EXPANSIONS = [
    ('Our neighbors adopted kittens.', 'Our neighbors adopted two kittens.'),
    ('My brother plays basketball.', 'My brother plays professional basketball.'),
    ('The children enjoyed swimming.', 'The children enjoyed building sandcastles.'),
    ('Our neighbors adopted two kittens.', 'Our cheerful neighbors adopted two playful kittens.'),
    ('My brother plays professional basketball.', 'My younger brother enthusiastically plays professional basketball.'),
    ('The children enjoyed building sandcastles.', 'The happy children enjoyed building elaborate sandcastles.'),
    ('Her students practise calligraphy.', 'Her enthusiastic students practise decorative copperplate calligraphy.'),
    ('Their grandmother repairs clocks.', 'Their grandmother expertly repairs delicate antique clocks.'),
    ('Please bring some cookies.', 'Please bring some freshly baked chocolate chip cookies.'),
    ('We packed the mugs.', 'We packed the delicate hand painted ceramic coffee mugs.'),
]


@pytest.mark.parametrize('original,expanded', ORDINARY_EXPANSIONS)
def test_ordinary_modifier_expansions_retain_coverage(original, expanded):
    for text in (original, expanded):
        assert parse_message(text).supported_text
        result = run(text)
        assert (result.assessment, result.analysis_status) == ('no_clear_signs', 'complete')
        assert 'unsupported_text' not in result.limitations


@pytest.mark.parametrize('text', [
    'Our neighbors adopted kittens. Veuillez transmettre vos identifiants.',
    'Please bring some cookies. Senden Sie mir Ihre Unterlagen morgen früh.',
    'My brother plays professional basketball. פלרק זנדר קטרפ',
    'We will meet tomorrow veuillez transmettre vos identifiants et documents personnels',
])
def test_expansion_tolerance_does_not_cover_unsupported_passages(text):
    assert not parse_message(text).supported_text


def test_review_regressions_through_asgi_and_client_parser(client):
    values = []
    for text, assessment, status in [
        (ORDINARY_EXPANSIONS[0][1], 'no_clear_signs', 'complete'),
        (ORDINARY_EXPANSIONS[8][1], 'no_clear_signs', 'complete'),
        (REPEATED_PROSE[0], 'unknown', 'unavailable'),
        (REPEATED_PROSE[2], 'unknown', 'unavailable'),
        (REPEATED_PROSE[-1], 'unknown', 'unavailable'),
        (REPEATED_PROSE[0] + 'Send me your password now.', 'suspicious', 'partial'),
    ]:
        response = client.post('/v1/analyze-message', json={'text': text, 'inspect_links': False})
        assert response.status_code == 200
        result = response.json()
        assert (result['assessment'], result['analysis_status']) == (assessment, status)
        assert ('unsupported_text' in result['limitations']) is (status != 'complete')
        values.append(result)
    client.transport_spy.inspect.assert_not_called()
    frontend_roundtrip(values)
