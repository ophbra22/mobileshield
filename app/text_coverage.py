"""Bounded English/Hebrew prose coverage, not language identification or safety.

Content words need plausible shapes, not dictionary membership. Each substantial
sentence/script run must supply its own structural evidence; greetings cannot
lend evidence to other prose. See docs/architecture.md (Text coverage) for the
approach and its deliberate blind spots. No I/O or warning-rule dependencies.
"""
from __future__ import annotations

import re
import unicodedata
from collections import Counter

# Closed-class grammar and discourse markers, not a content-word vocabulary.
_EN = frozenset("""
a an the i you he she it we they me us him her them my your his our their its
this that these those and or but if when where why how who what which whose
because unless until before after of to from for with without by via in on at
as is are was were be been being have has had do does did not no never must
should can cannot will would could may might please here there now then today
tomorrow yesterday also still only all any some each other than so
""".split())
# These existing anchors can introduce a noun phrase containing several
# modifiers. Classifying their grammatical role adds no content-word lexicon.
_NOMINAL = frozenset('a an the my your his her our their its this that these those all any some each'.split())
_HE = frozenset("""
אני אתה את הוא היא אנחנו אתם אתן הם הן לי לך לו לה לנו לכם לכן להם להן
של שלי שלך שלו שלה שלנו שלכם שלהן שלהם את זה זו זאת אלה אלו עם על אל
אצל בין ליד בלי עד כדי כי אם אבל או גם רק כל לא אל אין יש היה היתה יהיה
מה מי איך למה מתי איפה האם אפשר נא בבקשה כאן שם פה היום מחר אתמול עכשיו
אחרי לפני בזמן עדיין בכתובת
""".split())
_GREETINGS = frozenset('hello hi goodbye thanks thankyou שלום תודה'.split())
# Short conventional acknowledgments/link prompts can stand alone. This
# allowance supplies no extra structural anchors to longer passages.
_SHORT = _GREETINGS | frozenset('yes no read see look check review ראו בדקו כן לא'.split())
_KEYBOARD_ROWS = ('qwertyuiop', 'asdfghjkl', 'zxcvbnm', 'קראטוןםפ', 'שדגכעיחלךף', 'זסבהנמצתץ',
                  'abcdefghijklmnopqrstuvwxyz', 'אבגדהוזחטיכלמנסעפצקרשת')
_WORD = re.compile(r"[^\W\d_]+(?:['’][^\W\d_]+)?", re.UNICODE)


def _script(word: str) -> str | None:
    scripts = {('he' if 'HEBREW' in unicodedata.name(c, '') else
                'en' if 'LATIN' in unicodedata.name(c, '') else 'other')
               for c in word if c.isalpha()}
    return next(iter(scripts)) if len(scripts) == 1 and 'other' not in scripts else None


def _shape(original: str, word: str, script: str) -> bool:
    letters = word.replace("'", '')
    if re.search(r'(.)\1{2}', letters) or re.fullmatch(r'(.{1,3})\1{2,}', letters):
        return False
    if len(letters) >= 4 and any(letters in row or letters in row[::-1] for row in _KEYBOARD_ROWS):
        return False
    if script == 'he':
        return (len(letters) <= 16 and not any(c in 'ךםןףץ' for c in letters[:-1]))
    if len(letters) > 30:
        return False
    # Short uppercase abbreviations are allowed as content, never as anchors.
    if original.isupper() and len(letters) <= 5:
        return True
    return (len(letters) < 4 or bool(re.search('[aeiouy]', letters))) and not re.search('[^aeiouy]{7}', letters)


def _anchor(word: str, script: str) -> str | None:
    if script == 'he':
        return word if word in _HE else None
    # Ordinary English contractions preserve their structural root.
    root = word.split("'")[0]
    if root in _EN:
        return root
    if word in {"don't", "doesn't", "didn't", "isn't", "aren't", "wasn't", "weren't", "can't", "won't", "shouldn't", "wouldn't", "couldn't"}:
        return word
    return None


def _bounded_spans(evidence: list[str | None], tail_limit: int = 4) -> bool:
    positions = [index for index, item in enumerate(evidence) if item]
    return (bool(positions) and positions[0] <= 4 and len(evidence) - 1 - positions[-1] <= tail_limit
            and all(right - left - 1 <= 8 for left, right in zip(positions, positions[1:])))


def _covered(words: list[str], script: str) -> bool:
    if len(words) <= 2 and words[0] in _SHORT - _GREETINGS:
        return True
    anchors = [_anchor(word, script) for word in words]
    present = [anchor for anchor in anchors if anchor]
    count = len(words)
    # Density alone sets the evidence minimum, avoiding a second-anchor cliff
    # at word five. English allows one marker per eight tokens, Hebrew per six.
    # A nominal marker can introduce up to eight content words (modifiers,
    # subject/predicate or object phrase). Other tails keep the four-word bound:
    # an introduction ending in "tomorrow" cannot cover a foreign passage.
    tail_limit = 8 if script == 'en' and present and present[-1] in _NOMINAL else 4
    token_budget = 8 if script == 'en' else 6
    if present and len(present) * token_budget >= count and _bounded_spans(anchors, tail_limit):
        return True
    if script == 'he':
        # Attached Hebrew prepositions/articles/conjunctions are weak evidence.
        # Combine full anchors with weak prefixes on at least half the words.
        # Require two different evidence classes; one prefixed noun or a
        # greeting cannot cover an entire passage. Do not double-count words.
        evidence = [anchor or ('prefix:' + word[0] if len(word) >= 4 and word[0] in 'הבכלמשו' else None)
                    for word, anchor in zip(words, anchors)]
        present = [item for item in evidence if item]
        return len(present) * 2 >= count and len(set(present)) >= 2 and _bounded_spans(evidence)
    return False


def _repetitive(words: list[str]) -> bool:
    """Linear bounded work before greeting removal; punctuation is irrelevant."""
    count = len(words)
    if count >= 6 and (len(set(words)) <= 2 or Counter(words).most_common(1)[0][1] * 5 >= count * 3):
        return True
    # Three consecutive copies of a 1–16-token unit, occupying at least six
    # tokens, anywhere in the message. A warning suffix must not hide a cycle.
    for period in range(1, min(16, count // 3) + 1):
        matched = 0
        for index in range(period, count):
            matched = matched + 1 if words[index] == words[index - period] else 0
            if matched >= 2 * period and matched + period >= 6:
                return True
    # Also catch longer repeated passages without an unbounded period search.
    # Any prefix with at least nine tokens, 60% duplicate trigrams and a
    # trigram occurring three times is degenerate. Once observed, appending a
    # warning cannot erase it. Different content keeps ordinary frames varied.
    trigrams: Counter[tuple[str, str, str]] = Counter()
    most_common = 0
    for total, trigram in enumerate(zip(words, words[1:], words[2:]), start=1):
        trigrams[trigram] += 1
        most_common = max(most_common, trigrams[trigram])
        if total >= 7 and (total - len(trigrams)) * 5 >= total * 3 and most_common >= 3:
            return True
    return False


def supported_text(text: str) -> bool:
    """Assess prose after link exclusion; caller enforces 10,000 codepoints."""
    text = re.sub(r'[\w.+-]+@[\w.-]+', ' ', text)
    # Preserve script identity, while tolerating accents and Hebrew niqqud.
    text = unicodedata.normalize('NFD', text)
    text = ''.join(c for c in text if not unicodedata.category(c).startswith('M'))
    segments: list[tuple[str, list[str]]] = []
    all_words: list[str] = []
    for sentence in re.split(r'[.!?;\n]', text):
        current: list[str] = []
        current_script = ''
        for original in _WORD.findall(sentence):
            script = _script(original)
            word = original.casefold().replace('’', "'")
            if script is None or not _shape(original, word, script):
                return False
            all_words.append(word)
            if script != current_script and current:
                segments.append((current_script, current))
                current = []
            current_script = script
            current.append(word)
        if current:
            segments.append((current_script, current))
    if not all_words:
        return False
    if _repetitive(all_words):
        return False
    substantial = False
    unresolved_short = 0
    for script, words in segments:
        # Greetings are recognized alone, but removed from evidence for prose.
        words = [word for word in words if word not in _GREETINGS]
        if not words:
            continue
        if len(words) >= 3:
            if not _covered(words, script):
                return False
            substantial = True
        elif _covered(words, script) and len(words) == 2:
            substantial = True
        elif not all(word in _SHORT for word in words):
            unresolved_short += len(words)
    # Tiny headings/names/acronyms can borrow context from actual prose, never
    # from a greeting. Cap borrowed context at TWO tokens across the message:
    # punctuation/script changes cannot hide a passage in many tiny fragments.
    return (substantial and unresolved_short <= 2) or (not unresolved_short and all(word in _SHORT for word in all_words))
