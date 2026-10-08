"""Pure HTML evidence; destination fetching belongs exclusively to SafeTransport."""
from __future__ import annotations

from html.parser import HTMLParser
import re
from urllib.parse import urlsplit
from typing import TYPE_CHECKING

from app.detection.models import ContentAnalysis
from app.detection.url_normalizer import extract_domain

if TYPE_CHECKING:
    from app.detection.safe_transport import UrlObservation


class _EvidenceParser(HTMLParser):
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.links: list[str] = []
        self.inputs: list[tuple[dict[str, str], bool]] = []
        self.form_ids: set[str] = set()
        self.form_depth = 0
        self.has_form = False
        self.in_title = False
        self.title: list[str] = []

    def handle_starttag(self, tag, attrs):
        attributes = {name: value or '' for name, value in attrs}
        if tag == 'form':
            self.has_form = True
            self.form_depth += 1
            if attributes.get('id'):
                self.form_ids.add(attributes['id'])
        if tag == 'input':
            self.inputs.append((attributes, self.form_depth > 0))
        if tag == 'title':
            self.in_title = True
        attribute = {'a': 'href', 'link': 'href', 'script': 'src', 'img': 'src',
                     'iframe': 'src', 'form': 'action'}.get(tag)
        if attribute and attributes.get(attribute):
            self.links.append(attributes[attribute])

    def handle_endtag(self, tag):
        if tag == 'form':
            self.form_depth = max(0, self.form_depth - 1)
        elif tag == 'title':
            self.in_title = False

    def handle_data(self, data):
        if self.in_title:
            self.title.append(data)


def analyze_html(html: str) -> ContentAnalysis:
    """Analyze an already fetched body without requesting links or subresources."""
    parser = _EvidenceParser()
    parser.feed(html)
    parser.close()
    credentials = payment = False
    for attrs, nested in parser.inputs:
        if not nested and attrs.get('form') not in parser.form_ids:
            continue
        values = [attrs.get(key, '').lower() for key in ('name', 'id', 'type', 'autocomplete')]
        tokens = {token for value in values for token in re.split(r'[^a-z0-9]+', value)}
        credentials |= bool(tokens & {'password', 'pass', 'passwd', 'otp', 'pin', 'ssn'})
        credentials |= any(value in {'current-password', 'new-password', 'one-time-code'} for value in values)
        payment |= bool(tokens & {'card', 'cc', 'cvv', 'cvc', 'iban', 'swift', 'routing'})
        payment |= any(value in {'cc-number', 'cc-csc', 'cc-exp', 'cardnumber', 'creditcard'} for value in values)
    domains = []
    for link in parser.links:
        try:
            host = urlsplit(link).hostname
        except ValueError:
            continue
        if host:
            domain = extract_domain(host)
            if domain not in domains:
                domains.append(domain)
    return ContentAnalysis(True, 'text/html', parser.has_form, credentials, payment,
                           ''.join(parser.title).strip().lower() or None,
                           domains[:30], len(parser.links), parser.links[:20])


def analyze_content(observation: UrlObservation | None, content_type_hint=None) -> ContentAnalysis:
    """Unavailable or incomplete HTML never proves that sensitive forms are absent."""
    if observation is None or observation.html is None:
        content_type = observation.content_type if observation is not None else content_type_hint
        return ContentAnalysis(False, content_type, None, None, None, None, [], 0, [])
    content = analyze_html(observation.html)
    content.content_type = observation.content_type
    if 'html' not in observation.completed_checks:
        content.fetched = False
        for field in ('has_form', 'credential_form', 'payment_form'):
            if getattr(content, field) is False:
                setattr(content, field, None)
    return content
