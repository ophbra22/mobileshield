# MobileShield full-message analysis and interface design

Date: 2026-10-08

Status: written specification for review. The overall product scope was approved in the parent conversation. This document and the subsequent implementation plan still require review under the requested brainstorming workflow. Product implementation has not started.

## Purpose and approved scope

Help a person decide how to respond to a suspicious pasted message by examining its wording and any links, explaining concrete warning signs, and identifying analysis limitations. Support Hebrew and English, messages without links, standalone URLs, and messages containing several links. Improve the existing Next.js/FastAPI product rather than introduce a new paid AI service.

The experience must be clear on phones, respect RTL/LTR text, and avoid false reassurance when checks fail. It is an aid to judgment, not a guarantee that a message or destination is safe. Automatic SMS permissions, inbox access, OCR, accounts, saved message history, new credentials, paid providers, and production publishing are outside this implementation scope.

## Why this needs an architectural specification

The current API accepts one URL and persists each result. The current interface extracts only one link and maps backend `phishing` to its benign fallback. There is no message analyzer, no per-link response contract, and no uncertainty model. Redirect, content, and certificate analyzers independently access the network without an active private-address barrier.

This change introduces a message-analysis contract and orchestration layer, a shared outbound network boundary, and an ephemeral data flow. Keeping the existing framework does not remove the need to define these interfaces.

Baseline repository: `8abb3078c01ce26e605c9129d48484c770b574e7`. Checkout: `/Users/braude/Documents/Codex/2026-10-08/task/MobileShield`. Branch: `codex/mobileshield-design-review`.

## Approach and tradeoffs

- **Recommended: repair and extend the existing rule engine.** Add focused message parsing and result aggregation, reuse Next.js/FastAPI, and consolidate existing network calls. This provides explainable results without a new provider; subtle social engineering will still require uncertain outcomes and careful evaluation.
- **Minimal patch:** fix verdict mapping and close unsafe fetching/history, retaining URL-only analysis. It is smaller but does not meet the approved full-message goal.
- **External semantic AI or reputation service:** could broaden detection, but adds disclosure, credentials, cost and provider evaluation. Defer it to a separate decision.

Static checks by default reduce link activation and data disclosure, at the cost of less destination evidence. An explicit deeper-inspection option provides that evidence when requested. Ephemeral results avoid retaining private content but remove server history and saved reports; the user can inspect the current result in the page.

## Architecture and data flow

1. The browser sends a bounded message after the user presses Check message.
2. FastAPI validates the request and applies bounded public-request work limits.
3. A pure message parser preserves the original input in request memory, analyzes a normalized copy, extracts links, and records text/Unicode evidence.
4. A message evaluator combines contextual text indicators with static URL/domain evidence. It supports zero links.
5. Optional deeper link inspection uses a single guarded transport for DNS, redirects, HTTP content and TLS. The URL analyzer receives observations rather than opening independent sockets.
6. An assessment builder aggregates evidence and coverage without averaging away a dangerous link.
7. A typed response is returned to that requester. New message scans are not written to the scan database or browser storage.
8. The browser validates the response and presents the assessment, next action, reasons, per-link coverage and limitations.

Keep units focused: request/response models; text/link parsing; text evidence; network policy/transport; URL evidence; assessment aggregation; localized presentation. Do not refactor unrelated auth, key management, deployment, or other projects.

## API contract

Add `POST /v1/analyze-message`. Keep `POST /v1/analyze` as a legacy URL adapter through the same safety boundary so it cannot remain an unsafe bypass. Existing URL request fields remain accepted. Do not make full message support depend on callers disguising text as a URL.

New request fields:

| Field | Meaning |
| --- | --- |
| `text` | Required non-whitespace string, at most 10,000 Unicode code points; validated server-side. |
| `inspect_links` | Boolean, default false. Explicitly permits deeper network inspection of extracted links. |

Maximum 10 distinct extracted links. Reject excess input with a structured validation error; do not truncate or silently ignore links. A malformed link can remain a reported unassessable candidate without invalidating usable message text. Non-HTTP schemes are never fetched.

New response fields:

| Field | Meaning |
| --- | --- |
| `schema_version` | Fixed response version used for runtime validation. |
| `assessment` | `phishing`, `suspicious`, `no_clear_signs`, or `unknown`. |
| `analysis_status` | `complete`, `partial`, or `unavailable`, relative to the requested checks. |
| `reasons` | Structured reason codes with bounded, typed evidence suitable for translated presentation. |
| `recommended_actions` | Action codes such as avoid interaction or verify through an independently obtained official channel. |
| `links` | Ordered, deduplicated link results, each with assessment, inspection status, display host and reason/limitation codes. |
| `limitations` | Explicit missing checks, unsupported text, blocked destinations, or unavailable evidence. |
| `request_id` | Opaque identifier for error correlation, containing no submitted content. |

The response need not repeat the full message. Link identifiers refer to the submitted snapshot; technical details may return URLs only to the current requester, and the UI masks query strings and personal path data by default. Display domains as text, not navigation links.

Transport and validation failures use structured errors and suitable HTTP codes (422 input, 429 rate limit, 503 unavailable), not a successful safe assessment. Unexpected response values, non-JSON responses, or mismatched versions are client errors. The legacy adapter retains its known `phishing`, `suspicious` and `legitimate` values, mapping `no_clear_signs` to `legitimate` only when applicable checks completed. It adds explicit `unknown` and completion metadata for insufficient evidence. The upgraded frontend recognizes both the actual legacy enum and the older `malicious`/`safe` aliases if needed during rollout; an unrecognized value is rejected. Neither frontend nor backend may use a benign fallback.

## Analysis semantics

Use deterministic, explainable rules in this release. Combine message signals such as urgency, requests to disclose OTP/password/payment details, impersonation claims and contradictory link destinations. Distinguish an instruction to share an OTP from an ordinary notification telling the recipient not to share it. A keyword such as payment, verify, or urgent alone must not determine phishing.

The parser handles Hebrew, English, mixed scripts, bare domains, ordinary URL punctuation, duplicate links, IDNs, and bidi/zero-width controls. Preserve original text for evidence alignment; normalized text is a separate value. Do not silently transform an ambiguous host into a different destination. Recognize suspicious obfuscation while avoiding a blanket rule that Hebrew IDNs or punycode are malicious. Unsupported language may still yield URL evidence, with text coverage marked limited.

Assessment meanings:

- `phishing`: strong, explainable combined evidence of a phishing attempt; wording remains “Strong phishing indicators.”
- `suspicious`: meaningful warning signs merit independent verification.
- `no_clear_signs`: completed applicable checks found no clear warning signs; explicitly not a safety guarantee.
- `unknown`: evidence is insufficient for a meaningful conclusion.

Completeness is separate. A strong message-level phishing signal remains visible even if a link times out. Missing evidence, an unknown enum, a blocked network request, or a timeout must never imply low risk. Successful HTTPS only establishes encrypted transport; it must not cancel phishing evidence. Trusted domains and marketing redirects are limited context, not broad safety overrides.

Fix the ordinary input-field parser, use actual blocklist evidence in assessment, and distinguish failed TLS observation from verified certificate mismatch. The existing three-entry internal blocklist is a limited local rule source, not a current comprehensive threat-intelligence feed. Do not invent external reputation coverage.

No confidence percentages are displayed. Any internal heuristic scoring remains implementation evidence, not a calibrated likelihood. Measured evaluation results must identify the tested dataset and its limitations.

## Privacy and safe networking

### Default and optional inspection

The primary action checks message text and static URL characteristics without contacting URLs extracted from the message. The UI offers an unchecked “Also inspect linked pages” option, with a short explanation that this contacts those sites from the server and could activate tracking or a one-time link. Static mode does not call RDAP, remote reputation providers, or DNS for submitted destinations.

This default is a concrete proposal for written-spec review. It makes the no-storage policy meaningful without implying that avoiding storage alone prevents disclosure. The result always identifies whether linked pages were visited. Users can still get useful text/static URL warnings with deeper inspection disabled.

### Shared transport

All destination-derived network operations, including legacy URL analysis, use the same guarded implementation:

- Allow only HTTP and HTTPS, initially on ports 80/443 matching their schemes. Reject userinfo, malformed ports, zone identifiers, ambiguous numeric addresses, and invalid hosts.
- Reject local/internal names and every non-global IPv4/IPv6 destination, including loopback, private, link-local, metadata, multicast, reserved and unspecified addresses. If any resolved address is disallowed, reject the host.
- Validate each redirect independently. Bind the connection to a validated address, preserve Host/SNI and TLS verification, and prevent re-resolution from bypassing validation.
- Disable ambient proxies and inherited authentication. Send no user cookies, authorization, referer, or private headers. Never execute page scripts, load page subresources, submit forms, or download executable content for execution.
- Share verified transport observations with certificate/content analyzers rather than refetching through independent libraries.
- Enforce a 20-second overall inspection deadline per message, at most two concurrent link inspections, at most five followed redirects per link, connection/read limits within the overall budget, and a 256 KiB decompressed HTML-body cap enforced while streaming. Resolve DNS within a bounded execution path; a library timeout alone must not be mistaken for a DNS deadline.
- Return per-link blocked, skipped or unavailable states when limits apply. A timeout does not erase already observed risk.

Remote configuration refresh or domain metadata lookups must not open an alternate destination-controlled fetch path. Keep static lists local for default mode. If deeper mode retains RDAP, restrict its service destinations and redirects, send only the canonical public domain, bound responses, and explain the domain disclosure.

This applies application-layer measures from the [OWASP SSRF guidance](https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html). Infrastructure firewall or Render permission changes are not authorized by this spec.

### Storage and public access

Do not persist new message text, submitted/final URLs, evidence containing private text, or result bodies in PostgreSQL, browser storage, analytics, or logs. Retain only non-sensitive operational metrics. Language preference may remain in local storage. Responses use `Cache-Control: no-store`.

Disable unauthenticated scan list/detail/PDF access in the local implementation. Preserve existing database records; deletion or retention migration requires a separate decision. New URL-adapter scans must also stop adding publicly retrievable raw scan records. Returning `scan_id: null` is a documented compatibility change where no scan is persisted; the current web scan flow does not require report download. Obsolete report UI must not imply that a scan was saved.

Do not promise zero infrastructure retention until hosting/proxy/observability behavior is verified. UI copy describes application behavior precisely and warns against pasting unnecessary secrets. Errors and logs must not echo payloads or secret-bearing URLs.

Bound public request sizes, inspection concurrency and request rate using existing stack capabilities. Do not expose an environment flag that allows arbitrary private destination fetching. Test injection belongs in test-only interfaces, not a production bypass.

## Interface and accessibility

Use a calm, precise visual style: warm pale background, white cards, navy text, one teal primary action, restrained borders, generous spacing. Reserve red and amber for actual findings. Keep brand and language switch in a compact header; move contact/social links to a footer to prevent current mobile clipping.

The input card contains a visible label, large multiline message field, clear/paste controls, length feedback, optional deeper-inspection control and one Check message action. Clipboard denial displays a local explanation and leaves manual paste available. Empty input and over-limit input have explicit guidance.

Results show assessment first, then an actionable recommendation, concise evidence and expandable per-link/technical details. Explain “No clear warning signs” without calling a link safe. Show “Could not complete all checks” alongside meaningful partial evidence. An API failure displays retry guidance, not a verdict.

Use localized Hebrew/English copy for interface, evidence and errors. Set `lang` and page `dir`; apply `dir="auto"` to message text and isolated LTR presentation to URLs/domains. Use logical spacing, safe wrapping and semantic headings/labels. Icons accompany words; color is never the only status cue.

Provide visible keyboard focus, accessible names, adequate contrast and touch targets, result status announcements and reduced-motion support. Follow [W3C status-message guidance](https://www.w3.org/WAI/WCAG22/Understanding/status-messages.html). Verify at 320, 390, 768 and 1440 px with Hebrew, English, zoom and long mixed-script content.

### Requests and stale results

Each analysis is bound to an immutable submitted-text snapshot. Editing the message marks/removes its previous result so it cannot be mistaken for a result for new text. Cancel/retry uses an abortable client request and a request sequence identifier; responses from older requests cannot overwrite newer state. Loading, partial, failure and completed states are explicit. Never automatically retry a deeper check that could reactivate a link; offer manual retry.

## Acceptance criteria and verification

1. Exact contract regression: backend `phishing` displays a phishing warning. Unknown/missing/malformed verdicts never display low risk.
2. Full-message fixtures cover ordinary Hebrew/English, OTP sharing and negation, payment lures, benign urgency, zero/one/multiple links, bare/punctuated/duplicate links, Unicode/IDN/bidi, unsupported text and length/count limits.
3. Dangerous links cannot be averaged away. Incomplete checks cannot create reassuring evidence. HTTPS and allowlist discounts cannot override strong evidence. Blocklist observations reach the assessment.
4. Real HTML fixtures recognize password/card inputs; failed content checks differ from a page observed without forms. Timeout differs from a confirmed TLS mismatch.
5. Mocked transport tests cover every forbidden address class, alternative IP representations, mixed DNS answers, redirects to private destinations, rebinding, invalid schemes/ports, redirect loops, oversized/slow responses and deadline exhaustion. Forbidden targets receive zero connection attempts.
6. Privacy tests verify no new raw scan persistence, no message browser storage, no payload/error logging, no cacheable result response and closed unauthenticated history/detail/PDF routes. Tests use synthetic records only.
7. Local API/browser tests cover repeated submissions, editing during analysis, stale responses, cancellation, retry, offline/503/429, partial failure and clipboard denial. Real backend/frontend integration is verified with deterministic local fixtures, without submitting to production or following live malicious links.
8. Backend suite, TypeScript checking, lint and production frontend build pass after dependencies are installed in this isolated project. Report pre-existing failures and skips separately. Revisit obsolete tests that accept auth-route 404 as success; they must not be used as evidence of privacy protection.
9. Capture before/after screenshots and keyboard/accessibility observations at the specified sizes. Report exact passed, failed and not-run checks.

A fixed evaluation corpus and explicit expected outcomes are required before tuning rules. Passing handcrafted examples does not establish general phishing-detection accuracy; document false positives, false negatives and uncertain outcomes observed in that corpus.

## Rollout constraints

All work remains on a separate local branch. Both existing Render services auto-deploy main, so no main push, merge, production deployment, new paid service, credential or security-permission change is authorized.

Before requesting publication, show the reviewed diff, test/build results, browser screenshots and exact proposed deployment sequence. Account for independently deployed frontend/backend commits: release a frontend that tolerates backend unavailability and explicitly maps legacy/new results, then the compatible backend; confirm both deployed revisions afterward only when deployment is approved. During a version mismatch, a clear unavailable result is acceptable; false reassurance is not. Prepare rollback information without changing the live services.

## Review checkpoint

Review this specification, particularly the static-by-default/optional link-inspection behavior and the legacy history/scan-ID compatibility changes. After approval, create the written implementation plan through the writing-plans skill and select its execution method. Only then install product dependencies or edit product code.

Specification self-review: checked for unresolved placeholders, assessment/completeness consistency, network bypasses, retention contradictions, compatibility changes and scope creep. The explicit legacy verdict mapping above resolves the identified contract ambiguity. There are no unresolved placeholders. Review of the proposed product decisions remains pending.

## October 9 correction: practical text coverage

Live acceptance exposed that the later 223-word all-token English coverage gate rejects commonplace messages. The user-directed continuation explicitly requires a durable correction within the approved scope, without another approval cycle. This section supersedes that gate and the historical local-only publication status: the current reviewed baseline is live at e91f147c227e9d28e045c2542f3811302e15d52e; controlled reviewed publication remains authorized, while paid services, credentials, security changes and unrelated work remain excluded.

Retain the rule-based evidence engine and its warning precedence. Replace word-by-word membership with a bounded, offline coverage heuristic based on script and English/Hebrew structural evidence. Unfamiliar ordinary nouns, proper names and inflected words must not individually invalidate otherwise recognizable prose. Evidence must be assessed across meaningful prose segments so a greeting or Hebrew fragment cannot make a substantial unsupported passage appear fully covered. URL/email characters do not establish prose coverage. Unsupported scripts, clear repetitive/keyboard/random text and text with insufficient language evidence retain explicit uncertainty. Hebrew-script gibberish must not be presumed meaningful solely because of its script. Mixed recognizable Hebrew/English can be covered; mixed unsupported text remains limited. Short phrases and names can remain uncertain when evidence is insufficient.

Do not add only words from the reproduced examples, make all Latin text supported, call an external service, add a language model/dependency, infer language from phishing rule matches, or claim comprehensive language identification. Use a compact set of general structural anchors and independently tested shape/segment rules, with thresholds and remaining limitations documented. Rules are coverage heuristics, not calibrated probabilities. Keep the API schema and reason-code vocabulary compatible. No-clear-signs continues to mean no matched warning in the applicable bounded checks, never a safety guarantee.

Unknown/unsupported text with no other evidence remains unknown; recognized warnings remain suspicious/phishing even when coverage is partial. With only unsupported_text and unavailable analysis, localize the result as limited text coverage rather than suggesting a service outage. Real HTTP/transport failures retain error/unavailable wording. No raw text excerpts or new persistence/logging are added.

Validate the two exact cloud-browser English cases plus independently authored ordinary English/Hebrew (names, scheduling, household, work, uncommon nouns, morphology), mixed languages, unsupported scripts, plausible and clear gibberish, punctuation/Unicode, URL-only and URL-containing inputs, and preserved secret/payment warnings. Test known negative-language cases without silently relabeling them. The synthetic suite establishes regression behavior only, not general accuracy. Maintain all safe URL, privacy, request-limit and stale-client protections.
