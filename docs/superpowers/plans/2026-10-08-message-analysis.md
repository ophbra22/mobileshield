# MobileShield Message Analysis Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Deliver a private-by-default Hebrew/English pasted-message checker with reliable result semantics, guarded optional link inspection, and a polished responsive interface.

**Architecture:** Extend the existing Next.js/FastAPI application with pure message parsing and assessment around the repaired URL analyzer. Route every destination-derived network operation through one guarded transport; return ephemeral typed results through a new endpoint and a legacy adapter. Keep assessment separate from check completion and do not introduce a provider, queue, account system or new deployment service.

**Tech Stack:** Existing React 18, Next.js 14, TypeScript, Tailwind, FastAPI and Python 3.11; pytest/HTTPX for backend tests and Vitest/React Testing Library for frontend tests. New packages are development dependencies only. Use Python standard-library HTTP/TLS/DNS primitives and the existing bundled public-suffix data for runtime networking/parsing.

**Spec:** `docs/superpowers/specs/2026-10-08-message-analysis-design.md` — approved by Ophir on 2026-10-08. Read the complete spec before this plan.

## Global Constraints

- Checkout: `/Users/braude/Documents/Codex/2026-10-08/task/MobileShield`; branch: `codex/mobileshield-design-review`. Preserve unrelated work and do not touch GetEvent.
- Planning baseline: `d87de55`; product baseline: `8abb3078c01ce26e605c9129d48484c770b574e7`. No product implementation before plan approval and execution-method selection.
- `text`: required non-whitespace string, at most 10,000 Unicode code points; maximum 10 distinct extracted links. Reject rather than truncate.
- `inspect_links`: Boolean, default false. Static mode does not call RDAP, remote reputation providers, or DNS for submitted destinations.
- Assessments: `phishing`, `suspicious`, `no_clear_signs`, `unknown`. Completion states: `complete`, `partial`, `unavailable`. No benign fallback or confidence percentages.
- Deep inspection: 20-second overall deadline, at most two concurrent link inspections, at most five followed redirects per link, 256 KiB decompressed HTML-body cap enforced while streaming.
- HTTP/HTTPS only, ports 80/443 matching their schemes. Reject local/internal and all non-global destinations; validate every redirect and pin connections to validated public addresses with correct Host/SNI/TLS verification.
- Do not persist new raw message text, submitted/final URLs, private evidence or result bodies in PostgreSQL, browser storage, analytics or logs. Responses use `Cache-Control: no-store`.
- Disable unauthenticated scan list/detail/PDF access; preserve historical database records. No deletion or retention migration.
- Hebrew/English, RTL/LTR, keyboard/status accessibility, reduced motion and widths 320/390/768/1440 px are acceptance requirements.
- Both Render services auto-deploy main. No main push, merge, production deployment, paid provider, credential or security-permission change is approved.

## Review Focus

These five implied failure modes receive explicit tests below:

1. Emoji and combining characters at the text limit: browser and Python must count the same Unicode code points and never split submitted content (Tasks 1, 5).
2. DNS timeout/rebinding and a valid TLS connection to an attacker: no leaked workers, re-resolution bypass, or cancellation of strong evidence (Tasks 2, 3).
3. An official-domain link accompanying “send me your OTP”: trusted-link evidence must not suppress the message warning; “do not share this OTP” must remain distinct (Tasks 3, 4).
4. A late response arriving after edit, cancel, language switch or retry: it must not overwrite the current request, restore cleared text or mislabel a result (Tasks 5, 6).
5. JSON validation and transport exceptions containing tokens: HTTP errors, request IDs and logs must not expose submitted content even when analysis never starts (Task 4).

## File Map and Stable Interfaces

| Files | Responsibility |
| --- | --- |
| New `app/message_models.py`, `app/message_parser.py` | Typed contract, bounded text/link parsing; no I/O. |
| New `app/detection/network_policy.py`, `app/detection/safe_transport.py` | Canonical destination validation, bounded DNS, pinned HTTP/TLS, redirect and byte budgets. |
| Existing detection modules `url_normalizer.py`, `content_analyzer.py`, `domain_analyzer.py`, `risk_scorer.py`, `classifier.py`, `engine.py`, `models.py`, `brand_spoof_detector.py`, `__init__.py` under `app/detection/`, plus `app/brand.py` | Pure URL observations, offline domain extraction, repaired content detection, evidence and uncertainty. |
| Existing `app/detection/redirect_analyzer.py`, `certificate_analyzer.py`, `app/reputation.py` | Remove independent outbound paths from scan execution; use the guarded transport or pure observations. |
| New `app/detection/message_analyzer.py`; existing `app/analysis.py` | Text evidence, assessment aggregation, static/deep orchestration and legacy response adaptation. |
| New `app/routers/analyze.py`, `app/scan_limits.py`; existing `app/main.py`, `app/db/database.py` | Stateless endpoints, bounded requests/rate/concurrency, redacted errors, retired history; narrowly extract the existing DB startup initializer for hermetic tests. |
| New `mobileshield-web/lib/analysis.ts`, `app/hooks/useMessageAnalysis.ts`; existing `lib/api.ts` | Runtime response validation, aliases, API client and request lifecycle. |
| Existing `mobileshield-web/app/page.tsx`, `mobileshield-web/app/components/ScanForm.tsx`, `mobileshield-web/app/components/ResultDisplay.tsx`, `mobileshield-web/app/components/HeaderBar.tsx`, `mobileshield-web/app/components/ui/textarea.tsx`, `mobileshield-web/app/context/LanguageContext.tsx`, `mobileshield-web/app/globals.css`, `mobileshield-web/app/layout.tsx` | Message UX, evidence, language, responsive styling and accessibility. |
| Existing `mobileshield-web/app/api/report/pdf/route.ts`, `mobileshield-web/app/components/AnalyzeForm.tsx` | Retire obsolete report behavior and keep existing consumers type-correct. |
| New backend/frontend test files named in tasks | Synthetic regression fixtures; no production data or external scans. |

Define these contract types in `app/message_models.py` in Task 1 and mirror them in TypeScript in Task 5:

- `MessageRequest(text: str, inspect_links: bool = False)`; strict Boolean and `extra='forbid'`.
- `Assessment = Literal['phishing','suspicious','no_clear_signs','unknown']`; `AnalysisStatus = Literal['complete','partial','unavailable']`; `ActionCode = Literal['avoid_interaction','verify_independently','do_not_share_secrets','consider_link_inspection','retry_later']`.
- `Reason(code: str, strength: Literal['info','medium','strong'], source: Literal['message','url','inspection'], link_id: str | None, params: dict[str,str])`. Parameters contain at most four safe facts of 256 characters each, not message excerpts or secret-bearing URLs; a code registry restricts accepted keys. Limit each reasons list to 32 entries.
- `LinkCandidate(link_id: str, raw: str, canonical_url: str | None, display_host: str | None, parse_error: str | None)` and `ParsedMessage(text: str, normalized_text: str, links: list[LinkCandidate], supported_text: bool)`. These are request-memory models, not persisted records.
- `LinkResult(link_id: str, assessment: Assessment, inspection_status: Literal['not_requested','completed','blocked','failed','skipped'], display_host: str | None, reasons: list[Reason], limitations: list[str], technical: LinkTechnical | None)`. `LinkTechnical(normalized_url: str | None, final_url: str | None)` is returned only to the requester and never persisted; UI masks private URL parts by default. Missing HTML/deadlines are limitations even if some checks complete.
- `AssessmentSummary(assessment: Assessment, analysis_status: AnalysisStatus, reasons: list[Reason], recommended_actions: list[ActionCode], limitations: list[str])` and `MessageResponse`, which adds `schema_version: Literal[1]`, `links: list[LinkResult]` and `request_id: str`. Limitations use the reason-code registry, not raw exception messages.
- Runtime reason codes include `credential_request`, `payment_request`, `urgency`, `brand_destination_mismatch`, `lookalike_host`, `suspicious_obfuscation`, `credential_form`, `payment_form`, `local_blocklist_hit`, `certificate_mismatch`, `unsupported_text`, `invalid_link`, `inspection_disabled`, `inspection_failed`, `destination_blocked`, `body_limit`, `deadline_exceeded`. Each emitted code has Hebrew/English copy; unknown client codes produce a generic limitation.

Commands below run from the checkout root unless stated otherwise. Each task follows red → green → focused review → local commit; stage only its named files. Record pre-existing failures before changing expected outcomes.

## Task 1: Bounded Input Contract and Message Parser

**Files:** Create `app/message_models.py`, `app/message_parser.py`, `tests/conftest.py`, `tests/test_message_parser.py`, `tests/fixtures/messages.json`, `requirements-dev.txt`; modify `app/detection/url_normalizer.py`, `app/detection/__init__.py`, `.gitignore`.

**Interfaces:** Produce `parse_message(text: str) -> ParsedMessage` and the models above. Add `split_domain(host: str) -> tldextract.ExtractResult` and `extract_domain(host: str) -> str` using one `tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, include_psl_private_domains=True)` instance. No runtime public-suffix downloads; remove the eager engine import from `app/detection/__init__.py` so importing pure parsing does not initialize network analyzers.

- [ ] **1. Prepare isolated verification.** After plan approval, use the discovered `/opt/homebrew/bin/python3.11` to create `.venv`; install existing requirements and development-only HTTPX through a pinned `requirements-dev.txt`. Ignore `.venv/` and test artifacts. In `tests/conftest.py`, disable remote allowlist refresh before imports and make unexpected network connections fail. Record existing backend test outcomes without contacting live destinations.
- [ ] **2. Write failing parser/model tests.** Use these assertions plus Hebrew/mixed-script fixtures:

```python
assert parse_message('שלום, נדבר מחר').links == []
assert len(parse_message('See example.com/a, https://example.com/a.').links) == 1
assert len(parse_message('https://a.example/a https://b.example/b').links) == 2
assert MessageRequest(text='🙂' * 10_000).text == '🙂' * 10_000
with pytest.raises(ValueError): MessageRequest(text='🙂' * 10_001)
with pytest.raises(ValueError): parse_message(' '.join(f'https://a{i}.example' for i in range(11)))
with pytest.raises(ValueError): MessageRequest(text='   ')
```

Add named cases for balanced URL parentheses, Hebrew punctuation, email addresses not becoming links, duplicate normalization, malformed/unsupported schemes, IDNs, bidi/zero-width characters and uninterpretable text. Preserve the complete original input.
- [ ] **3. Run red.** `.venv/bin/python -m pytest tests/test_message_parser.py -q`; confirm the new interface/assertions fail for the expected missing behavior.
- [ ] **4. Implement the exact models and `parse_message`.** Extract candidates from original text, use a normalized analysis copy, and canonicalize only unambiguous URLs. Do not make every non-empty string a URL. Keep valid-language IDNs separate from spoof evidence; count code points, not bytes.
- [ ] **5. Run green and record the baseline.** Repeat the focused command; expected all tests pass with zero unexpected network calls. Save a fixed corpus of at least 60 synthetic cases: 30 Hebrew and 30 English, each covering benign/risk/uncertain cases. Keep expected outcomes explicit before tuning rules.
- [ ] **6. Commit.** `git commit -m "feat: add bounded message contract and parser"` after staging the Task 1 files and reviewing the diff.

## Task 2: One Safe, Bounded Network Transport

**Files:** Create `app/detection/network_policy.py`, `app/detection/safe_transport.py`, `tests/test_network_policy.py`, `tests/test_safe_transport.py`.

**Interfaces:** Produce `canonical_target(url: str) -> NetworkTarget`; `resolve_public(target: NetworkTarget, *, deadline: float) -> tuple[str, ...]`; and `SafeTransport.inspect(url: str, *, deadline: float) -> UrlObservation`. Define `NetworkTarget(url: str, scheme: str, hostname: str, port: int, path_query: str)` in network_policy and `UrlObservation(final_url: str | None, hops: list[RedirectHop], tls: CertificateAnalysis | None, html: str | None, content_type: str | None, completed_checks: list[str], limitations: list[str])` in safe_transport, reusing the existing observation dataclasses. Deadlines use `time.monotonic()`; SafeTransport owns one shared process-wide two-slot inspection guard.

- [ ] **1. Write failing policy/transport tests.** Parametrize loopback/private/link-local/metadata/multicast/reserved/unspecified IPv4/IPv6, IPv4-mapped IPv6, noncanonical numeric encodings, `.localhost`/internal names, userinfo, zones, malformed ports, control characters, ambiguous whitespace/backslashes and non-HTTP schemes. Assert `connection_attempts == []` for forbidden targets; assert a public/private DNS mix is rejected. Test redirect-to-private, rebinding, Host/SNI preservation and certificate verification.
- [ ] **2. Add resource-boundary assertions.** Assert followed redirects `<= 5`, body bytes retained `<= 256 * 1024`, two concurrent inspections maximum, and completion/termination within the remaining 20-second message budget. A deliberately stalled DNS worker must be terminated and joined. HTTP timeout errors must not contain full requested URLs. Oversized/slow bodies close the connection and return limitations.
- [ ] **3. Run red.** `.venv/bin/python -m pytest tests/test_network_policy.py tests/test_safe_transport.py -q`; expected failures identify missing validation/transport behavior.
- [ ] **4. Implement policy and transport.** Use a bounded child process for DNS so timeout can terminate work; validate every answer. Connect with stdlib HTTP/TLS to a numeric validated address and retain the original hostname for Host/SNI. Never fall back to hostname-based connection. Validate every redirect and carry one overall deadline. Request `Accept-Encoding: identity`; if a server sends unsupported compression, skip content with a limitation rather than unbounded decompression. Stream and cap identity HTML, close resources, and do not execute content or load subresources. Inject resolver/connector/clock only through Python interfaces used by tests, never a public private-network bypass flag.
- [ ] **5. Run green.** Repeat the focused command; expected all cases pass, zero forbidden connections and no outstanding test DNS workers. Include a successful simulated public HTTPS redirect to prove the boundary also permits intended work.
- [ ] **6. Commit.** `git commit -m "fix: guard all destination network inspection"` after staging Task 2 files.

## Task 3: Repair URL Evidence and Remove Unsafe Bypasses

**Files:** Modify `app/detection/engine.py`, `app/detection/models.py`, `app/detection/content_analyzer.py`, `app/detection/domain_analyzer.py`, `app/detection/risk_scorer.py`, `app/detection/classifier.py`, `app/detection/redirect_analyzer.py`, `app/detection/certificate_analyzer.py`, `app/detection/brand_spoof_detector.py`, `app/brand.py`, `app/reputation.py`; create `tests/test_url_evidence.py`, `tests/fixtures/credential-form.html`; adapt `tests/test_analysis_smoke.py`, `tests/test_detection_dataset.py` where approved semantics change.

**Interfaces:** Consume `LinkCandidate`, `Reason`, `LinkResult`, `UrlObservation`. Produce `collect_url_evidence(candidate: LinkCandidate, observation: UrlObservation | None) -> list[Reason]` and `analyze_url_candidate(candidate: LinkCandidate, observation: UrlObservation | None) -> LinkResult`. Make `analyze_html(html: str) -> ContentAnalysis` pure; certificate/redirect wrappers consume transport observations instead of opening sockets.

- [ ] **1. Write failing evidence tests.** A real HTML form with password/card/CVV inputs must set the respective flags. An unfetched page must not mean “no credential form.” A valid certificate cannot override brand/credential evidence. A timeout is not a verified certificate mismatch. A local blocklist hit must appear as a warning reason; it is not represented as verified external intelligence. Hebrew IDN/punycode alone must not cause a phishing verdict.
- [ ] **2. Run red.** `.venv/bin/python -m pytest tests/test_url_evidence.py -q`; confirm the parser and missing-evidence regressions fail on the original behavior.
- [ ] **3. Implement evidence-only analysis.** Route all public-suffix/brand parsing through Task 1's offline helpers, including `app/brand.py`. Remove the blanket HTTPS/safe-case downgrade, cap allowlist discounts so strong evidence survives, and distinguish observed absence from unavailable checks. Remove RDAP and remote allowlist refresh from scan execution and module-import side effects in this first release; this avoids an extra network/disclosure path. The hard-coded local blocklist remains labeled limited local evidence. Remove/refactor direct `requests` and raw socket paths so all destination-derived I/O uses Task 2. Add a production-import regression with network denied and without the test allowlist opt-out to prove ordinary import remains offline.
- [ ] **4. Run green and adapt existing tests explicitly.** `.venv/bin/python -m pytest tests/test_url_evidence.py tests/test_analysis_smoke.py tests/test_detection_dataset.py -q`. Document intentional differences, including private addresses now being blocked/unassessable instead of fetched and scored. Do not weaken assertions merely to pass. Keep synthetic network observations.
- [ ] **5. Commit.** `git commit -m "fix: preserve phishing evidence and distinguish missing checks"` after staging Task 3 files.

## Task 4: Ephemeral Message Analysis, API and Privacy Closure

**Files:** Create `app/detection/message_analyzer.py`, `app/routers/analyze.py`, `app/scan_limits.py`, `tests/test_message_analysis.py`, `tests/test_message_api.py`, `tests/test_scan_privacy.py`; modify `app/analysis.py`, `app/main.py`, `app/db/database.py`, `app/settings.py`, `tests/test_auth_flow.py`.

**Interfaces:** Produce `text_evidence(parsed: ParsedMessage) -> list[Reason]`; `assess_message(parsed: ParsedMessage, links: list[LinkResult]) -> AssessmentSummary`; and `analyze_message(payload: MessageRequest, *, request_id: str, transport: SafeTransport) -> MessageResponse`. In the router expose `get_scan_transport() -> SafeTransport` for dependency injection. Produce `to_legacy_response(result: MessageResponse, raw_url: str) -> dict`; new `scan_id` is always null. Preserve `app.main:app` as the production entry point. Extract existing startup DB work to `initialize_database() -> None`, preserving its production behavior; test fixtures substitute only this initializer.

- [ ] **1. Write failing message/API/privacy tests.** Static mode has `transport.inspect.call_count == 0`; both zero-link and multi-link messages return the declared schema. “Send me your OTP now” remains warned even with an official-domain link; “Do not share your OTP” does not trigger the same rule. A phishing link plus a failed link remains phishing/partial. Unsupported text without usable evidence returns unknown. A malformed backend condition never returns a safe result.
- [ ] **2. Add boundary assertions.** `/v1/scans`, `/v1/scans/1`, `/v1/scans/1/report.pdf` return 410 without database reads; POST scans perform no `Scan`/raw-result writes. Errors containing a sentinel token never reproduce it in response/logs; Pydantic validation errors must omit their `input` field. Results and error responses include `Cache-Control: no-store`. Old records remain unchanged. Test 422/413/429/503 separately and replace auth-test skip-on-404 with explicit assertions that the currently disabled auth routes are unavailable; do not claim auth flow coverage.
- [ ] **3. Run red.** `.venv/bin/python -m pytest tests/test_message_analysis.py tests/test_message_api.py tests/test_scan_privacy.py -q`; expected failures cover the old URL-only/persistent/public behavior.
- [ ] **4. Implement message evidence and aggregation.** Require combinations of contextual evidence for phishing; a single keyword is insufficient. Apply risk precedence before coverage: never average a dangerous link away. Unknown/missing checks prevent `no_clear_signs` where those checks were required, but cannot erase strong observed risk. No-link supported messages can complete; static linked messages clearly say pages were not visited. Keep reason/action codes stable and translated later in Task 6.
- [ ] **5. Implement stateless routes and bounded work.** Add `/v1/analyze-message`; adapt `/v1/analyze` through the same service with optional `inspect_links=false`. Remove scan persistence and history reads without deleting data. Enforce a 128 KiB incoming JSON-body cap before parsing, including streamed bodies. Use the existing `RATE_LIMIT_PER_MINUTE` (default 60), a process-memory expiry-bounded limiter with at most 10,000 identities, and Task 2's shared two-slot inspection guard; refuse excess work rather than queue without bound. Keep identity only in short-lived limiter memory, never logs or persistent storage; if the identity cap is full after expiry cleanup, return 429. Key from the ASGI client identity, never blindly trust submitted forwarding headers; document proxy identity validation as a release check. Generate server request IDs and log only route template/status/duration/request ID. Sanitize validation and unexpected errors.
- [ ] **6. Run green.** Repeat Task 4 tests plus Tasks 1–3. Assert historical synthetic rows are identical before/after and no forbidden route touches the DB. Include deadline-skipped links and slot-exhaustion outcomes; verify rate-limit memory expires and remains bounded.
- [ ] **7. Commit.** `git commit -m "feat: add private message analysis and retire public scan history"` after staging Task 4 files.

## Task 5: Validated Frontend Contract and Request Lifecycle

**Files:** Create `mobileshield-web/lib/analysis.ts`, `app/hooks/useMessageAnalysis.ts`, `lib/analysis.test.ts`, `app/hooks/useMessageAnalysis.test.tsx`, `vitest.config.ts`, `tests/setup.ts`, `.eslintrc.json`; modify `lib/api.ts`, `package.json`, `package-lock.json`, `tsconfig.json`. All listed paths are under `mobileshield-web`.

**Interfaces:** Mirror Task 1 types; produce `parseAnalysisResponse(value: unknown) -> MessageResponse`, `normalizeLegacyVerdict(value: unknown, analysisStatus: AnalysisStatus) -> Assessment`, `analyzeMessage(input: MessageRequest, signal: AbortSignal) -> Promise<MessageResponse>`, and `useMessageAnalysis()` exposing `{state, submit, cancel, invalidate, retry}`. State includes immutable submitted text, sequence ID and loading/result/error status; retry remains a user action.

- [ ] **1. Prepare component verification.** In `mobileshield-web`, run `npm ci`, then install and lock development-only Vitest, jsdom and React Testing Library packages, including its DOM peer, matchers and user-event. Keep runtime framework versions unchanged in this feature. Configure JSX/alias resolution, noninteractive lint, `test: vitest run`, `typecheck: tsc --noEmit`, and ignore generated test output. Local Node is 26.7.0; verify any added dev-tool engine requirement without changing Render runtime settings.
- [ ] **2. Write failing contract/lifecycle tests.** Assert `normalizeLegacyVerdict('phishing', 'partial') === 'phishing'`; legacy `malicious` maps likewise; explicit `unknown` remains unknown; `legitimate`/`safe` become `no_clear_signs` only with complete coverage and otherwise unknown; unrecognized values such as `alien` and missing values throw. Malformed JSON/envelopes yield errors, and no score becomes a probability. Assert an older deferred response cannot replace a newer one; edit/cancel invalidates it; changing language retains submitted content. `Array.from(text).length` matches Python's code-point limit for emoji/combining fixtures. A 503/429/non-JSON response exposes a localized error code, not raw server text.
- [ ] **3. Run red.** `npm --prefix mobileshield-web test -- lib/analysis.test.ts app/hooks/useMessageAnalysis.test.tsx`; expected missing-interface/behavior failures.
- [ ] **4. Implement validation and lifecycle.** Reject invalid enums/versions and bound arrays/strings. Send full text and the explicit inspection Boolean, never the client-extracted first URL. Use AbortController plus sequence IDs; use a 30-second client request limit around the server's 20-second inspection budget. Do not auto-retry, cache payloads, write messages to storage, or attach unrelated saved user credentials to the public scan call. Preserve other API consumers without broad auth changes.
- [ ] **5. Run green.** Repeat focused tests and `npm --prefix mobileshield-web run typecheck`; all pass. Verify prior result is invalidated when its input changes and that cancellation cannot restore it.
- [ ] **6. Commit.** `git commit -m "fix: validate scan responses and prevent stale results"` after staging Task 5 files.

## Task 6: Bilingual Responsive Message and Evidence UI

**Files (relative to `mobileshield-web/`):** Modify `app/page.tsx`, `app/components/ScanForm.tsx`, `app/components/ResultDisplay.tsx`, `app/components/HeaderBar.tsx`, `app/components/AnalyzeForm.tsx`, `app/components/ui/textarea.tsx`, `app/context/LanguageContext.tsx`, `app/globals.css`, `app/layout.tsx`, `app/api/report/pdf/route.ts`; create `app/components/ScanForm.test.tsx`, `app/components/ResultDisplay.test.tsx`.

**Interfaces:** `ScanForm` submits `MessageRequest` and notifies input invalidation; `ResultDisplay` consumes the validated `MessageResponse` and request status. Both use Task 5 lifecycle and the existing language context. No second verdict mapper or separate response model in components.

- [ ] **1. Write failing user-facing tests.** Assert the textarea has a visible accessible label, deep inspection is unchecked, clipboard denial leaves manual input working, and all four assessments plus partial/error states render distinct copy. Unknown does not render “Safe Link.” Warning reason codes and actions translate in both languages; domains render isolated LTR text, not clickable navigation. Test editing/cancel/retry and language switching during loading, and ensure clear removes both input and result.
- [ ] **2. Run red.** `npm --prefix mobileshield-web test -- app/components/ScanForm.test.tsx app/components/ResultDisplay.test.tsx`; expect failures reflecting the current URL-only UI.
- [ ] **3. Implement the approved design.** Warm pale background, white cards, navy text, teal primary action; compact brand/language header and footer contact/social links. Add labeled full-message input, clear/paste, code-point count, explicit optional deeper inspection disclosure and one primary action. Show assessment → action → concise reasons → expandable per-link coverage/details. Use exact label “No clear warning signs” with a no-guarantee explanation; show incomplete analysis separately. Display no invented confidence or numeric probability.
- [ ] **4. Implement accessibility and report retirement.** Set page language/direction, message `dir="auto"`, isolated URLs, logical spacing, safe wrapping, visible focus, 44 px primary touch targets, restrained status announcements and reduced-motion behavior. Use semantic headings and a keyboard-operable evidence disclosure. Retire the obsolete frontend PDF endpoint with 410, remove report controls that imply saved scans, and update remaining typed legacy components to compile without reintroducing history.
- [ ] **5. Run green.** Repeat component tests, run all frontend tests and `npm --prefix mobileshield-web run typecheck`; all pass. Contrast checks must meet WCAG AA text/control requirements; record manual screen-reader coverage separately from DOM assertions.
- [ ] **6. Commit.** `git commit -m "feat: redesign bilingual message analysis experience"` after staging Task 6 files.

## Task 7: Integrated Verification and Independent Review

**Files:** Create `tests/browser_app.py`, `tests/test_scan_integration.py`, `docs/verification/2026-10-08-message-analysis.md`; save screenshots under `../MobileShield-review/after/`. Change product files only to fix reproduced findings, with focused regressions.

**Interfaces:** `tests.browser_app:app` imports the production FastAPI app, replaces only the extracted DB initializer and `get_scan_transport` dependency with deterministic synthetic fixtures, and binds to loopback. This test-only module is absent from the production Docker image, which copies only `app/`; no production bypass option is added.

- [ ] **1. Add integrated regression tests.** Assert real endpoint serialization → frontend parser fixtures agree on every enum and schema version. Use the fixed 60-case corpus, multi-link partial failures and all original severe bugs. Test fixture transports cannot open real sockets and static runs remain network-free. Run `.venv/bin/python -m pytest tests/test_scan_integration.py -q`; expect all pass after integration fixes, with every fix first demonstrated by a failing regression.
- [ ] **2. Run final automated checks once changes stabilize.** `.venv/bin/python -m pytest -q`; `npm --prefix mobileshield-web test`; `npm --prefix mobileshield-web run typecheck`; `npm --prefix mobileshield-web run lint`; `npm --prefix mobileshield-web run build`; `git diff --check`. Record exact counts, exit codes, skips and known baseline differences. Report failures honestly; do not suppress type/lint errors or weaken tests. A production database-startup check is separate and remains not-run if no isolated PostgreSQL is available.
- [ ] **3. Exercise the real local browser flow.** Start the fixture API on `127.0.0.1:8001` and the Next app on `127.0.0.1:3001`, using a task-local environment pointing only at that API. Through the supported browser tool, submit ordinary/risky/text-only/multi-link messages; toggle deeper inspection; edit during scanning; cancel; repeat; retry after stopping/restarting the local API. Verify actual UI results, including no stale or green fallback. Do not run a production scan.
- [ ] **4. Capture responsive/accessibility evidence.** At 320/390/768/1440 px in Hebrew and English, capture input and representative result/error views. Check long URLs, bidi/emoji, 200% zoom, keyboard order/focus, named controls, contrast and reduced motion. Inspect screen-reader announcements with available tooling; label anything not exercised as not-run. Restore temporary browser viewport settings afterward.
- [ ] **5. Request a fresh independent whole-branch review.** Reviewer reads approved spec/plan, complete diff and verification report, focusing on SSRF bypasses, worker/resource leaks, data persistence/logging, API/frontend drift, false reassurance and stale requests. The chosen execution method may additionally review each task. Fix material findings with regressions, rerun affected checks, and obtain a clean follow-up review. Do not broaden into unrelated product work.
- [ ] **6. Finish the local deliverable.** Commit reviewed fixes and `docs/verification/2026-10-08-message-analysis.md` with `git commit -m "test: verify message analysis safety and end-to-end behavior"`. Return checkout/branch/commits, screenshots and exact passed/failed/not-run checks. Explain corpus limitations; do not claim general detection accuracy from synthetic tests.
- [ ] **7. Prepare, but do not execute, publication steps.** Provide a reviewable diff/PR proposal and sequence: user-approved frontend compatibility release, user-approved backend release, then revision/health/synthetic acceptance checks and rollback references. Verify effective proxy client identity and infrastructure logging before public privacy claims. Neither pushing main nor publication is part of this plan's execution authorization.

## Plan Self-Review

- Spec coverage: parsing/contracts → Tasks 1/5; optional safe networking → Tasks 2/3; evidence/uncertainty → Tasks 3/4; privacy/history/rate limits → Task 4; design/accessibility/request states → Tasks 5/6; evaluation, independent review and publication boundaries → Task 7.
- All seven tasks name files, interfaces, failing assertions, verification commands and commit checkpoints. Task 7 is an integration/acceptance deliverable, not a second implementation subsystem.
- Type/field names and limits are consistent across the task interfaces. Each of the five Review Focus items has an owning test step. Self-review also caught and resolved legacy unknown/alias ambiguity, shortened file paths, duplicate concurrency ownership, and implicit public-suffix downloads/import-time refresh. No unresolved placeholders remain.
- No infrastructure change, provider, permanent message store, automated SMS access or OCR has been added. Raw historical data is never fetched for demonstration or deleted.

## Execution Choice for Review

**Recommended: Subagent-driven, sequentially.** A fresh implementer handles each task and a fresh reviewer checks it before the next task begins, followed by whole-branch review. Seven tasks share security-sensitive contracts, and a missed privacy or false-benign defect has a substantial cost; per-task review is justified. It uses more agent contexts.

**Alternative: Native.** The current agent implements the same seven tasks, then a fresh independent reviewer checks the complete branch. This uses fewer contexts and can be faster, but independent review arrives later.

Please review the plan and choose Subagent-driven or Native before product implementation. Publication remains a separate approval.

Test-tool references: [Vitest setup](https://vitest.dev/guide/), [React Testing Library setup](https://testing-library.com/docs/react-testing-library/intro/), [FastAPI testing](https://fastapi.tiangolo.com/tutorial/testing/).
