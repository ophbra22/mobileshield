# Practical text coverage correction — October 9, 2026

Task 12 replaces the all-token English dictionary and blanket Hebrew-script acceptance with a pure structural coverage helper. The API schema, reason codes, warning extraction, risk ordering, URL inspection policy, privacy controls, input limits, dependencies and legacy-client guard are unchanged. The controller-authored October 9 design correction is the authority. Publication and independent review remain controller-owned.

## Observable behavior

The exact ordinary acceptance message, `Hi, our book club meets tomorrow at ten by the library. See you then!`, now produces `no_clear_signs / complete`, no limitations, and no links.

The exact suspicious acceptance message, `Urgent! Your account will be blocked in one hour. Enter your password and verification code now at https://account-verify.example.com/login or http://security-update.example.net/confirm .`, produces `suspicious / complete`, `credential_request` and `urgency`, both links `not_requested`, and only `inspection_disabled`. Both cases are pinned through FastAPI's actual ASGI boundary and the actual TypeScript response parser, with `inspect_links=false` and zero transport calls. The established risk rules decide the warning level; coverage does not infer language from those rules.

Unknown/unavailable results with exactly `unsupported_text` now say **Limited text coverage** / **כיסוי טקסט מוגבל** in their heading, coverage label and live announcement, with a localized explanation. Ordinary HTTP/network errors, unavailable analysis with other limitations, and partial warnings retain their existing presentation. The complete ordinary response still carries the safety-guarantee caveat. Component tests preserve Hebrew RTL, English LTR, accessible headings/status, and existing safe rendering.

## Coverage policy and exact thresholds

`app/text_coverage.py` has no I/O, diagnostic output, corpus identifiers, model, added dependency, or warning-rule import. The caller retains the existing 10,000-codepoint limit and original message. URL candidates are removed by the parser and replaced with whitespace, preventing accidental joining of neighboring words. Email addresses are also excluded from evidence. Only the coverage copy undergoes Unicode decomposition and mark removal, allowing ordinary Latin accents and Hebrew niqqud. Unsupported or mixed-script words reject coverage.

The helper uses 97 English and 77 Hebrew closed-class/functional markers (pronouns, determiners, auxiliaries, prepositions, conjunctions, question/discourse/time words). Content words do not need membership. English contractions retain their grammatical root. Seven conventional greetings are removed from structural evidence. Eighteen short acknowledgments/link prompts, including those greetings, are recognized alone; a nongreeting short prompt may also introduce one plausible content token.

Coverage is assessed separately for sentence boundaries (`. ! ? ;` and newline) and contiguous script runs. Every run of at least three remaining words must pass independently. A two-word run can establish context with its own structural evidence. Unknown one/two-word headings, names or acronyms can borrow context only when substantial covered prose exists, and only up to **two such tokens in the entire message**. A greeting alone provides no borrowed context; dividing a passage into many short sentences cannot bypass the token budget.

For each substantial run:

- Direct evidence requires at least one marker per eight English tokens or six Hebrew tokens. Density sets the minimum; there is no separate second-marker requirement at the fifth word. Repeated grammatical markers count: “Our compost improves our vegetable patch” is normal structure. This admits ordinary determiner–subject–predicate sentences when modifiers are added.
- Leading content spans allow at most four unanchored words. Internal spans allow at most eight, bounded by structural markers on **both** ends. Trailing spans normally allow four. In English only, a last marker from the existing article/determiner/possessive subset (`a an the my your his her our their its this that these those all any some each`) allows up to eight following content words. This supplies room for nominal subjects, predicates and objects with modifiers. An introduction ending in a time/discourse marker such as “tomorrow” retains the four-word tail bound. No content nouns or verbs were added to the marker inventory.
- Hebrew also allows a combined evidence path: direct markers plus attached prefixes `ה ב כ ל מ ש ו` on words at least four letters long. At least half the words must supply evidence, with at least two distinct evidence classes (a full marker or a prefix class). A word is never counted twice. The ordinary four-word edge/eight-word internal span bounds apply. A single attached prefix is insufficient.

All words must also pass conservative shape checks:

- Reject a character repeated three times or a 1–3-character unit repeated at least three times throughout the word.
- Reject whole words of four or more letters that are contiguous forward/reverse runs of common English/Hebrew keyboard rows or alphabetical order.
- Hebrew words have at most 16 letters and cannot place a final-form letter internally.
- Latin words have at most 30 letters; words of at least four letters need an `a/e/i/o/u/y`, and seven consecutive nonvowels reject. Uppercase abbreviations up to five letters bypass those vowel checks, but never supply anchors merely for being uppercase.
- Messages of at least six words reject if they contain at most two distinct words or one word occupies at least 60% of the message. Before removing greetings, also reject any three consecutive copies of a 1–16-token unit occupying at least six tokens, anywhere in the input and across punctuation. For longer cycles, scan token prefixes: at least nine tokens, at least 60% duplicate trigrams, and at least one trigram occurring three times establishes repetitive structure. Once a prefix meets that condition, a warning suffix cannot erase it. This takes linear work with a constant 16-period scan and linear-size trigram storage; no unbounded pattern-length search is used.

These are bounded deterministic heuristics, **not** calibrated confidence or comprehensive language identification. The density, length and span thresholds are engineering limits, not empirical accuracy estimates.

## Regression evidence and deliberate limitations

The initial independent-authored matrix contains 25 ordinary/mixed cases (including at least 12 additional English and 8 Hebrew messages across household, work, scheduling, hobbies and names), 29 uncertain cases, 20 positive/negative greeting-prefix transformations, eight warning-preservation combinations, and the exact ASGI acceptance pair. Added structural controls cover longer noun phrases, repeated grammatical markers, long unsupported tails in both scripts, and fragmented unsupported passages. Production helper outputs did not generate the expectations. Existing corpus/negative-language expectations were not relabeled or relaxed.

Before implementation, the new backend matrix had **36 failures / 47 passes**, and new component cases had **2 failures / 29 passes**. Focused iterations exposed and fixed ordinary Hebrew combined-prefix constructions, overly strict distinct-marker and noun-span rules, and a Hebrew fallback missing the common tail bound. A final self-review exposed unlimited borrowing across tiny sentence fragments; two new failing regressions led to the global two-token borrowing cap. All historical expectations remain unchanged.

Residual limitations are material: plausible invented words in grammatical English/Hebrew frames can pass; other Latin languages sharing the markers can be mistaken for covered text; Hebrew prefixes are ambiguous; up to two unsupported-looking short tokens can inherit context; short repetitive strings below the six-token cutoff can pass. Conversely, clipped prose, lists/names without structure, unusually long words, vowel-poor transliterations, and some legitimate noun-heavy sentences remain uncertain. Shape checks may reject stylized spelling. Punctuation and script switching affect segmentation. No-clear-signs continues to mean only that the applicable bounded checks found no clear warning, never that the message is safe. Longer cycles diluted by unrelated leading text can escape the prefix-trigram rule. Nominal-marker roles are heuristic: a shared or ambiguous determiner can admit unsupported language or invented content shaped like a noun phrase. The synthetic regression suite establishes behavior, not general accuracy.

## Verification commands and outcomes

Working directory: `/Users/braude/Documents/Codex/2026-10-08/task/MobileShield`.

Every command below used this **process-local** prefix, including inherited child processes:

```sh
PATH="/Users/braude/Documents/Codex/2026-10-08/task/MobileShield-review/qa-runtime/node-v22.22.0-darwin-arm64/bin:$PATH"
```

Observed runtime: Node **v22.22.0**, npm **10.9.4**, existing virtualenv Python **3.11.14**. No global runtime/configuration changes.

| Command following that prefix | Exit / result |
| --- | --- |
| `.venv/bin/python -m pytest tests/test_text_coverage.py tests/test_message_parser.py tests/test_message_analysis.py tests/test_message_api.py tests/test_scan_integration.py tests/test_final_review.py -q` | 0; 449 passed (review-fix round 1) |
| `npm --prefix mobileshield-web test -- app/components/ResultDisplay.test.tsx` | 0; 33 passed |
| `.venv/bin/python -m pytest -q` | 0; 762 passed (review-fix round 1) |
| `npm --prefix mobileshield-web test` | 0; 131 passed in four files |
| `npm --prefix mobileshield-web run typecheck` | 0 |
| `npm --prefix mobileshield-web run lint` | 0; no ESLint warnings/errors |
| `NEXT_PUBLIC_API_BASE_URL=https://mobileshield-backend.onrender.com NEXT_TELEMETRY_DISABLED=1 npm --prefix mobileshield-web run build` | 0; Next 15.5.27; six static pages generated |
| `git diff --check` | 0 |

The public origin was confirmed in the generated page JavaScript. Supplying it at build time did not call the API. Backend tests enforce the existing collection/execution-time socket guard against live DNS/HTTP and use mock/fake transports. No browser, live API, push, merge, publication, or Render-setting actions were performed.

Warnings: existing Starlette/AnyIO BlockingPortal and Python `crypt` deprecations; Next `next lint` deprecation; Tailwind configuration `MODULE_TYPELESS_PACKAGE_JSON` warning during build. No dependency or runtime changes were made to suppress these.

Detailed commands, red–green logs and self-review are in `.superpowers/sdd/2026-10-08-message-analysis/task-12-report.md` and its adjacent `task12-logs/` directory (local workflow evidence, intentionally ignored by Git).

## Review-fix round 1 — I1/I2

Review at `226ab01` identified clear multiword cycles that bypassed the original distinct-word guard and ordinary modifier expansions rejected by the fifth-token/edge-span rules. Added 34 cases before changing the helper: greeting/function-word/Hebrew cycles, punctuation and long-cycle variants, exact 10,000-codepoint input, warning-appended cycles, varied ordinary repeated grammatical frames, ten original/expanded sentence pairs, unsupported-passage controls, and an ASGI/client-parser matrix. New full file RED: **24 failed / 107 passed**, exit 1. No existing expectation changed.

The first fix run had **448 passed / 1 failed**: the longer-than-16-token cycle was detected alone, but a warning suffix diluted the global trigram ratio. Prefix-based accumulation fixed that class without changing warning extraction. Final focused: **449 passed**, exit 0. Final full backend: **762 passed**, exit 0. The unchanged controller holdout was read only after review authorization and passed **25/25** in an offline check with zero transport calls. Controller retains independent rerun/review authority.

Commands use the same exact process-local Node 22 PATH and six-file focused/full commands above. Logs: `task12-fix1-red.log`, `task12-fix1-focused.log`, `task12-fix1-focused-final.log`, `task12-fix1-heldout.log`, `task12-fix1-full-backend.log` in the existing ignored `task12-logs/` directory. Frontend source did not change in this round; its prior 33 component / 131 full tests, typecheck, lint and production build remain the relevant checks and were not repeated. The only full-backend warnings remain the existing AnyIO and `crypt` deprecations. No browser, external service, publication or deployment action was taken by the implementer.
