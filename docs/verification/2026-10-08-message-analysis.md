# Message analysis verification — 8 October 2026

Status: functional integration checks pass; publication remains blocked by unresolved dependency advisories, missing environment-specific acceptance checks, and pending independent controller review. No push, deployment, production scan, history access, credential change or permission change was performed.

## Scope and tested state

Checkout: `/Users/braude/Documents/Codex/2026-10-08/task/MobileShield`; branch `codex/mobileshield-design-review`. Product baseline `8abb3078c01ce26e605c9129d48484c770b574e7`, planning baseline `d87de55`, Task7 base `2f1bb7b06810fc33a25862f1bdbd0581d5114d82`. The Task7 commit accompanying this document contains the tested changes. Logs identify the base plus exact working-tree diffs; new test files are committed alongside this report. Backend checks preceded only the subsequent localized disclosure/test edit; affected frontend checks were rerun after it.

Reproduced fixes:

- Fronted secret requests ending “send that by email” or “send that via email” now retain `credential_request`, `suspicious/complete`, and `do_not_share_secrets`. Only the existing demonstrative delivery boundary was extended; prior negation/reference regressions remain passing.
- Latin script alone no longer establishes supported English text. A 220-word, hand-curated lexical coverage gate uses ordinary function words and the product's greetings, scheduling and account-security vocabulary. This is a small auditable coverage boundary, not a language detector or general dictionary. No corpus IDs, risk labels, provider or new dependency is used by the gate. Already parsed URL spans and email addresses are removed from prose evidence; numbers/punctuation are ignored. Unknown Latin words remain limited even alongside Hebrew. Independent message/URL warnings survive as partial results.
- Optional inspection help in English and Hebrew explicitly says the server visit may activate tracking or a one-time link. Two visible-copy tests also assert the checkbox is off by default and associated with that help using `aria-describedby`.
- Compatible npm graph remediation: Next and eslint-config-next 14.1.0→14.2.35; ESLint 8.56.0→8.57.1 for compatible peer resolution; PostCSS 8.4.33→8.5.23, including Next's PostCSS override; Next ESLint plugin glob override→10.5.0 within its major. Compatible transitives were regenerated through npm. React18 and Tailwind3 remain. No forced audit fix, ignored peers or cross-major override.

Coverage tradeoff: unfamiliar ordinary English and names (for example “Aurelia discusses photosynthesis.”) intentionally become unknown/limited. Supported vocabulary can also overlap other languages, and Hebrew script coverage is not semantic understanding. The gate prevents the reproduced false reassurance but does not identify a message's language or claim comprehensive detection. The warning rules remain bounded heuristics.

## Automated evidence

Raw stdout/stderr and exits are in `../MobileShield-review/verification-logs/`. `results.json`, `results-after-copy.json`, `tested-product.diff` and `tested-product-after-copy.diff` identify each tested state. No final test is skipped or xfailed.

| Final command (repository root) | Result | Raw log |
| --- | --- | --- |
| `.venv/bin/python -m pytest tests/test_scan_integration.py -q` | 17 passed, 3 warnings, exit 0 | integration.log |
| `.venv/bin/python -m pytest -q` | 481 passed, 3 warnings, exit 0 | backend.log |
| `npm --prefix mobileshield-web test` | 112 passed in 4 files, exit 0 | frontend-test-after-copy.log |
| `npm --prefix mobileshield-web run typecheck` | exit 0 | typecheck-after-copy.log |
| `npm --prefix mobileshield-web run lint` | exit 0, no warnings/errors | lint-after-copy.log |
| `npm --prefix mobileshield-web run build` | exit 0, Next14.2.35, 6 generated static pages | build-after-copy.log |
| `git diff --check` | exit 0 | diff-check-after-copy.log; final-diff-check.log |
| `npm --prefix mobileshield-web ci --cache /Users/braude/Documents/Codex/2026-10-08/task/MobileShield-review/npm-cache` | exit 0, 514 installed/515 audited | npm-ci-final.log |
| `npm --prefix mobileshield-web ls --all --json` | exit 0, consistent dependency graph | npm-tree.log |
| `npm --prefix mobileshield-web audit --json --cache /Users/braude/Documents/Codex/2026-10-08/task/MobileShield-review/npm-cache` | exit 1, 8 vulnerable packages | npm-audit-final.json |

Python warnings: RequestsDependencyWarning for urllib3 2.8.0/chardet7.6.0/charset_normalizer3.5.2 compatibility; Starlette deprecated AnyIO BlockingPortal alias; Passlib deprecated crypt (planned Python3.13 removal). These are retained, not suppressed. npm ci warns about deprecated inflight, humanwhocodes config/object-schema, rimraf3, whatwg-encoding, glob7/10, crypto-js and ESLint8. Existing install-script approval policy reports esbuild/fsevents/unrs-resolver scripts not covered; no permissions were broadened. Tests and build nevertheless passed. Functional success does not erase these maintenance concerns.

### RED/GREEN history and setup failures

- Initial `.venv/bin/python -m pytest tests/test_scan_integration.py -q`: 11 failed/1 passed (exit1), demonstrating unsupported Latin reassurance and both delivery-preposition false negatives; `task7-integration-red.log`.
- Covering `.venv/bin/python -m pytest tests/test_message_parser.py tests/test_message_analysis.py tests/test_scan_integration.py -q`: first iterations 7 failed/222 passed (exit1), then 229 passed/3 warnings (exit0); `task7-focused-green1.log`, `task7-focused-green2.log`, `task7-focused-green3.log`. Ordinary English omissions `them`, `report`, `missing` were corrected as genuine function/scheduling vocabulary. The second run still failed because a preceding restricted `ps` command prevented the intended edit; no hidden passing claim.
- Expanded integration initially 15 passed, then two added preservation assertions failed (15 passed/2 failed): URL obfuscation can independently warn, and one blocklist observation is suspicious rather than phishing. Assertions were corrected to test coverage preservation and existing aggregation semantics; corpus labels were not changed. See `task7-integration-final-focused.log`.
- A run during concurrent npm ci failed 13/17 cases because TypeScript was temporarily absent from replaced node_modules (`task7-integration-ready.log`). This was a verification setup ordering error; the stable final integration run passed all17 without product changes.
- `npm --prefix mobileshield-web test -- app/components/ScanForm.test.tsx`: disclosure RED 2 failed/16 passed, exit1 (`inspection-copy-red.log`); after both translations, GREEN18 passed, exit0 (`inspection-copy-green.log`). Full frontend final112 includes those two tests.
- Final full suite before this copy-only edit was backend481/frontend110; only affected frontend checks were repeated afterward. No backend rerun was needed for translation/test-only changes.
- Initial restricted audit had network ENOTFOUND; authorized registry access succeeded. An early install without task-local cache was canceled (exit130) before product changes. Initial lock regeneration retained stale nested PostCSS despite the override; clean npm-generated lock/node_modules regeneration resolved it. Final ci and npm ls both pass. No audit warnings were hidden.

## Integration boundaries and corpus provenance

`tests/browser_app.py` imports the production FastAPI application and substitutes exactly the extracted DB initializer and `get_scan_transport`. No routes, rate limits, service aggregation or runtime bypass flags are replaced. Docker copies only `app/`, so the fixture module is not shipped. Supported fixture hosts yield synthetic HTML/TLS data; all other hosts fail without sockets. Existing conftest guards DNS/socket use, including swallowed attempts. The fixed corpus invokes the real ASGI endpoint, validates no-store, checks static transport call count zero and executes the actual TypeScript runtime parser using the installed compiler. Enum coverage exercises every assessment, completion, action, inspection, strength/source, schema version and reason code through response validation/serialization and that parser. Multi-link failure/capacity behavior retains warning evidence and explicit limitations. Existing full-suite regressions cover original severe failures: Unicode limits, SSRF/redirect/DNS/resource bounds, trusted-link plus secret requests, redacted exceptions/history retirement, malformed client responses and stale requests.

The fixed synthetic corpus contains60 authored cases (30 Hebrew/30 English):22 no_clear_signs,18 suspicious,18 unknown,2 phishing. Task7 leaves raw messages and expected labels unchanged. Earlier controller-approved Task4 IDN interpretation changed en-29/he-29 to no_clear_signs while retaining `original_expected_assessment: unknown` and a provenance note. These are specification-oriented authored labels, not independently annotated real-world data. Passing60/60 is regression agreement, not measured detection accuracy, precision, recall or language coverage. Beyond-corpus French/Spanish/German, ASCII French, mixed Hebrew/German, English/French and unfamiliar-English controls are included, plus independently positive message/URL warning survival.

## Real browser and accessibility evidence

Supported CUA only; hidden IAB browser2/tab2. Actual localhost Next UI used fixture API, with no production scans or destination visits. Hebrew RTL and English LTR input/result/error screenshots at320/390/768/1440px are saved under `../MobileShield-review/after/`; full manifest is `../MobileShield-review/screenshot-manifest.md`. Every final image listed in the manifest was opened and visually inspected. The separate controller-created mobileshield-root-hydration-blocker.jpg is diagnostic failure evidence and excluded from the success manifest. Geometry observations show document scrollWidth equal viewport width at all prescribed widths. Long synthetic URLs, Hebrew/English/emoji wrapping, default unchecked inspection, hierarchy, localized results, warnings and retry are visible.

Actual flows: ordinary text→no_clear_signs/complete plus explicit non-guarantee; text-only secret request→warning; multi-link deep inspection→phishing/partial despite failed link; French text→unknown/unavailable; edit during slow request clears result and late completion stays cleared; cancel stays cleared after server completion; language switch during request preserves submitted snapshot and translates completed result; repeated submissions; actual API stop produces explicit network error, restart plus explicit retry recovers. Final error screenshots show deterministic fixture503 capacity error (the stop/restart network-error flow remains in browser-evidence.json).

Keyboard: actual native Enter/Space toggled the single details/summary disclosure that contains link evidence and technical details, in both languages; verified closed/open DOM and 3px visible outline. Hebrew forward Tab order: language→paste→clear→textarea→inspection checkbox→submit→summary→contact→LinkedIn. Named controls, textarea helper/count association, checkbox help association and persistent role=status/aria-atomic=true were observed. DOM snapshots show pending/result/error status content. This is DOM/AX evidence, not spoken screen-reader output. Technical URL paths/query tokens remain masked and are not clickable.

Contrast: Task6's22 source-color pair calculations pass their specified4.5:1 text/3:1 control thresholds (Task6 report retained). Task7 visually inspected rendered controls, native checkbox (accent rgb14,105,99), text, focus and error/warning states. This is not a complete WCAG claim. Reduced-motion CSS exists; current browser preference was false.

**Not run:** native browser200%zoom; reduced-motion on/off emulation; manual spoken screen-reader testing; forced-colors OS mode. Available IAB capabilities expose only visibility/viewport; no supported zoom/media/reader interface. CSS zoom was not substituted. Controller independently confirmed the capability gap. Temporary viewport override was reset. Production PostgreSQL startup not run: Docker daemon unavailable and postgres/initdb/pg_ctl/psql absent. Infrastructure proxy identity, production logging and real deployment health remain release acceptance work.

Capture limitation: fullPage stitching produced clipped/blank images while DOM geometry and normal viewport captures were correct; one HE1440 capture was explicitly rejected. All final files are recaptured normal viewport images with separate scrolled views, not that bad artifact. A transient dev hydration SyntaxError during dependency/build restart cleared after compilation and reload; generated layout syntax check passed, subsequent checks/captures worked. At final handoff, controller's fresh tab after the last dev restart again showed static HTML without responsive React controls (count stayed0 and language did not switch). Server logs were clean, and actual served layout/page JavaScript both passed node --check; see preview-served-assets.log. Fresh-reload confirmation is pending with the controller, so the final restarted preview is not yet accepted. This does not invalidate the earlier observed interactive flows, but its cause is unresolved. No layout change was made to hide compositor behavior. Stale filled-input captures are outside final after/ in superseded-captures and are not deliverables.

## Task-owned processes and handoff

API current PID48678/session94842, loopback8001:

```sh
env DATABASE_URL=sqlite:// ALLOWLIST_ENABLED=false ALLOWLIST_SOURCES=local_popular ALLOWLIST_CACHE_PATH= CORS_ORIGINS=http://127.0.0.1:3001 .venv/bin/python -m uvicorn tests.browser_app:app --host 127.0.0.1 --port 8001 --no-access-log
```

Frontend current PID50670/session29853, loopback3001:

```sh
env NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8001 NEXT_TELEMETRY_DISABLED=1 npm --prefix mobileshield-web run dev -- --hostname 127.0.0.1 --port 3001
```

First sandbox API bind failed (session30568 exit1); approved exact loopback escalation succeeded. API session99293 was stopped with Ctrl-C exit0 to prove outage, then current94842 restarted. Frontend38306 and93797 were stopped exit0 for clean install/build; current29853 restarted ready after final build. Only these task services were controlled. No automatic approval-review rejection occurred. Process IDs verified with lsof; no credentials read. Browser tab marked handoff, but root sees task-scoped separate tabs and may open its own localhost tab. Services intentionally left for controller acceptance; stop only these task-owned sessions afterward.

## Dependency audit and unexecuted migration

Final online npm audit exits1 with8 packages:2 moderate,5 high,1 critical. Initial22 (3 moderate/18 high/1 critical) reduced through install/update stages18→12→9→8; preserved before/intermediate12 JSON plus installation logs, with final raw JSON authoritative. All stages used compatible changes; no security permissions changed. Next14.2.35 is the highest selected same-major maintenance update, not a full security fix.

| Package | Installed | Severity | Underlying dependency or advisory |
| --- | --- | --- | --- |
| braces | 3.0.3 | high | GHSA-vfj7-8cjw-p6xm |
| chokidar | 3.6.0 | high | braces |
| fast-glob | 3.3.3 | high | micromatch |
| micromatch | 4.0.8 | high | braces |
| next | 14.2.35 | critical | GHSA-9g9p-9gw9-jx7f, GHSA-h25m-26qc-wcjf, GHSA-ggv3-7p47-pfv8, GHSA-3x4c-7xq6-9pq8, GHSA-q4gf-8mx6-v5v3, GHSA-8h8q-6873-q5fj, GHSA-3g8h-86w9-wvmq, GHSA-ffhc-5mcf-pf4q, GHSA-vfv6-92ff-j949, GHSA-gx5p-jg67-6x7h, GHSA-h64f-5h5j-jqjh, GHSA-c4j6-fc7j-m34r, GHSA-wfc6-r584-vfw7, GHSA-36qx-fr4f-26g5, GHSA-m99w-x7hq-7vfj, GHSA-89xv-2m56-2m9x, GHSA-68g3-v927-f742, GHSA-4633-3j49-mh5q, GHSA-4c39-4ccg-62r3, GHSA-p9j2-gv94-2wf4, GHSA-955p-x3mx-jcvp, GHSA-p293-qw3h-jr36, GHSA-2xp9-vwfh-vxw4 |
| postcss-nested | 6.2.0 | moderate | postcss-selector-parser |
| postcss-selector-parser | 6.1.4 | moderate | GHSA-rj75-hqrm-r3gf |
| tailwindcss | 3.4.1 | high | chokidar, fast-glob, micromatch, postcss-nested, postcss-selector-parser |

Next's two highest-threshold advisories GHSA-2xp9-vwfh-vxw4 (AVIF image optimizer) and GHSA-p293-qw3h-jr36 (Windows-hosted) list patched15.5.24/16.3.3; no patched14.x is listed. Minimum evidenced major-line target is15.5.24. npm's automatic proposed target is16.4.0, which is not asserted to be minimal. Package presence does not prove production exploitability; configuration applicability was not probed.

Tailwind3 branch retains braces3.0.3 (no patched3.x observed), through micromatch/fast-glob/chokidar, and postcss-selector-parser6.1.4 through postcss-nested. Selector-parser advisory is patched at>=7.1.6, outside installed major. Audit proposes Tailwind4.3.3 as a major migration target; it has NOT been proved the minimal fixed Tailwind release. No major transitive overrides were forced. Review Tailwind4 CSS/plugin/config changes and compatible patched graph separately, or establish a smaller supported fix from maintainer evidence; repeat clean install/audit/frontend/browser checks. Next15 migration separately reviews React/types/peers, async request APIs/cache defaults and no-store/privacy/retired report behavior. Detailed controller scope: `../MobileShield-review/dependency-migration-scope.md`. Publication remains blocked pending approved, independently verified dependency resolution.

Exact underlying final advisories (transitive package rows above inherit these; there are25 distinct underlying advisories):

| Package | Advisory | Affected range reported | Title |
| --- | --- | --- | --- |
| braces | [GHSA-vfj7-8cjw-p6xm](https://github.com/advisories/GHSA-vfj7-8cjw-p6xm) | `<=3.0.3` | braces vulnerable to stack-exhaustion denial of service through deeply nested patterns |
| next | [GHSA-9g9p-9gw9-jx7f](https://github.com/advisories/GHSA-9g9p-9gw9-jx7f) | `>=10.0.0 <15.5.10` | Next.js self-hosted applications vulnerable to DoS via Image Optimizer remotePatterns configuration |
| next | [GHSA-h25m-26qc-wcjf](https://github.com/advisories/GHSA-h25m-26qc-wcjf) | `>=13.0.0 <15.0.8` | Next.js HTTP request deserialization can lead to DoS when using insecure React Server Components |
| next | [GHSA-ggv3-7p47-pfv8](https://github.com/advisories/GHSA-ggv3-7p47-pfv8) | `>=9.5.0 <15.5.13` | Next.js: HTTP request smuggling in rewrites |
| next | [GHSA-3x4c-7xq6-9pq8](https://github.com/advisories/GHSA-3x4c-7xq6-9pq8) | `>=10.0.0 <15.5.14` | Next.js: Unbounded next/image disk cache growth can exhaust storage |
| next | [GHSA-q4gf-8mx6-v5v3](https://github.com/advisories/GHSA-q4gf-8mx6-v5v3) | `>=13.0.0 <15.5.15` | Next.js has a Denial of Service with Server Components |
| next | [GHSA-8h8q-6873-q5fj](https://github.com/advisories/GHSA-8h8q-6873-q5fj) | `>=13.0.0 <15.5.16` | Next.js Vulnerable to Denial of Service with Server Components |
| next | [GHSA-3g8h-86w9-wvmq](https://github.com/advisories/GHSA-3g8h-86w9-wvmq) | `>=12.2.0 <15.5.16` | Next.js's Middleware / Proxy redirects can be cache-poisoned |
| next | [GHSA-ffhc-5mcf-pf4q](https://github.com/advisories/GHSA-ffhc-5mcf-pf4q) | `>=13.4.0 <15.5.16` | Next.js vulnerable to cross-site scripting in App Router applications using CSP nonces |
| next | [GHSA-vfv6-92ff-j949](https://github.com/advisories/GHSA-vfv6-92ff-j949) | `>=13.4.6 <15.5.16` | Next.js vulnerable to cache poisoning via collisions in React Server Component cache-busting |
| next | [GHSA-gx5p-jg67-6x7h](https://github.com/advisories/GHSA-gx5p-jg67-6x7h) | `>=13.0.0 <15.5.16` | Next.js has cross-site scripting in beforeInteractive scripts with untrusted input |
| next | [GHSA-h64f-5h5j-jqjh](https://github.com/advisories/GHSA-h64f-5h5j-jqjh) | `>=10.0.0 <15.5.16` | Next.js has a Denial of Service in the Image Optimization API |
| next | [GHSA-c4j6-fc7j-m34r](https://github.com/advisories/GHSA-c4j6-fc7j-m34r) | `>=13.4.13 <15.5.16` | Next.js vulnerable to server-side request forgery in applications using WebSocket upgrades |
| next | [GHSA-wfc6-r584-vfw7](https://github.com/advisories/GHSA-wfc6-r584-vfw7) | `>=14.2.0 <15.5.16` | Next.js vulnerable to cache poisoning in React Server Component responses |
| next | [GHSA-36qx-fr4f-26g5](https://github.com/advisories/GHSA-36qx-fr4f-26g5) | `>=12.2.0 <15.5.16` | Next.js has a Middleware / Proxy bypass in Pages Router applications using i18n |
| next | [GHSA-m99w-x7hq-7vfj](https://github.com/advisories/GHSA-m99w-x7hq-7vfj) | `>=13.0.0 <15.5.21` | Next.js: Denial of Service in App Router using Server Actions |
| next | [GHSA-89xv-2m56-2m9x](https://github.com/advisories/GHSA-89xv-2m56-2m9x) | `>=14.1.1 <15.5.21` | Next.js: Server-Side Request Forgery in Server Actions on custom servers |
| next | [GHSA-68g3-v927-f742](https://github.com/advisories/GHSA-68g3-v927-f742) | `>=13.0.0 <15.5.21` | Next.js: Cache confusion of response bodies for requests with bodies |
| next | [GHSA-4633-3j49-mh5q](https://github.com/advisories/GHSA-4633-3j49-mh5q) | `>=13.0.0 <15.5.21` | Next.js: Cache confusion of response bodies for requests with bodies containing invalid UTF-8 byte sequences |
| next | [GHSA-4c39-4ccg-62r3](https://github.com/advisories/GHSA-4c39-4ccg-62r3) | `>=13.0.0 <15.5.21` | Next.js: Unbounded Server Action payload in Edge runtime |
| next | [GHSA-p9j2-gv94-2wf4](https://github.com/advisories/GHSA-p9j2-gv94-2wf4) | `>=12.0.0 <15.5.21` | Next.js: Server-Side Request Forgery in rewrites via attacker-controlled destination hostname |
| next | [GHSA-955p-x3mx-jcvp](https://github.com/advisories/GHSA-955p-x3mx-jcvp) | `>=13.0.0 <15.5.21` | Next.js: Unauthenticated disclosure of internal Server Function endpoints |
| next | [GHSA-p293-qw3h-jr36](https://github.com/advisories/GHSA-p293-qw3h-jr36) | `>=13.4.0 <15.5.24` | Next.js: Unauthenticated Remote Code Execution on windows-hosted servers |
| next | [GHSA-2xp9-vwfh-vxw4](https://github.com/advisories/GHSA-2xp9-vwfh-vxw4) | `>=10.0.0 <15.5.24` | Next.js: Unauthenticated Remote Code Execution in Image Optimization API when AVIF files are used |
| postcss-selector-parser | [GHSA-rj75-hqrm-r3gf](https://github.com/advisories/GHSA-rj75-hqrm-r3gf) | `<7.1.6` | PostCSS: Quadratic complexity in flat selector parsing allows CPU exhaustion |

## Reviewable publication proposal — not executed

Proposed PR title: “Add stateless bilingual message analysis with bounded optional link inspection”. Review complete diff from product baseline8abb3078c01ce26e605c9129d48484c770b574e7 to the final local feature revision, with this verification and screenshot manifest. Controller owns fresh Task7 and whole-branch review; those reviews are pending at implementer handoff. No reviewer approval is claimed here.

1. Resolve/review breaking dependency migrations and remaining environment acceptance gaps. Prepare a separate compatibility frontend revision; it does not yet exist. It must accept old/new malicious/phishing semantics, never fall through to benign for unknown status, and remain fail closed for endpoint/version mismatch. User review/approval is a release prerequisite.
2. Publish that explicit compatibility frontend revision first only after approval. Original frontend at8abb307 maps only malicious and otherwise falls to BENIGN; the new backend's legacy adapter emits canonical phishing. Backend-first into that original frontend is unsafe. Final new frontend requires /v1/analyze-message, absent from old backend; frontend-first would fail closed but temporarily cannot scan. Compatibility design and synthetic acceptance must settle that overlap before publication.
3. Publish reviewed backend feature revision after approval; verify deployed SHA/health, effective trusted proxy client identity and rate limiting, infrastructure request/body/log configuration, isolated PostgreSQL startup, no-store and synthetic static/deep acceptance. Never claim infrastructure-wide non-retention from application tests alone.
4. Publish final reviewed frontend only after backend contract acceptance; verify actual deployed revision, HE/EN, errors/unknown/partial behavior, disclosure and stale-request acceptance. No production submitted messages are needed.
5. Rollback reference is the known backend baseline8abb307 and the separately reviewed fail-closed compatibility frontend revision (hash must be recorded when it exists). Retain the fail-closed frontend during backend rollback; never restore original BENIGN fallback. History records remain untouched. Both services auto-deploy main, so no push/merge/deployment is authorized by this implementation task.

Self-review: inspected focused product diff, fixture substitution boundary, contract/parser tests, raw final outputs, screenshots and compatible npm graph. No general language-accuracy claim, production bypass, persistence or unapproved network path was introduced. Remaining concerns are the explicit coverage tradeoff,8 dependency audit packages,3 Python warnings/deprecated JS maintenance dependencies, environment-only not-run checks, and pending independent reviews. Local cache/old node_modules backup is marked disposable in `../MobileShield-review/DISPOSABLE-LOCAL-CACHES.txt`; never bundle caches/node_modules in final artifacts. Controller owns Library upload of selected images/report.
