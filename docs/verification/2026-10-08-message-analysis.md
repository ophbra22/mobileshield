# Message analysis verification — 8 October 2026

Status: all implementation and scoped review gates through Task11 are accepted with no open Critical/Important findings. Final backend: **631 passed**; explicit integration/rollout: **76 passed**; frontend: **123 passed**. Typecheck, lint, production build and clean dependency installation pass. Final isolated Chrome acceptance passes 12 workflow checks, 16 focused direction/value assertions and 3 post-Python-update browser/API smoke checks. [Before/after screenshots and capture evidence](browser-evidence.md) cover the final UI. npm audit reports zero findings at the recorded check; Python's remaining advisory groups have independently accepted, conditional dispositions, not a zero-vulnerability result. GitHub/Render publication is approved conditionally, but main and production remain unchanged while the release configuration and environment gates are resolved. [Exact release settings and remaining checks](release-settings.md).

## Task 11 — compatible Python fixes and advisory dispositions

Requests is now 2.33.0 and python-jose is 3.5.0; all other final installed versions remain unchanged. The initial jose 3.4.0 target forced vulnerable pyasn1 0.4.8, so verified same-major 3.5.0 was required to retain patched pyasn1 0.6.4 through the normal resolver. CSP policy selection now uses the actual ASGI path, with malformed-Host regressions. Backend: 631 passed (610 prior + 21 new); explicit integration/rollout: 76 passed; pip check passed. A clean temporary environment reproduced all 48 versions and passed all 631 tests. Requests' compatibility warning is resolved; Starlette/Passlib deprecations remain.

[Python dependency evidence and all remaining advisory dispositions](python-dependencies.md) document the offline archive, aliases, withdrawn duplicate, precise API reachability and maintenance paths. Final Python comparison still has 29 advisory records in 15 alias groups; package presence is not proof of exploitation, and npm's earlier zero count does not apply to Python. The concrete CSP exposure is corrected; residual crypto/framework/test/bootstrap risks have bounded dispositions accepted by a fresh independent Task11 reviewer, with no Critical/Important finding in that scope. No framework/provider migration, auth enablement, credentials, permission changes, publication or frontend rebuild occurred. Current release status remains pending controller-owned release prerequisites; local Task11 acceptance is complete.


## Task 10 — displayed reasons and blank-input direction

Base: `eee48c93f38b580a98bde140afbf6b0dcd6c7c80`. The preceding controller Chrome acceptance found two visual defects: repeated indistinguishable organization/destination summary lines and a left-aligned empty Hebrew placeholder. Each summary or individual link reason list now displays each reason code once, in first-seen order. Full response objects remain intact; different reason codes, independent links and limitations retain their evidence. An empty or whitespace-only textarea follows the selected UI language (`rtl` Hebrew / `ltr` English). Actual text retains `dir="auto"`, including mixed-language content and language changes; the controlled value is preserved.

Ten new component cases cover HE/EN duplicate codes with different brand/host parameters and link/source contexts, first-seen display order, independent per-link occurrences, unchanged response objects and retained partial/limitation copy; empty/whitespace direction before and after a language change; and Hebrew-first/English-first mixed text keeping automatic direction until cleared. Existing request, clipboard, stale-state, privacy, error/uncertainty and accessibility tests remain green.

| Check | Result | Raw log under `../MobileShield-review/verification-logs/` |
| --- | --- | --- |
| Focused semantic RED before product edits | 11 failed / 40 passed, exit1; expected duplicate-line and blank-direction assertions | `task10-red.log` |
| Focused component GREEN | 51 passed, exit0 | `task10-focused-green.log` |
| `npm --prefix mobileshield-web test` | 123 passed in 4 files (113 prior + 10 new), exit0 | `task10-frontend.log` |
| `npm --prefix mobileshield-web run typecheck` | exit0 | `task10-typecheck.log` |
| `npm --prefix mobileshield-web run lint` | exit0; no ESLint warnings/errors | `task10-lint.log` |
| Production build with fixture API URL and telemetry disabled | exit0, Next15.5.27, 6 static pages | `task10-build.log` |

The exact build command is `env NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8001 NEXT_TELEMETRY_DISABLED=1 npm --prefix mobileshield-web run build`. The existing Node `module.register`, module-type warning and Next lint deprecation remain. `task10-results.json` records actual child exits and timestamps; `task10-tested-product.diff` records the tested changes. No dependencies or backend code changed, and no backend suites were rerun. Root stopped its owned servers before the build; Task10 starts no servers. The controller subsequently recaptured the final UI and verified **computed** textarea direction for empty, whitespace, Hebrew-first and English-first mixed input in both UI languages; see the linked browser evidence. Component attribute assertions and a successful build do not establish browser visual acceptance. Preceding browser captures and any external harness errors remain historical controller evidence; the new build has not been captured by Task10. No push, deployment, credentials, paid services, security-permission or GetEvent changes occurred.

## Task 9 — stale-browser compatibility guard

Base: `f25097a17645451b11f35aacbe74d569d61be45f`. The original browser at `8abb3078c01ce26e605c9129d48484c770b574e7` maps canonical `phishing` and `unknown` to its benign fallback. Frontend-first deployment cannot remove already-open tabs. The legacy `/v1/analyze` route now requires exactly one `X-MobileShield-Response-Version: 1` on any Origin-bearing request. Otherwise it returns a sanitized `409 client_upgrade_required` with fixed refresh/update guidance before analysis or destination inspection. Existing no-store, opaque request ID, input/body/work/rate limits and CORS behavior remain. The new endpoint and Origin-less API callers retain their contract.

This is negotiated compatibility, not authentication or an Origin trust rule. Compatible legacy browser callers must understand canonical `phishing`/`suspicious`/`legitimate`/`unknown`, separate completion metadata and `scan_id: null`. Third-party browser integrations must add the header or migrate to `/v1/analyze-message`; otherwise the new explicit upgrade error is an intentional compatibility cost. Public contract and rollout matrix: [API documentation](../api.md).

`tests/test_rollout_compatibility.py` covers missing/empty/unknown/duplicated versions, phishing-capable/unknown/ordinary URLs with static and deep requests, Origin presence including empty/null/unlisted origins, zero analysis/transport work on blocked calls, payload/header/log redaction, opaque request IDs, allowed and denied CORS, preflight and retained body/rate/work admission. Compatible browser and Origin-less paths execute the real service for all four legacy verdicts.

The frozen `tests/fixtures/baseline-client/api.ts` and `ScanForm.tsx` are exact Git copies from `8abb307`. The installed TypeScript compiler executes that complete API module and the exact syntax-tree-extracted `mapStatus` function. Three actual ASGI409 responses throw the old `ApiError` with **zero result mappings and zero JSON result reads**. HTTP200 controls deliberately reach `BENIGN` for `phishing` and `unknown`, so the harness detects the original defect. Current API code separately rejects a controlled old-server404 with `request_failed` and accepts a real new-server response. This is executable adapter/ASGI evidence, not a live old-backend or browser claim; root owns those browser mismatch checks.

| Check | Result | Raw log under `../MobileShield-review/verification-logs/` |
| --- | --- | --- |
| RED, final corrected controls | 42 failed / 16 passed; expected missing guard and old client missing rejection, exit1 | `task9-red-final.log` |
| Focused rollout + API GREEN | 73 passed, exit0 | `task9-green-matrix-fixed.log` |
| `.venv/bin/python -m pytest -q` | 610 passed, exit0 | `task9-backend.log` |
| `.venv/bin/python -m pytest tests/test_scan_integration.py tests/test_rollout_compatibility.py -q` | 76 passed (17 existing integration +59 rollout), exit0 | `task9-integration.log` |

All final Python runs retain the same three Requests/Starlette/Passlib warnings. `task9-results.json` records commands, actual child exits, timestamps, fixture hashes and tested diff. Earlier attempts are preserved: initial RED had three incorrect control expectations (`Send your password` is suspicious without additional evidence); a later new-client harness initially omitted the required `inspect_links` boolean and failed with `invalid_request` before fetch. Both test setup errors were corrected without changing product behavior, corpus or language rules. No frontend product edits, dependency installation, build or server restart was performed. The previous frontend suite/build/audit evidence remains separate.

The current rollout instructions below supersede the earlier proposal for a separate compatibility frontend. After fresh review and release checks, either independently auto-deployed Render service can finish first; deployments are not atomic. Old/old remains defective until either service is live. Stale old tabs are protected once the guarded backend is live. Backend rollback to an unguarded baseline would reopen the defect for those tabs, even with a new frontend deployment; retain the guard during rollback or use a forward fix. No push, deployment, credentials or permission changes were made in Task9.

## Task 8 — dependency migration and Hebrew conjunction regression

The approved local migration starts at `a83337f8aa33f6bb08027902fb8f925096f2eb9e`. R1 is fixed in separate commit `0ee3cfa`: a bounded optional Hebrew conjunction prefix restores requests such as `שלח לי שם וסיסמה` and `שלח לי שם והסיסמה`. Thirteen endpoint-to-TypeScript-parser cases include prevention, explicit contrast, plural, OTP and ordinary-word boundary controls. RED: 6 failures/20 passes; GREEN: 228 focused message/final-review/integration passes. The 60-message evaluation corpus and its labels are unchanged.

Chosen frontend graph:

| Dependency | Final version and rationale |
| --- | --- |
| Next | **15.5.27**. The initial 15.5.24 candidate resolves the previously known critical advisory, but a fresh audit reported two additional moderate SSG/ISR advisories affecting `<15.5.27`: [GHSA-4jqv-mc3x-m676](https://github.com/advisories/GHSA-4jqv-mc3x-m676) and [GHSA-mcj8-r9mp-w47p](https://github.com/advisories/GHSA-mcj8-r9mp-w47p). Thus 15.5.27 is the smallest currently verified patched 15.5 target. No Next 16 migration is needed. These advisories describe specific cache/router conditions; this audit is not evidence of an exploited deployment. |
| React / React DOM | **19.0.8** together; types **19.0.14 / 19.0.6**. Follow the [Next 15 App Router React 19 requirement](https://nextjs.org/docs/app/guides/upgrading/version-15), using the maintained 19.0 patch line ([release](https://github.com/react/react/releases/tag/v19.0.8)) rather than an unnecessary later minor. Framework-bundled RSC fixes are assessed through the patched Next package and final audit; React DOM version alone is not RSC security proof. |
| Lucide React | **0.474.0**, stable React 19 peer support and compatible declarations. 0.468 passes ordinary project typecheck only because of existing `skipLibCheck`; a dedicated declaration check exposes removed `ReactSVG` ([upstream issue](https://github.com/lucide-icons/lucide/issues/2667)). Inspected adjacent 0.469–0.473 releases retain that reference; 0.474 removes it and passes with library checking enabled. Existing icon imports/API remain. No Lucide 1.x migration. |
| Tailwind / PostCSS plugin | **4.0.17 / 4.0.17**. Tailwind 3.4.19 still carries the affected braces/selector-parser chains. The last patch of the first v4 minor has a coherent, exact 4.0.17 node/oxide/core graph and clears those chains. 4.0.0 uses floating `^4.0.0` internal dependencies; choosing 4.0.17 avoids mixing internal minor versions and includes the initial release's compatibility fixes. This is a conservative verified patch-line choice, not a claim that every earlier 4.0 patch is vulnerable. Tailwind 4.3.3 is unnecessary. |
| tailwind-merge | **3.0.0**, the [first release supporting Tailwind 4](https://github.com/dcastil/tailwind-merge/releases/tag/v3.0.0). |
| PostCSS | **8.5.23**, retained. The existing Next-only override replaces its pinned affected 8.4.31 with the compatible patched PostCSS 8 API; no cross-major override. |
| ESLint / Next lint config | **8.57.1 / 14.2.35**, deliberately retained with the existing compatible `glob:10.5.0` override. Published Next lint plugins 15.5.27 and 16.4.0 depend on fast-glob3.3.1 → micromatch → unpatched braces, introducing five high audit package flags. Controller approved retaining the existing lint tool, rather than adding that chain or suppressing checks. This maintenance exception requires independent review. |

Lint coverage comparison: both Next plugins expose the same 21 rule names, recommended severities and Core Web Vitals settings. Most implementation changes support ESLint 9 context APIs; Next 15 also exempts metadata images and adds App Router internal-anchor matching to `no-html-link-for-pages`. The current app has only HTTPS/mailto anchors and no metadata image JSX, so those differences do not change current findings. Future internal App Router links need explicit review while the older lint plugin remains. ESLint 8 and `next lint` are deprecated; a clean audit does not resolve that maintenance debt. Raw published-source comparison is in `task8-lint-rule-comparison.json` and `task8-lint-rules-normalized.diff`.

Compatibility edits follow the [Tailwind migration guide](https://tailwindcss.com/docs/upgrade-guide): use `@tailwindcss/postcss`, CSS import plus explicit existing config, remove redundant autoprefixer, preserve the previous account-control color palette and default border/placeholder colors, use explicit sRGB gradients, equivalent blur/focus utilities, and flex gaps in the existing account layouts. Existing scan CSS, RTL/LTR, focus and reduced-motion rules remain. Tailwind 4 requires **Safari16.4+, Chrome111+, Firefox128+**; older browser support is not claimed. Next tracing is explicitly rooted at the frontend directory because the repository has a separate root lockfile. Next-generated route type references are retained. There are no asynchronous request API consumers requiring migration, and no change to no-store scan handling, the retired PDF route's 410/no-store response, auth/key behavior, storage or network policy.

Final verification after the last compatibility correction, using Node26.7.0 and npm11.19.0:

| Command | Actual result | Raw log under `../MobileShield-review/verification-logs/` |
| --- | --- | --- |
| `npm --prefix mobileshield-web ci --strict-peer-deps --cache /tmp/mobileshield-task8-npm-cache --fetch-retries=0 --fetch-timeout=15000` | exit0; clean install, no peer bypass | task8-ci-final.log |
| `npm --prefix mobileshield-web audit --json --cache /tmp/mobileshield-task8-npm-cache --fetch-retries=0 --fetch-timeout=15000` | exit0; **0 vulnerabilities in all severities** | task8-audit-final.json |
| `.venv/bin/python -m pytest -q` | 551 passed, 3 retained warnings, exit0 | task8-backend-final.log |
| `.venv/bin/python -m pytest tests/test_scan_integration.py -q` | 17 passed, 3 retained warnings, exit0 | task8-integration-final.log |
| `npm --prefix mobileshield-web test` | 113 passed in4 files, exit0 | task8-frontend-final.log |
| `npm --prefix mobileshield-web run typecheck` | exit0 | task8-typecheck-final.log |
| `npm --prefix mobileshield-web run lint` | exit0; no lint findings | task8-lint-final.log |
| `NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8001 NEXT_TELEMETRY_DISABLED=1 npm --prefix mobileshield-web run build` | exit0; Next15.5.27, 6 generated static pages | task8-build-final.log |
| `npm --prefix mobileshield-web ls --all` | exit0; valid installed tree | task8-tree-final.log |
| `git diff --check` | exit0 | task8-diff-check-final.log |
| Dedicated Lucide declaration `tsc --noEmit --skipLibCheck false --esModuleInterop --moduleResolution bundler --module esnext --target es2017 .../lucide-react.d.ts` | exit0; React19 types checked without hiding dependency errors | task8-lucide-types-green.log |

`task8-results.json` records commands, exit codes, timestamps, exact base and tested product diff SHA256; `task8-tested-product.diff` includes R1 plus the migration. Frontend tests use the default API environment; only the build uses the fixture URL. Final audit success and functional success are separate results. Earlier candidate and failed-probe evidence remains: initial audit6 packages, aligned lint audit5 high packages, initial lock refresh warnings against stale React18 installation, and Lucide declaration RED. Strict clean installation and final tree validation supersede the initial stale-peer warnings. No `--force`, `--legacy-peer-deps`, install-script-policy changes, or blind overrides were used.

Remaining warnings: Requests compatibility, Starlette BlockingPortal and Passlib crypt; npm's existing ESLint/glob/rimraf/inflight/whatwg-encoding/CryptoJS and humanwhocodes deprecations; unchanged install-script-policy notices for esbuild/fsevents/unrs-resolver; Node26 `module.register()` deprecation and Tailwind TypeScript-config module detection. The install/build work despite those notices; none was hidden or solved by changing approval policy. The Next15 lint command itself is deprecated. These are maintenance concerns, not current npm audit findings.

Independent review (especially the lint exception), controller-owned production-mode browser/fixture acceptance and the previously listed environment/rollout prerequisites remain. Render's actual Node/build configuration, PostgreSQL startup, trusted proxy identity and infrastructure retention are not proven by these local checks. Native accessibility omissions below remain not-run. GitHub/Render publication is conditionally approved but **was not performed by Task8**; root owns rollout. No service listeners, external messages, credentials, permissions, paid services, GetEvent or corpus labels were changed.

The sections below are historical Task7/fix-wave evidence. Their earlier dependency counts and authorization boundaries are superseded by this Task8 status.

## Final whole-branch review fix wave

The combined fix wave starts at `5e2995d60477f4c5a9274b720a0f70f70e0976e4`. The commit containing this update addresses Important findings I1–I7 and related Minors M1/M2/M3/M4/M6 from `../MobileShield-review/final-branch-review.md`. Independent scoped re-review and the controller's clean production-mode first-load check remain pending; these local checks do not establish release readiness. Later user approval now authorizes local major dependency migration and GitHub/Render publication only after the remaining fixes, dependency work, reviews, tests and safe-rollout prerequisites are satisfied. No paid plans, new credentials or security-permission changes are authorized; this fix wave performs no publication. Historical Task7 authorization statements below describe the earlier scope and are superseded by this conditional approval.

- Basic English secret noun plurals and bounded Hebrew request families (imperative gender/number, infinitive and corresponding second-person prevention forms) use the existing action-scoped negation logic. Positive requests and genuine prevention statements run through the ASGI endpoint and actual TypeScript parser. Three matching English plural vocabulary entries were added; the conservative language-coverage limitation remains.
- Non-2xx HTML has an explicit inspection failure, and useful warning evidence is retained. Tests cover 200/201, 403/404/429/500/503 and successful redirects. Password, one-time-code and card fields are recognized without a form wrapper; form presence remains a separate observation, hidden input metadata does not create a warning, and unseen fields remain unknown after incomplete reads.
- A monotonic, absolute ten-second inbound POST body-read deadline expires stalled/dribbling uploads, returns sanitized `408 request_timeout` with no-store, generated request ID and allowed-origin CORS, and releases the existing 32-slot work admission. The deadline covers complete buffering and does not renew per chunk. Short injected test budgets exercise all32 slots, overflow and subsequent recovery. This fixed controller-selected budget can reject unusually slow legitimate uploads, which must retry; no environment bypass was added.
- Read timeout, read error and exhausted inspection budget preserve the bounded observed HTML prefix and positive brand/credential facts while leaving HTML incomplete. The same connection/deadline/guard still applies, with no second fetch. A failed check cannot create no_clear_signs or completed inspection.
- Parser and network policy share raw-authority validation before canonical reconstruction. Repeated trailing host dots, empty ports and malformed bracket suffixes stay invalid and make zero DNS/connection attempts. Single DNS trailing dots, ordinary punctuation, scheme-matching public ports and IDNs remain supported. The reported bug was silent malformed-authority repair, not a demonstrated SSRF bypass.
- The legacy HTTP adapter maps complete no_clear_signs to legitimate only in its status/verdict aliases; canonical assessment remains no_clear_signs. Unknown/suspicious/phishing and completion metadata, scan_id:null, no-store and no-database behavior remain. In-process legacy explanations/scores also retain an initial local blocklist hit after a trusted redirect.
- Certificate verification failures retain a generic warning without falsely setting hostname_matches=false; English/Hebrew copy describes verification failure, and content copy describes fields. Vitest now resolves the general root alias, reason-registry integration coverage batches at the contract cap and asserts the serialized set matches the registry, and dense result JSX/fixtures were expanded for review.

Final actual verification (repository root):

| Command | Result | Raw log |
| --- | --- | --- |
| `.venv/bin/python -m pytest tests/test_final_review.py -q` | 57 passed, 3 warnings, exit0 | final-fix-focused-final.log |
| `.venv/bin/python -m pytest -q` | 538 passed, 3 warnings, exit0 | final-fix-backend.log |
| `.venv/bin/python -m pytest tests/test_scan_integration.py -q` | 17 passed, 3 warnings, exit0 | final-fix-integration.log |
| `npm --prefix mobileshield-web test` | 113 passed in4 files, exit0 | final-fix-frontend-test.log |
| `npm --prefix mobileshield-web run typecheck` | exit0 | final-fix-typecheck.log |
| `npm --prefix mobileshield-web run lint` | exit0, no warnings/errors | final-fix-lint.log |
| `env NEXT_PUBLIC_API_BASE_URL=http://127.0.0.1:8001 NEXT_TELEMETRY_DISABLED=1 npm --prefix mobileshield-web run build` | exit0, Next14.2.35, 6 generated static pages | final-fix-build.log |
| `git diff --check` | exit0 | final-fix-diff-check.log |

All raw logs remain under `../MobileShield-review/verification-logs/`. `final-fix-results.json` records command exit statuses, exact base and tested diff SHA256; `final-fix-tested-product.diff` includes the new regression file. The full suite was run after the final product/test edits. Subsequent changes only update this documentation and the local coordination report, so suites were not redundantly repeated. The original60 synthetic messages, labels and provenance are unchanged (corpus SHA256 `d621f8ae23f669d7590128f8a21713da52130216769058542165a5bcdcf0f1d7`).

Preserved failures and corrections: main RED33 failed/22 passed (`final-fix-red.log`, exit1), then focused55 passed; M1 RED1 failed, root-alias import RED1 failed suite, and localized-copy RED1 failed/22 passed; all now pass. Expanded focused checking caught1 existing timeout regression because an empty prefix became an empty HTML string; preserving None when no bytes were observed restored497 passing focused cases. The first full frontend run mistakenly inherited the fixture API build URL, causing1 default-URL test failure/112 passes (`final-fix-frontend-fixture-env-failed.log`, exit1). The normal test environment then passed113; only the build uses the fixture URL. No product change was made for that setup error.

M5 remains deferred: Requests compatibility, Starlette BlockingPortal, Passlib crypt, npm deprecations and install-script-policy notices require separate maintenance. No dependency files/install/audit were changed or rerun in this wave. The prior audit remains8 affected packages (2 moderate/5 high/1 critical), including the separate breaking Next/React/Tailwind migration work. Subsequent user approval authorizes that local major-migration follow-up; it has not been performed in this fix wave. Publication is now conditionally approved after the remaining verification and rollout prerequisites; none was performed here. Package presence is not proof of runtime exploitability; the controller's maintainer clarification says the selector-parser advisory does not affect ordinary trusted-source build-time use. Other existing publication blockers and unperformed native accessibility/PostgreSQL/infrastructure checks below remain open. A separately reviewed fail-closed rollout frontend still does not exist. No production scan, push, deployment, new credential/permission, or GetEvent change occurred.

Root owns browser acceptance, screenshot/Library updates and fresh fixture processes. This wave did not stop, start or restart servers. The prior development first-load issue is not diagnosed by a successful build; root must record clean production first-load evidence separately.

## Prior Task7 scope and tested state

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

Capture limitation: fullPage stitching produced clipped/blank images while DOM geometry and normal viewport captures were correct; one HE1440 capture was explicitly rejected. All final files are recaptured normal viewport images with separate scrolled views, not that bad artifact. A transient dev hydration SyntaxError during dependency/build restart cleared after compilation and reload; generated layout syntax check passed, subsequent checks/captures worked. At final handoff, controller's first fresh tab after the last dev restart showed static HTML without responsive React controls (count stayed0 and language did not switch). Server logs were clean, and actual served layout/page JavaScript both passed node --check; see preview-served-assets.log. An intentional controller reload restored language switching and input behavior: French text ‘Envoyez-moi votre mot de passe immédiatement.’ counted45 characters, enabled submit, and returned Unable to assess / Analysis unavailable / Some message text could not be assessed through the actual fixture API. A separate newly opened tab immediately supported Hebrew-to-English switching. The transient first post-restart unresponsive page was therefore observed and resolved by reload; its root cause is not diagnosed, and this is not production verification. Controller screenshot mobileshield-root-unsupported-language.jpg records the successful unsupported-language result; the earlier failure screenshot remains excluded from successful evidence. No layout change was made to hide compositor behavior. Stale filled-input captures are outside final after/ in superseded-captures and are not deliverables.

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

## Current publication and rollback instructions — not executed by Task9

Proposed PR title: “Add stateless bilingual message analysis with bounded optional link inspection”. Review the complete diff from product baseline `8abb3078c01ce26e605c9129d48484c770b574e7` to the final feature revision, with this verification and screenshot manifest. Tasks8/9 were accepted; controller owns fresh Task10 review, affected browser recapture and final release acceptance. Task10 does not claim reviewer approval or publication.

1. Complete fresh Task10 scoped review, controller production-mode browser recapture/mismatch acceptance and remaining release checks. No separate compatibility frontend is required: the legacy browser-response guard protects the original client, while the new frontend fails closed against the old backend's missing endpoint.
2. Root may publish the reviewed revision under the user's conditional approval. Both Render services auto-deploy main independently. A coordinated main merge tolerates either service finishing first: old frontend/new backend produces an upgrade error; new frontend/old backend produces an unavailable/error state; new/new supports normal assessment. Old/old retains the baseline defect until either service is live. Do not claim atomic deployment or that a frontend deployment evicts stale tabs.
3. Verify each deployed SHA and health, effective trusted proxy client identity/rate limiting, infrastructure request/body/log configuration, isolated PostgreSQL startup, no-store and synthetic static/deep acceptance. Never claim infrastructure-wide non-retention from application tests alone.
4. Verify HE/EN, errors/unknown/partial behavior, inspection disclosure, stale-request acceptance and the baseline browser's409 rejection after the backend updates. Use synthetic inputs. Record both service revisions and mismatch observations.
5. Retain the guarded backend during rollback: restoring unguarded baseline `8abb307` would expose stale original tabs to the known benign fallback even if the frontend stays new. Prefer a forward fix or a reviewed rollback build retaining the compatibility guard and approved safety boundary; never restore the original benign-fallback frontend. Preserve historical records. Task9 itself only commits local changes; root owns external publication and deployment settings.

Historical Task7 self-review inspected the focused product diff, fixture substitution boundary, contract/parser tests, raw outputs, screenshots and compatible npm graph. Task8 supersedes its earlier eight-package audit concern; Task9 supersedes the original rollout proposal. Current remaining concerns are the explicit language-coverage tradeoff, retained Python/JS maintenance warnings, environment-only checks, controller browser acceptance and fresh Task10 review. No general language-accuracy claim, production bypass, persistence or unapproved network path was introduced. Local cache/old node_modules backup is marked disposable in `../MobileShield-review/DISPOSABLE-LOCAL-CACHES.txt`; never bundle caches/node_modules in final artifacts. Controller owns Library upload of selected images/report.
