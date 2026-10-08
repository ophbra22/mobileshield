# Release settings and acceptance

Source at the final local product gate: `c143e1756d99922d5a1be91fd6e64920091df388`. Both existing Render services automatically deploy `main` independently. Keep main unchanged until the configuration and environment checks below are resolved. No paid services, credentials or security-permission changes are part of this release.

## Frontend

| Setting | Required value / evidence |
|---|---|
| Service | `srv-d6irq6ma2pns73e4r62g` — mobileshield-web |
| Root | `mobileshield-web` |
| Package manager | npm, using `mobileshield-web/package-lock.json`; no Yarn lock |
| Build | `npm ci --include=dev --strict-peer-deps && npm run build` |
| Start | `npm start -- -p $PORT` |
| Build-time public API | `NEXT_PUBLIC_API_BASE_URL=https://mobileshield-backend.onrender.com` |
| Runtime observed locally | Node 26.7.0, npm 11.19.0 |

The explicit install succeeded under `NODE_ENV=production` using the already populated task cache; the subsequent production build with the real public API origin passed, including lint and type checking. The public API literal was confirmed in generated browser chunks without making live scans. Raw commands/exits are saved in `release-build-results.json`, `release-build-ci.log` and `release-build-production.log` outside the repository. Existing npm deprecations and install-script notices remain; no permission policy was changed.

The API variable is embedded at build time. `NEXT_PUBLIC_API_BASE` remains a fallback; absent both variables, the existing fallback is localhost and unsuitable for production. `--include=dev` ensures Tailwind/PostCSS/TypeScript are available even if the build environment sets NODE_ENV=production. No peer bypass or alternate lockfile is needed.

The existing Render setting was independently read as `install --frozen-lockfile && yarn build`, with start `yarn start -p $PORT`; it needs correction before this npm-locked candidate is released. The root directory is already correct. Inspect actual Node/npm output rather than assuming the platform default. Linux-applicable package-lock engine ranges admit Node 22.22.0, 24.21.0 and 26.7.0; only 26.7.0 was functionally tested here. An existing compatible even Node line need not be changed solely to match the workstation. [Render documents Node version selection and creation-date defaults](https://render.com/docs/node-version).

## Backend

Existing service `srv-d6hk5hv5r7bs73evcjhg` uses Docker context `.`, Dockerfile `./Dockerfile`, no Render start override. Source declares Python 3.11 and uvicorn on port 8000. These settings match the source. Preserve existing DATABASE_URL and secrets; no secret value is needed in this report. Verify existing CORS_ORIGINS contains the approved website origin without broadening permissions or enabling admin/auth routes. `/health` is process health; `/readyz` checks database readiness.

## Merge and deployment gates

1. Confirm the corrected frontend build/start/root/API settings and actual runtime. A settings change may itself trigger a build of old main; record it and avoid duplicate deploy triggers.
2. Retain local test/review evidence, inspect the actual Linux dependency resolution, and verify PostgreSQL startup. Floating Python transitives and Docker's bootstrap tools are not guaranteed by the macOS installation evidence.
3. Verify the trusted proxy chain used for ASGI client identity/rate limits and infrastructure request/log retention. Application no-store/redaction tests do not establish infrastructure-wide non-retention.
4. Once gates pass, merge the reviewed exact candidate and verify remote main, both deployment IDs, statuses and actual live SHAs. Use only harmless synthetic messages with inspect_links=false for live scans; no private messages, malicious visits or historical-record reads.

Task9's explicit legacy response-version guard protects stale old browser tabs. Old UI/new backend receives409 before the old BENIGN mapper; new UI/old endpoint404 displays an error without an assessment. Both service completion orders therefore fail closed during mismatch. Already displayed old results cannot be remotely cleared. See [the complete API/rollout contract](../api.md).

Rollback must retain the legacy guard. Restoring unguarded backend baseline8abb307 reopens the stale-tab defect even with a new frontend. Prefer a forward fix or a separately reviewed guarded rollback; never restore BENIGN-by-default UI. Historical database rows remain intact.

## Remaining limits

Native 200% zoom, spoken screen-reader output, Safari/Firefox and real destination-network inspection were not exercised. Browser reduced-motion/forced-colors emulation and local synthetic end-to-end checks passed. The heuristic analyzer cannot guarantee detection; unfamiliar English vocabulary may correctly be presented as outside its supported coverage. The synthetic regression corpus is not a real-world accuracy measurement.
