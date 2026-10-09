# Message analysis API

`POST /v1/analyze-message` accepts `{"text":"Hello","inspect_links":false}`.
It returns response `schema_version: 1`, canonical `assessment` (`phishing`,
`suspicious`, `no_clear_signs`, `unknown`), separate `analysis_status`, evidence,
limitations, recommended actions, per-link results and an opaque `request_id`.
No response-version request header is required on this endpoint.

Checks are static by default. Setting `inspect_links: true` permits bounded
destination inspection through the shared guarded transport. Application scans
are stateless and responses use `Cache-Control: no-store`; infrastructure
retention must be verified separately. See the [design](superpowers/specs/2026-10-08-message-analysis-design.md)
for input limits, privacy and coverage semantics.

## Legacy URL adapter and browser compatibility

`POST /v1/analyze` still accepts `{"url":"https://example.com","inspect_links":false}`.
Requests with any `Origin` header must also send exactly one
`X-MobileShield-Response-Version: 1` header. Only declare version 1 when your
integration understands canonical verdicts and incomplete results. Alternatively,
migrate to `/v1/analyze-message`. Existing server/API callers without an `Origin`
header retain the legacy adapter behavior without negotiating a version.

Version 1 returns `phishing`, `suspicious`, `legitimate` or `unknown` in the
legacy `verdict` and `status` fields. Canonical `assessment` remains
`no_clear_signs` when the legacy aliases are `legitimate`; that alias requires
complete applicable checks and is not a safety guarantee. Responses retain
completion metadata and `scan_id: null`; no saved scan or report is created.
Missing, unfamiliar or failed results must never be treated as benign.

An Origin-bearing request with a missing, empty, unsupported or duplicated
response-version header is rejected before analysis or destination inspection:

```http
HTTP/1.1 409 Conflict
Cache-Control: no-store
X-Request-ID: <server-generated opaque ID>
Content-Type: application/json
```

```json
{
  "detail": "client_upgrade_required",
  "message": "Refresh or update your client before trying again.",
  "request_id": "<server-generated opaque ID>"
}
```

The error contains no assessment, verdict or submitted payload. Existing input,
body, rate and work limits still apply and can reject earlier with their normal
422/413/429/503 errors. Allowed origins receive the existing CORS headers;
unlisted origins do not gain access. Refresh/update guidance is returned in the
error body; an old browser bundle may display its existing generic error UI.

This header negotiates client compatibility. It is **not authentication** and
does not make `Origin` an access-control boundary: arbitrary clients can declare
the header. No CORS allowlist, credentials, transport or security permissions
are weakened. Third-party browser integrations on the legacy route must add the
supported header or migrate; otherwise they receive an explicit upgrade error.

## Independent frontend/backend rollout

| Browser client | Backend | Outcome |
| --- | --- | --- |
| Original baseline, including already-open tabs | New guarded backend | Legacy call receives 409; baseline API rejects before mapping a result. Refresh/update is required. |
| New frontend | Original backend | `/v1/analyze-message` is absent; HTTP failure produces an unavailable/error state, with no assessment. |
| New frontend | New backend | Normal full-message assessment. |
| Original baseline | Original backend | Known baseline benign-fallback defect remains until either new service is live. |

After review and release checks, a coordinated main merge can tolerate either
Render service completing first. Deployments are independent, not atomic.
Check the deployed commit and synthetic acceptance for both services. The guard
also covers stale original browser tabs after the backend updates; deploying the
frontend alone cannot evict those tabs. The server cannot force a tab refresh or
remove an already-displayed historical result.

During rollback, keep the guarded backend available for stale original tabs.
Rolling back the backend to the unguarded baseline restores their defect even
if the current frontend remains new. Prefer a forward fix or a rollback build
that retains this compatibility guard and the approved safety boundary. Do not
restore the original frontend's benign fallback. Controller owns publication,
live mismatch checks and deployment settings.
