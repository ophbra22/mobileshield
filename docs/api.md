# Message analysis API

`POST /v1/analyze-message` accepts `{"text":"Hello","inspect_links":false}`.
It returns response `schema_version: 1`, canonical `assessment` (`phishing`,
`suspicious`, `no_clear_signs`, `unknown`), separate `analysis_status`, evidence,
limitations, recommended actions, per-link results and an opaque `request_id`.
No response-version request header is required on this endpoint.

Checks are static by default. Setting `inspect_links: true` permits bounded
destination inspection through the shared guarded transport. Application scans
are stateless and responses use `Cache-Control: no-store`; infrastructure
retention must be verified separately. See [architecture.md](architecture.md)
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

## Rollout compatibility

The frontend and backend deploy independently. Browser tabs still running the
pre-message-analysis bundle call the legacy route without the version header and
receive `409 client_upgrade_required` instead of a result they would misread as
benign. A new frontend talking to an old backend gets an HTTP error and shows an
unavailable state, never an assessment. Rollbacks should keep this guard.
