# MobileShield

**A bilingual (Hebrew/English) phishing-message checker.** Paste a suspicious SMS, WhatsApp or email message and MobileShield explains *why* it looks risky: credential or payment requests, pressure tactics, brand impersonation, look-alike domains and dangerous landing pages.

![Python](https://img.shields.io/badge/Python-3.11-3776AB?logo=python&logoColor=white)
![FastAPI](https://img.shields.io/badge/FastAPI-0.115-009688?logo=fastapi&logoColor=white)
![Next.js](https://img.shields.io/badge/Next.js-15-000000?logo=nextdotjs&logoColor=white)
![TypeScript](https://img.shields.io/badge/TypeScript-5-3178C6?logo=typescript&logoColor=white)
![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16-4169E1?logo=postgresql&logoColor=white)
![Tests](https://img.shields.io/badge/tests-893%20passing-2ea44f)

<p align="center">
  <img src="docs/verification/images/mobileshield-he-1440-input.png" alt="MobileShield home screen in Hebrew" width="640">
  &nbsp;
  <img src="docs/verification/images/mobileshield-en-390-evidence.png" alt="Per-link evidence on mobile" width="200">
</p>

---

## Why

Most phishing in Israel now arrives as a short text message ("your package is held", "your bank account will be blocked") rather than a web page. Existing URL scanners judge only the link and often ignore Hebrew. MobileShield analyzes the **whole message**, so the text and the link are judged together. A message that asks for your password and points to a domain that doesn't belong to the bank it names is flagged, even when the domain is brand new and on no blocklist.

## Features

- **Whole-message analysis in Hebrew and English.** Finds requests for passwords, OTP codes, card details and payments, plus urgency and account threats. It handles negation, so "never share your password" is not flagged.
- **Robust link extraction.** Extracts links from free text, including bare domains, IDN/punycode hosts, bidi control characters and trailing Hebrew punctuation. Every link is canonicalized before any check runs.
- **Brand and look-alike detection.** Checks claimed brands (PayPal, Microsoft, Israeli banks…) against their official domains. Catches typosquats (`paypa1`), homoglyphs and brand names hidden in subdomains.
- **Optional live page inspection.** With the user's opt-in, the server visits the link and reports credential/payment forms, page-title brand claims, redirect chains and TLS certificate problems.
- **Explainable results.** Every verdict (`phishing` / `suspicious` / `no_clear_signs` / `unknown`) comes with typed reasons, per-link evidence, recommended actions and an honest coverage status. A check that could not run is never reported as "safe".
- **Privacy by design.** No database dependency on the scan path, nothing is stored, responses are `Cache-Control: no-store` and request logs contain only route, status, duration and a random request ID.

## Security engineering highlights

Fetching user-supplied URLs on a server is an SSRF risk. The link inspector (`app/detection/safe_transport.py`, `network_policy.py`) was built to fail closed:

| Threat | Mitigation |
| --- | --- |
| SSRF to internal networks / cloud metadata | Every DNS answer is validated as a public address (private, loopback, link-local, reserved, multicast, NAT64/6to4/Teredo and IPv4-mapped ranges are rejected) |
| DNS rebinding | The socket connects to the **already-validated IP** with the original `Host`/SNI; validation is repeated on **every redirect hop** |
| Obfuscated hosts (`0x7f.1`, `2130706433`, `user@host`) | Rejected before resolution; non-default ports and internal TLDs (`.local`, `.internal`…) are blocked |
| Slow-loris / header dribbling | An absolute per-request deadline enforced by a watchdog that shuts the socket down mid-read |
| Resolver hangs | `getaddrinfo` runs in a disposable child process that is killed at the deadline |
| Resource exhaustion | 128 KB request cap (counted on received bytes), 256 KB response cap, max 5 redirects, bounded concurrency, per-client rate limiting |
| Information leakage | Exception text, URLs and validation details are never echoed or logged; strict security headers and CSP |

## Architecture

```mermaid
flowchart LR
    U[User] --> W["Next.js web app<br/>(Hebrew RTL / English)"]
    W -->|POST /v1/analyze-message| M["Request middleware<br/>size cap · rate limit · work admission"]
    M --> P["Message parser<br/>link extraction + canonicalization"]
    P --> T["Text evidence<br/>requests · urgency · brand claims"]
    P --> S["Static URL evidence<br/>look-alikes · brand mismatch · obfuscation"]
    S -->|inspect_links = true| X["SafeTransport<br/>validated DNS → pinned IP → bounded fetch"]
    X --> C["Content and TLS evidence<br/>credential/payment forms · cert errors"]
    T --> A[Assessment aggregator]
    S --> A
    C --> A
    A -->|typed reasons + coverage| W
```

## API example

```bash
curl -s -X POST http://localhost:8000/v1/analyze-message \
  -H 'Content-Type: application/json' \
  -d '{"text": "Your PayPal account will be suspended. Log in now to confirm your password: https://paypa1-secure.top/verify", "inspect_links": false}'
```

```jsonc
{
  "assessment": "phishing",
  "analysis_status": "complete",
  "reasons": [
    { "code": "credential_request", "strength": "strong", "source": "message" },
    { "code": "urgency", "strength": "strong", "source": "message" },
    { "code": "brand_destination_mismatch", "strength": "strong", "source": "message", "params": { "brand": "paypal" } },
    { "code": "lookalike_host", "strength": "strong", "source": "url", "params": { "display_host": "paypa1-secure.top" } }
  ],
  "recommended_actions": ["avoid_interaction", "verify_independently", "do_not_share_secrets", "consider_link_inspection"],
  "limitations": ["inspection_disabled"],
  "links": [ { "link_id": "link_1", "assessment": "phishing", "inspection_status": "not_requested", "...": "..." } ],
  "schema_version": 1,
  "request_id": "3f9c2a7e…"
}
```

(The response is shortened here.) The full contract is in [`docs/api.md`](docs/api.md); interactive docs are served at `/docs` when the API is running.

| Endpoint | Description |
| --- | --- |
| `POST /v1/analyze-message` | Analyze a message (`text` up to 10,000 characters, up to 10 links) |
| `POST /v1/analyze` | Legacy single-URL adapter (kept for older clients) |
| `GET /health`, `GET /readyz` | Liveness and database readiness probes |

## Tech stack

- **Backend:** Python 3.11, FastAPI, Pydantic v2 (strict contracts), SQLAlchemy 2, PostgreSQL, `tldextract`, `idna`
- **Frontend:** Next.js 15 (App Router), React 19, TypeScript, Tailwind CSS 4, bilingual RTL/LTR UI with an accessibility focus
- **Testing:** pytest (762 hermetic tests that make no network or DNS calls), Vitest + Testing Library (131 tests)
- **Infrastructure:** Docker, Docker Compose

## Getting started

### Docker Compose (everything)

```bash
git clone https://github.com/ophbra22/mobileshield-backend.git
cd mobileshield-backend
cp .env.example .env
docker compose up --build
```

- Web app: http://localhost:3000
- API + Swagger UI: http://localhost:8000/docs

### Local development

**Backend**, which needs PostgreSQL at startup (the easiest way is `docker compose up -d db`):

```bash
python3.11 -m venv .venv && source .venv/bin/activate
pip install -r requirements-dev.txt
export DATABASE_URL=postgresql+psycopg2://mobileshield:mobileshield@localhost:5432/mobileshield
uvicorn app.main:app --reload --port 8000
```

**Frontend:**

```bash
cd mobileshield-web
npm ci
NEXT_PUBLIC_API_BASE_URL=http://localhost:8000 npm run dev
```

### Running the tests

```bash
# Backend: hermetic, no database or network needed
python -m pytest

# Frontend
cd mobileshield-web
npm test            # Vitest
npm run typecheck   # tsc --noEmit
npm run lint
```

## Project structure

```
app/
├── main.py                 # FastAPI app, security headers, error handling
├── scan_limits.py          # ASGI middleware: body cap, rate limit, admission, redacted logs
├── message_parser.py       # Link extraction & canonicalization from free text
├── message_models.py       # Strict request/response contracts (schema v1)
├── text_coverage.py        # Hebrew/English text-coverage heuristics
├── analysis.py             # Orchestrates parsing, evidence and optional inspection
├── brand.py                # Brand roots, typosquat & homoglyph detection
├── detection/
│   ├── message_analyzer.py # Text evidence + final assessment aggregation
│   ├── engine.py           # Per-link evidence collection
│   ├── safe_transport.py   # SSRF-hardened HTTP/TLS inspector
│   ├── network_policy.py   # URL authorization & isolated DNS resolution
│   └── content_analyzer.py # HTML form / title evidence
├── routers/                # HTTP routes
└── db/                     # SQLAlchemy models & session
mobileshield-web/           # Next.js frontend
tests/                      # pytest suite + fixtures (labelled message dataset)
docs/                       # API contract, design notes, verification reports
```

## Limitations

MobileShield is a heuristic decision aid, **not a safety guarantee**. Detection relies on rules, a curated brand list and a small local blocklist rather than live threat-intelligence feeds, so new or subtle attacks can be missed. Rate limiting is in-process. In production it should sit behind a proxy that sets the real client IP, or move to a shared store such as Redis. User accounts and API-key routes exist in the codebase but are disabled in the public beta.

## Author

**Ophir Braude** · [LinkedIn](https://www.linkedin.com/in/ophir-braude-188252378/)
