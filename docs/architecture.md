# Architecture

MobileShield helps a person decide what to do with a suspicious message. It
examines the message wording and every link in it, explains concrete warning
signs, and states plainly which checks could not run. It is a decision aid, not
a guarantee that a message or site is safe.

## Request flow

1. The browser sends `{"text": ..., "inspect_links": false}` to
   `POST /v1/analyze-message`.
2. `PrivateRequestMiddleware` (`app/scan_limits.py`) applies the per-client rate
   limit, a global cap on concurrent request work, and a 128 KB body cap counted
   on received bytes. It also replaces every log line with route/status/duration/request-ID only.
3. `parse_message` (`app/message_parser.py`) extracts up to 10 distinct links
   from free Hebrew/English text, including bare domains and IDN hosts. Each link
   is canonicalized. Ambiguous forms (credentials in the authority, control or bidi characters,
   unusual ports, unsupported schemes) are kept as invalid links instead of being guessed at.
4. **Static evidence** is collected for every link (`app/detection/engine.py`):
   brand impersonation and look-alike hosts (`app/brand.py`), hidden URL
   characters and deep/hyphenated hosts, and the local blocklist.
5. **Optional inspection** (`inspect_links: true`) visits each public link once
   through `SafeTransport` and adds page evidence: credential or payment forms,
   brand claims in the page title, redirect hops and TLS failures.
6. **Text evidence** (`app/detection/message_analyzer.py`) finds requests for
   secrets or payments (with negation handling: "never share your password" is
   not a request), urgency and account threats, and named organizations whose
   links point elsewhere.
7. `assess_message` combines everything into one typed response (schema v1).

Nothing is written to the database or logs on this path. Responses carry
`Cache-Control: no-store`.

## Assessment rules

Each reason has a strength (`strong`, `medium`, `info`) and a source
(`message`, `url`, `inspection`).

| Level | Rule |
| --- | --- |
| Link `phishing` | Two or more distinct strong reasons on that link |
| Message `phishing` | Any phishing link, **or** a direct credential/payment request plus another strong signal (or a medium URL/inspection signal) |
| `suspicious` | Any medium or strong reason |
| `no_clear_signs` | No warning reasons **and** every applicable check completed |
| `unknown` | Coverage is incomplete: inspection failed, the text is not recognizable English/Hebrew, or a bare link was not inspected |

A failed or skipped check never counts as evidence of safety. `analysis_status`
(`complete` / `partial` / `unavailable`) reports coverage separately from the
verdict, and `limitations` names exactly what was missing.

## Brand registry

`app/brand.py` keeps one entry per organization: its official registrable
domains, a claim pattern (English and Hebrew), hostname tokens, and whether the
name is also an ordinary word. All brand checks use this registry:

- **Hostname tokens, not substrings.** `paypal-login.example` and
  `paypalsecure.example` name PayPal. `purchase.com` does not contain the token
  `chase`, and `applebees.com` is not Apple.
- **Ambiguous names need context.** `apple`, `office`, `discount`, `pepper` and
  similar words only count in a hostname next to an account/login token
  (`office365-login.example`). In text they need a qualifier ("Microsoft Office",
  "Discount Bank", "בנק דיסקונט").
- **Look-alikes:** homoglyphs (`paypa1`, `rnicrosoft`, `googIe`), swapped
  neighbouring letters (`mircosoft`), repeated or dropped letters (`gooogle`,
  `whatsap`) and truncation (`paypa`). Distinctive brand names only.
- The web client validates the `brand` field of responses against the same list
  (`mobileshield-web/lib/analysis.ts`). A test keeps the two lists in sync.

## Link inspection (SSRF boundary)

`app/detection/network_policy.py` and `safe_transport.py` are the only code that
opens connections to user-supplied destinations.

- Every URL is re-authorized before each request, including each redirect target.
  Only `http`/`https` on default ports are allowed. Numeric-looking hosts (`0x7f.1`, `2130706433`),
  internal suffixes (`.local`, `.internal`, …) and userinfo are rejected.
- DNS runs in a disposable child process killed at the deadline. Every answer
  must be a public unicast address: private, loopback, link-local, reserved,
  multicast, IPv4-mapped and NAT64/6to4/Teredo ranges are refused.
- The socket connects to the validated IP while sending the original `Host` and
  SNI, so a second DNS answer cannot redirect the connection (DNS rebinding).
- A watchdog enforces one absolute deadline (20 s) even while headers are being
  read slowly. Bodies are capped at 256 KB, with at most 5 redirects and 2
  concurrent inspections per process. No cookies, proxies or subresources are used.
- Exception text is never returned or logged, because libraries can embed URLs.

## Text coverage

`app/text_coverage.py` decides whether the prose is recognizable English or
Hebrew structure, without a dictionary or language model. It looks for
closed-class words (pronouns, prepositions, auxiliaries), Hebrew attached prefixes
and plausible word shapes, and rejects keyboard runs and repeated characters.
When coverage fails, the result is `unknown` with `unsupported_text` rather than
a reassuring verdict.

## Accounts and API keys

User registration, JWT login and per-user API keys (`app/routers/auth.py`,
`app/routers/keys.py`) are implemented but **not mounted** in the public beta.
Tests assert that these routes return 404. An admin-only
`POST /admin/create-api-key` exists behind `ENABLE_ADMIN`, an admin token and an
optional IP allowlist. API keys are stored as HMAC-SHA256 digests and looked up
by digest.

## Deployment notes

- `ENV=prod` refuses to start with placeholder or short secrets
  (`JWT_SECRET`, `SERVER_KEY`, and `ADMIN_TOKEN` when admin is enabled).
- The scan rate limiter is per process and keyed by the ASGI client address
  (IPv6 grouped by /64). Behind a reverse proxy, configure Uvicorn's
  `--proxy-headers`/`--forwarded-allow-ips` so the client address is the real one.
  With several workers, use a shared store such as Redis.
  Uvicorn also reads `FORWARDED_ALLOW_IPS`; set it to the proxy's address range
  rather than `*`, which would let any client choose its own rate-limit identity.
- With `ENV=prod` the interactive API docs (`/docs`, `/redoc`, `/openapi.json`) are not served.
- The database is only needed for the admin/key routes and `/readyz`. If it is
  unreachable at startup, the API logs a warning and keeps analyzing messages.
- `NEXT_PUBLIC_API_BASE_URL` is compiled into the web bundle, so set it as a
  Docker build argument, not a runtime variable.
