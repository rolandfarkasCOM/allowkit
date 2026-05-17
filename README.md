# AllowKit

Minimal, developer-first consent backend for GA4, Microsoft Clarity, and Brevo. Cloudflare-native: Worker + KV + D1.

AllowKit stores and synchronises consent across web, mobile, and desktop apps under a single domain instance. **You bring your own UI.** AllowKit provides the API.

## What it does not provide

- UI / cookie banners
- npm packages or script loaders
- IAB TCF support
- Legal advice

## Core principles

- Default-deny for all non-essential tracking
- No tracking before consent
- Append-only audit log (D1 + DB-level triggers)
- Cross-platform consistency — one consent state per subject, shared across all apps under the instance
- One Worker instance per TLD
- No vendor lock-in
- Minimal surface area

---

## Architecture

```
Client (web / mobile / desktop)
        |
        v
AllowKit Worker (Hono)
        |
        ├── KV  → latest consent state, keyed by hashed subject ID
        └── D1  → append-only audit log (UPDATE/DELETE blocked by trigger)
```

Consent state is **per-subject, per-instance** — last write wins. If a user withdraws on mobile, web reads the same withdrawn state immediately. The audit log records *which* app made each change.

---

## Threat model

AllowKit has two distinct surfaces with different auth posture. Understand the difference before you integrate.

### Anonymous web (no login)

Industry-standard model — same as CookieYes / OneTrust / Cookiebot:

- Customer's site **generates a UUIDv4 subjectId client-side** on first visit, stores in a first-party cookie or `localStorage`, scoped to the customer's domain.
- That UUID *is* the user's identity for consent purposes — possession of the cookie = "this user."
- Server-side defense is **strict Origin enforcement**: AllowKit returns `403` if the request's `Origin` header is missing or not in `ALLOWED_ORIGINS`.
- Threat acceptance: an attacker who learns a specific user's UUID could forge consent for them. UUIDs are high-entropy and never transmitted publicly, so this is treated as equivalent to session-cookie theft.

**Integrator responsibilities:**
- Generate UUIDv4 subjectIds (`crypto.randomUUID()` in browsers).
- Store in `Secure; HttpOnly; SameSite=Strict` cookie OR localStorage on your own domain.
- Never log or expose subjectIds in URLs, server logs, or shared analytics.

### Authenticated apps (mobile, desktop, customer dashboard)

Stronger than the web case — every write is bound to a specific authenticated user via JWT.

- Customer's backend **mints an HS256 JWT** with claims `{sub: <subjectId>, iss: <appId>, exp: <≤5min>, iat: <now>}`, signed with the per-app secret.
- App sends `Authorization: Bearer <jwt>` on every POST.
- AllowKit verifies signature, enforces `iss === appId`, `sub === subjectId`, expiry, and the configured lifetime cap (default 300s, hard cap 900s).
- `alg: none` and any non-HS256 algorithm are rejected (alg-confusion defense).

**Integrator responsibilities:**
- Customer's backend holds `APP_SECRET_<APPID>`. Never ship it to the client.
- **Secret length:** at least 32 bytes (256 bits — matches the HMAC-SHA256 MAC width). AllowKit rejects shorter secrets with a 500 at use; whitespace-only secrets are treated as missing.
- Mint short-lived JWTs on demand from your backend (e.g. when the user opens the consent screen).
- Never reuse JWTs across users; `sub` must always be the user requesting the operation.

---

## API

| Method | Path                       | Purpose                                                                                  |
|--------|----------------------------|------------------------------------------------------------------------------------------|
| GET    | `/config/:appId`           | Returns consent contract for the app (`{ appId, categories, version }`).                 |
| GET    | `/consent`                 | Header-based read. `X-Subject-Id: <uuid>`. Returns `{ consent, updatedAt }`. `updatedAt` is `null` for unknown subjects, a millisecond epoch for known ones — see Threat model on this acceptable existence-disclosure trade-off. |
| POST   | `/consent`                 | Records consent. Returns `{ consent, updatedAt }` on a fresh write, or `{ consent, updatedAt, replayed: true }` when `Idempotency-Key` matched a prior identical body. Strict-shape clients must permit the optional `replayed` field. |
| POST   | `/withdraw`                | Resets all non-necessary categories to `false`. Appends `withdraw` row. No `Idempotency-Key` support (withdraws are state-idempotent already). |

### Consent shape

```json
{
  "necessary": true,
  "functional": false,
  "analytics": false,
  "marketing": false
}
```

`necessary` must be `true`. Mapping (web): `analytics → GA4 + Clarity`, `marketing → Brevo tracking`.

### Examples

```bash
# Record consent — anonymous web (Origin allowlist enforced server-side)
curl -X POST https://allowkit.example.com/consent \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://example.com' \
  -d '{
    "appId": "web",
    "subjectId": "11111111-1111-4111-8111-111111111111",
    "consent": { "necessary": true, "functional": true, "analytics": true, "marketing": false }
  }'

# Read latest consent (subjectId in header, not URL)
curl https://allowkit.example.com/consent \
  -H 'X-Subject-Id: 11111111-1111-4111-8111-111111111111'

# Withdraw
curl -X POST https://allowkit.example.com/withdraw \
  -H 'Content-Type: application/json' \
  -H 'Origin: https://example.com' \
  -d '{ "appId": "web", "subjectId": "11111111-1111-4111-8111-111111111111" }'

# Record consent from a signed app — JWT auth (mobile/desktop)
JWT=$(node -e "
  const {signJwt} = require('./src/lib/jwt');
  const now = Math.floor(Date.now()/1000);
  signJwt({iss:'mobile', sub:'<subject-uuid>', iat:now, exp:now+300}, process.env.APP_SECRET_MOBILE)
    .then(t => process.stdout.write(t));
")
curl -X POST https://allowkit.example.com/consent \
  -H 'Content-Type: application/json' \
  -H "Authorization: Bearer $JWT" \
  -d '{
    "appId": "mobile",
    "subjectId": "<subject-uuid>",
    "consent": { "necessary": true, "functional": true, "analytics": false, "marketing": false }
  }'
```

### Optional headers

| Header              | Purpose                                                                          |
|---------------------|----------------------------------------------------------------------------------|
| `Authorization`     | `Bearer <jwt>` — required for apps in `APP_SIGNED_IDS`.                          |
| `Idempotency-Key`   | Client-generated key (1–128 chars, `[A-Za-z0-9_-]`). Same key + same body → replay. Same key + different body → 409. |
| `X-App-Id`          | Optional hint for finer-grained per-app rate limiting on POST routes (must be in `APP_IDS`). |

---

## Security

| Layer | Protection |
|---|---|
| Transport | TLS via Cloudflare. |
| Origin (browser) | Strict CORS allowlist (`ALLOWED_ORIGINS`). |
| Origin (server-side) | POST from un-signed app without allowlisted Origin → 403. CORS is browser-only; this catches non-browser callers. |
| App identity | `appId` validated against `APP_IDS` allowlist on every request. Lowercase only; `-`/`_` collision-prone IDs rejected. |
| App auth (signed) | HS256 JWT with `sub`/`iss`/`exp`/`iat` claims. Hard 15 min lifetime cap. Alg-confusion defense (`alg: none`/RS*/ES* rejected). Signature verified via constant-time `crypto.subtle.verify`. |
| Body shape | Valibot `strictObject` — unknown keys rejected with 400. |
| Body size | 4 KB cap → 413. |
| Content type | `Content-Type: application/json` required on POST → 415 otherwise. |
| Subject ID | UUIDv4 default; per-instance regex override via `SUBJECT_ID_PATTERN`. **Fail-closed** if pattern fails to compile. SHA-256-with-salt before storage. Never echoed to clients. |
| Replay protection | Optional `Idempotency-Key` header bound to body hash. Replay returns cached state; conflict returns 409. |
| Rate limit | Configured at the Cloudflare edge (WAF rate-limit rule on the zone) — runs before requests reach the Worker, free, no KV writes burned. See setup step 5 below. |
| Cache | `Cache-Control: no-store` on every response — consent state can change at any time. |
| Audit integrity | D1 triggers reject `UPDATE` and `DELETE` on `consent_audit`. |
| Information disclosure | Generic `internal_error` on 500 — no stack traces. Server-side `subjectHash` and `lastAppId` never returned. SubjectId never in URL path. |
| User-Agent | Truncated to 256 chars before storage; control chars stripped. |
| SQL injection | Parameterized D1 queries only. |

### Acknowledged trade-offs

- **Idempotency under concurrency.** The check is `kv.get` + `kv.put`, non-atomic. Two parallel requests with the **same key but different bodies** could both observe a fresh slot and both proceed; the 409-conflict guarantee is best-effort, not strict. Replay protection should rely on JWT `exp` and subject-binding, not on idempotency. Move to a Durable Object if you need true compare-and-swap.
- **`updatedAt: null` reveals subject existence.** `GET /consent` returning `null` vs a timestamp tells the caller whether a UUID has consented before. Acceptable in the threat model since the caller already possesses the high-entropy UUID, but document for compliance reviewers.
- **Audit-first / KV-second write order.** `POST /consent` and `POST /withdraw` write the audit row first, then the KV cache. If the KV write fails after the audit row commits, the audit log is ahead of runtime state. This is the **safe** failure direction — runtime falls back to default-deny while the audit log shows the user's intent. The reverse order (KV-first) would have produced the unsafe direction: KV grants tracking with no auditable record.
- **Idempotency replay fallthrough on KV eviction.** If KV evicts the consent record but the idempotency entry survives, the next call with the same `(subject, key)` falls through to a fresh write rather than returning a stale-looking response. A coordinated cardinality attack (spamming `consent:*` writes to evict legitimate records) could amplify legit retries into extra audit rows. Bounded by the WAF rate limit.

---

## Setup

```bash
npm install
```

### 1. Provision Cloudflare resources

```bash
# KV namespace for latest consent
npx wrangler kv namespace create allowkit_consent

# D1 database for the audit log
npx wrangler d1 create allowkit_audit
```

Copy the returned `id` values into `wrangler.toml` (replace `REPLACE_WITH_KV_ID` and `REPLACE_WITH_D1_ID`).

### 2. Set secrets

```bash
npx wrangler secret put HASH_SALT
# paste a long random string; this is per-instance

# For each app in APP_SIGNED_IDS:
npx wrangler secret put APP_SECRET_MOBILE
npx wrangler secret put APP_SECRET_DESKTOP
```

### 3. Apply migrations

```bash
npm run db:migrate:remote
# or for local dev: npm run db:migrate:local
```

### 4. Configure per-instance vars in `wrangler.toml`

| Var                       | Example                                       | Purpose                                                            |
|---------------------------|-----------------------------------------------|--------------------------------------------------------------------|
| `APP_IDS`                 | `web,mobile,desktop`                          | Lowercase allowlist of valid `appId` values for this instance.     |
| `ALLOWED_ORIGINS`         | `https://example.com,https://app.example.com` | Strict origin allowlist (server-side, not just CORS).              |
| `APP_SIGNED_IDS`          | `mobile,desktop`                              | Apps that MUST send a JWT. Browser apps usually omitted.           |
| `JWT_MAX_AGE_SECONDS`     | `300`                                         | Hard cap on JWT lifetime. Default 300 (5 min). Max 900 (15 min).   |
| `SUBJECT_ID_PATTERN`      | `^[0-9a-f]{32}$` (optional)                   | Override default UUIDv4 pattern. Fails closed on parse error.      |
| `HASH_SALT` (secret)      | (random string)                               | Salt for hashing subject IDs and IPs. Never commit.                |
| `APP_SECRET_<APPID>` (secret) | (random string)                           | JWT signing secret for that app. One per signed app.               |

### 5. Configure rate limiting at the Cloudflare edge — **mandatory**

AllowKit has no in-app rate limiter; brute-force JWT verification and audit-log spam are bounded **only** by Cloudflare's edge rate limiting. **Configure this before exposing the worker publicly** — without it, a single attacker can exhaust the free-tier 100k Workers requests/day quota and flood the audit log within minutes.

Configure once at the zone dashboard:

- **Cloudflare dashboard** → your zone → **Security** → **WAF** → **Rate limiting rules**
- Add rule: `URI Path matches /consent OR /withdraw OR /config` → block requests when `requests per IP > 60 per 1 minute` → action **Block**
- Free plan includes one custom rate-limit rule. Paid plans get more granular controls.

You can tune the threshold to taste; 60/min is generous for normal use and blocks brute-force forgery attempts.

### 6. Run

```bash
npm run dev      # local (Miniflare — uses in-memory KV/D1)
npm run deploy   # to Cloudflare
```

`workers_dev = false` is set in `wrangler.toml` — the worker will only be reachable through your registered domain after deploy, never via `*.workers.dev`. This forces all traffic through your zone's CF protections (rate limiting, WAF managed rulesets, custom rules).

---

## Development

```bash
npm run typecheck    # tsc --noEmit
npm run test         # vitest run (64 tests)
npm run test:watch
```

Tests run on plain Vitest with hand-rolled in-memory KV and D1 fakes. They cover the full request → middleware → route → storage path, including JWT verification (alg-confusion defense, expiry caps, claim mismatch), Origin enforcement, idempotency body-binding, rate-limit bucket evasion, body limits, content-type enforcement, subject pattern fail-closed behaviour, and the audit-log write contract. For end-to-end checks against the real Workers runtime, run `npm run dev` and exercise with `curl`.

---

## Deployment model

One Worker instance per TLD:

```
allowkit.your-product.com
allowkit.your-other-product.dev
allowkit.client-project.io
```

Each instance has its own KV namespace, D1 database, allowed origins, `HASH_SALT`, and per-app JWT secrets. **No shared database with your app.**

### Salt rotation

Rotating `HASH_SALT` orphans every existing `consent:*` KV entry and `subject_hash` D1 row — they were derived from the old salt and won't match new lookups. **There is no migration path** in this version. Treat the salt as permanent for the life of the instance, or accept a full audit-log reset on rotation.

---

## License

MIT
