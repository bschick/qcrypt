# Quick Crypt Security Review — Findings Report

**Scope:** monorepo at `/home/bschick/shared/angular/qcrypt-main/` — Angular web client (`apps/web`), AWS Lambda server (`apps/server`), CLI (`apps/cli`), crypto library (`libs/crypto`), API SDK (`libs/api`).
**Emphasis:** client↔server authentication protocol and `libs/crypto` cipher protocol, per the request. Holistic coverage included.

Findings are grouped by severity. Each includes impact, evidence (file:line), and a suggested remediation.

---

## Re-review — 2026-04-17

Full re-review by Opus 4.7 against the live tree. All prior findings re-verified end-to-end (server auth protocol, crypto library, web client, CLI, shared API types). Results:

**Re-verified as still fixed (no regression):** C1, H1, H2, H4, M5, M8, L1, S2, S3, S4.
- `verifyCsrf` (`server.ts:1648`), `postRecover` (`server.ts:1426`), `postRecover2` (`server.ts:1507`) all use `timingSafeEqual`.
- `_doPostRegVerify` (`server.ts:475+`) enforces `challenge.purpose ∈ {'reg','add'} && challenge.userId === unverifiedUser.userId`.
- `postPasskeyVerify` passes `verifiedUser` and `expectedPurpose='add'` directly; `body.userId` no longer consulted on this path.
- `getSessionKey` (`server.ts:1582+`) includes `sessionVersion` in HKDF `info` alongside `purpose:authCount`.
- `deleteSession` (`server.ts:273+`) bumps `authCount`, invalidating prior cookies.
- `postAuthOptions` (`server.ts:755+`) returns a dummy `allowCredentials` via `dummyAllowedCreds` (seeded by `HKDF(jwtMaterial, inputUserId)` into a weighted profile table) plus an equivalent-cost DB call and 5–35 ms jitter to align timing for unknown users.
- `Authenticators` now has a `credentialid-index` GSI; `postAuthVerify` (`server.ts:296+`) uses it to resolve the passkey to a userId and cross-checks `userHandle`, eliminating the "trust caller's `body.userId`" shape.

**Still active (unchanged from prior review):**
- **H5 — legacy `/v1/users/{userid}/recover/{usercred}` route remains mounted.** `METHODMAP` in `server.ts:1804` still registers `postRecoverOld` against `Patterns.recoverOld` (`urls.ts:88`). The fix note "external urls cannot change" addresses client migration, but any caller that still hits the legacy URL — including an attacker — gets their `userCred` written to access logs and `Referer` headers. Fully closing H5 requires removing the route from `METHODMAP` so the endpoint 404s server-side; client-side migration alone does not protect against third-party replay of a logged path. Log scrubbing and `userCred` rotation for historical users remain the follow-up.
- **M2, M3 — fixed in V7.** Key derivation moved to `libs/crypto/src/lib/keys.ts`; V7 salt‑mixes the per‑message `slt` into every `crypto_kdf_derive_from_key` call (per‑ciphertext hint/signing/block keys) and derives a distinct hint IV from the data IV via a labeled KDF step (`_genHintCipherKeyAndIV` with purpose `"Hint_Key"`, instance 2). V6 retains the old unsalted derivation and shared IV for backward compatibility when decrypting existing ciphertexts.
- **S1 — streaming dispatch precedes MAC validation.** `streamDecipher` (`ciphers.ts`) still routes by `verOrAlg` before any MAC is checked, leaving V1/V4/V5 code paths reachable for every user (their `userCred`-derived signing key authenticates under any version). Low current risk (no known parser bugs in legacy deciphers), but the surface persists.

**New observations (not previously documented):**
- **`dummyAllowedCreds` distinguishability drift (very low, informational).** The dummy response is deterministic per `inputUserId` and frozen for the lifetime of `jwtMaterial`. A real user's `allowCredentials` list *is* allowed to change as they add/remove passkeys. An attacker who records responses for a narrow-scope `userId` over time can in principle distinguish "real user whose credential set evolved" from "frozen dummy" — but this requires prior targeted enumeration of a specific `userId` (already 128-bit unguessable), spans multiple observations across long time windows, and does not reveal the `userId` itself, only a binary "probably-real vs probably-bogus" signal for an already-guessed value. Mitigation is not worth the code cost; documented here for completeness.
- **Minor schema-name drift in the C1 write-up (doc-only).** The live `Challenges` entity in `apps/server/src/models.ts` uses `purpose: ['reg', 'add', 'auth']`. The original C1 fix narrative above refers to `'addpasskey'` in places. No code impact — the server consistently uses `'add'`. Worth fixing the doc on next pass for reader clarity.
- **`libsodium` KDF context truncation is fine.** `_genDerivedKey` / `_genHintCipherKey` / `_genSigningKey` pass multi-byte "purpose" / "context" strings to `crypto_kdf_derive_from_key`, which truncates to 8 bytes internally. First-8-byte prefixes across the three contexts ("cipherda", "hint enc", "block en") are distinct, so the truncation does not collide domain-separation labels.
- **Web client XSS sinks confirmed benign.** `[innerHTML]` is used in three places: FAQs (static content in `faqs.component.ts`), and `core.component.ts` `clearMsg` / `cipherMsg`, which are written only by `showClearMsg` / `showCipherMsg` (`core.component.ts` lines 876, 914) after passing each fragment through `DomSanitizer.sanitize(SecurityContext.HTML, …)`. No user input reaches these fields un-sanitized.
- **`DomSanitizer.bypassSecurityTrustResourceUrl` usage in `core.component.ts` lines 155/161/167** points at three local `../assets/*.svg` string literals registered as Material icons. No user input, no external URL — safe.

**Overall disposition:** The production tree is in strong shape. The single biggest remaining item is H5 route retirement; everything else is either previously accepted, documented, or tracked against a future protocol version.

---

## CRITICAL

### C1. (fixed) Cross‑user passkey binding via unbound challenge + trusted `body.userId` — **FIXED**

> **Status:** Fixed in the current tree. The `Challenges` entity now carries `purpose: 'reg' | 'add' | 'auth'` (required) and an optional `userId` (`apps/server/src/models.ts`). `postRegOptions`, `getPasskeyOptions`, and the recover paths store challenges with `purpose` + `userId`; `postAuthOptions` stores `purpose: 'auth'` and includes `userId` only when the caller narrows it. `_doPostRegVerify` takes `expectedPurpose` from its caller (`'reg'` or `'add'`) and rejects if `challenge.purpose !== expectedPurpose || challenge.userId !== unverifiedUser.userId`; `postAuthVerify` rejects if `challenge.purpose !== 'auth'` and, when `challenge.userId` is bound, requires it to match the user resolved from `userHandle`. All challenge‑failure paths now throw a uniform `'challenge not valid'` error to reduce oracle leakage. Challenges are still delete‑on‑read to prevent reuse. Original finding preserved below for history.

**Where:** `apps/server/src/server.ts` — `_doPostRegVerify` (used by `POST /v1/reg/verify` and `POST /v1/passkeys/verify`).

**What:** The `Challenges` table keys purely on the random challenge string — it is not bound to the acting user, nor to the *purpose* of the challenge (registration vs authentication vs add‑passkey). It is created in three places that have very different user contexts:

| Creator | Userid known at creation? |
|---|---|
| `postRegOptions` (`/v1/reg/options`) | Yes — a brand‑new `userId` is minted server‑side before the challenge is stored. |
| `getPasskeyOptions` (`/v1/passkeys/options`) | Yes — the session is authenticated, `verifiedUser.userId` is known. |
| `postAuthOptions` (`/v1/auth/options`) | **Optional** — `userId` is taken from the request body if supplied (narrowing `allowCredentials` to that user); otherwise the flow is discoverable‑credential and no userId is known. |

`_doPostRegVerify` then pulls `challenge` and `userId` from the request body, loads the challenge record by challenge alone, loads the user by `body.userId`, and binds the new passkey to **whatever `userId` the caller sent**. `postPasskeyVerify` is marked `authorize: true` but still trusts `body.userId` over the authorizer's `verifiedUser`.

**Impact:** An attacker who obtains any outstanding challenge value (within its 5‑minute TTL) can present it on `/v1/reg/verify` or `/v1/passkeys/verify` and cause the server to bind a passkey they control to an arbitrary `userId`. `userId` is 128‑bit random so blind enumeration is infeasible, but it is returned by several legitimate endpoints, appears in URLs and recovery mnemonics, and is confirmable via `/v1/auth/options`.

A corollary issue is that an authentication challenge (from `/v1/auth/options`) and a registration challenge (from `/v1/reg/options` or `/v1/passkeys/options`) are indistinguishable to the verify endpoints — whichever is submitted first wins. Challenge intent is not recorded.

**Fix (refined, accounting for `/v1/auth/options`):**

The server can bind by *purpose* always, and by userId when the purpose has one:
- Extend the `Challenges` schema with `purpose: 'reg' | 'addpasskey' | 'auth'` and an optional `userId`.
- `postRegOptions` → store `{ challenge, purpose: 'reg', userId: <newly minted> }`.
- `getPasskeyOptions` → store `{ challenge, purpose: 'addpasskey', userId: verifiedUser.userId }`.
- `postAuthOptions` → store `{ challenge, purpose: 'auth', userId: body.userId ?? undefined }` — bind when the caller narrows to a specific user, leave unset for the discoverable flow.
- `_doPostRegVerify` → reject unless `challenge.purpose ∈ {'reg','addpasskey'}` *and* `challenge.userId === (verifiedUser?.userId ?? body.userId)` — with `postPasskeyVerify` additionally refusing any `body.userId` that disagrees with `verifiedUser.userId`.
- `postAuthVerify` → reject unless `challenge.purpose === 'auth'`, and if `challenge.userId` is set, reject unless the assertion's resolved user matches it. WebAuthn's assertion itself cryptographically ties the response to a specific credential, so the unbound discoverable case remains safe; binding when it *is* known prevents a narrow‑scope auth challenge from being reused to sign in as another user.
- Consume the challenge atomically (delete‑on‑read) to prevent reuse within the TTL window.

Also: `postPasskeyVerify` should simply stop reading `body.userId` — it always has `verifiedUser` from the authorizer.

---

## HIGH

### H1. (fixed) CSRF token comparison is not constant‑time

**Where:** `apps/server/src/server.ts` — `verifyCsrf`:
```ts
if (checkCsrf && (serverCsrf !== headerCsrf || !headerCsrf)) {
   throw new AuthError('invalid csrf token');
}
```
**Impact:** `!==` on strings short‑circuits on first differing character. In principle this leaks byte‑by‑byte information about the expected CSRF token to an attacker who can issue many requests and measure response timing. The token is a derived secret; leaking it defeats CSRF protection on every authorized endpoint.
**Fix:** Compare with a constant‑time comparison (e.g. `crypto.timingSafeEqual` on equal‑length Buffers, or `sodium.memcmp`). Check length first and return `false` on mismatch without early‑exit.

### H2. (fixed) Recovery/userCred comparisons are not constant‑time

**Where:** `apps/server/src/server.ts` — `postRecover` (legacy) and `postRecover2`. Both compare the submitted `userCred` / `recoveryId` against the DB value with `!==` on base64 strings.
**Impact:** Same timing‑oracle shape as H1, but on higher‑value secrets (user credential, recovery ID). Recovery deletes all existing passkeys and lets the attacker register a new one, so leaking these is account‑takeover grade.
**Fix:** Decode both sides to bytes and compare with `sodium.memcmp` / `timingSafeEqual`. Also consider returning a generic 401 on both "user not found" and "credential mismatch" (currently distinguishable by error path).

### H3. (reduced cached time) CSP nonce reused within CloudFront cache window — **REDUCED SEVERITY**

> **Status:** Deployment verified — the string in `apps/web/src/index.html` is a placeholder sentinel, not a production‑served nonce. A Lambda origin (`apps/server/src/nonce/lambda_function.py`) fetches `index.html` from S3, generates a fresh 128‑bit nonce via `secrets.token_bytes(16)`, computes `sha384` integrity hashes for every inline `<script>` / `<style>` (plus `rel=stylesheet` `<link integrity=…>` values), rewrites the CSP placeholders, and returns both the body and a `Content-Security-Policy` response header in lock‑step. Primary XSS protection is therefore **hash‑based allowlisting**, not the nonce. Original finding is preserved below and the residual concern (cache‑window nonce reuse) is re‑stated below it.

**Where:**
- `apps/server/src/nonce/lambda_function.py` — origin Lambda that builds CSP + body per cache miss.
- `apps/web/src/index.html` — contains the sentinel `ngCspNonce="ew26COJKMG8qrA/bjTcl0w=="` that the Lambda searches for and replaces.
- `apps/web/src/app/qcrypt.config.server.ts` — SSR `CSP_NONCE` provider is commented out; dead code in the static‑SPA deployment (`apps/web/project.json` has `ssr:false, prerender:false`).

**Residual issue — nonce reuse across cached responses:**
The Lambda emits `Cache-Control: public, max-age=86400` with an `ETag`, so CloudFront (and every intermediate cache / browser) can serve the same body + CSP pair to all users for up to 24 hours per edge. Within that window the `'nonce-…'` value is **not** per‑request — it is per‑cache‑entry. An attacker who learns the current nonce (e.g. by fetching the HTML themselves) has the freedom of the nonce for the remainder of that cache window. CloudFront cannot rewrite body content for cached items, so caching HTML that contains a nonce inherently means the nonce is shared.

What this nonce actually gates:
- `script-src <sha384 hashes> 'wasm-unsafe-eval'` — **no `'nonce-…'`**. Scripts are purely hash‑locked; a known nonce does **not** enable injected `<script>` execution.
- `style-src 'self' 'nonce-…' <sha384 hashes>` — nonce covers Angular's runtime‑injected inline styles, which do not have a statically‑computable hash. A known nonce therefore enables injected `<style>` / `style=…` content (CSS‑based exfiltration, UI redressing, `@import` to an attacker origin only if not also blocked by `default-src 'none'` — it is here).
- `require-trusted-types-for 'script'` and `trusted-types angular angular#components` — further script‑injection defense layer.

So the realistic impact is **style‑injection XSS within a 24 h cache window** if a DOM‑injection sink is ever found, not full script execution. That is a meaningful narrowing of the original finding.

Other observations in the Lambda:
- `stashed` is a module‑level dict keyed by `index.html` / `maintenance.html` — warm‑container cache of the parsed S3 object. Fine; survives only a single container's life.
- `hashlib.md5` is used to compute the response `ETag` only (not security‑sensitive).
- `csp_base` is hard‑coded in the Lambda and the comment flags this as fragile vs. the CloudFront response‑headers policy; any policy drift there is a separate operational risk.

**Fix options, ordered by cost/benefit:**
1. **Shorten `max-age`** on the Lambda response (e.g. `max-age=60, must-revalidate`) and tune the CloudFront behaviour's min/default/max TTL to match. Dramatically shrinks the nonce‑reuse window; modest extra Lambda invocations (one per minute per edge per PoP), and the S3 `IfNoneMatch` fast‑path keeps origin cost low.
2. **Drop `'nonce-…'` from `style-src` entirely** if Angular's runtime styles can be enumerated and added as static `sha384` hashes (some Angular CDK components generate styles at build time — worth auditing). That eliminates the residual style‑injection risk without touching caching.
3. **Keep a nonce but make it per‑viewer** via a CloudFront Function/Lambda@Edge on the *viewer‑response* path that rewrites the nonce after cache retrieval. Expensive and requires moving body‑rewrite out of the origin Lambda.
4. ~~Clean up dead code: remove the commented `CSP_NONCE` provider in `qcrypt.config.server.ts` and the unused `apps/web/server.ts` SSR scaffold.~~ **Done** — SSR scaffold (`server.ts`, `main.server.ts`, `qcrypt.config.server.ts`) and associated deps removed. Consider adding a short comment next to the `ngCspNonce` attribute in `apps/web/src/index.html` pointing at `apps/server/src/nonce/lambda_function.py` so future readers know the string is a replace‑target, not a production nonce.
5. Add a deploy‑time test that fetches `/` twice within a short window and asserts the `Content-Security-Policy` `nonce-…` value *changes* (after adopting option 1 or 3), as an ongoing regression guard.

---

<details>
<summary>Original finding (superseded by the status note above)</summary>

**Where:** `apps/web/src/index.html`:
```html
<qcrypt-root ngCspNonce="ew26COJKMG8qrA/bjTcl0w=="></qcrypt-root>
```
Plus `apps/web/src/app/qcrypt.config.server.ts` where the proper per‑request nonce code is present but **commented out**:
```ts
//const nonce = crypto.getRandomValues(new Uint8Array(16));
/*,{ provide: CSP_NONCE, useValue: nonce }*/
```
**Configuration note:** `apps/web/project.json` has `"ssr": false, "prerender": false`, so the production build is static — `apps/web/server.ts` is not on the request path in production.

**Impact (original, pre‑deployment verification):** Two possible states — both bad:
- If CloudFront sets a strict CSP of the form `script-src 'nonce-…'` (the standard shape Angular's `ngCspNonce` targets), the static nonce in `index.html` makes the nonce predictable to any attacker and defeats the CSP for XSS.
- If CloudFront sets no CSP (or a loose one), the `ngCspNonce` attribute is a no‑op that creates a false sense of protection in the codebase.

**Actual behaviour:** Neither. See the Lambda described above.
</details>

### H4. (fixed) `POST /v1/passkeys/verify` ignores the authenticated user — **FIXED**

> **Status:** Fixed. `postPasskeyVerify` now passes `verifiedUser` directly into `_doPostRegVerify` with `expectedPurpose = 'add'`; `body.userId` is no longer read on this path (`apps/server/src/server.ts` ≈ line 452). Original finding preserved below for history.

**Where:** `apps/server/src/server.ts` — `postPasskeyVerify` used `body.userId` rather than `verifiedUser`.
**Impact:** This was the authenticated counterpart of C1. Even without a challenge leak, a logged‑in user who could forge a registration ceremony could bind the new passkey to a target `userId` they choose. The fact that the authorizer successfully resolved a user was wasted if the handler then trusted the body.
**Fix:** Drop `body.userId`; rely solely on `verifiedUser.userId`. Reject the request if `body.userId` is present and doesn't match.

### H5. (fixed API, external urls cannot change) Legacy `/v1/users/{userid}/recover/{usercred}` places `userCred` in the URL path

**Where:** `apps/server/src/server.ts` — `postRecover`; route pattern `apps/server/src/urls.ts:84` — `/v:ver/users/:userid/recover/:usercred`.

**Impact:** `userCred` is the 32‑byte long‑term master secret for the account — it re‑derives every cipher/signing key the user ever uses. Carrying it in the URL path means it lands in places that are commonly retained and aggregated:
- CloudFront / API Gateway / Lambda access logs (typically long retention)
- the `Referer` header of any outbound link clicked from a page that loaded that URL
- browser history, browser sync (if enabled), and any upstream proxy/CDN that logs full paths
- any error/exception telemetry pipeline that captures the request URL

Exposure of `userCred` is *permanent account‑takeover grade* — it is not bounded by session TTL because it re‑derives persistent keys. This is why the issue is High even though the endpoint is marked deprecated: every user that hasn't migrated is still vulnerable, and logs are retrospectively grep‑able.

**Fix:** `postRecover2` already does this correctly — `recoveryId` and `userId` are both in the POST body. The remediation is therefore:
- Stop routing `/v1/users/:userid/recover/:usercred` entirely (remove the `postRecover` handler and its pattern), forcing all clients onto `/v1/recover2`.
- If there is still a transitional migration window, at minimum scrub `:usercred` from CloudFront / API Gateway access logs (request‑mapping template or log‑filter pattern) before the logs are archived.
- Rotate `userCred` for any account that has ever used this legacy path — historical logs already contain the secret in plaintext.

### H6. (invalid, WAF rate limiting exists on prod) No rate limiting on authentication / recovery / registration endpoints

**Where:** All unauthenticated POSTs: `/v1/reg/options`, `/v1/reg/verify`, `/v1/auth/options`, `/v1/auth/verify`, `/v1/recover2`, legacy `/v1/users/{userid}/recover/{usercred}`.
**Impact:** Enables:
- Online brute force of `userId`, `recoveryId` (16 bytes each, so still infeasible, but no defense in depth).
- Enumeration / mapping of the `/v1/auth/options?userId=…` response (allowed‑credentials list implicitly confirms user existence).
- Account‑creation flooding (registration creates a TTL user record regardless of verification).
- Amplification of the timing oracles in H1/H2.
**Fix:** Apply per‑IP and per‑userId throttling (WAF/API Gateway usage plans / AWS WAF rate rules), with tighter caps on recover/auth options. Reject repeat challenge consumption on known userIds.

---

## MEDIUM

### M1. (planned remediation — at-rest client encryption of userCred) `GET /v1/session` returns `userCred` with only a session cookie

**Where:** `apps/server/src/server.ts` — `getSession`. Returns `LoginUserInfo` including `userCred` when the `__Host-JWT` cookie validates. No CSRF token required (by design, since this is how the client obtains CSRF).
**Impact:** The server itself notes the session cookie is the "weakest link." Because `userCred` is the long‑term cryptographic secret that re‑derives all cipher/signing keys, any temporary theft of the session cookie (local malware with cookie access, XSS that bypasses CSP, subdomain scoping mistakes) yields permanent decryption capability for existing ciphertexts, not just account access until logout.

#### Planned remediation — at-rest client encryption of userCred (per-tab sessionStorage + BroadcastChannel handoff)

The naïve fix ("stop returning `userCred` from `/session`, force re-auth on refresh") was rejected as too disruptive — it was the pre-existing behavior and was fairly annoying in practice. Simply stashing raw `userCred` in `sessionStorage` or `localStorage` was also rejected: the bytes would be trivially recoverable from DevTools or a stolen browser-profile snapshot.

An earlier iteration of this design put the wrapped `userCred` in `localStorage` (shared across tabs, persistent across browser restarts). That was abandoned because it creates indefinite-lifetime orphan state: the most common user flow — close a tab or the browser without explicit logout — leaves wrapped ciphertext and its IndexedDB key sitting on disk until the user next runs Quick Crypt and triggers cleanup. `localStorage` also inherits a timeout regression relative to the current `__Host-JWT` cookie, which expires after 3 hours and bounds a profile-theft attacker's window. Keeping wrapped `userCred` in `localStorage` removed that bound entirely.

The design below keeps the non-extractable wrap key but moves the wrapped ciphertext into `sessionStorage` (per-tab, wiped on tab close) with a `BroadcastChannel` handoff so a freshly opened tab can obtain the ciphertext from a living peer tab without re-auth. When the last tab closes, no wrapped `userCred` remains on disk — the IndexedDB key alone is useless without the ciphertext it is paired with.

**Storage layers, in lookup order**

1. **`sessionStorage` (per-tab ciphertext buffer).** Holds `{iv, ciphertext}`. Wiped on tab close by the browser. Refresh in the same tab hits this path and is fast.
2. **`BroadcastChannel('qcrypt-session')` (cross-tab handoff).** A newly opened tab that missed `sessionStorage` broadcasts a request; any live peer tab on the same origin responds with its own `{iv, ciphertext}`. The requester writes that into its own `sessionStorage` and proceeds.
3. **`IndexedDB` (non-extractable `CryptoKey`).** The AES-GCM unwrap key. Persistent (IndexedDB outlives tab close), but useless in isolation — if the paired ciphertext is gone, the key decrypts nothing.
4. **Server (passkey re-auth).** True cold start — no live tabs and no `sessionStorage`. The user performs the passkey ceremony and a fresh wrap key is generated; the orphan IndexedDB key from any prior session is overwritten.

**Flow**

1. **Login** (passkey ceremony returns `userCred` and the server-confirmed `userId`):
   - Generate a fresh AES-GCM `CryptoKey` via `crypto.subtle.generateKey({name:'AES-GCM', length:256}, false, ['encrypt','decrypt'])`. The `false` argument is the `extractable` flag — the browser enforces at the platform layer that `exportKey()` throws for this key and that structured clone preserves the restriction across storage boundaries.
   - Write the `CryptoKey` to IndexedDB under a known object-store entry, overwriting any prior entry.
   - Generate a random 96-bit IV, compute `encrypt(AES-GCM, iv, userCred, aad=utf8(userId))`, and write `{iv, ciphertext, userId}` to this tab's `sessionStorage`. The `userId` field is stored in the clear alongside the ciphertext so the tab knows which identity the ciphertext is bound to before attempting decrypt; the AEAD tag is what actually enforces the binding.
   - Zero-fill and drop the raw `userCred` buffer from memory.
2. **On-demand `userCred` access** (any operation needing the secret):
   1. Check `sessionStorage` for `{iv, ciphertext, userId}`. If present and `userId` matches the current logged-in user → read `CryptoKey` from IndexedDB → `decrypt(AES-GCM, iv, ciphertext, aad=utf8(currentUserId))` → hand bytes to the operation → zero-fill after. If the AEAD tag fails (wrong user, wrong key, or tampering) the operation aborts — *never* fall back to using a partially-decrypted buffer.
   2. Otherwise, broadcast a `{type:'req', userId:currentUserId, nonce}` over `BroadcastChannel` and wait a short timeout. A peer tab responds only if its own live session is signed in as the same `userId`, and its response carries `{type:'res', nonce, userId, iv, ciphertext}`. The requester verifies `response.userId === currentUserId` before writing to `sessionStorage`, and the AEAD tag check at decrypt time is the belt-and-braces backstop. Mismatch → discard and fall through to re-auth.
   3. Otherwise, fall through to the passkey ceremony. On success, write `{iv, ciphertext, userId}` to `sessionStorage` and generate a fresh IndexedDB key (step 1 of Login).
3. **`GET /v1/session`** — reduced responsibility:
   - Validates the session cookie, rotates CSRF, returns user metadata (authenticators list, username, `userId`, etc.).
   - Does **not** return `userCred`. This directly closes M1.
4. **Logout** — fan out everywhere (see "Logout fan-out" below).
5. **401 from any protected endpoint** — treat as implicit logout; same fan-out.

**Rationale for each design choice**

- **Non-extractable `CryptoKey`.** `extractable: false` is part of the WebCrypto spec and enforced by the browser, not an application-level convention. `crypto.subtle.exportKey()` throws `InvalidAccessError` for these keys, and structured clone preserves the flag across IndexedDB round-trips. DevTools inspection or an XSS payload in the tab can still *use* the key to decrypt — that is a necessary corollary of making the key available to the app at all, so in-tab XSS remains game-over for the active session. What the flag prevents is **exfiltration of the raw key bytes to another origin or device**, and therefore offline decryption of a copied blob.
- **Client-side encryption of `userCred`.** TLS already encrypts transport, so encrypting `userCred` "on the wire" buys nothing. The real benefit is **at-rest encryption in client storage**: a DevTools "Application → Storage" inspection returns only opaque ciphertext, and raw `userCred` exists in memory only during the actual encrypt / decrypt operations that need it — exposure shrinks from session-long (current `this._userCred` held for the whole session) to operation-long.
- **`sessionStorage` (not `localStorage`) for the ciphertext.** `sessionStorage` is scoped to the tab and wiped on tab close. This collapses the orphan-state window: when the user closes the last tab or the browser, no wrapped `userCred` remains persisted. The IndexedDB key outlives that moment, but alone is useless — it decrypts nothing. `localStorage` would keep the ciphertext on disk indefinitely after tab close, and in the profile-theft threat model that removes the 3-hour bound that the current `__Host-JWT` cookie provides.
- **`BroadcastChannel` for cross-tab handoff.** `sessionStorage` isolates tabs, so opening a second tab would otherwise force re-auth. A `BroadcastChannel` on the same origin lets a new tab ask "anyone have the ciphertext?" and lets a living peer respond. Support is effectively universal on current browsers (Safari 15.4+, Chrome/Firefox since ~2016). The channel never carries plaintext `userCred` — only the wrapped ciphertext — so the exposure is identical to `sessionStorage` itself.
- **No SharedWorker.** An earlier iteration used a `SharedWorker` as the cross-tab cache. It works, but adds a separate execution context, a separate build entry, and port-lifecycle code. For a pure ciphertext cache, `BroadcastChannel` is a functionally equivalent drop-in that collapses to one module with ~15 lines of correlation/timeout logic. The SharedWorker's only real advantage — a dedicated thread that responds while tabs are busy encrypting large files — was judged not worth the complexity.
- **IndexedDB for the key.** Neither IndexedDB nor `sessionStorage` is more access-restricted than the other from a same-origin-JS perspective. The reason to use IndexedDB for the key is mechanical: it is the only browser storage that can hold a `CryptoKey` *object* via structured clone, preserving the non-extractable flag. `sessionStorage` and `localStorage` are string-only, and a non-extractable `CryptoKey` cannot be serialized to a string — that is the whole point of non-extractable.
- **Fresh key per login.** A new AES-GCM key is generated on every successful passkey ceremony, overwriting the prior IndexedDB entry. This prevents an orphan IndexedDB key (left over from a crashed or abruptly closed session) from ever decrypting ciphertext produced in a subsequent session, even on the off-chance cleanup missed something. Since the key is regenerated on every login anyway, no additional rotation scheme is needed.
- **`userId` binding via AEAD associated data.** The wrapped `userCred` is cryptographically bound to the `userId` that was logged in at the moment of encryption, using AES-GCM's associated-data (AAD) slot. Decrypt passes the *current* tab's `userId` as AAD — if the stored ciphertext was wrapped under a different user's session (e.g. cross-tab handoff from a tab that had since switched accounts, a stale `sessionStorage` entry from a previous user on a shared browser, or an attacker trying to trick the tab into decrypting someone else's wrapped secret), the GCM tag fails and `decrypt` throws. This is the critical guard against a subtle class of corruption bug: if Tab A signed in as user X hands its ciphertext to Tab B signed in as user Y, and Tab B proceeds to *encrypt data* using X's `userCred` while believing it belongs to Y, the resulting ciphertext is effectively lost — it cannot be decrypted by either user's future session and the error surfaces only much later, if ever. AAD binding makes the mismatch a loud crypto-level failure at the moment of access, before any user data gets encrypted with the wrong key. Plain string-comparison of the stored `userId` field adds an earlier sanity check for clarity, but the AEAD tag is what makes this impossible to silently bypass.
- **Eliminating `userCred` from `GET /v1/session`.** Once the client can recover `userCred` via `sessionStorage` or cross-tab handoff, there is no reason to keep shipping it over the wire on every session resume. `/session` retains its role of validating the cookie, bootstrapping CSRF, and returning user metadata, but no longer exposes the long-term secret to anyone holding the cookie.

**Things to wire up**

- **BroadcastChannel message schema.**
  - Request: `{type:'req', userId, nonce}` — `userId` is the requester's current logged-in identity; `nonce` is a `crypto.randomUUID()` for response correlation.
  - Response: `{type:'res', nonce, userId, iv, ciphertext}` — `nonce` echoes the request; `userId` confirms the responder's identity matches.
  - Logout: `{type:'logout', userId}` — every tab checks whether the `userId` matches its own session and clears local state if so (a logout from user Y's tab should not drop user X's ciphertext in a different tab, even though in normal use the browser has only one active user at a time).
- **Two-sided `userId` verification for handoff.** A peer tab ignores requests whose `userId` does not match its own current session; the requester ignores responses whose `userId` does not match its own. Both sides must agree before the ciphertext is accepted. The AEAD AAD check at decrypt time then catches any remaining mismatch at the cryptographic layer. This belt-and-braces approach is necessary because the BC transport carries no identity guarantees — any same-origin JS can impersonate either side.
- **Request correlation.** `BroadcastChannel` is pub/sub, not request/response. Requests include a `nonce` (`crypto.randomUUID()`); responses echo the `nonce`; requester matches on it, first matching-and-`userId`-agreeing response wins, later duplicates are ignored.
- **Response timeout.** Requester waits ~150–300 ms (200 ms is a reasonable default) for any response before falling through to re-auth. Longer forgives a slow peer main thread; shorter feels snappy. A peer tab's handler runs on its main thread, so if it is mid-encrypt of a large file the response arrives late and the requester re-auths — an accepted UX regression vs SharedWorker in exchange for the simpler design.
- **Cold-start race via Web Lock.** Two tabs opened simultaneously both miss `sessionStorage` and both broadcast into an empty channel. Without coordination, both initiate passkey ceremonies and the user sees two prompts. Wrap the "broadcast → timeout → re-auth" sequence in `navigator.locks.request('qcrypt-auth', ...)` so the second tab waits, then re-checks `sessionStorage` / re-broadcasts after the first tab finishes and finds the now-populated state.
- **Logout fan-out.** Five places must be invalidated, via two independent mechanisms so that one path cannot silently miss:
  - **Primary — `BroadcastChannel` logout message.** The tab that initiated logout broadcasts a `logout` message; every peer tab clears its `sessionStorage`, zero-fills its in-memory `userCred`, deletes the IndexedDB key (idempotent), and any other in-memory session state. The message should carry the `pkId` being logged out (in addition to `userId`), so a peer tab that has already rotated to a different passkey can ignore a logout that no longer applies to its session. Once this is in place, the `logout(true)` call in `deletePasskey` in `authenticator.service.ts` — currently used to fan out sign-out after deleting the caller's own active passkey — should be changed to `logout(false)`. The `logout(true)` path today leans on the localStorage expiry nudge, which is coarse: a peer tab that logged in with a different passkey between Tab1's login and Tab1's delete click gets forcibly signed out even though its own session is still valid server-side. A pkId-scoped BC `logout` event lets peers decide for themselves and removes the need for Tab1 to use the coarse nudge at all.
  - **Backstop — existing session-expiry timer loop.** The app already has a timer loop (`potentialSession()` / activity-expiry check in `authenticator.service.ts`) that periodically verifies session validity and forces logout on expiry or change. Extend that loop so that on every tick it also checks whether the server session still agrees with local state (cookie still valid, `authCount` unchanged). This catches the case where a tab was frozen (mobile background) or busy (long-running op) at the moment the `BroadcastChannel` logout message was dispatched and missed the event. On next tick it reconciles and logs itself out.
  - The two paths together mean a tab either receives the broadcast and cleans up immediately, or reconciles at the next timer tick — either way it does not keep operating with stale `userCred` after a peer tab has logged out.
- **Attack-surface parity.** Any same-origin JS can connect to the `BroadcastChannel` and request the ciphertext. That is identical to the existing threat model: same-origin JS was already trusted with `userCred` at runtime. The channel is not a new exposure; it is the same exposure on a different wire.

**Residual risks (explicit)**

1. **XSS with script execution in the Quick Crypt origin remains game-over for that tab's session.** An attacker with JS execution can call `decrypt()` with the non-extractable key themselves and read `userCred` during the attack window, or connect to `BroadcastChannel` and request the ciphertext. What this design prevents is exfiltration of the raw key bytes to another origin or device — the attacker's leverage is bounded to "what they can do inside this tab while running."
2. **Operation-window in-memory exposure remains.** During an active encrypt / decrypt, raw `userCred` sits in `_userCred` on the cipher instance for the operation's duration. The existing `_purge()` hook already zero-fills on stream finish / error; pairing it with zero-fill at every operation boundary keeps the window as narrow as possible. This window is actually **narrower** than the current design, because `userCred` is no longer held in memory for the whole session — it is decrypted on demand and re-zeroed after each use.
3. **Browser-profile theft while tabs are open.** If the attacker captures `sessionStorage` (possible if the browser has flushed tab state to disk for crash recovery) *and* the IndexedDB key simultaneously, they can decrypt `userCred`. "Attacker has live filesystem access to the profile" remains out of scope — same as before.
4. **Browser-profile theft after all tabs closed.** This is the case the new design specifically addresses: `sessionStorage` is gone, so the attacker gets only the orphan IndexedDB key, which decrypts nothing. A material improvement over the `localStorage` variant.
5. **Privacy-mode / ITP eviction.** Incognito windows wipe `sessionStorage` and IndexedDB on close; Safari ITP wipes IndexedDB for origins with no user interaction after ~7 days. In these cases the app falls back to a fresh passkey ceremony, matching current behavior for affected users.
6. **Mobile background suspension.** On mobile, the OS may freeze backgrounded tabs. A frozen peer tab will not respond to `BroadcastChannel` requests, so a newly opened tab re-auths rather than hand off. Correct failure mode; same trade-off as any cross-tab coordination scheme.

**Out-of-scope / follow-up considerations**

- **Migration.** Users already authenticated when this ships have an old-style session with no wrapped blob and no wrap key. Simplest path is a one-shot re-auth at the next session boundary — stripping `userCred` from `/session` forces this naturally because the old client has nowhere to store the wrap key yet. Alternative: keep `/session` returning `userCred` for one release cycle while clients adopt the new flow, then remove.
- **Multi-user / multi-account on the same origin.** The fresh-key-per-login discipline plus logout fan-out together ensure a second user on the same browser never inherits the first user's wrap key or ciphertext. The key to check during implementation: that the login flow's "generate fresh key and overwrite IndexedDB entry" happens *before* any write of new `{iv, ciphertext}` to `sessionStorage`, so there is never a moment where a new ciphertext could be paired with a stale key. The AEAD AAD binding to `userId` is the additional crypto-level guarantee that closes the cross-user corruption class (see rationale above).

**Staged implementation plan**

The design has several independently-testable pieces. Implementing them in stages lets each be verified in isolation and keeps the blast radius of any one change small.

- **Stage 1 — single-tab wrap + refresh-restore.** Wrap `userCred` with a fresh non-extractable AES-GCM `CryptoKey` on login, store `{iv, ciphertext, userId}` in `sessionStorage` and the `CryptoKey` in IndexedDB, decrypt on-demand with AAD=`userId`, zero-fill after use. Remove `userCred` from the `GET /v1/session` response in the same stage so the dependency is actually broken (not merely optional). Success criteria: refreshing a tab does not require re-auth and does not call `/session` for `userCred` recovery. No cross-tab coordination yet; opening a second tab still forces re-auth. Existing logout path is extended to clear `sessionStorage` and delete the IndexedDB key.
- **Stage 2 — `BroadcastChannel` cross-tab ciphertext handoff.** Add the BC request/response protocol with two-sided `userId` verification. Success criteria: opening a second tab restores session via BC handoff instead of re-auth; a tab signed in as user X does not respond to a request from user Y, and vice versa. Add the Web Lock coordination to prevent the two-tabs-opened-simultaneously double-prompt race.
- **Stage 3 — `BroadcastChannel` logout fan-out + timer-loop backstop reconciliation.** Add the BC `logout` message and the periodic server-session reconciliation in the existing timer loop so a missed broadcast is recovered at the next tick. Success criteria: logging out in one tab clears session state across all peer tabs; a tab that was frozen during the broadcast still reconciles on unfreeze.

### M2. (fixed in v7) Static hint/signing key per user — (key, random IV) reuse risk

**Where (V6):** `libs/crypto/src/lib/ciphers-current.ts` — V6's hint and signing keys were derived via `sodium.crypto_kdf_derive_from_key` with `userCred` as the only master input and fixed `instance`/`purpose`, making both keys a pure function of `userCred`.
**Impact:** Every V6 encryption a user performed used the same hint‑encryption key. For AES‑GCM with random 96‑bit IVs, collision probability becomes non‑negligible at ~2^32 operations (~4 billion encryptions of hints for a single user). Signing key reuse is acceptable for HMAC‑like MACs but still means one key compromise unlocks verification across all V6 ciphertexts that user ever produced.

**Fix applied (V7):** Key derivation moved to `libs/crypto/src/lib/keys.ts`. In `PWDKeyProvider._genDerivedKey`, the V7 branch pre‑mixes the per‑message salt into the KDF master: `mixedKey = sodium.crypto_generichash(cc.KEY_BYTES, slt, master)` before `crypto_kdf_derive_from_key`. Because `slt` is fresh per encryption, the hint cipher key (`_genHintCipherKeyAndIV` → purpose `"Hint_Key"`, instance 1) and signing key (`_genSigningKey` → purpose `"Sign_Key"`, instance 1) are now per‑ciphertext, and block keys (`_genBlockCipherKey` → purpose `"Blck_Key"`) are also salt‑bound. V6 still uses the old unsalted derivation when decrypting existing ciphertexts.

### M3. (fixed in v7) Identical IV across derived keys in block0 of V6

**Where (V6):** `libs/crypto/src/lib/ciphers-current.ts` — V6's `encryptBlock0` used the single random `iv` for both the hint encryption (`hk`) and the payload encryption (`ek`):
```ts
const iv = randomArray.slice(cc.SLT_BYTES, cc.SLT_BYTES + ivBytes);
encryptedHint = await EncipherV6._doEncrypt(eparams.alg, hk, iv, hintBytes);
const encryptedData = await EncipherV6._doEncrypt(eparams.alg, this._ek, iv, clearBuffer, additionalData);
```

**Impact (for completeness):** Using the same IV with two distinct keys is safe in the single‑user/single‑message sense for AEAD — it does not produce the classic "nonce reuse with the same key" break. However:
- It violates the "unique nonce per (alg, key) space" hygiene rule.
- For XChaCha20‑Poly1305 and AEGIS‑256 with large IVs (24 and 32 bytes) it is defensively fine; for AES‑GCM it offers no extra margin.
- Analytical fragility: if one of the derived keys (hk) ever leaks, an attacker learns the exact IV used for the other encryption — this is generally acceptable but narrows the distance to a real break if another flaw is introduced downstream.

**Fix applied (V7):** In `libs/crypto/src/lib/keys.ts`, `_genHintCipherKeyAndIV` now returns a distinct hint IV derived from the data IV via a labeled KDF step: `_genDerivedKey(baseIV, "Hint_Key", 2)` (with the same V7 salt‑mixing as M2). In `EncipherV7.encryptBlock0`, the hint is encrypted under `hIV` and the payload under the original random `iv`, so the two encryptions use different nonces. V6 continues to return `baseIV` unchanged for backward compatibility.

### M4. (moved) — legacy `/recover` userCred‑in‑URL promoted to **H5**

This finding was promoted to the High section on further reflection: logs and `Referer` retention make this a direct route to long‑term `userCred` disclosure, which is account‑takeover grade rather than merely hygienic. See H5.

### M5. (fixed at `/auth/options`; second-leg leak at `/auth/verify` — see sub-finding) User enumeration

**Where:** `apps/server/src/server.ts` — `postAuthOptions` returns `allowCredentials` when a `userId` is present; `postAuthVerify` has distinguishable error paths.
**Impact:** A response that differs (empty vs populated) on a submitted `userId` lets an attacker confirm `userId` existence. Mitigated by 128‑bit `userId` entropy (not practically enumerable), but leakage of `userId` from other vectors (logs, referrers, recovery mnemonics sent over insecure channels) is confirmable here.
**Fix:** Always return a plausible non‑empty `allowCredentials` list (mix in random dummy credentialIds) when the `userId` is unknown, or reject with a generic 400 for unknown users at the same response time.

#### M5b. (fixed) Second-leg enumeration via `/auth/verify`

Even with the `/auth/options` dummy-credentials mitigation in place, `/auth/verify` was distinguishable. After calling `/auth/options` with a guessed `userId`, an attacker could forge an `AuthenticationResponseJSON` that echoes the `userId` back in `response.userHandle` and sends a bogus signature. Three distinguishers fell out of the existing code paths:

1. **Response body.** `postAuthVerify` threw `AuthError()` (default message `"not authorized"`) on `byCredId` miss and on `userHandle` mismatch, but `AuthError('invalid authorization')` on `verifyAuthenticationResponse` exceptions against a real credential. `makeResponse(err.message, 401)` serializes the message verbatim.
2. **Status code.** `@simplewebauthn/server`'s `verifyAuthenticationResponse` **returns `{verified: false}`** (doesn't throw) when the ECDSA signature check fails — other pre-signature failures throw. The server was forwarding that `{verified: false}` as an HTTP 200 response. So a real `userId` + bogus signature returned **HTTP 200 `{verified: false}`**, while a dummy `userId` returned **HTTP 401 `"not authorized"`**. Status code differed.
3. **Timing.** The real-credential path runs an extra DynamoDB `GET` (`getUnverifiedUser`) plus the full ECDSA verification inside `verifyAuthenticationResponse`. The dummy-credential path exited at the `byCredId` miss. The real-cred path was ~one DDB round-trip (5–10 ms) plus ~1–5 ms of crypto slower — enough to distinguish with modest sampling against a Lambda endpoint.

**Fix applied** (`apps/server/src/server.ts`):
- **Unified error body.** `throw new AuthError('invalid authorization')` in the `verifyAuthenticationResponse` catch block was changed to `throw new AuthError()` so both branches return the identical `"not authorized"` body.
- **Soft-failure converted to throw.** After `verifyAuthenticationResponse` returns, `if (!verification.verified) throw new AuthError();` converts the library's soft `{verified: false}` return into the same 401 the miss path returns, closing the status-code distinguisher. Legitimate clients never hit `verified: false` (the browser rejects before sending anything), so this path only affects the forged-assertion attack.
- **Matched work on the miss path.** On `byCredId` miss, the code now calls `getUnverifiedUser(<hardcoded never-resolving userId>)` and `verifyAuthenticationResponse(..., credential: { publicKey: randomBytes(77), ... })` before throwing. Both calls fail (userId doesn't exist; garbage publicKey fails COSE parse), but they still pay the DDB round-trip and the library's pre-signature setup cost against the attacker's actual payload. The remaining ~3 ms gap (real ECDSA verify vs parse-fail on the miss path) is below typical WAN jitter.
- **Why not a hand-encoded COSE key with real curve coordinates.** An earlier draft of the patch generated a throwaway ES256 keypair at cold start and hand-encoded a valid COSE key so the library would reach the actual ECDSA verify on the miss path and close the ~3 ms gap completely. That adds ~25 lines of CBOR encoding and cold-start keygen for a gap that is already below the remote-timing noise floor; the simpler version was judged the better trade-off.
- **Why not a randomized sleep.** Static sleep ranges drift as AWS rotates Lambda hardware — a range calibrated today becomes mis-matched next year, and the fixed component can be statistically subtracted. Matched work using the same DDB + library primitives tracks hardware scaling automatically, no calibration required.

**Tests.** `apps/server/spec/dummy-auth.spec.ts` — `auth/verify response parity` covers both legs: (a) two independent unknown `userIds` produce identical status and body, and (b) a real `userId` with a forged signature produces identical status and body as an unknown `userId` (skipped on `QC_ENV=prod` since no real test user exists there).

### M6. (moved) Internal admin endpoints — reclassified as L12

On closer review, the phrase check is layered on top of two stronger controls (private `/v0/*` routing + AWS account boundary) and does not meaningfully raise the bar against an attacker who already has AWS account access. See L12.

### M7. (won't fix) CLI accepts secrets via command‑line flags

**Where:** `apps/cli/src/cli.ts` — `--cred` / `-c` and `--pwds` / `-p` flags accept the userCred and passwords on the command line.
**Impact:** Command arguments are visible via `/proc/*/cmdline`, shell history, and process accounting. Pasting a userCred URL with the credential as a query string (the `new URL(credText).searchParams.get('usercred')` convenience code path) leaks to history.
**Fix:** Prefer stdin/tty prompts (already supported). If flags stay, document the risk prominently, zero argv after consumption (`process.argv[...] = '•'`), and refuse `--pwds` in non‑silent mode. Consider reading userCred from an env var or file path rather than a raw flag.

### M8. (fixed) No global session‑invalidation lever; cookies forgeable from DB dump + `jwtMaterial`

**Where:** `apps/server/src/server.ts` — `getSessionKey` at `server.ts:1540`; `setupJwtMaterial` at `server.ts:205`.

**What:** Session signing keys are `HKDF(userCredEnc || jwtMaterial, salt=userId, info=purpose+authCount)`. `userCredEnc` is the ciphertext bytes straight from DynamoDB — it is used as HKDF input without ever going through KMS decrypt. `jwtMaterial` is obtained once per Lambda cold start by KMS‑decrypting `process.env.EncMaterial`. Two consequences:

1. **Cookie forgery requires two things, not one.** Attacker needs (a) a DynamoDB dump (for `userCredEnc`, `userId`, `authCount`) and (b) `jwtMaterial` — which in turn requires either KMS `Decrypt` on the EncMaterial key, or direct Lambda process memory. Neither alone is sufficient. This is the "password" factor: KMS is a genuine second control.
2. **No proactive fleet‑wide revocation lever.** If `jwtMaterial` is ever suspected compromised, the only way to invalidate outstanding sessions today is to rotate `jwtMaterial` itself, which also breaks forensic re‑derivation of historical keys and is disruptive. There is no throwaway "session epoch" knob.

**Impact:** Scenario‑specific rather than systemic. A single control breach (DB snapshot leak, or KMS policy mistake, or Lambda role compromise) does not by itself produce cookie forgery — but combined breaches do, and there is no fast way to cut the blast radius short of rotating the underlying KMS material.

**Fix (per user preference):** Add a `SessionVersion` Lambda environment variable and include it in the HKDF `info`:
```ts
info: `${purpose}:${user.authCount}:${process.env.SessionVersion ?? '0'}`
```
Bumping `SessionVersion` and redeploying instantly invalidates every outstanding session globally (forces all users to re‑login) without touching KMS or `jwtMaterial`. Cheap, reversible, fits an incident response playbook. Pair with the per‑user `authCount` bump on logout (see L1) so individual revocation remains possible without a global nuke.

---

## LOW / INFORMATIONAL

### L1. (fixed) No server‑side session revocation on logout

**Where:** `apps/server/src/server.ts` — `deleteSession` at `server.ts:272`; session keys re‑derived in `getSessionKey` at `server.ts:1540`.

**Observation:** Session signing keys are a pure function of `userCredEnc`, `userId`, `jwtMaterial`, and `authCount`. Only `authCount` is variable at runtime, and it is incremented **only on a new successful login** — `deleteSession` clears `lastCredentialId` and tells the browser to drop the cookie, but does not bump `authCount`. Any cookie still within its 3‑hour `exp` therefore keeps validating after "logout", and — while it does — `GET /v1/session` will keep returning `userCred` (see M1). Cookie theft (malware reading the cookie jar, briefly borrowed laptop, scoped XSS) is the realistic attack; logout gives the user no real defence against it.

**Fix:** Bump `authCount` inside `deleteSession` so the prior cookie's signing key becomes unrecoverable. One‑line change; acceptable that it invalidates every device the user is logged in on, since re‑login is a single passkey ceremony. (For global invalidation across all users, see M8's `SessionVersion` suggestion.)

### L2. (no fix) Terminal flag + MAC chain in V6 — good

`EncipherV6` sets a terminal flag on the last block and MAC‑chains every block via the prior block's MAC. This correctly prevents truncation and block reordering/splicing. V4 (legacy, in `deciphers-old.ts`) lacks the chain — not exploitable without the signing key, but worth retiring old V4 ciphertext support once feasible.

### L3. (no fix) Key zeroization on purge — good

Master/cipher keys are overwritten with `crypto.getRandomValues` on purge. JS engine cannot fully guarantee no copies, but the intent is correct.

### L4. (no fix) MAC equality uses `sodium.memcmp` — good

Constant‑time verification of block MACs. Same pattern should be applied in `verifyCsrf`, `postRecover`, `postRecover2` (H1/H2).

### L5. (won't fix) `sanitizeString` double‑pass (FilterXSS + tag strip) — reasonable

`sanitizeString` in `apps/server/src/utils.ts` uses empty‑whitelist `xss` and then strips remaining angle brackets. Good defense in depth for usernames/descriptions, but validate max lengths *before* sanitization too (a sanitizer that shrinks input can make a "too long" check inconsistent with what gets stored).

### L6. (fixed) Challenge TTL and scoping

`Challenges` entity has a 5‑minute TTL — appropriate. Once C1 is fixed, consider also consuming the challenge atomically (delete‑on‑read) to prevent replay within the 5‑minute window.

### L7. (reduced to 1 hour) `apps/web/server.ts` cache policy

Static assets are served with 1‑year immutable caching, which is correct for hashed bundles. `index.html` is served by the nonce Lambda (`apps/server/src/nonce/lambda_function.py`) with `Cache-Control: public, max-age=86400` — see H3 for the resulting nonce‑reuse window and suggested shorter TTL.

### L8. (wont fix) JWT algorithm is HS512 with symmetric secret

Server‑side symmetric signing is fine for a single‑origin API, but rotation is all‑or‑nothing. Consider a two‑key rolling scheme (accept N and N‑1, sign with N) so compromise response doesn't force mass re‑auth.

### L9. (wont fix) PBKDF2 minimum iteration count (420,000) and default (1,000,000)

`libs/crypto/src/lib/cipher.consts.ts`. Values are in line with current OWASP guidance for PBKDF2‑SHA512. Ongoing review advised — no action today.

### L10. (wont fix, don't care if people DOS themselves) Armor parsing uses `decodeURIComponent` / `JSON.parse`

`libs/crypto/src/lib/armor.ts`. Input is attacker‑controlled ciphertext. Both APIs can throw; callers correctly wrap in try/catch. Large/adversarial inputs should be length‑bounded before parsing to avoid memory pressure on the CLI/web client.

### L11. (no fix) `getInvitables` is a capability‑URL lookup (by design; documented here for clarity)

**Where:** `apps/server/src/server.ts:1119` — `getInvitables` (GET `/v1/invitables/:invid`):
```ts
const invitables = await Invitables.query.byInvitableId({ invitableId }).go();
```

**Observation:** The endpoint is marked `authorize: true` but the query is keyed solely by the URL‑supplied `invitableId` — `verifiedUser.userId` is not part of the lookup. The response exposes the **creator's `userName`** (stored in `description`, set at `server.ts:653`). This is deliberate: invitables are the sender‑link sharing primitive, so the expected flow is "user A looks up user B's invitable in order to encrypt‑to‑username." Scoping by `verifiedUser.userId` would break that use case — `loadInvitables` already handles the "list my own invitables" path and is correctly scoped.

**Why it is safe as‑is:**
- Invitable IDs are 128 random bits (`cc.INVITABLEID_BYTES = 16`), allocated via `GenerateRandomCommand`, with a retry loop on collision — online enumeration is infeasible.
- The endpoint requires a valid session, so only authenticated users consume capacity (authentication here acts as a rate/cost limiter, not as an authorization check on the target data).
- The only data returned is `{ invitableId, description }`; no ciphertext, user credentials, or authenticator data.

**Recommendation (documentation‑level, no code change required):**
- Add a code comment at the handler noting that this is an intentional capability lookup and that auth is a rate‑limiter rather than an ownership check, so a future reader is not tempted to "fix" it by adding a `userId` filter that would break sender links.
- Optionally, separate the route pair for clarity: `GET /v1/invitables/:invid` (capability lookup, current behaviour) vs `GET /v1/me/invitables` (own‑list, currently served via `loadInvitables` inside other responses). Purely hygienic.
- If `getInvitables` is ever changed to return more than `{ invitableId, description }`, re‑evaluate this finding — additional fields would need explicit unlinkability review.

### L12. (accepted risk) Internal `/v0/*` endpoints authorized via a KMS‑encrypted sentinel phrase (defence‑in‑depth only)

**Where:** `apps/server/src/server.ts:135` — `INTERNAL_PHRASE = "Yup, I'm internal"`; internal authorizer accepts callers whose header ciphertext decrypts (via KMS) to this value.

**Observation:** This check is layered on top of two stronger controls that the security posture actually relies on:
1. **Network boundary.** Internal routes use `version: INTERNAL_VERSION` (`/v0/*`) and are not mapped in CloudFront, so they are unreachable from the public internet. Only direct Lambda / API Gateway invocation inside the AWS account can hit them.
2. **AWS account boundary.** Producing a valid ciphertext requires KMS `Encrypt` on the phrase key; decrypting it server‑side requires the Lambda's KMS `Decrypt`. An attacker at the AWS account level has enough privilege to bypass the Lambda entirely and read/write DynamoDB / KMS directly — "trash or steal whatever they want" is trivially possible without any Lambda interaction. The phrase check therefore does not raise the bar for that attacker.

Because the phrase itself is in the (open‑source) code, it is not confidential — the only thing the check verifies is that the caller possessed an appropriate KMS key at some point. That is defence‑in‑depth against an operator accidentally exposing the `/v0/*` routes via CloudFront misconfiguration, not a primary auth control.

**Status:** Accepted risk in the pre‑E2E threat model. Until payload ciphertext is end‑to‑end encrypted against the user's key (so the server cannot read it), an attacker with AWS account access already has full read/write on user data via DynamoDB — further gating the Lambda does not move the needle.

**Optional hardening if ever desired:** Replace the phrase check with IAM / SigV4 on the internal routes (admin role only) so the control at least surfaces caller identity in CloudTrail. Low priority given the above.

---

## Streaming cipher wrapper (`libs/crypto/src/lib/cipher-streams.ts`, `ciphers.ts`) — focused review

The streaming layer is a thin wrapper over `EncipherV6` / `DecipherV{1,4,5,6}`. Overall it looks correct, but three items worth calling out:

### S1. (no fix, V4 is no longer created) Version dispatch precedes MAC validation

**Where:** `ciphers.ts` — `streamDecipher` peeks the first `HEADER_BYTES_6P` bytes, reads `verOrAlg = bytesToNum(header[MAC_BYTES .. MAC_BYTES+VER_BYTES])`, and chooses `DecipherV1 / V4 / V5 / V6` before any MAC check. The MAC check then happens inside the chosen decipher against the signing key derived from the user's `userCred`.

**Risk:** Because the signing key is a deterministic KDF of `userCred` (see M2), the same user's userCred can authenticate a ciphertext under *any* version's framing. An attacker can therefore force a victim's client down the V1/V4/V5 code path by handing them a ciphertext in those framings. V4 specifically lacks the inter‑block MAC chain (confirmed in `deciphers-old.ts`), and V1 uses HMAC‑SHA256 rather than the current MAC construction. If any of the legacy decipher paths has a parsing bug (e.g. length confusion, truncation, hint handling), that bug remains reachable forever even though nobody encrypts at those versions anymore.

**Fix options:**
- Fast‑fail on legacy versions unless the user has an explicit "allow legacy decrypt" flag, or unless the ciphertext carries an AD tag indicating it was produced by this user's prior client.
- Add a "minimum accepted version" per user, stored server‑side and included in the session payload.
- Retire V1/V4 decode once call‑site telemetry shows no real traffic.

### S2. (fixed for exceptions, close handler not valid) Cipher state / key material not purged on stream error

**Where:** `cipher-streams.ts` — `pull(controller)` in both enc and dec wraps body in try/catch and calls `controller.error(err)`. The `EncipherV6` / `DecipherV6` instance (and its derived `_ek`, `_sk`, etc.) remains reachable from the closed stream until GC. `purge()` / overwrite paths exist in the cipher classes but aren't invoked here.

**Impact:** Low. An attacker who can pause GC or read freed memory can recover message‑level keys. Realistic in a browser process only via co‑resident exploitation.

**Fix:** In the `catch` block (and on `controller.close()` for enc), call the encipher/decipher's purge/clear method so keys are overwritten deterministically before the object becomes unreachable.

### S3. (fixed) Recursive nested‑loop decryption reads lp from ciphertext

**Where:** `decryptStream` re‑enters itself while `cdInfo.lp > 1`. `lp` is pulled from the authenticated AD of the first block — good — and `LP_MAX` is enforced on encryption. On the decrypt path `cdInfo.lp` is not re‑validated against `LP_MAX` before recursing.

**Impact:** Very low. `lp` is AEAD‑authenticated, so a forged value is rejected at MAC check. But a belt‑and‑braces assert of `cdInfo.lp <= LP_MAX` in `decryptStream` before recursing prevents any future KDF/encoding change from accidentally enabling runaway recursion.

### S4. (fixed) Host‑header trust in `apps/web/server.ts` — **RESOLVED (scaffold removed)**

> **Status:** The SSR scaffold (`apps/web/server.ts`, `apps/web/src/main.server.ts`, `apps/web/src/app/qcrypt.config.server.ts`) has been deleted along with its `@angular/ssr` / `@angular/platform-server` / `@types/express` dependencies and the `serve:ssr:web` script. The host‑header trust concern no longer has a landing site in the repo. If SSR is reintroduced in the future, any new request→URL construction should bind to a fixed canonical origin from env (`QCRYPT_CANONICAL_ORIGIN`) or validate `headers.host` against an allow‑list rather than trusting the incoming `Host`.

---

## SSR / CSP / WAF / deploy config — what's in repo vs not

What the repo contains:
- `apps/web` — static SPA build (`@angular/build:application` with `ssr: false, prerender: false`) out of `dist/web/browser`. No Node/Express server sits in front of the browser code.
- `apps/server/src/nonce/lambda_function.py` — Python Lambda that serves `index.html` / `maintenance.html` from S3 through CloudFront, rewriting a sentinel token with a fresh 128‑bit nonce and injecting a `Content-Security-Policy` response header that includes per‑render `sha384` hashes of every inline `<script>` / `<style>`. See H3 for the cache‑window caveat; the sentinel `ngCspNonce="ew26COJKMG8qrA/bjTcl0w=="` in `apps/web/src/index.html` is this Lambda's match target, not a leaked production nonce.
- The Python Lambda is the only place CSP is set. HSTS / `X‑Frame‑Options` / `Referrer‑Policy` / `Permissions‑Policy` must come from a CloudFront response‑headers policy (not in repo — see below).
- CI: CodeQL workflow present (`.github/workflows/codeql.yml`) using default (non‑extended) query pack and "javascript-typescript" / "actions" languages. Consider enabling `security-extended` for more coverage.

What the repo does **not** contain — requires out‑of‑repo verification:
- CloudFront distribution config, response‑headers policy, or functions (where CSP/HSTS/etc. would live for a static SPA).
- API Gateway configuration, usage plans / throttling (where rate limits for the Lambda endpoints would live — see H6).
- AWS WAF rules (e.g. rate limiting, geoblocking, managed rule sets).
- IAM policies on the internal‑authorizer Lambda (to determine whether M6's "secret phrase" is the only control or if IAM also restricts callers).
- KMS key policies on `KMSKeyId_New` / `KMSKeyId_Old` (who can `kms:Decrypt` — compromise scope).
- DynamoDB point‑in‑time recovery settings (backup/forensics).
- S3 bucket policy for the SPA origin (access logging, public‑read scoping).
- Logging/observability retention & PII scrubbing (relates to H5 — does the access log pipeline strip the URL path before archiving?).
- Domain/TLS config — HSTS preload listing, TLS 1.2+ enforcement, OCSP.

**Recommended follow‑up**, since the app's effective defence posture lives in these configs:
1. `curl -I https://quickcrypt.org/` and `curl -I https://quickcrypt.org/index.html` — confirm CSP, HSTS, XFO, Referrer‑Policy, CT, Permissions‑Policy, cache control.
2. `aws cloudfront get-response-headers-policy` for the distribution.
3. `aws wafv2 list-web-acls` and inspect rules on the API Gateway / CloudFront distribution.
4. `aws apigateway get-usage-plans` (throttle bursts/limits) for the v1 stage.
5. `aws kms get-key-policy` for both KMS keys — confirm only the Lambda role has `kms:Decrypt`.
6. `aws logs describe-metric-filters` / any alarms on 4xx spikes at `/v1/auth/*`, `/v1/recover*`, `/v1/reg/*` (detect H6 brute‑force if rate limits aren't already set).
7. Once the infra configs are reviewed, fold the results into this report.

---

## Summary of Priority Fixes

1. ~~**C1** — Bind challenges to `userId`; make `/v1/passkeys/verify` ignore `body.userId`.~~ **Fixed** (see C1 status note).
2. **H1, H2** — Replace `!==` secret comparisons with constant‑time comparisons in `verifyCsrf`, `postRecover`, `postRecover2`.
3. **H3** — Shorten `Cache-Control: max-age` on the nonce Lambda response (or move nonce injection to the viewer‑response path) to shrink the cache‑window nonce‑reuse exposure. Optionally drop `'nonce-…'` from `style-src` if Angular's runtime styles can be fully hash‑listed. (SSR scaffold cleanup — previously fix #4 — is done.)
4. ~~**H4** — Use `verifiedUser.userId` in `postPasskeyVerify`.~~ **Fixed** (see H4 status note).
5. **H5** — Retire legacy `/v1/users/{userid}/recover/{usercred}`; scrub historical logs; rotate `userCred` for any account that used it.
6. **H6** — Add WAF/API‑GW rate limits on auth, recover, reg endpoints.
7. **M1** — Stop returning `userCred` from `GET /v1/session`; ship the at-rest client-encryption flow (non-extractable AES-GCM key in IndexedDB + wrapped ciphertext in per-tab `sessionStorage` + `BroadcastChannel` handoff for cross-tab continuity) so refresh and new tabs work without re-auth while avoiding indefinite orphan state on disk. Logout fans out over both `BroadcastChannel` and the existing session-expiry timer loop. Full design documented under M1.
8. ~~**M2, M3** — Per‑message derivation for hint/signing keys; distinct IVs for hint vs data.~~ **Fixed in V7** (`libs/crypto/src/lib/keys.ts`: salt‑mixed KDF master + labeled hint‑IV derivation).
9. **M7** — Discourage `--cred`/`--pwds` CLI args; prefer tty/stdin.
10. **M8** — Add `SessionVersion` Lambda env var into the session HKDF `info` so there is a cheap global session‑invalidation lever.
11. **L1** — Bump `authCount` on `deleteSession` so logout actually revokes the cookie server‑side.
12. **L11** — Document that `getInvitables` is a capability‑URL lookup (intentional; included for clarity).
13. **L12** — Accepted risk: internal `/v0/*` phrase check is defence‑in‑depth behind network + AWS account boundaries.

The overall cryptographic design (AEAD + MAC‑chained blocks, user‑bound KDF, PBKDF2 parameters, constant‑time MAC checks, key zeroization) is sound. The highest‑value fixes are on the **server authentication protocol** (challenge binding, constant‑time compares, session userCred exposure) rather than in the cipher library itself.

---

## Coverage Notes (what was / wasn't deeply inspected)

**Read in depth:**
- `apps/server/src/server.ts` (all routes, auth/challenge/session/recover flow, internal authorizer)
- `apps/server/src/internal.ts`, `apps/server/src/models.ts`, `apps/server/src/utils.ts`, `apps/server/src/urls.ts`, `apps/server/src/consts.ts`
- `apps/server/API.md`, `apps/server/AGENTS.md`, `apps/server/hybrid.md`
- `libs/crypto/src/lib/ciphers-current.ts` (V6 encipher/decipher), `libs/crypto/src/lib/ciphers.ts` (version dispatch + `latestEncipher`/`streamDecipher`), `libs/crypto/src/lib/cipher-streams.ts` (streaming wrapper), `libs/crypto/src/lib/deciphers-old.ts` (V1/V4/V5), `libs/crypto/src/lib/cipher.consts.ts`, `libs/crypto/src/lib/armor.ts`
- `apps/web/src/app/services/authenticator.service.ts`, `apps/web/src/app/services/cipher.service.ts`, `apps/web/src/index.html`, `apps/web/src/main.ts`, `apps/web/src/app/qcrypt.config.ts`, `apps/web/project.json`, `apps/web/AGENTS.md` (the SSR scaffold `apps/web/server.ts` / `main.server.ts` / `qcrypt.config.server.ts` was reviewed but subsequently removed; see S4 status)
- `apps/server/project.json`, `.github/workflows/{codeql,new-version,playwright}.yml`
- `apps/cli/src/cli.ts`
- Root `AGENTS.md`, `SECURITY.md`

**Skimmed (likely additional review value):**
- `libs/api/src/server.ts` (client SDK; behaviour exercised via `authenticator.service.ts`, which was reviewed)
- Angular route components (`welcome`, `newuser`, `recovery2`, `qcrypt.component`) — UI layer; XSS/DOM‑sink risks there not individually walked
- Test suites

**Out of repo (must be reviewed against AWS account state):**
- CloudFront distribution + response‑headers policy / functions
- API Gateway config / usage plans / stage settings
- AWS WAF rules
- IAM policies (Lambda execution role, internal‑authorizer)
- KMS key policies (`KMSKeyId_New`, `KMSKeyId_Old`)
- DynamoDB settings (PITR, backups)
- S3 bucket policy for SPA origin
- Log retention / PII scrubbing for access logs
- TLS / HSTS preload registration

See the "SSR / CSP / WAF / deploy config" section above for a suggested verification checklist (curl headers, AWS CLI commands).
