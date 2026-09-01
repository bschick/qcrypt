# Quick Crypt — Security Review Findings

**Reviewer model:** Fable (entire review; no Opus fallback).
**Date:** 2026‑07‑19.
**Scope:** design + implementation of the Angular web client (`apps/web`), the AWS
Lambda server (`apps/server`), the shared crypto library (`libs/crypto`), and the
shared API/proof library (`libs/api`). Emphasis, per request, on the new PRF additions:
client‑side generated `userCred`, proof‑of‑user‑credentials (`x‑proof`), and
proof‑of‑recovery‑secret. **Authentication & authorization** and **cryptography** are
reported as separate tracks.

**Method:** static source + protocol/API design review, cross‑referencing the V7
protocol (`apps/web/src/assets-src/main.tex`), the API spec (`apps/server/API.md`), and
the implementation line‑by‑line. Behavioral evidence: `nx test crypto` (124/124 pass)
and `nx test api` (11/11 pass) were run green in this environment; server/e2e suites
that need an emulator/backend were read, not executed. No attacks were run against the
live production service. The prior `SECURITY_REVIEW.md` was used only as an additional
checklist; its still‑relevant items are re‑verified in a dedicated section below.

---

## 1. Executive summary

**Quick Crypt's security posture is strong, and materially stronger than at the time of
the prior review.** The historical critical/high issues (cross‑account passkey binding,
non‑constant‑time secret compares, `userCred` in the `/session` response, `userCred` in
a URL path) are all fixed in the current tree, and the new PRF architecture removes the
server from the trust base for accounts that use it. The design meets its stated
confidentiality/integrity/authenticity goals for the threat models a personal‑storage
tool must resist, and several constructions are above the bar for comparable tools.

**No Critical, High, or Medium findings were identified in this review.** The most
significant items are:

- **Low–Medium (auth):** the proof replay‑nonce store **fails open** on any non‑duplicate
  DynamoDB error, silently disabling replay protection for state‑changing requests during
  a DB fault.
- **Low (auth, compliance):** the proof timestamp skew is `180 s` in code
  (`consts.ts:53`) but `60 s` in the protocol spec (`main.tex`) — a 3×‑wider acceptance
  window than documented.

The remainder are Low/Informational: the inherent no‑PRF fallback asymmetry (server can
forge proofs / read `userCred` for server‑managed accounts), a still‑mounted legacy
`/v1/recover` body path, a defense‑in‑depth `hostname` constraint that is defined but not
wired up, a WebAuthn options/verify user‑verification inconsistency (UV *is* enforced —
see A1), and the long‑standing legacy‑version decode surface. Data confidentiality does
**not** depend on any of these: the user's password is always an independent factor that
the server never receives.

The most valuable actions — fail the replay‑nonce store closed (A2) and align the proof
skew with the spec (A3) — **have since been applied** (along with A1 and the A9 path+query
binding). Each finding below carries a **Disposition** line with its current status;
everything not applied is accepted‑risk or by‑design.

---

## 2. Security model recap (for grounding the findings)

Understanding what protects what makes the severities below precise:

- **Stored ciphertext confidentiality** depends on the **password** (PBKDF2 input) *and*
  `userCred`. The server never receives the password, and never stores user ciphertext.
  So a full server compromise **cannot by itself decrypt user data**.
- **`userCred`** re‑derives the per‑message signing key, hint key, and (with the password)
  the cipher key, and is the seed for the ML‑DSA proof keypair. For **PRF accounts** the
  server holds only ciphertext of `userCred` (under the passkey PRF and under the recovery
  secret) plus the ML‑DSA *public* key — it cannot recover `userCred` or forge proofs.
  For **no‑PRF (server‑managed) accounts** the server holds `userCred` KMS‑encrypted and
  can both decrypt it and forge proofs.
- **Authorized API requests** require three independent factors: the `__Host‑JWT` cookie,
  the CSRF token, and a fresh ML‑DSA proof of `userCred` possession. Cookie theft alone is
  insufficient — even `GET /v1/session` (which mints CSRF) demands a valid proof.
- **Account recovery** requires either the recovery‑words secret (proved by an ML‑DSA
  signature the server verifies without ever seeing the secret) or, on the legacy path,
  the raw `userCred`.
- **Passkey ceremonies enforce user verification.** Both registration and authentication
  reject assertions whose `uv` flag is unset (the `@simplewebauthn` default,
  un‑overridden), so login and passkey enrollment require PIN/biometric/local unlock — not
  mere possession of the authenticator (see A1).

---

## 3. Strengths (novel or above expectation)

These are called out because they exceed what comparable personal‑encryption tools
typically implement. Routine good practices (HTTPS, `__Host‑` cookies, TTL'd challenges)
are not listed.

**Cryptography**

1. ~~**AEAD key commitment (`k_C`).**~~ **Withdrawn — this was not a strength.** V7 derived
   `k_C = KDF(_ek, "Cmit_Key")` from the message key and folded it into the AEAD associated
   data on both encrypt and decrypt. Because *both* parties derive it independently and it is
   never transmitted, there is nothing on the wire to compare it against: a wrong key changes
   the AEAD key and the folded value together, leaving the tag equation with the same single
   free block. It therefore did **not** close the partitioning-oracle or key-substitution
   weakness for AES-GCM or XChaCha20-Poly1305; under V7 only AEGIS-256 was key-committing, by
   its own native CMT-1 property. Confirmed by a GF(2^128) collision against the real
   decipher in `libs/crypto/src/lib/keycommit.spec.ts`. Protocol V8 replaces the fold with a
   32-byte commitment **stored with the ciphertext and compared before decryption**, which
   does close the class. See `vibes/keycommit_finding.md`.
2. **MAC‑before‑decrypt, done deliberately.** Block 0 verifies the keyed‑BLAKE2b MAC
   before any decryption (`ciphers-current.ts:1079-1084`, explicit "Doom Principle"
   comment), with the version bound into the MAC input and the signing key salt‑mixed from
   `userCred`. Constant‑time `sodium.memcmp` compare. Inter‑block MAC chaining plus a
   terminal flag prevent truncation and block reordering.
3. **Per‑message key separation.** V7 mixes the fresh per‑message salt into every derived
   key (signing/hint/block/commit) via a keyed‑BLAKE2b step before `crypto_kdf_derive_from_key`
   (`keys.ts:753-768`), so keys are per‑ciphertext rather than static per‑`userCred`, and
   the hint gets a distinct IV. (Both were prior‑review findings; confirmed fixed.)
4. **Post‑quantum proof primitive.** Proof‑of‑possession uses ML‑DSA‑65 (FIPS 204, via a
   vendored libcrux WASM build) with randomized/hedged signing and seeds zeroized after
   keygen (`libs/crypto/src/lib/proof.ts`).

**Authentication & authorization**

5. **Proof‑of‑user‑credentials as a genuine second factor over the cookie.** Every
   authorized request carries an ML‑DSA signature over `userId ∥ method ∥ path ∥ timestamp
   ∥ nonce ∥ SHA‑256(body)` (`libs/api/src/lib/proof.ts:39-59`, verified at
   `server.ts:1938-2003`). A stolen cookie is inert without `userCred`, and `GET
   /v1/session` requires the proof *before* it will issue a CSRF token — so a cookie‑only
   attacker cannot bootstrap the CSRF needed for other calls.
6. **Client‑side `userCred` (PRF accounts).** The browser generates `userCred`, ships the
   server only ciphertext it cannot read plus an ML‑DSA public key
   (`server.ts:543-561`, `API.md` "all‑or‑nothing" contract). This removes the server from
   the trust base for confidentiality *and* for proof forgery — a strong improvement over
   any server‑held‑secret design.
7. **Recovery by signature, not by secret.** `/v1/recover2` verifies an ML‑DSA signature
   over a single‑use server challenge (`server.ts:1708-1719`); the recovery secret and BIP‑39
   words never reach the server.
8. **Challenge binding + credential‑GSI identity.** Challenges are bound to a `purpose`
   *and* `userId` and atomically consumed (`_createAuthenticator` `server.ts:713-731`);
   authentication resolves identity from the credential‑id GSI and the signed assertion
   rather than the client‑supplied `userHandle` (`server.ts:343-387`). Together these close
   the two historical account‑takeover bug classes.
9. **At‑rest `userCred` protection in the browser.** A non‑extractable HMAC‑SHA‑512
   `CryptoKey` (`extractable:false`, `keystore.service.ts:158-165`) in IndexedDB derives
   `k_L`, which X20‑Poly1305‑wraps `userCred` (bound to `userId` as AAD) in per‑tab
   `sessionStorage`; cross‑tab continuity is a `BroadcastChannel` handoff of ciphertext
   only, matched on `pkId` at both ends (`broadcast.service.ts:191-211`). `userCred` is
   decrypted on demand and zeroized after each use (`authenticator.service.ts:347-363`).
10. **Enumeration resistance.** `/auth/options` returns deterministic dummy
    `allowCredentials` + timing jitter for unknown users; failure paths converge to a
    single 401 body (`server.ts:803-919`, `2079-2081`); a decoy WebAuthn verification runs
    on the credential‑not‑found path (`server.ts:349-372`). Dedicated `dummy-auth.spec.ts`
    and `fuzz.spec.ts` suites guard these.
11. **Session revocation levers.** The session key binds `lastCredentialId`, `authCount`,
    and a `SessionVersion` env value (`server.ts:1802-1823`); logout bumps `authCount` and
    clears `lastCredentialId` (`server.ts:283-303`), invalidating the cookie server‑side,
    and `SessionVersion` is a global cut‑over.

---

## 4. Weaknesses — Authentication & Authorization

### A1. (Informational) User‑verification options/verify inconsistency (UV *is* enforced)

**Disposition (2026‑07‑20):** Applied — options set to `'required'` and `requireUserVerification: true` passed to both verify calls.

**Where:** `registrationOptions` (`server.ts:1052-1055`) and `postAuthOptions`
(`server.ts:895-899`) set `userVerification: 'preferred'`, while
`verifyAuthenticationResponse`/`verifyRegistrationResponse` are called with **no**
`requireUserVerification` argument (`server.ts:398-404`, `735-741`).

**Assessment — not a weakness.** I initially flagged this as "UV not enforced," then
verified the library behavior: `@simplewebauthn/server` v13.3.2 defaults
`requireUserVerification = true` for **both** verify functions and throws "User
verification required, but user could not be verified" when the assertion/attestation
`uv` flag is absent (`verifyAuthenticationResponse.js:24,137`;
`verifyRegistrationResponse.js:35,118`). Because the server does not override that
default, **user verification is enforced at verification time** — a ceremony completed
without UV is rejected with a 401. The stated authenticity goal is therefore met: login
and passkey registration require PIN/biometric/local‑unlock.

**Residual (cosmetic) issue:** the ceremony *options* advertise `'preferred'` while the
server effectively requires UV. The only consequence is UX/robustness — an authenticator
that cannot do UV will pass the browser ceremony and then be rejected server‑side, rather
than being told up front. There is no security impact.

**Remediation (optional):** set `userVerification: 'required'` in both options builders so
the client and server agree, and (belt‑and‑braces) pass `requireUserVerification: true`
explicitly at both verify sites so the guarantee survives any future library default
change. Optionally assert `registrationInfo.userVerified === true` as well.

### A2. (Low–Medium) Proof replay‑nonce store fails open on DynamoDB error

**Disposition (2026‑07‑20):** Applied — the nonce‑store `catch` now sets `result = 'failed'`, so a non‑duplicate DynamoDB error fails **closed** on mutating requests.

**Where:** `verifyProof` (`server.ts:1979-1995`). For non‑GET requests the nonce is
inserted with a conditional put; a `rejected` result marks a replay, but any *other*
DynamoDB exception is logged and the request is **allowed through**:

```ts
} catch (err) {
   // This is a DynamoDB error caused by something other than a duplicate record
   // (likely load). Log the error, but do not block the request
   console.error(`proof nonce store error, allowing ${httpDetails.name} ...`, err);
}
```

**Impact:** Replay protection for state‑changing requests depends on DynamoDB
availability. During a DDB fault (throttling, partial outage), a captured, still‑valid
(`≤180 s`) authorized mutating request can be replayed. Reaching that state requires the
attacker to already possess a full valid authorized request (cookie + CSRF + a valid
proof) — i.e. a TLS interception or a header‑logging position — *and* a coincident DDB
error, which is why this is not High. But it is a deliberate availability‑over‑security
choice that silently removes a control exactly when the system is stressed.

**Remediation:** fail **closed** (return 401) on nonce‑store errors for mutating requests,
or degrade to a bounded in‑memory/ElastiCache nonce cache so the control survives DDB
faults. At minimum, alarm on the "allowing …" log so a fault window is visible.

### A3. (Low, compliance) Proof timestamp skew is 180 s in code vs 60 s in the spec

**Disposition (2026‑07‑20):** Applied — reconciled to **120 s** in both `consts.ts` (`PROOF_SKEW_MS`) and `main.tex` (`Δ`).

**Where:** `PROOF_SKEW_MS = 180 * 1000` (`consts.ts:53`); the protocol document specifies
`Δ = 60 seconds` (`main.tex`, Authentication Variables). `verifyProof` accepts
`|now − ts| ≤ 180 s` (`server.ts:1947`), i.e. a 360‑second window.

**Impact:** A design/implementation divergence and a wider‑than‑documented replay window.
For GET (no nonce check) a captured proof is replayable for up to ~360 s rather than the
~120 s the spec implies. Low risk (GETs are non‑mutating and still require the cookie and
a valid proof), but the spec and code should agree, and 60 s is comfortably enough for
legitimate clock skew.

**Remediation:** reduce `PROOF_SKEW_MS` to `60 * 1000` to match the protocol (it remains
well under the 300 s challenge/nonce TTL, preserving the no‑reopen invariant noted in the
`consts.ts` comment), or update `main.tex` and justify 180 s. Prefer the former.

### A4. (Informational — measured negligible) `/v1/recover2` has no timing jitter

**Where:** `postRecover2` (`server.ts`). Unlike the jittered sibling paths (`postRecover`,
`postAuthOptions`, `postAuthVerify`), it adds no randomized delay before returning a failure.
I first flagged the existent‑vs‑nonexistent timing gradient as a Low finding and proposed
jitter/matched‑work. Direct measurement closes it.

**Measurement (2026‑07‑20, instrumented test server, one real recovery):**
`lookup=41.18 ms  verify=0.75 ms  downstream=399.60 ms  total=441.53 ms`.

**Why it is not exploitable.** The only part of the request that differs between an existent
and a nonexistent `userId` is the `verify` slice — **0.75 ms** — because both paths pay the
~41 ms `getUnverifiedUser` DynamoDB round trip (a `get` on a missing key costs about the same
as one that returns an item, and it throws on the empty result rather than returning before
the round trip). A sub‑millisecond CPU delta riding on a ~41 ms matched, network‑variable
baseline is not measurable across the internet. The ~400 ms destructive `downstream` work runs
only after a *valid* proof, so an enumeration probe never reaches it. `userId` is also 128‑bit
and every failure returns a uniform 401.

**Disposition:** no action — jitter/matched‑work would only mask an already‑unmeasurable
signal. (Remove the temporary timing instrumentation added to `postRecover2` for this test.)

### A5. (Low, by design) No‑PRF fallback re‑exposes `userCred` to the server

**Disposition (2026‑07‑20):** Accepted risk — addressed by the roadmap: **Phase 4** migrates existing no‑PRF accounts to PRF and **Phase 5** deprecates new ones (`vibes/prf-implementation-plan.md`).

**Where:** `postRegVerify` non‑PRF branch (`server.ts:546-561`): the server generates
`userCred`, KMS‑encrypts it (`userCredEnc`, `userCredEncOld`), derives `userCredPubKey`
server‑side, and returns plaintext `userCred` at login (`makeLoginUserInfoResponse`
`server.ts:1101-1109`). Recovery for these accounts uses the raw‑`userCred` legacy path.

**Impact:** For server‑managed (no‑PRF) accounts, a server/DB compromise *with* KMS
decrypt yields `userCred`, which lets an attacker **forge proofs** (impersonate for
account management) and **decrypt password hints** (hints are encrypted under a
`userCred`‑derived key), aiding offline password guessing *if* the attacker also obtains
the user's externally‑stored ciphertext. It does **not** by itself decrypt data (password
still required). PRF accounts are immune to all of this. This is an inherent property of
the fallback, not a bug — but it is the sharpest edge of the two‑tier model and should be
explicit to users and operators.

**Remediation:** none required for correctness. Consider (a) surfacing PRF vs no‑PRF
status to the user as a security indicator (the `prf` flag already exists), (b) a roadmap
to retire server‑managed accounts as PRF coverage grows, and (c) ensuring the KMS key
policy restricts `Decrypt` to the Lambda role only (appendix).

### A6. (Low) Legacy `/v1/recover` (raw `userCred` in body) remains mounted

**Disposition (2026‑07‑20):** Accepted / won't fix — no risk to unmigrated accounts (which are likely unused), so this will very likely never change.

**Where:** `postRecover` (`server.ts:1569-1651`), route `Patterns.recover`
(`urls.ts:93-95`). It accepts `userCred` in the POST body, KMS‑decrypts the stored value,
and constant‑time compares (`server.ts:1612`). It is refused for any account that has a
recovery key (`server.ts:1601-1603`), so PRF accounts and migrated accounts cannot use it.

**Impact:** Low and shrinking. The dangerous *URL‑path* variant flagged as H5 in the prior
review is gone (no `…/recover/:usercred` pattern exists). What remains transmits `userCred`
only in a request body (not a URL), for legacy non‑PRF accounts whose `userCred` the server
already holds. Residual risk is body logging in an intermediary and the general presence of
a deprecated destructive path.

**Remediation:** set a removal date once telemetry shows no legacy traffic; until then
ensure request bodies are excluded from access/error logs.

### A7. (Low) Accounts lacking `userCredPubKey` are locked out of all authorized routes

**Disposition (2026‑07‑20):** Resolved — all production and test accounts have been verified to hold a `userCredPubKey`, so none are locked out.

**Where:** `verifyProof` requires a stored 1952‑byte `userCredPubKey`
(`server.ts:1950-1957`); absent/short → `'invalid'` → 401. All V7‑era registrations
populate it (client for PRF, server for no‑PRF), but any pre‑existing account without it
would fail every authorized call, including `GET /v1/session`.

**Impact:** A migration/rollout hazard rather than an attacker‑exploitable flaw (it fails
closed). If any legacy accounts predate `userCredPubKey`, they can still `auth/verify` but
then cannot hold a session.

**Remediation:** confirm a backfill of `userCredPubKey` for all pre‑existing verified
accounts before the enforcing build reaches production (the owner‑managed rollout already
tracks this); add a monitoring alarm on `proof invalid` spikes right after cut‑over.

### A8. (Low / Informational) `hostname` allow‑list is defined but not applied to routes

**Disposition (2026‑07‑20):** Resolved — the unused `hostname` constant was removed and a clarifying comment added.

**Where:** `urls.ts:69` defines `const hostname = '{*.}?quickcrypt.org'`, but the
`URLPattern`s specify only `pathname`, and `matchEvent` executes them with
`{ hostname: rpID, pathname: path }` (`urls.ts:162-165`) — with no host component in the
pattern, the host is effectively unconstrained. RP‑ID/origin trust rests entirely on
CloudFront injecting a correct `x-passkey-rpid` header (required at `urls.ts:142-149`).

**Impact:** Low, assuming the Lambda is only reachable via CloudFront (which sets/overrides
`x-passkey-rpid`) and never via a directly‑invocable Function URL / API Gateway route. If
the origin were ever directly reachable, a caller could set `x-passkey-rpid` to an
arbitrary `*.quickcrypt.org` value (and WebAuthn's own origin binding would still constrain
assertions). The in‑code allow‑list gives a false impression of enforcement.

**Remediation:** apply the `hostname` component to the `URLPattern`s (defense in depth), or
delete the unused constant and add a comment that host restriction is enforced upstream;
and verify at the infra layer that the origin cannot be invoked bypassing CloudFront.

### A9. (Informational) Proof does not cover the query string

**Disposition (2026‑07‑20):** Patched — the proof now binds the query string via a required `queryString` argument (client signs `url.search`; server signs `event.rawQueryString`).

**Where:** client signs `url.pathname` (`authenticator.service.ts:354`); server verifies
`httpDetails.path` = `event.requestContext.http.path` (`urls.ts:156`), both excluding the
query string, which is parsed separately (`urls.ts:187`).

**Impact:** None today — no public authorized handler reads `httpDetails.params`; the only
query‑param consumer is the internal `testkey` (`server.ts:2053`). This is a latent
gap: any future authorized route that makes a decision from a query parameter would have
that parameter outside both the proof and the body hash.

**Remediation:** either include the full path+query in the signed message and the server
verification, or add a lint/comment forbidding authorized handlers from consuming query
parameters.

### A10. (Informational) Internal `/v0/*` endpoints gated only by a KMS‑encrypted sentinel

**Disposition (2026‑07‑20):** Accepted risk — the internal `/v0/*` functions are designed to be safe and idempotent to run on any deploy; may move to IAM/SigV4 later.

**Where:** internal routes decrypt `params.testkey` and compare the plaintext to
`INTERNAL_PHRASE = "Yup, I'm internal"` (`server.ts:2050-2059`). The phrase is in the
open‑source tree; the only real control is possession of a KMS key plus the routes not
being exposed through CloudFront.

**Impact:** As the prior review concluded (L12), this is defense‑in‑depth behind the
network and AWS‑account boundaries, and an attacker with AWS‑account access already has
DynamoDB/KMS. The `testkey` ciphertext also travels in the query string (loggable), though
it is only ciphertext of a public phrase.

**Remediation:** optional — replace with IAM/SigV4 on the internal routes so caller
identity is captured in CloudTrail. Low priority.

### A11. (Informational) `getInvitables` is an unscoped capability lookup

**Disposition (2026‑07‑20):** By design — intentional capability‑URL lookup.

**Where:** `getInvitables` (`server.ts:1320-1348`) is `authorize:true` but keys solely on
the URL `invitableId`, returning the creator's `userName` in `description`. Any
authenticated user who knows a 128‑bit `invitableId` learns that name. This is the intended
"sender‑link" capability, and invitables are not yet shipped. Documented for completeness;
re‑evaluate if the response ever grows beyond `{invitableId, description}`.

### A12. (Informational) No application‑layer rate limiting

**Disposition (2026‑07‑20):** Resolved (infra) — AWS WAF rate limiting is deployed on production; intentionally left off the test server to allow more robust testing.

No throttling exists in `server.ts`; the unauthenticated `/auth/options`, `/auth/verify`,
`/reg/*`, `/recover*` endpoints rely on out‑of‑repo WAF/API‑Gateway limits.

**Live‑check update (2026‑07‑19):** a production WAF rate‑based rule (by source IP,
`path startsWith /v1`, **>38 req / 10 min**) was verified **firing on both IPv4 and IPv6**
(appendix #2). So the infrastructure throttling the app depends on is present and working
— with AWS WAF's inherent ~30 s evaluation latency, so it is volumetric/eventual rather than
a precise per‑request cap. The finding therefore stands only as a note that (a) the control
lives entirely outside application code, and (b) the latency lets a short burst through
before engaging, so per‑request‑sensitive concerns should be fixed in code rather than
assumed covered by the limiter.

---

## 5. Weaknesses — Cryptography

The cryptographic core is in good shape; the items here are low‑severity surface reduction.

### C1. (Low / Informational) Legacy version decode paths are reachable before MAC

**Where:** `getStreamDecipher` selects the decipher from the version byte *before* any MAC
check (`ciphers.ts:84-119`), so `DecipherV1/V4/V5` remain reachable for every user even
though encryption only ever emits V7. (Prior review S1.)

**Impact:** Low. The MAC is checked inside each legacy decipher using a signing key derived
from the user's `userCred`, so an attacker cannot forge a valid legacy ciphertext without
`userCred`. The residual risk is a parsing bug in a legacy decoder reachable *before* the
MAC check. The `Extractor` is bounds‑ and range‑checked and the version is whitelisted
(`{1,4,5,6,7}`), which makes this narrow, but the surface persists indefinitely.

**Disposition — inherent, won't fix.** Reading the version *before* the MAC is unavoidable:
the MAC's location and the signing‑key derivation both depend on the version, so a decoder
cannot check a MAC until it has parsed the version. And unlike most systems, **old versions
can never be retired**: (1) decryption happens entirely client‑side, so the server has no
telemetry on which versions are still being decrypted (by design); and (2) Quick Crypt's
whole purpose is long‑term storage — a ciphertext written today may not be opened for 10+
years, and dropping a version would mean telling users their data is unrecoverable. The
mitigation is therefore not retirement but defense‑in‑depth on the decoders: the `Extractor`
is bounds/range‑checked and the version is whitelisted; keep fuzzing them (extend the
existing `fuzz.spec.ts` pattern to the legacy deciphers).

### C2. (Invalid / retracted) Hint IV reuse in V6/legacy providers

**Where:** `PWDKeyProviderV6` and `PWDKeyProviderLegacy` reuse the data `baseIV` as the
hint IV, whereas V7 derives a distinct hint IV (`keys.ts`, confirmed in V7 at
`_genHintCipherKeyAndIV` instance 2, `keys.ts:722`). These are decrypt‑only legacy paths
(no new V6/legacy ciphertexts are produced), so this cannot affect newly created data.

**Retracted.** Not an actionable finding: the V6/legacy hint‑IV behavior is frozen and can
**never** change — decoding an old ciphertext requires reproducing exactly how it was
written, and (per C1) those versions can never be retired. There is nothing to fix.

### C3. (Informational) Armor parsing is unbounded before `JSON.parse`/`decodeURIComponent`

**Disposition (2026‑07‑20):** Accepted risk (self‑DoS only) — a code comment now documents why length limits are omitted.

**Where:** `parseCipherArmor` (`armor.ts:52-93`) runs `decodeURIComponent` and `JSON.parse`
on attacker‑supplied text with no length bound. Callers wrap in try/catch, and the input is
the user's own paste, so the only risk is self‑inflicted memory pressure (prior L10).
Optional: bound input length before parsing on the CLI/web client.

**Confirmed‑fixed crypto items (no action):** per‑message salt mixing and distinct hint IV
in V7 (prior M2/M3); `LP_MAX` is re‑validated on the decrypt recursion before re‑entry
(`cipher-streams.ts:182`, prior S3); constant‑time MAC compare via `sodium.memcmp`; all‑zero
/ wrong‑length `userCred` rejected at construction; key buffers zeroized on `purge()`.

---

## 6. Status of prior‑review still‑active items

| Prior item | Status in current tree | Evidence |
|---|---|---|
| **H5** — `userCred` in a URL path (`/users/:userid/recover/:usercred`) | **Resolved.** No such route/pattern exists; only body‑based `/v1/recover` (A6) and `/recover2` remain. | `urls.ts:74-137` (no `recoverOld`), `METHODMAP` `server.ts:2106-2121` |
| **S1** — version dispatch precedes MAC | **Still present**, Low. | `ciphers.ts:84-119` → finding C1 |
| **M2/M3** — static hint/signing key; shared hint IV | **Fixed in V7.** | `keys.ts:753-768`, `722` |
| **M1** — `userCred` returned by `GET /v1/session`; long in‑memory lifetime | **Fixed.** `/session` returns no `userCred`; at‑rest wrap + on‑demand decrypt implemented. | `server.ts:273`, `API.md:206`, `keystore.service.ts`, `authenticator.service.ts:347-363` |
| **C1/H4** — cross‑account passkey binding; `body.userId` trust | **Fixed.** Purpose+userId challenge binding; `postPasskeyVerify` uses `verifiedUser`. | `server.ts:728-731`, `455-474` |
| **H1/H2** — non‑constant‑time secret compares | **Fixed.** `knownLenTimingSafeEqual`/`timingSafeEqual` on CSRF, `userCred`, recovery. | `utils.ts:95-100`, `server.ts:1880`, `1612` |
| **M8/L1** — no session revocation levers | **Fixed.** `authCount`+`lastCredentialId` bump on logout; `SessionVersion` global lever. | `server.ts:283-303`, `1802-1823` |
| **M5/M5b** — user enumeration at `/auth/options` and `/auth/verify` | **Fixed.** Dummy creds, jitter, uniform 401, decoy verify. | `server.ts:803-919`, `349-372` |

---

## 7. Appendix — out‑of‑repo infrastructure to verify

The app's effective posture partly depends on configuration not in this repo. Items 1–2
were **spot‑checked live on 2026‑07‑19** (owner‑authorized: read‑only header fetches plus a
bounded rate probe); the rest remain owner‑runnable.

1. **CloudFront response headers — VERIFIED (strong).** Both `test.quickcrypt.org` and
   `quickcrypt.org` return `default-src 'none'`, hash‑locked `script-src` (+`wasm-unsafe-eval`,
   no script nonce), Trusted Types enforced (`require-trusted-types-for 'script'`), HSTS
   `max-age=63072000; includeSubDomains; preload`, `X-Frame-Options: DENY`, the full
   COOP/COEP/CORP trio, a comprehensive `Permissions-Policy` (incl. `publickey-credentials-*
   =(self)`), and `nosniff`. The served CSP matches `lambda_function.py`. `style-src` keeps a
   per‑cache‑entry nonce with `cache-control: public, max-age=3600`, so the style‑nonce reuse
   window is ~1 h (prior H3, Low — scripts are hash‑locked, so a known style nonce does not
   enable script injection).
2. **WAF — CONFIRMED ACTIVE and rate‑limiting correctly on both IPv4 and IPv6.** Blocks are
   returned as **HTTP 404** (a static page), not 403 — an intentional obfuscation that hides
   the control and makes external status‑probing ambiguous. Verified live (owner‑authorized,
   2026‑07‑19):
   - *Managed rules:* an injection‑pattern probe (`/?probe=<script>…`) was blocked
     (owner‑confirmed in WAF logs).
   - *Rate‑based rule* (by source IP, scope‑down `path startsWith /v1`, **>38 req / 10 min**):
     confirmed firing on **both** `curl -6` and `curl -4`. A burst of 40 `GET /v1/session` in
     ~10 s was allowed (all 401); after a ~45 s pause, subsequent requests were blocked (all
     404), reproducibly, on each family. The apparent "not firing" during fast bursts is **AWS
     WAF rate‑rule evaluation latency** (counts aggregate and re‑evaluate on a rolling ~30 s
     interval), not an address‑family gap — an initial IPv6‑bypass hypothesis was tested and
     refuted.
   - *Implication:* the limiter is **volumetric/eventual**, not a hard per‑request cap — an
     attacker gets a short burst (tens of requests) before throttling engages. Harmless here
     given 128‑bit `userId`/`recoveryId`, but it should not be relied on as a precise
     anti‑automation control. This closes the infrastructure side of finding A12.
3. **Origin isolation** — confirm the Lambda cannot be invoked bypassing CloudFront (no
   open Function URL / public API‑Gateway stage), which underpins the `x-passkey-rpid` trust
   (finding A8).
4. **KMS key policies** — only the Lambda execution role may `Decrypt` `KMSKeyId_New`/`_Old`
   and the `EncMaterial`/internal keys (bounds finding A5).
5. **DynamoDB** — point‑in‑time recovery/backups; confirm the `Challenges` TTL is actually
   enabled (the app relies on it for challenge/nonce expiry).
6. **Log hygiene** — access/error logs strip request bodies and the `x-proof`/cookie headers
   (bounds A2/A6); confirm `console.log(event)` debug lines stay disabled in prod
   (`server.ts:2025-2026`).
7. **CodeQL** — consider enabling the `security-extended` query pack.

---

## 8. Overall assessment

Quick Crypt achieves its confidentiality, integrity, and authenticity goals, and the new
PRF work is a substantial, correctly‑implemented improvement that removes the server from
the trust base for accounts that use it. The cryptographic library is careful and, in the
per‑message‑key area, ahead of typical practice. (This review's key‑commitment claim was
withdrawn — see item 1 above and `vibes/keycommit_finding.md`.) The authorization
model — cookie + CSRF + post‑quantum proof — is a genuine three‑factor design with sound
revocation levers and strong enumeration resistance. User verification is enforced, and no
Critical, High, or Medium issues were found. The highest‑value actions are to **fail the
replay‑nonce store closed** (A2) and **align the proof skew with the spec** (A3). The
remaining items are hardening, deprecation cleanup, and documentation.
