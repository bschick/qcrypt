# Quick Crypt — Phase 1 Detailed Plan: Proof of userCred

> Detailed execution plan for Phase 1 of the master plan (`vibes/prf-implementation-plan.md`). Names/tags here are concrete proposals; refine for clarity during implementation.
>
> **Library-agnostic:** the ML-DSA library (libcrux-WASM vs `@noble/post-quantum`) and parameter set (44/65/87) are decided by Step 1's benchmark and isolated behind a stable `libs/crypto` interface. Nothing in Steps 2–8 depends on which is chosen.

---

## Context

Pre-PRF, the server generates `userCred` and returns it in plaintext at login, so it can reconstruct the hint and MAC keys. Phase 1 adds a **proof of `userCred` possession** to **every** authorized API call: the client signs a request-bound message with an ML-DSA private key **deterministically derived from `userCred`**; the server verifies with a stored **public** key. This shrinks the blast radius of session hijack / the historical "User B attaches a passkey to User A" bug, and lays the cryptographic groundwork for post-PRF (the derivation is a pure function of `userCred`, so it carries over unchanged once `userCred` is PRF-recovered client-side). Phase 1 ships **standalone, pre-PRF**, for all accounts.

**`getSession` requires proof too.** The proof message does **not** include the CSRF token, which lets `getSession` itself require proof of `userCred` before it returns a CSRF — so CSRF issuance is gated on `userCred` possession, not merely on holding the cookie. A stolen cookie alone can no longer obtain a CSRF.

`getSessionKey`'s switch from `userCredEnc` → `lastCredentialId` is **deferred to Phase 3** (it only matters once post-PRF accounts lack `userCredEnc`, and forces a one-time mass re-login). Phase 1 leaves `getSessionKey` untouched.

---

## The proof contract (the crux — both runtimes must agree byte-for-byte)

**Canonical message** (UTF-8, ASCII fields, `\n`-joined, no trailing newline; 5 fields / 4 separators):

```
qcrypt-proof-v1
<METHOD>            # uppercase: GET|POST|PUT|PATCH|DELETE
<PATH>             # /v1/...  (client: new URL(path,baseUrl).pathname; server: event.requestContext.http.path)
<TS>               # x-proof-ts: Date.now() ms, decimal string (verbatim — sign the received string)
<BODYHASH>         # lowercase hex SHA-256(utf8(body ?? '')), computed for ALL methods
```

- **No CSRF field** — so `getSession` (which has no CSRF to send on a fresh tab) can still be proof-required.
- **Account binding / replay:** the proof is verified against the user's stored `proofPubKey`, and the user is identified by the cookie → **no cross-account replay**. Same-account replay is bounded by the timestamp window (same request, ≤SKEW_MS); no nonce table, no extra round-trip [R5].
- **BODYHASH for every method.** GET/DELETE bodies are `''` → empty-string SHA-256 `e3b0c442…b855`. The **server hashes the raw received body** (post-base64-decode, **pre-`JSON.parse`**) — never a re-serialized object [R1].
- **Query is excluded.** Drop `getSession`'s now-vestigial `usercred=false` param so no proof-required endpoint carries a query string; add canonical query binding only if a future proof-required endpoint needs it.
- **Signing:** `signProof(secKey, messageBytes, context)` with `context = "qcrypt/proof/v1"` (ML-DSA context string). Do **not** pre-hash (ML-DSA hashes internally).
- **Key derivation domain:** `deriveProofKeyPair(userCred32, "qcrypt/proofkey/v1")` — domain-separated from every `keys.ts` derivation.

**New request headers** (server reads lowercase): `x-proof-sig` = base64url(signature, unpadded); `x-proof-ts` = `Date.now()` ms decimal. (`x-csrf-token` is unchanged and still sent on non-`getSession` calls; it is simply not part of the signed message.)

**Shared builder, no drift:** `buildProofMessage(method, path, tsDec, bodyHashHex): Uint8Array` lives **once** in `libs/api` (pure string assembly; caller supplies the hex hash so `libs/api` stays crypto-free). Both web and server import it from `@qcrypt/api`. Crypto (`deriveProofKeyPair`/`signProof`/`verifyProof` + domain/context constants) lives in `libs/crypto`.

---

## Work breakdown (ordered; rollout gates between Steps 5→8)

### Step 1 — Throw-away PQ benchmark app (gates library + param set)
Scratch app mirroring `apps/cli` tooling (esbuild via `build.js`, `vitest.config.ts`; Node primary + minimal browser harness). Not shipped — remove/gitignore after the decision.
- Bring in **both** `@noble/post-quantum` (devDep) and a **libcrux-WASM** build (wasm-pack from `wasm-demo`); benchmark **keygen-from-seed / sign / verify** for **ML-DSA-44/65/87** in Node and browser-WASM; record key/sig sizes.
- **Validate the correctness linchpins:** deterministic keygen from a 32-byte seed; **byte-identical** keypair across the Node and browser builds (R2) — or standardize seed-expansion (SHAKE/HKDF) inside our wrapper so both match regardless.
- Check sig size vs the live CloudFront + API Gateway header budget (ML-DSA-87 sig ≈6 KB base64url) [R6]; confirm the library is **Node-safe** (no browser-only globals at import) [R3].
- **Output:** a short decision note (library, param set — leaning 65) feeding Step 2.

**Benchmark results (captured — the throw-away `apps/pqbench/` app and its `RESULTS.md` were deleted on close, so these are recorded here).** Node v24.16.0, 200 iterations/op after 20 warmup, head-to-head `@noble/post-quantum` (pure JS) vs libcrux-WASM:

| op (ML-DSA-65) | @noble (pure JS) | libcrux (WASM) | speedup |
|---|---|---|---|
| keygen | 1.68 ms | 0.16 ms | ~10× |
| sign (client, per request) | 8.2 ms | 0.37 ms | ~22× |
| verify (server, per request) | ~1.4 ms | ~0.11 ms | ~13× |

Sizes are identical between the two libraries (same FIPS-204 params): ML-DSA-65 pubkey 1952 B, secret key 4032 B, signature 3309 B (4412 B as base64url for the header). Full param-set sizes — ML-DSA-44: pubkey 1312 B, sig 2420 B (3227 B b64url); ML-DSA-87: pubkey 2592 B, sig 4627 B (6170 B b64url).

Takeaways: server-side **verify is already cheap** even on noble (≤2.2 ms across all param sets); the dominant per-request cost is **client-side sign** (~7–8 ms for ML-DSA-65 in pure JS). libcrux's edge is large on every op (~20× on sign) — well past the "skip the WASM complexity if the edge is small" bar — and it adds formal-verification assurance. **Decision: libcrux + ML-DSA-65.**

### Step 2 — Generic proof primitive in `libs/crypto`
New Node-safe module exported from `libs/crypto/src/index.ts`, following the `sodium.ts` lazy-init pattern:
- `deriveProofKeyPair(secret, domainTag) -> {pubKey, secKey}` — deterministic; **owns seed expansion** so results are identical across runtimes.
- `signProof(secKey, message, context)` / `verifyProof(pubKey, message, sig, context)`.
- Constants `PROOFKEY_DOMAIN`, `PROOF_CONTEXT`. Reuse `concatArrays`/`bytesToBase64`/`base64ToBytes`.
- **Tests** (`libs/crypto/src/lib/proof.spec.ts`, mirror `keys.spec.ts`): determinism, domain separation vs `keys.ts`, sign/verify round-trip, tamper rejection, Node-vs-browser parity vector.
- Add `buildProofMessage` to `libs/api` (`libs/api/src/index.ts`) + a spec for exact-bytes stability.

### Step 3 — Data model + new-account provisioning (server)
- `apps/server/src/models.ts` Users entity: add `proofPubKey: {type:"string", required:false}` (**plaintext base64url** — a public key, no KMS). **No `proofKeyVersion`.**
- `apps/server/src/server.ts` `_doPostRegVerify` (the `!verified` branch where plaintext `userCred` exists, ~`:630`): derive `pubKey = deriveProofKeyPair(userCred, PROOFKEY_DOMAIN)` and add `proofPubKey: base64UrlEncode(pubKey)` to the `Users.patch().set({…})` (~`:685`). Server imports `@qcrypt/crypto` (tsconfig path maps it; it already imports `@qcrypt/api`).
- Make `decryptField` (private in `server.ts:181`) shareable with the migration (move to a common module or mirror the KMS `DecryptCommand` with `EncryptionContext:{userId}`) [R4].

### Step 4 — Backfill migration (replace `postMunge` body)
The current `postMunge` code (`internal.ts`) is temporary — **replace it** with the proof-pubkey backfill (keeps the existing `testkey`-gated internal endpoint + batching scaffold). Scan Users in batches (`Users.scan.go({attributes:['userId','userCredEnc'], limit, cursor})`), skip sentinel `AAAAAAAAAAAAAAAAAAAAAA`, and for each verified user with `userCredEnc` and no `proofPubKey`:
`uc = decryptField(userCredEnc,{userId},USERCRED_BYTES)` → `pubKey = deriveProofKeyPair(uc, PROOFKEY_DOMAIN)` → `Users.patch({userId}).set({proofPubKey: base64UrlEncode(pubKey)}).go()`. Idempotent; report total/processed/skipped.

### Step 5 — Server enforcement (`server.ts` + `urls.ts`)
- **Thread through `HttpDetails`** (`urls.ts` type + `matchEvent` `:155-195`): `rawBody` (decoded body string before `JSON.parse`, `''` if none), `path` (matched `event…http.path`), `proofSig`/`proofTs` (lowercase headers) [R1].
- Add `requireProof?: boolean` to `HandlerInfo`/`HttpDetails`; set it `true` on **every** `authorize:true` route in `METHODMAP` — **including `getSession`** (which keeps `checkCsrf:false`): `getUser`, `getPasskeyOptions`, `getSession`, `getInvitables`, `postPasskeyVerify`, `patchPasskey`, `patchUser`, `deletePasskey`, `deleteSession`.
- New `verifyProof(verifiedUser, httpDetails): 'ok'|'fail'|'absent'|'grace'`: missing headers → `absent`; bad/expired `ts` (`|now-ts|>SKEW_MS`, default 60 s, env-tunable) → `fail`; missing `proofPubKey` → `grace`; else rebuild the canonical message (shared `buildProofMessage` + server-side raw-body hash) and `verifyProof(pubKey,…)` → `ok`/`fail`. `verifiedUser` (incl. `proofPubKey`) is already loaded by `verifyCookie` — no extra DB read.
- **Handler gating** — slot in right after `verifyCsrf` (`server.ts:1793`), inside `if (httpDetails.authorize)`. (`getSession`'s `verifyCsrf` is a no-op since `checkCsrf:false`, then `verifyProof` runs.)
  - **Observe-only (default, `PROOF_ENFORCE` unset/false):** run `verifyProof`, log result to CloudWatch via `console.log` (not a per-request DynamoDB row) [R10]; **never throw**.
  - **Enforce (`PROOF_ENFORCE=true`):** throw `AuthError`→401 on `fail`/`absent`; allow `grace` (mid-migration only).

### Step 6 — Web client (`authenticator.service.ts`)
- **Lazy key lifecycle:** add `_proofSecKey?` + `_proofKeyPromise?`. Derive via `getUserCred()` → `deriveProofKeyPair` → cache `secKey`, **`userCred.fill(0)` immediately** (finally), dedupe concurrent first calls via the shared promise. Clear **both** fields everywhere `_csrf` is cleared: `logout` (`:745`), `forgetUser` (`:695`), and the `logout(false)` paths from `_doFetch` 401 (`:329`) and `getUserCred` failure (`:266`) [R9].
- **Sign every authorized call, including `getSession`.** Compute `bodyHash = hex(SHA-256(utf8(bodyJSON ?? '')))` for **all** methods (extend the PUT/POST/PATCH-only computation at `:298-302`), build via `@qcrypt/api` `buildProofMessage(method, url.pathname, ts, bodyHash)`, `signProof`, append `x-proof-sig`/`x-proof-ts`. The signing gate is "a proof key is available" (i.e. `userCred` is accessible). Unauthenticated flows (`auth/*`, `reg/*`, `recover*`) have no `userCred` yet → no proof, and those endpoints are `authorize:false`.
- **Bootstrap reorder (`_restoreSession`):** obtain `userCred` first (BroadcastChannel `requestCredential`, or existing session state) → derive the proof key → then call `getSession` (now signed) to get the CSRF. The current parallel `Promise.all([requestCredential, getSession])` becomes sequential. If `userCred` cannot be obtained (no peer tab), the tab **re-authenticates** instead of restoring. Drop the vestigial `usercred=false` param from the `getSession` call.

### Step 7 — Tests
- **Server unit** (`apps/server/spec`, `nid-webauthn-emulator`; derive the keypair from the test `userCred`): accept valid; reject expired `ts` / wrong method-path-body / wrong key; `grace` when no `proofPubKey`; observe-only never rejects; enforce rejects `fail`/`absent`; `getSession` requires proof; migration-derived pubkey matches a client signature.
- **Web unit** (`authenticator.service.spec.ts`): proof key derived/cached when `userCred` available; both fields cleared on logout/forget; concurrent first calls derive once; `getSession` and `DELETE /session` both carry proof; no-peer restore falls back to re-auth.
- **E2E** (`apps/web/tests`, alongside `lifecycle/edit/api.spec.ts`): mutate + `getSession` succeed with proof under enforce; tampered/missing proof → 401; multi-tab logout wipes the key; fresh-tab restore via a peer works; no-peer fresh tab re-auths. Honor the user-tracking contract and `@nukeall`.

### Step 8 — Rollout (ordering invariant — violating it causes mass 401 lockout)
1. Deploy server: `proofPubKey` attribute + new-account provisioning + observe-only verify (`PROOF_ENFORCE` off).
2. Run the `postMunge` backfill until ~100% of active users have `proofPubKey`.
3. Ship the signing client (still observe-only); watch CloudWatch for `absent → ok` convergence and `fail ≈ 0`.
4. Flip `PROOF_ENFORCE=true`.

---

## Critical files
- `libs/crypto/src/index.ts` + new `libs/crypto/src/lib/proof.ts` / `proof.spec.ts` — Node-safe `deriveProofKeyPair`/`signProof`/`verifyProof` + domain/context constants.
- `libs/api/src/index.ts` — shared `buildProofMessage` (+ header-name/scheme constants).
- `apps/server/src/server.ts` — provisioning (`_doPostRegVerify`), `verifyProof`, handler gating after `verifyCsrf` (`:1793`), `METHODMAP` `requireProof` flags (incl. `getSession`), shareable `decryptField`.
- `apps/server/src/urls.ts` — thread `rawBody`/`path`/proof headers through `HttpDetails`; `requireProof` flag.
- `apps/server/src/models.ts` — Users `proofPubKey` (plaintext; no version field).
- `apps/server/src/internal.ts` — backfill replacing the temporary `postMunge` body.
- `apps/server/src/consts.ts` — `PROOF_*` constants (skew, enforce flag, domains).
- `apps/web/src/app/services/authenticator.service.ts` — lazy key lifecycle, `_doFetch` signing, `_restoreSession` reorder.
- Throw-away bench app (scratch, Step 1).

## Residual risks / explicit decisions
- **R1 raw-body hashing** (server hashes raw received body, not re-serialized JSON) — highest-impact correctness item.
- **R2 cross-runtime determinism** — Step 1 must prove byte-identical keypairs across browser-WASM and Node, or our wrapper standardizes seed-expansion.
- **R5 replay** — timestamp window *bounds* but doesn't *eliminate* replay (no nonce table, by design); no cross-account replay (pubkey + cookie identity). Same-account, identical request, ≤SKEW_MS. Accepted.
- **R6 header size** vs param set — verify ML-DSA-65/87 sig fits CloudFront/API-Gateway header caps in Step 1.
- **Bootstrap tradeoff** — a fresh tab with no peer must re-auth to get a CSRF (it already needs `userCred` for crypto); global logout from a `userCred`-less tab falls back to local logout. Intended, stricter posture.
- **Telemetry volume** — observe-only logs to CloudWatch, not per-request DynamoDB rows.

## Verification (end-to-end)
- **Step 1:** bench app prints timings/sizes + a passing Node↔browser keygen-parity vector.
- **Unit:** `pnpm test` (full) after the `libs/crypto` + `libs/api` changes.
- **Server:** `pnpm test:server` (against `test.quickcrypt.org`).
- **E2E:** `nohup pnpm serve &` then `pnpm test:e2e --reporter=list`; with `PROOF_ENFORCE` off (observe) and on (enforce), verify proof headers on all authorized calls incl. `getSession`, that enforce rejects a tampered proof, and that fresh-tab restore works via a peer / re-auths without one. Build via project scripts (`pnpm build:web`/`build:server`); confirm any WASM bundle passes strict-CSP (`deploy:web validate`).
