# Quick Crypt — Comprehensive Security Review (Plan)

## Context

Quick Crypt is a browser-based personal encryption tool (Angular SPA + AWS Lambda
server, Nx monorepo) for encrypting **highly sensitive personal data for long-term
storage in untrusted locations**, then decrypting it days or years later. It is
explicitly **not** for sharing or live communication. Stated goals: strong
confidentiality, integrity, authenticity, and website-forgery protection; no PII;
anonymous; fully offline after sign-in. Plaintext, passwords, and derived ciphertext
never leave the browser; the server only transports auth/crypto *metadata* and stores
per-user records it should ideally not be able to read.

The owner (Brad Schick, verified via the public site and GitHub repo) has requested a
deep, adversarial review of both **design** and **implementation**, judged against
Quick Crypt's own goals and modern best practice, with extra scrutiny on the recent
PRF additions: **client-side generated `userCred`**, **proof-of-user-credentials**
(`x-proof`, ML-DSA-65 signature over each authorized request), and
**proof-of-recovery-secret** (ML-DSA-65 over a server challenge). Throughout,
**authentication & authorization** are reviewed *separately* from **cryptography**.

**Constraint:** the whole review is performed with Fable — no fallback to Opus without
approval. All security *judgments* are made by Fable directly; any execution helper
agents are pinned to Fable and used only for parallel fact-gathering, never for the
verdicts.

**Deliverables:**
1. `vibes/security_review_plan.md` — this plan.
2. `vibes/security_findings.md` — the detailed findings report (primary output).

`SECURITY_REVIEW.md` (a prior Opus review) has been read in full and is used **only**
as an additional checklist of items to re-verify; it does not constrain this review.

---

## Grounding already completed during planning

Read in full: the overview, the V7 protocol (`main.tex`), the API spec (`API.md`), the
prior `SECURITY_REVIEW.md`, and the proof implementation + enforcement test
(`libs/api/src/lib/proof.ts`, `apps/server/spec/proof-enforce.spec.ts`). Produced
complete factual maps of `libs/crypto/src/lib/*`, the auth/API implementation
(`server.ts`, `authenticator.service.ts`, `libs/api`, `urls.ts`, `models.ts`,
`consts.ts`, `utils.ts`, `internal.ts`), and the repo/build/deploy structure. The
review below is therefore already well-oriented; Step 4 is line-level verification.

---

## Methodology — four steps, two tracks (auth/authz vs cryptography)

Primarily a **static source + design review**. No attacks against the live production
service. Existing unit/e2e tests are read and (where they run cleanly in this
environment) executed as behavioral evidence. Coverage is comprehensive but weighted
toward the new PRF additions, per the request.

- **Step 1 — Purpose & goals** *(done)*: security goals captured above.
- **Step 2 — Protocol design review** *(design only, `main.tex`)*: judge the V7 cipher
  protocol and the auth/authz protocols against the goals and against best practice.
- **Step 3 — API design review** *(design only, `API.md`)*: endpoint inventory, the
  cookie + `x-csrf-token` + `x-proof` authorization model, `x-amz-content-sha256` body
  binding, data models, and the invariant that no user plaintext/ciphertext is ever
  transported; compare to modern secure-web-API patterns.
- **Step 4 — Implementation vs design** *(the core, most effort)*: read the code
  line-by-line in two tracks, compare to Step 2/3 specs, hunt for **defects** (race
  conditions, error handling, XSS/DOM sinks, cross-account leaks, timing oracles,
  length/integer confusion, fail-open logic) and **compliance gaps** (code diverging
  from protocol or API). Re-verify still-active prior-review items and the historical
  cross-account passkey-binding bug class.

---

## Focus areas / candidate findings to verify in Step 4

Grounded in the maps; each resolves to confirmed / refuted / N/A with `file:line`
evidence. Items marked **[seed]** already look like probable findings.

### Authentication & authorization track
- **[seed] Proof timestamp skew mismatch:** protocol specifies `Δ = 60 s`
  (`main.tex`), implementation uses `PROOF_SKEW_MS = 180 s` (`consts.ts:53`) → ±180 s
  (360 s) acceptance window. Confirm value and assess the widened replay window.
- **[seed] Replay-nonce store fails open:** `verifyProof` allows a mutating request
  through on any non-duplicate DynamoDB error when storing the nonce
  (`server.ts:1990-1994`). Confirm and assess (replay protection depends on DDB).
- **GET proofs are replayable** within the skew window and `GET /v1/session` skips CSRF
  (`checkCsrf:false`): assess given cookie+proof are still required.
- **Proof binds `path` but likely not query string** (client signs `url.pathname`;
  server verifies `path`): check whether any authorized route relies on query params
  not covered by the proof or the body hash.
- **No-PRF fallback re-exposes `userCred`:** server generates `userCred`, KMS-stores it
  decryptably, and derives `userCredPubKey` server-side — so a server/DB+KMS compromise
  can both decrypt keystores and forge userCred proofs for non-PRF accounts. Contrast
  with PRF accounts (server holds only ciphertext + public key). Document the asymmetry
  and blast radius precisely.
- **`postRegVerify` falls through to `postRecoverVerify`** for already-verified users
  (`server.ts:496-499`): check the challenge purpose/userId binding can't be abused to
  cross flows.
- **Cross-account isolation / historical bug class:** re-verify challenge binding
  (purpose + userId, atomic delete-on-read), that `postPasskeyVerify` ignores
  `body.userId`, and that `postAuthVerify` resolves identity from the credential-id GSI
  rather than the client `userHandle`.
- **Recovery:** correctness of `verifyRecoveryProof` gating on `/v1/recover2`; the
  destructive "delete all passkeys" step reachable pre-auth (only a valid recovery
  signature or, legacy, raw `userCred`); enumeration timing between
  `/recover2/challenge` (no existence check) and `/recover2` (requires existence).
- **Legacy `/v1/recover`** (raw `userCred` in POST body, constant-time compared, rejects
  recovery-key accounts): document residual deprecation surface (prior H5 lineage).
- **WebAuthn policy:** `userVerification:'preferred'` (not `'required'`) and
  `counter:0` (clone-detection disabled) — assess against the sensitive-data threat
  model.
- **Session/JWT:** HS512 keyed by `HKDF(lastCredentialId‖jwtMaterial, salt=userId,
  info=purpose:authCount:sessionVersion)`; verify logout (`authCount`++ /
  `lastCredentialId` clear) truly invalidates cookie+CSRF; `__Host-` + Secure +
  HttpOnly + SameSite=Strict flags; global `SessionVersion` lever.
- **Enumeration resistance:** `postAuthOptions` dummy creds + jitter; uniform 401s.
- **Internal `/v0/*` endpoints** gated only by a KMS-encrypted sentinel phrase; and the
  **undocumented `invitables`** authorized endpoint keyed solely by URL id (capability
  lookup) — re-confirm and note doc drift.
- **Rate limiting** absent in app code (WAF/API-GW out of repo) — note as defense-depth
  gap and amplifier for timing oracles.

### Cryptography track
- **AEAD key commitment `k_C`:** confirm the commitment is folded into AAD on both
  encrypt and decrypt for V7/MasterKey and that it delivers partitioning-oracle
  resistance (a genuine strength if sound).
- **MAC-before-decrypt + constant-time compare** (`sodium.memcmp`), encrypt-then-MAC,
  inter-block MAC chain + terminal flag (truncation/reorder resistance) — verify across
  V7 and legacy deciphers.
- **Version-dispatch-before-MAC (prior S1):** legacy V1/V4/V5 decode paths remain
  reachable for any user; assess parser-bug surface.
- **Per-message salt mixing / IV uniqueness** in V7 (`keys.ts`); **hint-IV reuse** in
  V6/legacy vs distinct hint IV in V7.
- **At-rest `userCred` crypto** (`cd_p`/`cd_r`/`cd_u`): AAD binds `userId`; AEAD tag
  enforces user binding; `k_L` from a non-extractable IndexedDB HMAC key + `pkId`
  (`keystore.service.ts`); fresh-key-per-login; cross-tab handoff over
  `BroadcastChannel` carries only ciphertext (same-origin).
- **ML-DSA-65 proof keys:** deterministic seed derivation from `userCred` / recovery
  secret, 8-byte KDF-context handling, sig-context domain separation
  (`qcrypt/usercred/proof/v1` vs `.../recovery/...`), randomized signing, seed
  zeroization.
- **PRF handling:** fixed public `PRF_SALT` (documented non-secret), 32-byte length
  checks, `prfKey` zeroization, XChaCha20-Poly1305 wrap.
- **Input validation & robustness:** version whitelist, length/range checks in
  `Extractor`/`Packer`, `LP_MAX` on the decrypt recursion, armor-parse bounds, behavior
  on malformed/adversarial ciphertext; all-zero/short `userCred` rejection.
- **Randomness** sourced from libsodium `randombytes_buf`; **zeroization** coverage on
  stream error/close.

---

## Critical files

- **Crypto (`libs/crypto/src/lib/`):** `ciphers-current.ts` (V7), `deciphers-old.ts`
  (V1/V4/V5), `ciphers.ts` (version dispatch), `keys.ts` (all key derivation),
  `cipher-streams.ts`, `cipher.consts.ts`, `armor.ts`, `utils.ts`, `proof.ts`
  (ML-DSA primitives), `crux/` (WASM loader).
- **Auth/authz — server:** `apps/server/src/server.ts` (routes, auth, sessions,
  recovery, `verifyProof`), `models.ts`, `urls.ts`, `consts.ts`, `utils.ts`,
  `internal.ts`, `nonce/lambda_function.py` (CSP).
- **Auth/authz — client + shared:** `apps/web/src/app/services/authenticator.service.ts`,
  `prf.ts`, `keystore.service.ts`, `broadcast.service.ts`; `libs/api/src/lib/proof.ts`
  and `libs/api/src/index.ts`.
- **Docs/spec:** `main.tex`, `API.md`, `overview.component.html`.
- **Tests (evidence):** `apps/server/spec/*` (`proof-enforce`, `prf`, `nonprf`,
  `recovery.suite`, `dummy-auth`, `fuzz`), `libs/crypto/src/lib/*.spec.ts`,
  `libs/api/src/lib/proof.spec.ts`, web service specs, `apps/web/tests/` (e2e).

---

## Findings report structure (`vibes/security_findings.md`)

1. **Executive summary** — overall posture and headline risks.
2. **Strengths** — only novel or above-expectation items.
3. **Weaknesses by severity** (Critical / High / Medium / Low / Informational), each
   with description, `file:line`, impact, evidence, and concise remediation —
   **auth/authz** and **cryptography** findings separated within each severity.
4. **Status of prior-review still-active items** re-verified against the current tree.
5. **Appendix — out-of-repo infrastructure to verify.**

---

## Verification approach

- Cross-reference `main.tex` ↔ implementation ↔ `API.md` for every compliance check.
- Grep for concrete patterns (secret comparisons, `body.userId` trust, proof
  enforcement/skew, version dispatch, `LP_MAX`, IV/salt generation, fail-open paths).
- Run the pure unit suites that execute cleanly here (`nx test crypto`, `nx test api`)
  as evidence; read server/e2e specs that need backend/emulator setup rather than
  forcing them.
- Optional (owner approval): read-only `curl -I https://quickcrypt.org/` for deployed
  security headers. Otherwise these stay in the out-of-repo appendix.
