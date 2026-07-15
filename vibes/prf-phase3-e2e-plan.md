# PRF Phase 3 — E2E Plan (emulator-injection foundation)

> Finalized 2026-07-12. Supersedes the CDP-virtual-authenticator approach in the "Next" paragraph of
> `vibes/prf-phase3-plan.md`. All client + server PRF code is committed on branch `prf-phase3`; this is
> E2E test work only. Background facts: memory `project_prf_e2e_authenticator`, `project_prf_phase3_plan`,
> `project_keeper_creds_e2e`, `project_e2e_user_tracking`.

## Why injection, not CDP

The Chromium CDP virtual authenticator **cannot reproduce a credential's PRF output after the credential
is persisted and re-added** (`getCredentials` → `.creds.json` → `addCredential`) — the hmac-secret
`credRandom` lives in Chromium-internal state the CDP `Credential` struct never carries. Proven
empirically: same-authenticator asserts are stable, a re-added credential returns `prf.results = null`.
That makes keeper-PRF accounts impossible and the cleanup-fallback re-auth PRF-dead on CDP.

**Decision: remove CDP from E2E entirely** and route `navigator.credentials` to the vendored
`nid-webauthn-emulator` via its `BrowserInjection` hook. The authenticator runs Node-side in an emulator
we control; PRF state persists in a `PasskeysCredentialsFileRepository`. This unblocks keeper-PRF,
lets us use `hmac-secret-mc` (single-ceremony PRF, no renderer crash), unifies the auth path with the
server specs, and removes all CDP event/presence-simulation timing from the helpers.

Proven end-to-end 2026-07-12: injected `create` drives the real app's `@simplewebauthn` path and returns
a real 32-byte PRF `ArrayBuffer`.

### Fork prerequisite — DONE

`BrowserInjection` needed two JSON transform directions the fork lacked (the server specs never hit them
because they feed `createJSON`/`getJSON` pre-encoded JSON). Added symmetrically in
`webauthn-model-json.ts` on branch `feat/hmac-secret`, TDD'd, suite green, biome clean, re-vendored into
`vendor/nid-webauthn-emulator/dist/src`:
- **input encode** — `toExtensionInputsJSON`/`toPRFInputsJSON` in `toCreationOptionsJSON`/`toRequestOptionsJSON`
- **output decode** — `parseExtensionResultsFromJSON` in `parse{Registration,Authentication}ResponseFromJSON`
- the hook injects only **exported** functions and runs both transforms **in-page**, so the transform
  helpers are exported.

Owner owns: committing `feat/hmac-secret`, and the upstream PR.

## Harness — `apps/web/tests/common.ts`

**Remove (all CDP):** `setupAuthenticator`, `addCredential`, `clearCredentials`, `removeAuthenticator`,
`page.context().newCDPSession`, `WebAuthn.enable`/`addVirtualAuthenticator`, and the CDP internals of
`passkeyCreation`/`passkeyAuth` (the `credentialAdded`/`credentialAsserted` listeners, `setUserVerified`,
`setAutomaticPresenceSimulation`). Drop the `devtools-protocol` `Credential` type.

**Add — Node-side emulator injection:**
- `makeEmulator(mode)` → `new WebAuthnEmulator(new AuthenticatorEmulator({ hmacSecret, credentialsRepository }))`
  - `'prf'` → `hmac-secret-mc` (single-ceremony PRF — the default)
  - `'none'` → `none` (no-PRF / fallback path)
  - `'assert-only'` → `hmac-secret` (exercises the client's follow-up `get()` on create)
  - memory repo per test; **file repo** only for keepers.
- `attachEmulator(page, emulator)` → `exposeFunction(WebAuthnEmulatorCreate/Get, …createJSON/getJSON(origin, …))`
  + `page.addInitScript(HookWebAuthnApis)` so the hook re-applies on every navigation and every new tab.
  Multi-tab tests call `attachEmulator` per page against the **same** Node emulator (models one profile /
  synced passkeys).

**`passkeyCreation`/`passkeyAuth` collapse** to: run the UI trigger, await the relevant
`/reg|passkeys|auth/verify`. No events, no presence sim — the emulator resolves `create`/`get`
synchronously. The Case-B follow-up `get()` and the no-PRF **fallback dialog** fall out naturally (the
dialog opens after `create` resolves; the helper clicks `'standard'`/`'different'` then awaits verify —
deterministic).

**userCred (Node-side recompute):**
- no-PRF → plaintext from the `/reg/verify` response (as today).
- PRF → capture `passkeyUserCredEnc` from the verify **request** body; `emulator.getJSON(origin, { rpId,
  challenge, allowCredentials:[{id, type:'public-key'}], extensions:{prf:{eval:{first: PRF_SALT}}} })` →
  read `clientExtensionResults.prf.results.first` → `prfDecrypt(passkeyUserCredEnc, prfOutput, userId)`.
  (`PRF_SALT` + `prfDecrypt` mirror `apps/web/src/app/services/prf.ts`.)

**Default mode:** `createTestUser` defaults to **`'prf'`** (product default). `createTestUser(auth, 'none')`
covers no-PRF. Both auto-track user + passkey.

**Device presence:** one emulator with multiple resident credentials models "all my passkeys available."
The few tests that need a passkey *absent* on a context manipulate the repo (remove/re-add the credential
source, which preserves `credRandom`) rather than a second authenticator.

**Cleanup contract unchanged** (`trackUser`/`trackPasskey`/`addPasskey`; `@nukeall` stays clean). Fast-path
API delete works for both modes; the fallback re-auth now works for PRF too (emulator persists `credRandom`
for the test lifetime).

## Shared lifecycle suite

`lifecycle.suite.ts` exports `lifecycleSuite(prf: boolean)` (mirrors the server `core.suite.ts` pattern).
Thin clients:
- `parallel/lifecycle.spec.ts` → `lifecycleSuite(false)` — **no-PRF**; asserts **badge absent**; ports every
  current lifecycle test; adds *add-a-PRF-capable-passkey-to-a-no-PRF-account stays no-PRF (badge absent)*.
- `parallel/prf-lifecycle.spec.ts` → `lifecycleSuite(true)` — **PRF** (`hmac-secret-mc`); asserts **badge
  present**; ports every current lifecycle test; adds *add-a-no-PRF-passkey → `prfUnsupported` no-downgrade*.

Internal `if (prf)` branches only for: badge present/absent, userCred source, add-passkey direction, and
the **recompute-vs-`/cmdline` userCred equality** check (run in both modes, as a dedicated assertion — not
the per-user cleanup path).

Because the emulator persists credentials for the test lifetime, the re-add-heavy tests (e.g. *3 tabs switch
user*) port to PRF cleanly — the CDP "re-add kills PRF" problem is gone. Per-test porting notes captured as
the slice lands.

## New / updated specs

- `parallel/prf-fallback.spec.ts` — `'standard'` completes the **same** passkey → no-PRF account (badge
  absent, plaintext userCred); `'different'` discards + recreates → PRF account (assert no leaked/dup
  passkey; `@nukeall` clean).
- Existing specs migrate to injection; default PRF: `basics` (done), `edit`, `login-relay`, `lazy-routes`.
  The `create.spec.ts` keeper tool is handled with the keeper work (see Keepers), not here. One Case-B create
  test to exercise `_readPrfViaAssertion`.

## Keepers — keeper2 → PRF, keeper1 → no-PRF

Feasible now via the file repo. `.creds.json` changes from the CDP `Credential` to the emulator **credential
source** (carries `credRandom`) + recovery words. Regenerate keeper2 as a PRF account and keeper1 as no-PRF
through the injection create flow; `sequential/encryption.spec.ts` + `sequential/errors.spec.ts` load the
saved credential into the emulator repo instead of `addCredential`. Keeper skip-guards (`haveKeeperCreds`)
stay. **Owner must regenerate `E2E_CREDS_B64`** once the new `.creds.json` exists.

**Keeper-provisioning tool (`apps/web/tests/create.spec.ts`).** This is the manual, run-by-hand tool that
creates the persistent keeper accounts (deliberately untracked so they survive; `console.log`s the
credential + recovery words to paste into `.creds.json`). It is NOT run by the e2e runner. It still uses the
old CDP fixture and must be updated with the keeper work, since it needs the shared serialize/deserialize
emulator-credential API (credential source + `credRandom`) that the keeper specs also use. Design that API
once and use it in both the tool and the keeper specs. **TODO: rename `create.spec.ts` → `keeper.spec.ts`**
so its purpose is obvious (it is neither the automated create-path test — that lives in
`parallel/basics.spec.ts` — nor part of the run suite).

## Build order (vertical slice first)

1. **Slice — DONE.** Rewrote `common.ts` to injection + built `lifecycle.suite.ts(prf)`. Full lifecycle
   ported both modes (18 tests green): log in/out, check usercred (+ recompute-vs-`/cmdline`), check usercred
   and add pk, full lifecycle, delete active passkey signs out, regenerate recovery words, 3 tabs logout and
   forget, 3 tabs switch user, plus PRF add-passkey no-downgrade / no-PRF stays-non-PRF. The two-authenticator
   model (`newAuthenticator(mode)`) replaces CDP credential-swapping.
2. **`lifecycle.spec.ts` (no-PRF) + `prf-lifecycle.spec.ts` (PRF) — DONE**, thin clients of the suite.
3. **XSS username-sanitization — DONE**, added to `parallel/basics.spec.ts` (mode-independent, one no-PRF
   account). This is the automated create-path test; the `create.spec.ts` keeper tool is separate (see Keepers).
4. **Remaining `parallel/` specs — DONE.** `edit` (2), `login-relay` (15, byte-identical assertions +
   second-CDP-session collapsed to `passkeyAuth(auth, trigger, {page})`), `errors` (7 ported + 1 new
   wrong-device case), `lazy-routes` (13, no migration needed). Full `parallel/` suite: **60 green**.
   Error-path "no matching passkey" is simulated with a fresh empty `newAuthenticator()` (was
   `clearCredentials`); the new `another account passkey on device` case covers a populated-but-wrong device.
5. **`prf-fallback.spec.ts` — DONE.** `'standard'` completes the same passkey → no-PRF account (1 create,
   badge absent); `'different'` discards + recreates on a PRF authenticator → PRF account (2 creates, badge
   present). A `credentialCreateCount()` fixture counter is the regression signal; `createTestUser` gained an
   optional `differentAuth` for the 'different' path.
6. Keepers last: update the `create.spec.ts` provisioning tool + design the serialize/deserialize credential
   API, regenerate `.creds.json` (keeper2 PRF / keeper1 no-PRF), port `sequential/` specs, rename
   `create.spec.ts` → `keeper.spec.ts`, hand off `E2E_CREDS_B64` regen to owner.

Run: `pnpm test:e2e -- --reporter=list` (`-g "<name>"` to focus). The runner owns a frozen serve; a
watch-serve on :4200 blocks it, so stop that first or run `playwright test` directly against the running
serve during iteration.

## Risks / open items

- **Fork uncommitted** + upstream PR owed (owner).
- **`E2E_CREDS_B64` regen** after keeper `.creds.json` reformat (owner) — else prod-release CI keeper tests fail.
- **Fidelity note:** injection replaces Chromium's WebAuthn stack with a JS shim. Still exercised: the app,
  `@simplewebauthn` option-encode / result-parse, and the real server. No longer exercised: Chromium's
  native WebAuthn plumbing (which the CDP virtual authenticator wasn't either).
- **Multi-tab device semantics:** confirm each ported multi-tab test's intent maps to repo state (credential
  present/absent) rather than CDP authenticator presence.
