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

## Keepers — keeper2 → PRF, keeper1 → no-PRF — CODE DONE + LOCAL KEEPERS VERIFIED

Persistence switched from the single `.creds.json` (CDP `Credential`) to the emulator's own
**`PasskeysCredentialsFileRepository`**: one dir per keeper per host at
`apps/web/tests/keeper-creds/<host>/<keeper>/` (gitignored), holding one credential `.json` that carries
`credRandom` for PRF. Separate dirs give unambiguous *discoverable* sign-in ("I have used Quick Crypt") — the
dir name identifies the keeper, no credential→keeper map needed. Mode is **inferred** from `credRandom`
presence, so no metadata file.

- **`common.ts`:** `memAuthenticator(mode)` (was `newAuthenticator`, MemoryRepository) + two explicit file
  helpers: **`provisionAuthenticator(dir, mode)`** (FileRepository; a created passkey persists to dir — for
  the tool) and **`loadAuthenticator(dir)`** (reads the stored credential into an **in-memory copy**, infers
  PRF — for the keeper specs). `keeperDir(host, keeper)` helper; `haveKeeperCreds` = the keeper-creds dir
  exists. Removed `.creds.json`/`credentials`/`addCredential`.
- **`sequential/encryption.spec.ts` + `sequential/errors.spec.ts`:** load via
  `loadAuthenticator(keeperDir(host, keeper))` + `passkeyAuth`; skip-guards stay; **skip cleanly** with no creds.
- **`create.spec.ts` → `keeper.spec.ts`** (renamed): manual provisioning tool, edit-the-config-object,
  `provisionAuthenticator(dir, mode)` create → credential auto-persists; guards against overwriting a
  non-empty dir. Not run by the e2e runner; run commands (needs `--config` + `--project` for baseURL) are in
  its header. **Recovery words are discarded** — keeper specs never test recovery, and a lost passkey is
  fixed by re-running the tool (capture code is commented out, one line to restore if that changes).
- **CI workflows (`playwright.yml`, `new-version.yml`) already updated:** restore via
  `base64 -d | tar -xzf - -C apps/web/tests`.

**nid FileRepository race (found + worked around; separate upstream fix owed).** The emulator re-saves a
credential on every assertion (signCount) via delete-then-write, and `PasskeysCredentialsFileRepository`'s
`deleteCredential` uses **async `fs.unlink`** while `saveCredential` uses **sync `writeFileSync`** — the
unlink races the write and intermittently drops the file. `loadAuthenticator`'s in-memory copy dodges it
(disk never mutated on sign-in) and keeps keeper files immutable (stable `E2E_CREDS_B64`). Still owed: a
**standalone upstream PR** fixing the FileRepository to unlink synchronously (independent of the hmac-secret PR).

**Status — E2E PHASE COMPLETE (2026-07-24).** Keepers are provisioned and e2e-verified on **both** hosts —
local (`t1.quickcrypt.org`) and prod (`quickcrypt.org`) — the full suite passes including the new keeper
PRF-badge check, and `E2E_CREDS_B64` has been regenerated. The FileRepository PRF round-trip (credRandom → PRF
output → decrypt `passkeyUserCredEnc`) is validated end-to-end. No keeper/E2E TODOs remain.

**PRF-mode validation added (2026-07-24).** A gap surfaced when prod keepers were provisioned: keeper mode was
only inferred from `credRandom` and asserted nowhere at the app level, so a keeper made in the wrong mode passed
every keeper spec (encrypt/decrypt works either way) — and prod **KeeperOne was created WITH PRF and still
passed full e2e**. Closed it: `keeperPrf` map in `common.ts` (`{keeper1:false,keeper2:true}`) is the single
source of truth; `sequential/keepers.spec.ts` signs in as each keeper and asserts the shared
`expectPrfBadge(page,prf)` (credentials-drawer badge) every CI run; `keeper.spec.ts` now derives its `mode`
from `keeperPrf` (no hand-set `mode`) and asserts the badge right after creation. **KeeperOne has since been
re-provisioned no-PRF and the full suite (incl. the badge check) is green on both hosts.**

**Upstream nid PRs — DONE:** nid accepted **both** PRs (hmac-secret feature + FileRepository sync-unlink race)
**unchanged**, expected in the next nid release. Once released, `vendor/nid-webauthn-emulator` can be dropped
for the published package (optional cleanup, not required for CI).

(Reprovision command, for reference:
`NODE_EXTRA_CA_CERTS=./apps/web/localssl/qcrypt.pem pnpm exec playwright test --config apps/web/playwright.config.ts apps/web/tests/keeper.spec.ts --project=local`)

## Build order (vertical slice first)

1. **Slice — DONE.** Rewrote `common.ts` to injection + built `lifecycle.suite.ts(prf)`. Full lifecycle
   ported both modes (18 tests green): log in/out, check usercred (+ recompute-vs-`/cmdline`), check usercred
   and add pk, full lifecycle, delete active passkey signs out, regenerate recovery words, 3 tabs logout and
   forget, 3 tabs switch user, plus PRF add-passkey no-downgrade / no-PRF stays-non-PRF. The two-authenticator
   model (`memAuthenticator(mode)`) replaces CDP credential-swapping.
2. **`lifecycle.spec.ts` (no-PRF) + `prf-lifecycle.spec.ts` (PRF) — DONE**, thin clients of the suite.
3. **XSS username-sanitization — DONE**, added to `parallel/basics.spec.ts` (mode-independent, one no-PRF
   account). This is the automated create-path test; the `create.spec.ts` keeper tool is separate (see Keepers).
4. **Remaining `parallel/` specs — DONE.** `edit` (2), `login-relay` (15, byte-identical assertions +
   second-CDP-session collapsed to `passkeyAuth(auth, trigger, {page})`), `errors` (7 ported + 1 new
   wrong-device case), `lazy-routes` (13, no migration needed). Full `parallel/` suite: **60 green**.
   Error-path "no matching passkey" is simulated with a fresh empty `memAuthenticator()` (was
   `clearCredentials`); the new `another account passkey on device` case covers a populated-but-wrong device.
   With `prf-fallback` (step 5) the full `parallel/` suite is **62 green**.
5. **`prf-fallback.spec.ts` — DONE.** `'standard'` completes the same passkey → no-PRF account (1 create,
   badge absent); `'different'` discards + recreates on a PRF authenticator → PRF account (2 creates, badge
   present). A `credentialCreateCount()` fixture counter is the regression signal; `createTestUser` gained an
   optional `differentAuth` for the 'different' path.
6. **Keepers — DONE (code) + local verified.** Switched to the emulator `PasskeysCredentialsFileRepository`
   (per-keeper dir, PRF inferred from `credRandom`), `provisionAuthenticator`/`loadAuthenticator` split,
   worked around the nid FileRepository unlink/write race via in-memory load, renamed the tool to
   `keeper.spec.ts`, updated CI to `tar -xzf`. Local keepers provisioned; sequential specs pass. See the
   Keepers section above for the owner TODO (E2E_CREDS_B64 regen, prod keepers, upstream nid PR).

Run: `pnpm test:e2e -- --reporter=list` (`-g "<name>"` to focus). The runner owns a frozen serve; a
watch-serve on :4200 blocks it, so stop that first or run `playwright test` directly against the running
serve during iteration.

## Risks / open items

- **Fork uncommitted** + upstream PR owed (owner).
- **`E2E_CREDS_B64` regen** after the keeper-creds reformat (owner) — else prod-release CI keeper tests fail.
- **Fidelity note:** injection replaces Chromium's WebAuthn stack with a JS shim. Still exercised: the app,
  `@simplewebauthn` option-encode / result-parse, and the real server. No longer exercised: Chromium's
  native WebAuthn plumbing (which the CDP virtual authenticator wasn't either).
- **Multi-tab device semantics:** confirm each ported multi-tab test's intent maps to repo state (credential
  present/absent) rather than CDP authenticator presence.
