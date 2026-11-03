# ProVerif models of the Quick Crypt protocol

These are symbolic (Dolev-Yao) models of the protocol in `apps/web/src/assets-src/main.tex`,
checked with [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) 2.05. The models follow
the **code** wherever it differs from the tex.

## Running

```bash
# One time. The opam package needs GTK2 for ProVerif's interactive simulator.
sudo apt install opam m4 graphviz libgtk2.0-dev pkg-config
opam init -y --no-setup && opam install -y proverif

pnpm verify:proverif               # every variant; non-zero exit on any mismatch
node formal/proverif/run.mjs loops # only variants whose name contains "loops"
node formal/proverif/run.mjs --print commit   # show actual results as EXPECTPV blocks
```

The runner uses `$PROVERIF` if set, then `proverif` on `PATH`, then
`~/.opam/default/bin/proverif`. `QC_PROVERIF_TIMEOUT` sets the timeout for each variant in
seconds; the default is 900. `QC_PROVERIF_JOBS` sets how many variants run at once; the default
is half the CPU count, capped so each run has 4 GB of RAM.
A runaway saturation can use all available memory, so when experimenting with a model, run it
under `ulimit -v` (for example `ulimit -v 2000000` for 2 GB). The runner reports a process that
was killed, rather than a result. Generated `.pv` files and the full ProVerif output, including
attack traces and derivations, go to `dist/proverif/`.

`verify:proverif` is not part of any aggregate build or test script, because it needs opam.
Run it after any change to the protocol code, the tex, or a model.

## Layout

| File | Contents |
|---|---|
| `lib/qcrypt.pvl` | Primitives shared by every model |
| `cipher.pv.m4` | The V8 message format: block 0, block N, loops, hint, the V7 decode path, and u_c at rest |
| `account.pv.m4` | Registration, sign-in, authorized requests, passkeys, recovery words, recovery; honest and malicious server |
| `run.mjs` | Builds each variant with `m4 -P` and checks its results |
| `traces.mjs` | Lists every trace in the saved output, query by query, for review |
| `RESULTS.md` | Each variant's results, and what each attack and reachability trace shows |

Each template lists its variants in a `VARIANTS` block, one per line: a name followed by m4
flags. The main flag groups are:
- `SCN_*` selects the scenario.
- `LEAK_*` gives the attacker a secret.
- `MUT_*` deliberately breaks one protocol mechanism.
- The rest set options, described where they are used, here or in `RESULTS.md`: `NOPRF`,
  `DUALMODE`, `STRIPLOGIN`, `STORE`, `RCV`, `UNIQUSER`, `NOBT`, `PRECISE`, `KEY_UI`, `REACH_ONLY`,
  `MAL_RECOVERY`, `USE_V7`, `GENERIC_API`, `LOG_NOREGVER`, `EXISTING`, `FIRSTUSE`, `TWOACCOUNTS`
  and `REAUTH`.

The expected results for each variant sit at the end of the template in ProVerif's own
`EXPECTPV … END` comment format, so each generated `.pv` file is self-checking.

**To add or change a query:**
1. Edit the template.
2. Run with `--print`.
3. Read every trace in each variant the change affects, not only the results that changed.
   `node formal/proverif/traces.mjs --compact <variant>` lists each trace's events, the messages
   received, and the writes to the `users`, `recov`, `creds` and `pins` tables. The filter
   matches output file names such as `account-login-tls`.
   Confirm three things:
   - **Attack traces:** each one is the attack the variant names, and uses only steps the real
     system allows.
   - **Reachability traces:** each one is the honest run the related proof is about, for example
     Alice's own sign-in rather than one on the attacker's account. A proof without such a trace
     may hold only because the path it covers never runs.
   - **"cannot be proved" results:** each one has a written reason, and another variant shows the
     trace.
4. Paste the new block.
5. Record what each trace shows in `RESULTS.md`.

A result that matches its `EXPECTPV` line is not evidence on its own. The expected line can encode
a mistake, so never paste a result whose trace you have not read and explained.

## Names

The name each model uses for a `main.tex` symbol.

**Message format** (`cipher.pv.m4`, `lib/qcrypt.pvl`):

| Tex | Model | Notes |
|---|---|---|
| u_c, p, h | `uc`, `p`, `HINT` | |
| m_0, m_N | `MSG0`, `MSG1`, `MSG2` | fixed secret messages |
| a | `GCM`, `XCC`, `AEGIS` | type `alg` |
| v | `V8`, `V7` | |
| f | `F0`, `F1` | |
| e_l | `EL0`, `EL16` | messages, data at rest |
| i | `IC`, `IC0` | a valid count, and 0 |
| lp, le | `lp`, `le` (`LP1`, `LP2`) | |
| n_S, n_IV | `nS`, `nIV` | |
| t_L at the start of a loop | `TL0` | |
| kp_S, kp_H, kp_B, kp_C, kp_M, kp_U, kp_R | `kpS`, `kpH`, `kpB`, `kpC`, `kpM`, `kpU`, `kpR` | |
| D_H(n, kp, k) | `kdf(n, kp, k)` | subkey numbers `ID0`-`ID2`, blocks `B1`, `B2` |
| H_k(n_S, a, v, lp, e_l[, e]) | `hmix(k, xctx8(...))` | `mkX8`, `xAR` build the second argument |
| D_P and its material | `pbkdf`, `pwmat8` (`pwmat7`) | |
| E_a, E_a⁻¹ | `aead_enc`, `aead_dec` | |
| H_{k_S}(v‖l‖ad_F‖m_E‖t_L) | `mac(kS, macin(...))` | |
| n_IVH, k_H, k_S, k_M0, k_C, k_MN | `mkNIVH`, `mkKH`, `mkKS`, `mkKM0`, `mkKC`, `mkKMN` | `NOKC` for no k_C |
| ad_F for block 0 and block N | `ad0`, `adN` | |
| cd_0, cd_N | `blk(t, v, ad_F, m_E)` | built by `mkBlock0L`, `mkBlockN` |

**u_c at rest:**

| Tex | Model | Notes |
|---|---|---|
| cd_x | `mkAR`, `openAR` (cipher); `mkAtRest`, `openAtRest` over `ar_enc` (account) | |
| e | `UI` (cipher), the user id (account) | |
| k_KS, s | `kKS`, `SLOT` | |
| k_L | `dsl(kKS, (SLOT, pkId))` | |

**Account** (`account.pv.m4`):

| Tex | Model | Notes |
|---|---|---|
| u_i | `ui` | |
| u_i^* in a reply | `sui` | |
| u_i^* in ro | `oui`; `ui` at registration | |
| u_i in the new passkey's user handle | `hui` | at add passkey and recovery, the session's or words' `ui`, checked against `oui`; `MUT_SERVERHANDLE` takes `oui` |
| u_i in ar, the user handle | `uh` | |
| u_r, u_r‖u_i | `ur`, `rsec(ur, ui)` | |
| sk_U, pk_U | `proofKey(uc)`, `pkU` = `sig_pk(proofKey(uc))` | |
| sk_R, pk_R | `recoveryKey(ur, ui)`, `pkR` | |
| p_S, p_R | `PS`, `wa_prf(credKey, PS)` | |
| cd_p, cd_r, cd_u | `cdp`, `cdr`, `cdu` | |
| account tag in a user handle or word set | `ucid(uc)`; `NOTAG` for an untagged handle or 24-word set | a one-way function of u_c |
| prf | `PRF0`, `PRF1`; `sprf`, `sprf2` in replies | `sprf2` is the tex's prf^* |
| pkId, pk_M | `credId`, `credPk` = `wa_pk(credKey)` | `spkId` in a reply |
| M's passkey secret | `credKey` | |
| ro, rr | `(ch, oui)`, `regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN))` | |
| ar | `(credId, uh, ad, cd, wa_sign(credKey, (ad, cd)))` | `cdj(WA_GET, ch, ORIGIN)` |
| o | `ORIGIN` | |
| ch | `ch`, `chR` | `chR` is the confirm challenge |
| n_P, n_R | `nP`, `nPR` | |
| m_U, m_R, m_G | `muc(ui, mth, pth, nP, sha256(bd))`, `mrc(ui, nPR)`, `mrg(ui, ch, pkU)` | no timestamps or qs; the challenge form of m_U has ch in nP's place |
| σ_U, σ_R, σ_G | `sig_sign(proofKey(uc), ...)`, `sig_sign(recoveryKey(ur, ui), ...)` | |
| sc_U, sc_P, sc_R, sc_W, sc_G | `SCU`, `SCP`, `SCR`, `SCW`, `SCG` | sc_P for the challenge form of σ_U, sc_G for σ_G |
| ck, cs | `cookie(ui, sid)`, `csmac(skJWT, ui, sid)` | |
| H_2 | `sha256` | |
| b | the binding slot of `chal`: `pkU` for "reg" and "add", `(pkR, cnt)` for "confirm", `(pkR, cnt, pkU)` for "recover", `NOBIND` for "auth" | pk_U and `cnt` are compared, pk_R is not; the code also binds "confirm" to pk_U |
| c_A | `cnt`, a fresh name for each value an increment produces | only the values a challenge is bound to |
| "reg", "add", "auth", "recover", "confirm" | `PREG`, `PADD`, `PAUTH`, `PRECOVER`, `PCONFIRM` | |
| "api", "words" | `NAPI`, `NREC` | |

**Persisted state:**

| Tex | Model | Notes |
|---|---|---|
| S.chal | `chal(purpose, ch, ui, binding)` | |
| S.nonce | `NonceStored(purpose, nP, st)` events, made unique by the `STORE` restriction | |
| S.user's c_A | `Incremented(cnt, st)` events, made unique by the `STORE` restriction | an increment by recover/confirm or recover/verify of the value its challenge is bound to |
| S.user | `unverified(ui, pkU)`, `users(ui, pkU)`, `recov(ui, pkR, cdr)`; no-PRF `ucenc(ui, enc, encOld)` | |
| S.pk | `creds(ui, credId, credPk, cdp)` | |
| B.pin | `pins(bid, ui, prf, pkU)` | |
| B.sess | `sessions(aid, bid, ui, uc, pkId, ck, cs)` | holds u_c rather than cd_u |
| B.key | not a table; `kKS` per session | |
| M's passkeys, Alice's words | `passkeys(aid, uh, tag, credId, credKey)`, `words(aid, ui, ur, tag)` | |

## Shared assumptions

**Primitives.** These are ideal, with two deliberate exceptions where the attacker is made
stronger:
- **AES-GCM and XChaCha20-Poly1305 are not key-committing.** An attacker who knows two keys can
  build one ciphertext that decrypts under both, even with different associated data
  (`nc_forge`). AEGIS-256 is modeled as committing.
- **Signatures are not assumed to hide their message.**

**Encodings.** Every byte concatenation is modeled as an unambiguous tuple. That is sound only if
each real encoding can be parsed back into its fields in exactly one way. The argument for each
encoding:
- **E1. H_k(n_S‖a‖v‖lp‖e_l‖e).** Fields are 16, 2, 2 and 1 bytes, then the e_l byte, then e.
  e_l gives the length of e. For messages e_l = 0, so e is empty. For data at rest, e_l = |u_i|.
  The `u_i` length is capped at 255 but not fixed at 16; that is still injective because e_l
  records it. Source: `keys.ts:MasterKeyKeyProvider._extraContext`,
  `keys.ts:PWDKeyProviderV8._extraContext`.
- **E2. PBKDF2 material (V8).** p_l (4 bytes, LE) ‖ p ‖ u_c (32) ‖ a ‖ v ‖ lp ‖ e_l ‖ e. p_l
  delimits p, the next fields have fixed widths, and e_l delimits e. Source:
  `keys.ts:PWDKeyProviderV8._cipherKeyMaterial`. V7 had no p_l, but the web app always passes an
  empty e, so V7 parses uniquely from the end.
- **E3. k_C input.** H_{k_M0}(n_S): a single fixed-width field.
- **E4. MAC input.** v (2) ‖ l (3) ‖ ad_F ‖ m_E ‖ t_L.
  - l fixes |ad_F‖m_E|.
  - Inside block 0's ad_F, a fixes the n_IV width, and h_El and k_Cl delimit h_E and k_C. m_E is
    whatever remains of l.
  - t_L is the rest of the input: 1 byte for block 0 and 32 bytes for every later block. So the
    two kinds of block can never be confused. This justifies using separate constructors for
    block-0 and block-N associated data in the model.
- **E5. m_U.** Fields are joined with `\n`, and no field can contain a `\n`:
  - u_i and n_P, or the challenge in n_P's place, are base64url;
  - the method is uppercase letters;
  - the path and query string are percent-encoded;
  - ts is decimal;
  - the body hash is lowercase hex.

  The optional query string turns 6 fields into 7, which is also unambiguous. The nonce form,
  for authorized requests, is signed under sc_U, and the challenge form under sc_P, so neither
  passes as the other. Challenge-form proofs at different endpoints share sc_P and are told apart
  by the path. Source: `proof.ts:buildUserCredMessage` in `libs/api`.
- **E6. m_R.** u_i, ts and n_R joined with `\n`, by the same reasoning as E5. It uses a different
  key derivation (kp_R) and a different context from m_U. m_G, the registration proof made with
  sk_R, joins u_i, ts, the challenge and pk_U the same way, all base64 text except ts, under its own
  context sc_G. Source: `proof.ts:buildRecoveryNonceMessage` and
  `proof.ts:buildRecoveryChallengeMessage` in `libs/api`.
- **E7. D_H.** `crypto_kdf_derive_from_key` puts the 8-byte purpose in the BLAKE2b
  personalization and the subkey id in the salt. These are separate fields, so (id, purpose,
  key) is injective. In particular, `Cmit_Key` can never collide with any `Blck_Key` block
  number.
- **E8. k_L input.** s (the fixed 13-byte string `user-cred-key`) ‖ pkId. Source:
  `keystore.service.ts:_deriveKey`.
- **E9. Recovery secret.** u_r (16) ‖ u_i (16), taken from 32 bytes of BIP39 entropy.
- **E10. Challenge binding.** H(pk_U) for registration and add-passkey challenges. For confirm and
  recover challenges, H(pk_R ‖ ":" ‖ authCount ‖ ":" ‖ pk_U), where pk_R and pk_U are base64 text
  and so contain no ":", authCount is decimal, and pk_R may be empty. Source:
  `server.ts:buildChallenge`.

**Not covered:**
- computational strength, including PBKDF2 cost, nonce-collision bounds and length leaks;
- side channels;
- the browser running anything other than the published code;
- the origin and rpId the server builds from headers CloudFront sets, which the models fix as
  constants;
- WebAuthn sign counters, which the server ignores;
- the legacy `/v1/recover` path, and the endpoints outside registration, sign-in, authorized
  requests, adding passkeys, replacing words and recovery: session and user reads, passkey and
  user updates, passkey deletion, invitables and the internal routes.

## Message format model (`cipher.pv.m4`)

**Attacker.** The attacker controls the network and every ciphertext. It can ask Alice to
encrypt plaintexts it chooses, and can send her anything to decrypt. `LEAK_*` flags also give
it Alice's secrets.

**Bounds.**
- Messages have at most 3 blocks, and loops are at most 2 deep.
- The two-loop model uses one block per loop.
- Proofs are for unbounded sessions within those shapes.

## Account model (`account.pv.m4`)

### What is modeled

**Scenarios:**
- **`SCN_LOGIN`:** registration, sign-in, authorized requests, and adding passkeys.
- **`SCN_RECOVERY`:** registration, replacing recovery words, and recovery.
- **`SCN_MALICIOUS`:** registration, sign-in and adding passkeys against a malicious server.
  `MAL_RECOVERY` adds recovery, both from the registering browser and from a browser with no pin.
  `TWOACCOUNTS` adds a second account on the same browser, and `REAUTH` reauthentication.
  `EXISTING` starts from an account registered before the account tags, with an untagged passkey
  and 24-word set: the server is honest in phase 0 and the attacker takes it over in phase 1, or
  with `FIRSTUSE` the attacker is the server from the start.

**The browser's checks.** Alice's browser compares the user id in each server reply with the one
it already holds for that flow. It also checks the u_c it resolves against the account tag in her
passkey's user handle or her recovery words. Every session writes that tag, from the u_c it holds,
into each passkey and word set it creates. A credential without a tag falls back to the browser's
pin, or to trust on first use when there is none. A failed check stops the flow.

**Account modes.** Accounts are in PRF mode unless `NOPRF` is set. With `NOPRF`, Alice's
authenticator has no PRF and the server takes the code's no-PRF branches:
- the browser creates u_c and sends it in reg/verify, and the server keeps it under a main and a
  backup KMS key;
- sign-in, recover3 and recover/verify return u_c in plaintext;
- passkeys/verify and recover/verify refuse a cd_p, and replace words ignores a cd_r.

Each variant's server serves one mode, for every account. An account's mode never changes, and
the server never decrypts a ciphertext a client supplied, so the attacker gains nothing from
accounts of the other mode. The exception is reg/verify itself: the server picks the mode from
which fields the request carries (`server.ts:postRegVerify`), so with TLS broken the attacker
picks Alice's mode. `DUALMODE` gives the `tls-dualmode` and `tls-stripped` variants a server
that accepts both request shapes, with Alice's PRF registration halting on a no-PRF reply. The
no-PRF → PRF upgrade is not modeled.

**Who the attacker is.** The attacker is a full client of the server, with its own accounts. In
`SCN_MALICIOUS` it is the server. The browser and the static site that serves its code are
always honest.

**Channels.** TLS is a private channel with a fresh reply channel per request. `LEAK_TLS` and
`SCN_MALICIOUS` make it public, from phase 1 under `EXISTING`. The server endpoints then still
run only on the TLS channel, which the attacker can already use; a second copy on the public
channel would only multiply clauses.

**Abstractions, each chosen so the attacker is at least as strong as in the real system:**
- **Server state lives in tables, which can only grow.** Deleted passkeys and replaced recovery
  keys therefore stay usable.
- **Uniqueness restrictions are opt-in, and off in the base variants that make the proofs.** Each
  mirrors a guarantee of the real system:
  - `STORE`: each challenge and each replay nonce is used once, and each authCount value is
    incremented once (the atomic delete-on-read, conditional put and add).
  - `RCV`: each private request is received by one server session.
  - `UNIQUSER`: each user id is registered once.

  Without them, the attacker gets more traces, so a proof made without them also holds with them.
  The variants that look for an attack or for reachability turn them on, and so do the `log`
  variants, whose replay queries test the stores. Without the restrictions, ProVerif finds
  derivations in those variants that no real run can follow: one request on the private TLS
  channel "received" by several server sessions, or one user id registered twice through the "no
  such user yet" branch of a table lookup, which is always available. Reconstructing a trace from
  such a derivation does not finish in practical time. Under the restrictions the derivations are
  executable, and traces come back in seconds without backtracking (`NOBT`). `RESULTS.md`, "Results
  that rest on restrictions", lists the results that hold only under them.
- **authCount only where a challenge is bound to it.** The code binds the confirm and recover
  challenges to H(pk_R : authCount : pk_U). The model binds each to a fresh value for the
  authCount that recover3's or recover/confirm's increment produces, and the handler that
  consumes the challenge increments that value; it also binds the recover challenge to pk_U. The
  model leaves out the other increments, the comparison of pk_R, and confirm's pk_U, so a
  sign-in, a logout, another recover3 or new words leave a challenge valid where the code voids
  it. It also leaves out recover/verify's check for an empty `lastCredentialId`,
  which fails only where the binding check already fails, since the write that sets it also
  increments authCount. These only add attacker runs.

  One choice here removes runs instead: the model makes the binding check and the increment one
  step. The code reads authCount before it consumes the challenge and increments it at the end
  of the handler. With the challenge store on, no second request passes in that window. With it
  off, a replay sent inside the window would pass the binding, and the `log` variants, whose
  copy comes after the increment, do not cover it.
- **Timestamps, the skew window and TTLs are not modeled, so the stores never forget.** `STORE`
  keeps every challenge and nonce for good. The code keeps a nonce for the challenge TTL (300 s)
  and rejects a proof whose timestamp is more than 120 s off (`CHALLENGE_TTL_SECS` in the
  server's `consts.ts`, `PROOF_SKEW_MS` in `libs/api`), so replay stays closed while twice the
  skew fits in the TTL. The model assumes that check and that bound; a fault in either is outside
  it.
- **WebAuthn registration is unsigned**, as with attestation `none`.
- **The PRF output does not depend on user verification.**
- **u_c at rest uses an abstract committing encryption.** Its three assumed properties are proved
  on the real format in `cipher.pv.m4` (C-A1 to C-A3).

**Termination.** Every process creates its fresh names before reading any input or table. A
name created after an attacker-influenced value can nest through the attacker without bound, and
then saturation never finishes. The browser keeps its state (passkeys, words, sessions, pins) in
tables for the same reason. This also lets Alice sign in with any passkey she holds, including
ones added later or created by recovery.

**`[precise]`.** `PRECISE` is not a restriction. It marks three actions `[precise]`: the inputs of
auth/verify and recover3, and the lookup of the words a recovery uses. Each of them receives or
reads one value per run, so it adds no assumption and removes no trace. In no-PRF mode, recover3's
reply does not depend on the words, and without it reconstruction combines two requests in one
server session, or two sets of words in one recovery, and fails. Marking every action precise
(`preciseActions`) does not finish in practical time. The recover/verify reply that ends every
recovery is always `[precise]`, since the browser reads its mode as a boolean and constraining it
to PRF or no-PRF otherwise breaks reconstruction.

**Choosing Alice's accounts.** Queries identify Alice's accounts as those whose pk_U is derived
from a u_c she created (`new ucA`). The `KEY_UI` variants identify them instead by the user id
her browser received at registration. An attacker that holds Alice's u_c, as with a KMS key in
no-PRF mode, can register an account of its own under her pk_U, so `login-noprf-db-kms` and
`login-noprf-db-kmsold` need `KEY_UI`. The TLS, PRF database and log variants use it too.
Registration needs a proof made with u_c, so in those variants the attacker cannot register her
pk_U under an account of its own, and pk_U alone may identify her accounts; that is not checked.

In no-PRF mode the server keeps the u_c a registration sends. Alice's accounts are then the ones
whose pk_U is derived from the u_c the server stored when it registered her passkey: the
registration whose user id, credential id and public key match a passkey she created (`ServerUc`
with `AliceCredCreated`). The same pairing gives the no-PRF u_c secrecy query.

## Summary of results

`RESULTS.md` gives each variant's result, the mutation that turns each proof into an attack, and
what each trace shows. The headline properties, for PRF accounts:

| ID | Property | Holds against | Fails against, as expected |
|---|---|---|---|
| C-S1 | Message blocks stay secret | an attacker missing p or u_c | an attacker with both |
| C-W1, C-H1, C-H2 | p cannot be guessed offline; the hint stays secret, and a shown hint is one Alice wrote | an attacker without u_c | an attacker with u_c |
| C-I1/2 | An accepted message is exactly one honest encryption, and each block released while streaming is a prefix of one | an attacker missing p or u_c | — |
| C-K1 | No block 0 is accepted under two different (p, u_c) | V8, with every algorithm | V7 with AES-GCM or XChaCha20-Poly1305 |
| C-A1 to C-A3 | u_c at rest stays secret, and the at-rest format commits to (k, u_i) | an attacker without k; the commitment always | — |
| A-L1, A-R1 | The server signs Alice in only with a passkey she approved, and every passkey on her account is one she created | a network attacker; a leaked session or cd_u; an unlocked device whose passkeys require user verification; a database copy; live challenge reads; a request log | a device whose passkeys do not require user verification; broken TLS (the registration race); leaked words (A-R1, through recovery) |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | the same | a device whose passkeys do not require user verification; broken TLS |
| A-K2 | The server stores Alice's pk_U or pk_R only from a reg/verify her browser signed | all of the above, and broken TLS | a device whose passkeys do not require user verification |
| A-S1, A-K1 | Alice's u_c stays secret | all of the above, and broken TLS | a device whose passkeys do not require user verification; leaked words |
| A-V1 to A-V3 | recover3, confirm and new words on Alice's account come from her browser | a network attacker; a leaked session; a database copy; live challenge reads; a request log | leaked words; broken TLS |
| A-N1 | A logged request of Alice's is never accepted again | a request log | — |
| A-S2, A-E1 | A malicious server never learns Alice's PRF u_c, and every u_c her browsers adopt stays secret from it | a malicious server, for new accounts | a malicious server, for an existing account's untagged credentials (A-E1) |
| A-D1, A-S3, A-S4, A-S3R, A-S4R, A-T1, A-U1 | The browser's pin, tag and user-id checks keep it on Alice's account and her u_c | a malicious server | — |
| A-S5 | Messages Alice encrypts stay secret from a malicious server, even one that learns her password | for new accounts, by A-E1 and C-S1 together (two separate models) | — |

**No-PRF accounts.** The server keeps u_c, so a malicious server knows it by design, and broken
TLS, a request log that holds the reg/verify body, or a database copy with a KMS key also expose
it.
