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

Each template lists its variants in a `VARIANTS` block, one per line: a name followed by m4
flags. The main flag groups are:
- `SCN_*` selects the scenario.
- `LEAK_*` gives the attacker a secret.
- `MUT_*` deliberately breaks one protocol mechanism.
- The rest set options, described where they are used: `NOPRF`, `DUALMODE`, `STRIPLOGIN`, `STORE`, `RCV`, `UNIQUSER`,
  `NOBT`, `PRECISE`, `KEY_UI`, `REACH_ONLY`, `MAL_RECOVERY`, `USE_V7`, `GENERIC_API`, `LOG_NOREGVER`,
  `EXISTING`, `FIRSTUSE`, `TWOACCOUNTS` and `REAUTH`.

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
5. Record what each trace shows in this README.

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
| u_i^* in ro, the new passkey's handle | `hui` | |
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
| ro, rr | `(ch, hui)`, `regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN))` | |
| ar | `(credId, uh, ad, cd, wa_sign(credKey, (ad, cd)))` | `cdj(WA_GET, ch, ORIGIN)` |
| o | `ORIGIN` | |
| ch, ch_R | `ch`, `chR` | |
| n_P | `nP` (API), `nPR` (recovery proofs) | |
| m_U, m_R | `muc(ui, mth, pth, nP, sha256(bd))`, `mrc(ui, nP)`; at registration, `mrg(ui, ch, pkU)` | no timestamps; the challenge form of m_U has ch in nP's place |
| σ_U, σ_R | `sig_sign(proofKey(uc), ...)`, `sig_sign(recoveryKey(ur, ui), ...)` | |
| sc_U, sc_P, sc_R, sc_W, sc_G | `SCU`, `SCP`, `SCR`, `SCW`, `SCG` | sc_P for the challenge form of σ_U, sc_G for the σ_R at registration |
| ck, cs | `cookie(ui, sid)`, `csmac(skJWT, ui, sid)` | |
| H_2 | `sha256` | |
| b | the binding slot of `chal`: `pkU` for "reg" and "add", `(pkR, cnt)` for "confirm", `(pkR, cnt, pkU)` for "recover", `NOBIND` for "auth" | pk_U and `cnt` are compared, pk_R is not; the code also binds "confirm" to pk_U |
| c_A | `cnt`, a fresh name for each value an increment produces | only the values a challenge is bound to |
| "reg", "add", "auth", "recover", "confirm" | `PREG`, `PADD`, `PAUTH`, `PRECOVER`, `PCONFIRM` | |
| "api", "nonce" | `NAPI`, `NREC` | |

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

## Attacker and abstractions

**Attacker.** The attacker controls the network and every ciphertext. It can ask Alice to
encrypt plaintexts it chooses, and can send her anything to decrypt. `LEAK_*` flags also give
it Alice's secrets.

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
- **E6. m_R.** u_i, ts and n_P joined with `\n`, by the same reasoning as E5. It uses a different
  key derivation (kp_R) and a different context from m_U. The registration proof made with sk_R
  joins u_i, ts, the challenge and pk_U the same way, all base64 text except ts, under its own
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

**Bounds.**
- Messages have at most 3 blocks, and loops are at most 2 deep.
- The two-loop model uses one block per loop.
- Proofs are for unbounded sessions within those shapes.

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

## Results: message format (`cipher.pv.m4`)

All 19 variants pass. Each takes under 15 s.

In the tables below, **true** means the property holds. **attack** means ProVerif found a trace,
and each such trace was read to confirm it is the attack named in the table.

### Properties

| ID | Property | Holds when | Attack, as expected, when |
|---|---|---|---|
| C-S1 | Message blocks stay secret | the attacker lacks p or u_c | it has both (`secrecy-both`) |
| C-W1 | p cannot be guessed offline | u_c is secret | u_c leaks (`secrecy-uc`): k_C and the AEAD give an offline test |
| C-H1 | The hint stays secret | u_c is secret | u_c leaks |
| C-H2 | A shown hint is one Alice wrote | u_c is secret | u_c leaks: the hint is authenticated only under u_c |
| C-I1/2 | An accepted 1-, 2- or 3-block message is exactly one honest encryption: no truncation, extension, reorder or splice | p or u_c is secret (`integrity-uc`, `integrity-p`) | — |
| C-I2 | Each block released while streaming is a prefix of an honest message | p or u_c is secret (`integrity-uc`, `integrity-p`) | — |
| C-I2 | No loop is stripped from a two-loop message | the inner password is secret, even when u_c and the outer password leak | — |
| C-K1 | No block 0 is accepted under two different (p, u_c) | V8: always, for all three algorithms | — |
| C-K1-v7 | The same game on V7 | AEGIS-256 | AES-GCM and XChaCha20-Poly1305 (`commit-v7`) |
| C-D1 | A V8 message is never accepted through the V7 decode path, and the reverse | u_c leaks, p secret | — |
| C-A1 | u_c at rest stays secret, and an accepted blob was encrypted under k for that same u_i | k is secret (`atrest-net`) | — |
| C-A2 | The at-rest format commits to (k, u_i) | always (`commit-*`) | — |
| C-A3 | No block is accepted both as a message and as u_c at rest | always, under any keys (`commit-*`) | — |

**About `commit-v7`.** It reproduces the externally reported V7 key-commitment incompleteness: one u_c,
two passwords, and one block 0 accepted under both. It fails for exactly the algorithms the
report names, and holds for AEGIS. V8 closes it for every algorithm.

**About `loops-uc-pout`.** The attacker holds u_c and the outer password, so as expected it can
replace the outer layer of Alice's two-loop message. It can also wrap her one-loop message as
the inner layer of a two-loop message, since nothing compares the inner le with the outer le. In
both traces the inner layer, and so the
plaintext, is still hers. The reachability traces in this variant use a message the attacker
built under the leaked outer password. `loops-uc` shows honest acceptance for the same processes.

### Mutations

Each mutation removes one mechanism, and each must turn a proof into an attack:

| Variant | Mechanism removed | Attack found |
|---|---|---|
| `commit-v8-nokc` | Comparing the stored k_C | Two passwords accepted for one ciphertext (GCM, XChaCha) |
| `integrity-uc-nof` | f in the AEAD AD (kept in the MAC) | An attacker holding u_c flips f on block 0 and truncates a 3-block message |
| `integrity-uc-non` | Block number in the k_MN derivation | A later block replayed one position early, dropping the block before it: block 2 of a three-block message, or the empty final block of a two-block message |
| `integrity-net-emptymid` | The encryptor writing an empty block only as the last one | Truncation with no secret leaked, since the decryptor does not check f on an empty block |
| `loops-uc-pout-nolple` | The outermost lp = le check | The inner layer of a two-loop message accepted on its own |

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
picks Alice's mode. `DUALMODE` gives `login-tls-dualmode` a server that accepts both request
shapes, with Alice's PRF registration halting on a no-PRF reply. The no-PRF → PRF upgrade is not
modeled.

**Who the attacker is.** The attacker is a full client of the server, with its own accounts. In
`SCN_MALICIOUS` it is the server. The browser and the static site that serves its code are
always honest.

**Channels.** TLS is a private channel with a fresh reply channel per request. `LEAK_TLS` and
`SCN_MALICIOUS` make it public.

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
  The variants that look for an attack or for reachability turn them on (see "Attack and
  reachability variants" below). So do the `log` variants, whose replay queries test the
  stores.
- **Not modeled:** timestamps, the skew window and TTLs.
- **authCount only where a challenge is bound to it.** The code binds the confirm and recover
  challenges to H(pk_R : authCount : pk_U). The model binds each to a fresh value for the
  authCount that recover3's or recover/confirm's increment produces, and the handler that
  consumes the challenge increments that value; it also binds the recover challenge to pk_U. The
  model leaves out the other increments, the comparison of pk_R, and confirm's pk_U, so a sign-in, a logout, another recover3 or new words leave a challenge valid where
  the code voids it. It also leaves out recover/verify's check for an empty `lastCredentialId`,
  which fails only where the binding check already fails, since the write that sets it also
  increments authCount. These only add attacker runs.

  One choice here removes runs instead: the model makes the binding check and the increment one
  step. The code reads authCount before it consumes the challenge and increments it at the end
  of the handler. With the challenge store on, no second request passes in that window. With it
  off, a replay sent inside the window would pass the binding, and the `log` variants, whose
  copy comes after the increment, do not cover it.
- **The stores never forget.** `STORE` keeps every challenge and nonce for good. The code keeps
  a nonce for the challenge TTL (300 s) and rejects a proof whose timestamp is more than 120 s
  off (`CHALLENGE_TTL_SECS` in the server's `consts.ts`, `PROOF_SKEW_MS` in `libs/api`), so
  replay stays closed while twice the skew fits in the TTL. The
  model assumes that check and that bound; a fault in either is outside it.
- **WebAuthn registration is unsigned**, as with attestation `none`.
- **The PRF output does not depend on user verification.**
- **u_c at rest uses an abstract committing encryption.** Its three assumed properties are proved
  on the real format in `cipher.pv.m4` (C-A1 to C-A3).

**Termination.** Every process creates its fresh names before reading any input or table. A
name created after an attacker-influenced value can nest through the attacker without bound, and
then saturation never finishes. The browser keeps its state (passkeys, words, sessions, pins) in
tables for the same reason. This also lets Alice sign in with any passkey she holds, including
ones added later or created by recovery.

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

### Results: honest server

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-L1 | The server signs Alice in only with a passkey she approved, for that challenge | `net`, `session`, `cdu`, `device` | `device-nouv` (an unlocked device without UV); `unbound-trace`, `session-noproof` (each via the passkey A-R1 lets the attacker bind); `tls` (registration race) |
| A-R1 | Every passkey bound to Alice's account is one she created | `net`, `session`, `cdu`, `device` | `unbound-trace` (C1); `session-noproof`; `device-nouv` (once u_c leaks); `tls` |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | `net`, `session`, `cdu`, `device`, **and** `unbound` | `session-noproof` (cookie and CSRF alone); `device-nouv` (once u_c leaks); `tls` (the attacker holds Alice's user id) |
| A-K2 | The server stores Alice's pk_U or pk_R only from a reg/verify her browser signed, for that challenge | every variant except `device-nouv` | `device-nouv` (once u_c leaks); the mutations `tls-regsigr-nopku`, `db-chal-noregsigu` and `db-noregsigr` |
| A-S1, A-K1 | Alice's u_c stays secret, including when cd_u or the session cookie leaks, or TLS is broken | every variant except `device-nouv` | `device-nouv` (sign-in without UV yields cd_p, and the device yields the PRF output) |

**What the mutations and leaks show:**
- **`login-unbound-trace` rediscovers C1**, a bug fixed before the models, as
  a full trace. A signed-in attacker posts
  `passkeys/verify` with a body naming Alice's u_i and any outstanding challenge. The mutated
  server takes the user from the body and binds the attacker's passkey to Alice's account, and
  the attacker then signs in to her account with it. Even then, A-Z1 holds and u_c stays secret:
  the proof of userCred contains the damage. `login-unbound` proves those two properties with no
  restrictions.
- **`login-tls` and `recovery-tls` show the registration race.**
  - With TLS broken, the attacker answers Alice's registration options with the user id and
    challenge from registration options it requested itself, with its own pk_U. It then completes
    that registration first, with its own passkey and keys and proofs made with them.
  - With attestation `none`, nothing in a registration response says who built it. The attacker
    then holds the user id Alice's browser received, and can sign in, make requests, and recover
    on it.
  - Alice's u_c and words stay secret, and her own registration fails, so she notices.
  - Registration integrity rests on TLS.
  - With TLS broken, the attacker can also act as the server toward Alice's browser, so the
    malicious-server results apply.
- **`login-tls-dualmode` and `login-tls-stripped` show the attacker choosing Alice's account
  mode.** The server picks the mode from which fields reg/verify carries.
  - `login-tls-dualmode` traces the registration. The attacker gives Alice's browser the user id
    and challenge of registration options it requested with its own pk_U. It then sends a no-PRF
    reg/verify that pairs her new passkey's registration response with its own keys and its own
    u_c. The honest server registers the user id her browser received, with her passkey, as a
    no-PRF account whose u_c the attacker chose. Her browser never completes the registration,
    so it pins nothing.
  - `login-tls-stripped` traces the rest, and holds. Alice later signs in with that passkey, with
    no attacker involved, and the honest server answers with the attacker's u_c. Her browser
    checks it against the tag in the passkey's user handle, which it wrote from her own u_c, and
    stops. `login-tls-stripped-nohandletag` removes that check, and her browser then signs in
    holding the attacker's u_c. The query ties the reply her browser accepted to that server
    session by its cookie, which only that session can make. Without the tie, ProVerif satisfies
    the browser half with a reply the attacker builds, and reconstruction fails.
  - `login-tls-stripped` leaves out API requests and added passkeys, on both sides, because
    with them saturation does not finish. Leaving out honest processes only removes runs, so
    its trace is a trace of the full system.

  Her own PRF u_c stays secret throughout.

**Reachability.** `login-reach` shows Alice's own runs reaching the server:
- her sign-in with her passkey;
- a request she signed;
- a passkey she added through `passkeys/verify`;
- her browser completing a sign-in while holding her own u_c.

Each server-side query pairs the server's event with an event that only Alice's browser or
authenticator emits, so the attacker's own account cannot satisfy it. The browser query requires
the browser and the u_c to come from the same Alice (`!1 = alice`).

The variant turns on the uniqueness restrictions, because without them reconstructing these
traces does not finish. A restriction only removes traces. The other login variants only add
attacker knowledge (`LEAK_*`), relax server checks (`MUT_*`), change queries (`KEY_UI`), or make
TLS public, and with TLS public the attacker can forward Alice's messages unchanged. So each trace
is also a run of every other login variant, apart from the `Rcv` events that `RCV` records.

### Results: recovery

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-V1 | recover3 accepts a proof on Alice's account only from her browser recovering it | `net`, `session`, every `log` variant except `log-onectx-noreplnonce` | `words` (words leaked); `tls` (registration race); `log-onectx-noreplnonce` (a replace-words proof under one shared context) |
| A-V2 | recover/confirm on Alice's account is one her browser signed, for that challenge | every variant except `words` and `tls` | `words`; `tls` (registration race) |
| A-V3 | New recovery words on Alice's account are ones her browser created | every variant except `words` and `tls` | `words` (the original words give recovery, then a session); `tls` |
| A-R1 | Every passkey bound to Alice's account, including by recovery, is one she created | every variant except these five | `words`; `tls` (registration race); `log-noconfirmchal-nobind-noproof`, `log-norecoverchal-nobind-noproof` (a reused challenge with no binding check and no recover/verify proof, see "Results: replay"); `db-chalrec-norecverifyproof` (see "Results: database leak") |
| A-S1 | u_c, the original words, and replaced words stay secret | every variant, except u_c and the original words in `words` | `words` |

**Reachability.** `recovery-reach` shows each step of Alice's own recovery:
- her recover3, with her nonce;
- her confirm;
- `recover/verify` binding a passkey she created;
- her browser finishing with her own u_c.

It also shows her replacing her words. As in `login-reach`, each server event is paired with
Alice's client event, and the uniqueness restrictions are on. By the same argument, each trace
is also a run of every other recovery variant.

### Results: replay

`LEAK_LOG` copies each request the server accepts to the attacker, as a request log or a proxy
that records traffic would. The copy is made after the server accepts the request. A copy made
on receipt could be forwarded and accepted before the original, which is the race that broken TLS
already covers, not a replay. GET requests are not logged, since the server lets them repeat
(`utils.ts:verifyUserCredNonceProof`). Nor are reg/options and auth/options, which need no credentials, so the
attacker can send its own.

A-N1 asks, for each request type, whether Alice's account accepts a request on the attacker's
channel. The attacker cannot produce her signatures or passkey assertions, so that happens only
when a logged request is used again, at its own endpoint or another. The mutations then switch
off one store at a time: `MUT_NOSTORE_<purpose>` lifts `STORE` for one challenge purpose or nonce
namespace, at every endpoint that uses it, and `MUT_NOREPLNONCE` removes only replace words'
nonce. recover/confirm and recover/verify also check their challenge's authCount binding, and
`MUT_NOBIND` removes that check. recover/verify also needs a proof made with u_c, which
`MUT_NORECVERIFYPROOF` removes. `MUT_SHAREDCTX` signs the challenge-form proofs under sc_U, the
context of authorized requests, and `GENERIC_API` adds an authorized endpoint that accepts any
path. A no-PRF reg/verify body carries u_c, so the no-PRF `log` variants other than
`login-noprf-log` leave that request out of the log (`LOG_NOREGVER`) to keep testing the stores.

| Variant | Mode | Store switched off | A-N1 | Other properties |
|---|---|---|---|---|
| `login-log`, `recovery-log`, `recovery-log-api` | PRF | none | holds | hold |
| `login-noprf-log-noregver`, `recovery-noprf-log` | no-PRF | none, with reg/verify left out of the log | holds | hold |
| `login-noprf-log` | no-PRF | none | **attack**: all but registration | A-L1, A-R1, A-Z1, A-K2 and u_c secrecy **attack**: the logged reg/verify body carries u_c |
| `login-log-sharedctx` | PRF | none, with sc_U for the challenge-form proofs | **attack**: authorized requests | A-Z1 **attack** |
| `recovery-log-api-sharedctx` | PRF | the same, with reg/verify left out of the log | **attack**: authorized requests | hold |
| `login-log-noapinonce` | PRF | `'api'` nonce | **attack**: authorized requests | hold |
| `login-log-noauthchal` | PRF | auth challenge | **attack**: auth/verify | hold |
| `login-log-noaddchal` | PRF | passkey-add challenge | **attack**: passkeys/verify | hold |
| `login-log-noapinonce-noaddchal` | PRF | both of those | **attack**: authorized requests, passkeys/verify | hold |
| `login-log-noregchal` | PRF | registration challenge | holds: the existing-user check blocks it | hold |
| `recovery-log-norecnonce` | PRF | `'nonce'`, used by recover3 and replace words | **attack**: recover3 | hold |
| `recovery-log-noconfirmchal` | PRF | confirm challenge | holds: the authCount binding blocks it | hold |
| `recovery-log-noconfirmchal-nobind` | PRF | confirm challenge, and no binding check | **attack**: confirm | hold: recover/verify needs a proof made with u_c |
| `recovery-log-noconfirmchal-nobind-noproof` | PRF | confirm challenge, no binding check, and no recover/verify proof | **attack**: confirm, recover/verify | A-R1 **attack** |
| `recovery-log-norecoverchal` | PRF | recover/verify challenge | holds: the authCount binding blocks it | hold |
| `recovery-log-norecoverchal-nobind` | PRF | recover/verify challenge, and no binding check | **attack**: recover/verify, with Alice's own passkey | hold |
| `recovery-log-norecoverchal-nobind-noproof` | PRF | recover/verify challenge, no binding check, and no recover/verify proof | **attack**: recover/verify | A-R1 **attack** |
| `recovery-log-noapinonce` | PRF | `'api'` nonce | holds: replace words' own nonce blocks it | hold |
| `recovery-log-noreplnonce` | PRF | replace words' nonce | holds: the `'api'` nonce blocks it | hold |
| `recovery-log-noreplnonce-noapinonce` | PRF | both of replace words' nonces | **attack**: replace words | hold |
| `recovery-log-onectx` | PRF | none, with one context for replace and recover | holds | hold |
| `recovery-log-onectx-noreplnonce` | PRF | replace words' nonce, with one context | **attack**: recover3 | A-V1 **attack** |
| `login-noprf-log-noauthchal` | no-PRF | auth challenge | **attack**: all but registration | A-L1, A-R1, A-Z1, A-K2 and u_c secrecy **attack** |
| `recovery-noprf-log-norecnonce` | no-PRF | `'nonce'` | **attack**: all but registration | all **attack** except word secrecy |
| `recovery-noprf-log-noconfirmchal` | no-PRF | confirm challenge | holds: the authCount binding blocks it | hold |
| `recovery-noprf-log-noconfirmchal-nobind` | no-PRF | confirm challenge, and no binding check | **attack**: confirm | hold: recover/verify needs a proof made with u_c |
| `recovery-noprf-log-noconfirmchal-nobind-noproof` | no-PRF | confirm challenge, no binding check, and no recover/verify proof | **attack**: all but registration | all **attack** except word secrecy |
| `recovery-noprf-log-onectx-noreplnonce` | no-PRF | replace words' nonce, with one context | **attack**: all but registration | all **attack** except word secrecy |

The logged requests also carry the session cookie, CSRF token and pk_U, so the PRF base variants
show that a full request log breaks none of the other properties. In no-PRF mode the logged
reg/verify body carries u_c, so `login-noprf-log` gives the attacker the account.

**What the traces show.** Most PRF traces replay one logged request unchanged, and the server
stores its nonce or consumes its challenge a second time. Four go further:
- **`recovery-log-noconfirmchal-nobind-noproof`:** the replayed confirm returns a fresh
  recover/verify challenge to the attacker, which binds its own passkey to Alice's account with
  it. In `recovery-log-noconfirmchal-nobind` the attacker gets the same challenge, but cannot
  bind a passkey without a proof made with u_c.
- **`recovery-log-norecoverchal-nobind-noproof`:** the attacker sends recover/verify again with
  Alice's logged challenge and its own passkey.
- **`recovery-log-onectx-noreplnonce`:** the attacker sends the proof from Alice's logged
  replace-words request to recover3, which accepts it once her new recovery key is stored.
- **`login-log-sharedctx` and `recovery-log-api-sharedctx`:** with the challenge-form proofs
  under sc_U, the attacker sends a logged reg/verify or recover/confirm proof, with the cookie
  and CSRF token from one of Alice's logged requests, as an authorized request, and the endpoint
  that accepts any path takes it. With sc_P, `recovery-log-api` holds.

A passkey the attacker binds in PRF mode carries its own cd_p, so it reveals nothing about u_c,
and every authorized request still needs Alice's proof. In no-PRF mode a replay hands the
attacker u_c: a replayed auth/verify or recover3 in its reply; with the binding check and the
recover/verify proof also off, a replayed confirm through the recover/verify reply for the
passkey the attacker then binds; and with one context and no replace-words nonce store, Alice's
logged replace-words proof sent to recover3, in that reply. With u_c the attacker signs requests of its own,
so the other A-N1 attacks in those variants are its own requests, not replays.
`recovery-noprf-log-norecoverchal-nobind` is left out, since its reconstruction does not finish
in 300 s, and `recovery-log-norecoverchal-nobind` shows the same reuse.

**Cross-use of recovery proofs.** The per-operation contexts alone keep a replace-words
proof from passing recover3: `recovery-log-noreplnonce` holds without replace words' nonce store.
The `onectx` variants sign and verify replace words under sc_R, as with one context for both
operations. The shared nonce store then keeps the two apart, and without it the logged
replace-words proof passes recover3. So the tex leaves the replace proof's store out (N2): the
request that carries the proof has its own `'api'` nonce, and the contexts do the rest.

**What A-N1 does not cover.**
- **GET requests,** which may repeat. A recorded `GET passkeys/options`, sent again within the
  120 s skew window, gives the attacker a new add challenge for Alice's account (`server.ts:getPasskeyOptions`).
  Using that challenge takes a passkeys/verify request with a new proof over its body, which
  needs u_c.
- **Rejected requests,** which are not logged. A replay of one is rejected again, unless the
  first attempt failed from a transient error, such as a failed database read, before its
  challenge was consumed or its nonce stored. That replay can be accepted once, within the skew
  window or the challenge's lifetime, and it carries only what Alice sent.
- **Replies,** since each goes to a fresh private reply channel.
- **The timestamp check,** since the stores never forget (see "What is modeled").
- **A replay inside one handler,** sent after recover/confirm or recover/verify reads authCount
  and before it increments, which the model makes one step. It can pass only with that
  challenge's store off (see "What is modeled").

**Why not injective queries.** An `inj-event` correspondence states one-to-one acceptance
directly, but on the login queries saturation had not finished after 300 s. Queries that a
request is accepted at most once end in "cannot be proved", from derivations where one server
session receives two requests. The log query needs neither, and each variant finishes in under a
second, apart from the no-PRF mutations.

### Results: malicious server

The attacker is the server. It answers every request and holds the database, the KMS keys and
the session keys, so Alice's browser has only its own checks ("The browser's checks" above).

The variants:
- **`malicious`:** a new PRF account, whose passkeys and words carry tags. Alice registers, signs
  in on the registering browser and on a browser with no pin, and adds passkeys.
- **`malicious-recovery`** (`MAL_RECOVERY`) adds recovery on both browsers. The model gives Alice
  her words only once registration completes, since the app shows them only in a signed-in
  session.
- **`malicious-twoaccounts`** (`TWOACCOUNTS`, `REAUTH`) adds a second account on the same browser,
  and reauthentication. The second account is added as data, with its tagged passkey, tagged
  words and pin, since a second run of `Register` does not terminate.
- **`malicious-existing`** (`EXISTING`) starts from an account with an untagged passkey and
  24-word set. The server is honest in phase 0, and the attacker takes it over in phase 1.
  `malicious-existing-firstuse` (`FIRSTUSE`) makes the attacker the server from the start.
- **`malicious-noprf`, `malicious-existing-noprf`:** the same in no-PRF mode, where the server
  knows u_c by design.

| ID | Property | Result |
|---|---|---|
| A-S2 | In PRF mode the server never learns Alice's u_c | **true** in every PRF variant |
| A-E1 | Every u_c any of Alice's browsers adopts stays secret from the server | **true** for new accounts; for existing ones, see below |
| A-D1 | A browser never treats Alice's PRF account as no-PRF when it uses a credential tagged with her u_c | **true** |
| A-S3 | Once registration has completed in a browser, that browser never adopts a u_c the server knows | **true**, including for an existing account's untagged credentials |
| A-S4 | A browser with no pin for the account never adopts a u_c the server knows when it signs in | **true** |
| A-S3R, A-S4R | The same two, by recovery | **true** in `malicious-recovery`, where A-S3R is also checked for a registration whose reply named Alice's user id |
| A-T1 | A session started from a tagged credential holds the u_c the tag was made from | **true** in every variant; in no-PRF mode this is all the tag gives |
| A-U1 | A browser accepts a server reply only with the user id it already holds for the flow | **true** in every variant |
| — | A passkey Alice creates carries the user id of the session she added it in, or of her words | **true** in every variant |
| — | In no-PRF mode, the u_c Alice's browser holds stays secret from the server | attack, by design |

**End to end (A-S5).** For new accounts, messages Alice encrypts stay secret from a malicious
server, even one that learns her password. The argument has two parts. A-E1 keeps every u_c her
browsers adopt secret from the server, and C-S1 in `cipher.pv.m4` keeps a message secret while
u_c is secret, even when the attacker holds the password. The two are separate models; a combined
model was not built.

**Existing accounts.** In `malicious-existing`, credentials tagged with Alice's own u_c hold.
Untagged credentials do not: the trace is a recovery with the 24-word set, on a new browser in
phase 1, that accepts "no-PRF" with the server's u_c. The registering browser holds through its
pin and the user-id checks. In `malicious-existing-firstuse`, a first-use session accepts the
server's u_c and writes tagged words from it, and a later recovery with those words accepts that
u_c. Credentials tagged with Alice's own u_c still hold.

**Mutations.** Each removes one of the browser's checks:

| Variant | Check removed | Result |
|---|---|---|
| `malicious-nohandletag` | the tag check at sign-in | A-E1, A-D1, A-S4 and A-T1 **attack**; the registering browser still holds, through its pin |
| `malicious-noprf-nohandletag` | the same, in no-PRF mode | A-T1 **attack** |
| `malicious-recovery-nowordstag` | the tag check at recover3 | A-S4R **attack**, and A-S4: the recovered session tags a new passkey with the server's u_c, and a later sign-in on a new browser accepts it. A-E1, A-D1 and A-T1 **attack** too |
| `malicious-existing-nohandletag` | the tag check at sign-in, on an existing account | **attack** on credentials tagged with Alice's u_c: a passkey tagged by the registering browser's phase-1 recovery, used on a browser with no pin, accepts "no-PRF" with the server's u_c |
| `malicious-existing-nowordstag` | the tag check at recover3, on an existing account | **attack** on credentials tagged with Alice's u_c: words a session tagged from her u_c, used on a browser with no pin, accept "no-PRF" with the server's u_c |
| `malicious-recovery-serverhandle` | the browser building the user handle, at add passkey and recovery | passkey-handle **attack**: a new passkey carries the server's user id. A-E1 holds, because the handle's tag protects that passkey |
| `malicious-nouicheck-login` | the sign-in user-id check | everything holds: a tagged passkey switched to another account fails the tag check, because the server cannot produce that account's u_c with Alice's tag |
| `malicious-existing-firstuse-nouicheck-login` | the sign-in user-id check, on an existing account | A-S3 and A-U1 **attack**: on the registering browser, a sign-in with its untagged passkey is switched to an account the server controls, with "no-PRF" and the server's u_c |
| `malicious-recovery-nouicheck-reg` | the registration user-id check | A-U1 **attack**: registration pins and signs in under the user id the reply carries. A-S3R holds, because the words' tag protects a later recover3 |
| `malicious-recovery-nouicheck-recoververify` | the recover/verify user-id check | A-U1 **attack**: recovery ends on another user id, with Alice's own u_c |
| `malicious-twoaccounts-nouicheck-reauth` | the reauthentication user-id check | A-U1 **attack**: a reauthentication moves the session to Alice's other account |

So for tagged credentials, the tags protect u_c, and the user-id checks keep the pin and the
session on the right account. For untagged credentials, the sign-in check is what protects a
browser that holds a pin.

**Reachability.** Each query requires the browser and the u_c to come from the same Alice, so a
run that ends holding the server's u_c does not satisfy it:
- for new accounts, an honest sign-in on the registering browser, after a registration whose
  reply named Alice's user id, and on a browser with no pin;
- in `malicious-recovery`, an honest recovery on each of those browsers;
- in `malicious-twoaccounts`, honest reauthentication on the registering browser for each
  account, and on a browser with no pin;
- in `malicious-existing`, a phase-0 sign-in with the untagged passkey, and in phase 1 a sign-in
  with a tagged passkey, recoveries on a browser with no pin with tagged and with untagged words,
  and a recovery on the registering browser. The tagged-words recovery needs `PRECISE` to be
  found.

**Modeling note: the registering browser.** It signs in through `LoginRegistered` and recovers
through `RecoveryRegistered`. Two choices there make A-S3R provable for a registration that
pinned Alice's user id:
- **Positive pin lookups under the user id registration pinned:** at sign-in when the server
  names that account, and at recover3 when it is the words' user id. ProVerif treats the "no
  entry" branch of a table lookup as always possible. Through that branch, a sign-in with the
  code's negative form could pin a u_c the server chose under that user id, and recovery would
  then read that pin. The positive form drops no run of the code, because that pin exists from
  registration on. Under any other user id, the checks keep the code's negative form.
- **`[precise]` on both registration inputs:** the options and the reg/verify reply. Without
  it, ProVerif combines two registrations of one browser, under different user ids, into one
  derivation that no run follows. `[precise]` adds no assumption, since an input receives one
  message per run.

Whether A-S3R needs each of the four (either positive lookup, either `[precise]`) with tagged
words is not checked.

### Results: no-PRF accounts

The `noprf` variants repeat the login and recovery variants in no-PRF mode. The `log` variants
are repeated with the mutations whose replay hands the attacker u_c in this mode, and with the
confirm challenge store off but its binding kept ("Results: replay"). Results in bold differ from
PRF mode.

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-L1, A-R1 | Sign-in only with a passkey Alice approved; only passkeys she created are bound | `login-noprf-net`, `-session`, `-cdu`, `-device`, `-log-noregver` | `-device-nouv`, `-unbound`, `-session-noproof`, `-tls`, **`-log`**, **`-log-noauthchal`** |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | `login-noprf-net`, `-session`, `-cdu`, `-device`, `-log-noregver` | `-device-nouv`, **`-unbound`**, `-session-noproof`, `-tls`, **`-log`**, **`-log-noauthchal`** |
| A-K2 | Alice's pk_U and pk_R are stored only from a reg/verify her browser signed | `login-noprf-net`, `-session`, `-cdu`, `-device`, `-log-noregver`, `-db` | `-device-nouv`, **`-unbound`**, **`-session-noproof`**, **`-tls`**, **`-log`**, **`-log-noauthchal`**, **`-db-kms`**, **`-db-kmsold`**: each gives the attacker u_c, which signs a registration under her pk_U |
| A-S1, A-K1 | Alice's u_c stays secret: the u_c the server stored when it registered her passkey, and the u_c her browser holds | `login-noprf-net`, `-session`, `-cdu`, `-device`, `-log-noregver` | `-device-nouv`, **`-unbound`**, **`-session-noproof`**, **`-tls`**, **`-log`**, **`-log-noauthchal`** |
| A-V1-3, A-R1 | Recovery steps and new words on Alice's account are her browser's | `recovery-noprf-net`, `-session`, `-log`, `-log-noconfirmchal`, `-log-noconfirmchal-nobind`, `-db-chalrec` | `-words`, `-tls`, **`-log-norecnonce`**, **`-log-noconfirmchal-nobind-noproof`**, **`-log-onectx-noreplnonce`**, **`-db-chalrec-norecverifyproof`** |
| A-S1 | u_c, in both forms, and both word sets stay secret | `recovery-noprf-net`, `-session`, `-log`, `-log-noconfirmchal`, `-log-noconfirmchal-nobind`, `-db-chalrec`; the replaced words in every variant | `-words` (u_c, original words); **`-tls`** (u_c); **`-log-norecnonce`**, **`-log-noconfirmchal-nobind-noproof`**, **`-log-onectx-noreplnonce`**, **`-db-chalrec-norecverifyproof`** (u_c) |
| — | The server knows the u_c Alice's browser holds | — | `malicious-noprf`, by design |

What the traces show:
- **`login-noprf-unbound` (C1).** As in PRF mode, the attacker posts `passkeys/verify` naming
  Alice's user id, binds its own passkey to her account, and signs in with it. Here the sign-in
  reply carries her u_c, so u_c leaks and the attacker then signs requests on her account. The
  proof of userCred does not contain C1 in no-PRF mode.
- **`login-noprf-session-noproof`.** With the cookie and CSRF token alone, the attacker binds a
  passkey and signs in, and the reply carries u_c.
- **`login-noprf-device-nouv`.** A sign-in without user verification is enough. No PRF output is
  needed, since the reply carries u_c.
- **`login-noprf-tls`.** For the correspondence queries, the attacker gives Alice's browser the
  user id of a registration it opened and completes, as in `login-tls`. Her browser sends her
  u_c in plaintext in her reg/verify body, where the attacker reads it. The attacker also
  registers her passkey, under the user id her browser received, with its own keys and its own
  u_c, so the u_c the server stores for her passkey is one the attacker chose.
- **`recovery-noprf-words`.** recover3 returns u_c itself to anyone holding the words. The
  attacker then confirms, binds its own passkey at recover/verify, and replaces the words. The
  replaced words stay secret.
- **`recovery-noprf-tls`.** The correspondence traces and both u_c traces are as in
  `login-noprf-tls`.
- **`malicious-noprf`.** Alice's browser sends u_c to the server in reg/verify.

**Reachability.** `login-noprf-reach` and `recovery-noprf-reach` show the same runs of Alice's as
`login-reach` and `recovery-reach`. Her sign-in and her recovery each end holding the u_c her
browser created at registration.

### Results: database leak

`LEAK_DB` gives the attacker a copy of the server's account tables:
- users, with pk_U;
- recovery keys, with pk_R and cd_r;
- passkeys, with the credential id, public key and cd_p;
- for a no-PRF account, u_c under both KMS keys.

Replay nonces are not in the copy. `LEAK_CHAL` adds live reads of the challenge table, whose
entries last 300 s (`CHALLENGE_TTL_SECS`). `LEAK_KMS_NEW` and `LEAK_KMS_OLD` add the use of the main or
the backup KMS key. PRF mode keeps nothing under KMS, so the PRF variants leave the keys out.

| Variant | Mode | Leaked | u_c | Sign-in, binding, requests, recovery |
|---|---|---|---|---|
| `login-db` | PRF | tables | secret | hold |
| `recovery-db` | PRF | tables | secret, as are both word sets | hold |
| `login-noprf-db` | no-PRF | tables | secret | hold |
| `login-noprf-db-kms` | no-PRF | tables and the main KMS key | **exposed** | hold, except A-K2: with u_c the attacker registers an account of its own under her pk_U |
| `login-noprf-db-kmsold` | no-PRF | tables and the backup KMS key | **exposed** | hold, except A-K2, as above |
| `login-db-chal` | PRF | tables and live challenges | secret | hold |
| `recovery-db-chal` | PRF | tables and live challenges | secret, as are both word sets | hold |
| `recovery-db-chalrec` | PRF | tables and live recover/verify challenges only | secret, as are both word sets | hold |
| `recovery-noprf-db-chalrec` | no-PRF | tables and live recover/verify challenges only | secret, as are both word sets | hold |

In both exposure traces the attacker decrypts the copy of u_c under the key it holds. The
correspondence properties still hold there, because signing in still takes one of Alice's
passkeys.

Each check that keeps a challenge reader out has a mutation that removes it:

| Variant | Check removed | Result |
|---|---|---|
| `login-db-chal-noregbind` | reg/options stores pk_U and binds the challenge to it | **attack**: sign-in, binding and requests |
| `login-db-chal-noregsigu` | reg/verify checks the u_c proof | **attack**: sign-in, binding and A-K2; requests hold |
| `recovery-db-chalrec-norecverifyproof` | recover/verify checks the u_c proof | A-R1 **attack** |
| `recovery-noprf-db-chalrec-norecverifyproof` | recover/verify checks the u_c proof | **attack** on every property but word secrecy |
| `login-db-noregsigr` | reg/verify checks the proof of sk_R | **attack**: the registration of pk_R |

The `-noregbind` trace is a registration hijack without breaking TLS. The attacker reads Alice's
registration challenge, with her user id, from the table, and submits reg/verify with them and
its own passkey and keys before she does. It then holds her user id: it signs in and makes
requests. In the `-noregsigu` trace the challenge is bound to Alice's pk_U, but nothing checks
that the request comes from her u_c. The attacker registers her user id with her pk_U and its
own passkey and recovery key, so it signs in, but its requests still need her proof.

The `-norecverifyproof` variants leak only recover/verify challenges, so the registration hijack
cannot hide anything later. Alice runs recover3 and recover/confirm. The attacker reads the
challenge recover/confirm stored for her, and submits recover/verify with its own passkey before
she does. The server binds that passkey to her account. In PRF mode its cd_p is the attacker's
own, so signing in with it reveals nothing about her u_c, and every authorized request still
needs her proof. In no-PRF mode the reply carries u_c, which gives the attacker the account.

`login-db-noregsigr` needs no challenge read. Without the check of the sk_R proof, the attacker
registers an account of its own that carries Alice's recovery public key from the tables.

### Attack and reachability variants

Every attack in the account model is reported as a concrete trace ("is false"), and each trace
was read to confirm it is the attack its variant names.

The one exception is `login-unbound`. It runs without restrictions so that its A-Z1 and u_c
secrecy proofs hold for every run, and without backtracking (`NOBT`). Its two attack queries
therefore end in "cannot be proved". `login-unbound-trace` adds `UNIQUSER`, and returns those as
traces. A restriction only removes traces, so each of those traces is also a trace of
`login-unbound`.

**Why restrictions are needed.** Without the uniqueness restrictions, the derivations ProVerif
finds in these variants cannot be followed by any real run:
- In the Horn-clause abstraction, one request on the private TLS channel can be "received" by
  several server sessions.
- The "no such user yet" branch of a table lookup is always available, so a derivation can
  register one user id twice.

Reconstructing a trace from such a derivation searches away from it and does not finish in
practical time. Under the restrictions the derivations are executable, so traces come back in
seconds without backtracking (`NOBT`).

**Which restrictions each variant uses:**

| Variant | Restrictions |
|---|---|
| `login-session-noproof`, `login-noprf-session-noproof` | `STORE` |
| `login-device-nouv`, `login-noprf-device-nouv` | `RCV`, `STORE` |
| `login-unbound` | none |
| `login-unbound-trace`, `recovery-tls` | `UNIQUSER` |
| `recovery-words` | `RCV` |
| `login-tls`, `login-tls-regsigr-nopku`, `login-tls-dualmode`, `login-noprf-tls`, and the `db-chal`, `db-chalrec` and `db-noregsigr` variants in PRF mode | `STORE`, `UNIQUSER` |
| `login-reach`, `recovery-reach`, `login-noprf-reach` | `RCV`, `STORE`, `UNIQUSER` |
| `login-log`, `recovery-log`, `recovery-log-api`, `login-noprf-log-noregver`, `recovery-noprf-log`, `login-log-sharedctx`, `recovery-log-api-sharedctx`, `login-log-noaddchal`, `recovery-log-noapinonce`, `recovery-log-noreplnonce`, `recovery-log-onectx` | `STORE` |
| `login-log-noregchal` | `STORE`, `UNIQUSER`; without `UNIQUSER` a derivation registers Alice's user id twice and the existing-user check never applies |
| the other `log` mutations in PRF mode, `login-noprf-log`, `login-noprf-log-noauthchal` and `recovery-noprf-log-onectx-noreplnonce` | `RCV`, `STORE`, `UNIQUSER` |
| the other no-PRF recovery `log` mutations, `login-noprf-unbound`, `recovery-noprf-words` and `recovery-noprf-reach` | `RCV`, `STORE`, `UNIQUSER`, and `PRECISE` |
| `recovery-noprf-tls` and the no-PRF `db-chalrec` variants | `STORE`, `UNIQUSER`, and `PRECISE` |
| `login-tls-stripped`, `login-tls-stripped-nohandletag` | `STORE`, `UNIQUSER`, and `STRIPLOGIN`'s `[precise]` on Register's two inputs and the reg/verify input |
| `malicious-existing-nowordstag` | `RCV`, `STORE`, `UNIQUSER`; without them the attack query ends in "cannot be proved" or does not finish in 900 s |
| `malicious-existing`, `malicious-existing-nohandletag` | `PRECISE` |
| the other `malicious` variants | none |

`PRECISE` is not a restriction. It marks three actions `[precise]`: the inputs of auth/verify
and recover3, and the lookup of the words a recovery uses. Each of them receives or reads one
value per run, so it adds no assumption and removes no trace. In no-PRF mode, recover3's reply
does not depend on the words, and without it reconstruction combines two requests in one server
session, or two sets of words in one recovery, and fails. Marking every action precise
(`preciseActions`) does not finish in practical time. The recover/verify reply that ends every
recovery is always `[precise]`, since the browser reads its mode as a boolean and constraining
it to PRF or no-PRF otherwise breaks reconstruction.

`login-noprf-unbound` has no unrestricted counterpart. Its counterpart in PRF mode exists to
prove A-Z1 and u_c secrecy, and in no-PRF mode both are attacks.

With TLS public, the server endpoints run only on the TLS channel, which the attacker can already
use. A second copy on the public channel only multiplies clauses.

**What each trace shows:**
- **`session-noproof`:** the attacker sends Alice's stolen cookie and CSRF token, with an
  arbitrary signature, to `passkeys/options`, `passkeys/verify`, and the generic endpoint. It
  then signs in with the passkey it bound.
- **`unbound-trace`:** C1, as described under "What the mutations and leaks show".
- **`device-nouv`:** the attacker feeds an auth challenge to the unlocked device, posts the
  assertion it made without UV, is signed in, and decrypts the returned cd_p with the device's
  PRF output.
- **`recovery-words`:** leaked words, then recover3, then confirm with the u_c from cd_r, then
  recover/verify with the attacker's passkey.
- **`login-tls` and `recovery-tls`:** the registration race above.

**What these variants' "true" results mean.** In these variants they hold for runs that respect
the real server's uniqueness guarantees. Most also have an unrestricted proof in a base variant.
Three groups have none, so their results hold only under the restrictions:
- **Broken TLS:** every `tls` variant is restricted (`login-tls`, `recovery-tls`, the two no-PRF
  `tls` variants, `login-tls-dualmode`, `login-tls-stripped`, and the mutations
  `login-tls-regsigr-nopku` and `login-tls-stripped-nohandletag`). So u_c and
  recovery-word secrecy under broken TLS is proved only under their restrictions.
- **Live challenge reads:** every result of the `db-chal` variants.
- **Replay:** the `log` variants' results, with every accepted request leaked, hold only under
  `STORE`, the stores and authCount binding they test. `login-log-noregchal` also needs
  `UNIQUSER`.
