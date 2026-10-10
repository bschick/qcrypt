# ProVerif models of the Quick Crypt protocol

These are symbolic (Dolev-Yao) models of the protocol in `apps/web/src/assets-src/main.tex`,
checked with [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) 2.05. The models follow
the **code** wherever it differs from the tex. `conformance.md` maps every tex step to its code
and model, and keeps the issue log.

## Findings

**What holds.**
- **Message format:**
  - V8 is key-committing for all three algorithms.
  - An attacker holding u_c but not the password cannot truncate, reorder, splice or strip loops.
  - Reading a message takes both the password and u_c.
- **Honest server:**
  - Sign-in, passkey binding and per-request proofs hold even when the session cookie and CSRF
    token leak.
  - Per-request proofs limit the damage of an unbound passkey challenge (C1, a bug fixed
    earlier; see `vibes/security_review.md`).
  - Recovery requires the recovery words.
  - u_c stays secret against the network, a leaked cd_u, a leaked session, and broken TLS. The
    broken-TLS result assumes the server's uniqueness guarantees (single-use challenges, one
    registration per user id).
- **Malicious server:**
  - In PRF mode, the server never learns u_c (A-S2).
  - Recovery on the browser that registered never adopts a u_c the server knows, provided the
    reg/verify reply named Alice's user id (A-S3R). At recover3 that browser compares the u_c it
    receives with its pin. The browser does not check that reply's user id (I-01), so without
    the proviso recovery can adopt the server's u_c.
- **No-PRF accounts**, where the server draws u_c and keeps it under KMS:
  - Against an honest server, sign-in, passkey binding, per-request proofs, recovery, and u_c
    secrecy hold in the same cases as in PRF mode: the network, a leaked session, a leaked
    cd_u, and an unlocked device that enforces user verification.
  - Every sign-in, recover3 and recover/verify reply carries u_c in plaintext. So u_c is exposed
    with TLS broken, or to anyone who can bind a passkey to the account, as with C1 or a stolen
    session and no proof check. PRF mode keeps u_c secret in all three cases.
  - The server knows u_c by design.
- **Database leak:** a copy of the server's account tables reveals u_c in neither mode, and does
  not let anyone sign in. In no-PRF mode, u_c is exposed to anyone who can also use either KMS
  key: the main key, or the backup key, which holds a second copy that the server never
  decrypts. The challenge table is not part of that result (I-30).

**What does not hold, or holds only through a dependency.** Each item was confirmed against the
code. `conformance.md` §5 has the details and code locations:

| Issue | Finding | Evidence | Status |
|---|---|---|---|
| I-01 | The browser accepts whatever user id the server names at sign-in, registration, add passkey and recovery. A malicious server can switch Alice's browser to an account whose u_c it chose, so messages she then encrypts rest on her password alone. This breaks the tex's claim that PRF accounts protect u_c from the server. | `malicious`: A-S3 attack, and a passkey Alice adds carries the user id the server names; `malicious-recovery`: A-S3R attack, where the server names another user at reg/verify, and the server names another user at `recover/verify` | fix planned (`conformance.md` §7) |
| I-03 | Account mode and u_c are trusted on first use in each browser, at sign-in and at recovery. A browser with no pin accepts "no-PRF" and a u_c the server chose, even for Alice's own user id. | `malicious`: A-S4 attack; `malicious-recovery`: A-S4R attack, where recover3 pins the server's u_c under Alice's own user id | fix planned (§7) |
| I-04 | Recovery and replace-words signatures are kept apart by two layers: per-operation contexts, and the shared nonce store for the legacy context. Either one alone is enough. | `recovery-replay-*` | the store stops being needed once the legacy context is removed |
| I-14 | Truncation resistance depends on the encryptor never writing an empty block before the last one, because the decryptor does not check f on an empty block. | `integrity-net-emptymid` | hardening, pending |
| I-17 | The inner le is not compared with the outer le. An attacker holding u_c and the outer password can wrap a one-loop message as the inner layer of a two-loop message. The plaintext is still authentic. | `loops-uc-pout` | low, pending |
| I-29 | With TLS broken, an attacker can win the registration race and hold Alice's user id. Her u_c and words stay secret, and her browser notices on first use. It can also strip the PRF fields from her reg/verify. The server then registers her user id and passkey as a no-PRF account and returns its u_c, which the attacker sees. Her browser halts, but a later sign-in with that passkey, over intact TLS, receives that u_c, and with no pin she accepts it. | `login-tls`, `recovery-tls`; `login-tls-dualmode`, `login-tls-stripped` | race accepted; stripping pending, and the planned handle tag (§7.2) targets it |
| I-30 | A live read of the challenge table hijacks registration without breaking TLS: the attacker submits reg/verify with Alice's user id and outstanding challenge, and its own passkey and keys, before she does. A read of her recover/verify challenge likewise lets it bind its own passkey to her account. Her u_c and words stay secret. | `login-db-chal`, `recovery-db-chal`, `recovery-db-chalrec` | pending; fix candidates in `conformance.md` §7.3 |
| — | The externally reported V7 key-commitment incompleteness, reproduced. V8 closes it. | `commit-v7` | known |

The other issue-log entries are gaps in the tex, differences between the tex and the code, or
modeling notes. None of them has a security effect the models found. The approved notation changes
(`conformance.md` §6) address most of them.

## Running

```bash
# One time. The opam package needs GTK2 for ProVerif's interactive simulator.
sudo apt install opam m4 graphviz libgtk2.0-dev pkg-config
opam init -y --no-setup && opam install -y proverif

pnpm verify:proverif               # every variant, including fixes/*; non-zero exit on any mismatch
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
| `fixes/<version>/` | Models of proposed fixes, kept apart from the models of the current code, each with its own README |
| `conformance.md` | Tex ↔ code ↔ model trace, encoding-injectivity arguments, issue log, notation proposal, planned fixes |
| `remediation-tests.md` | Failing unit tests for planned code fixes, kept out of the source tree until each fix ships |
| `run.mjs` | Builds each variant with `m4 -P` and checks its results |
| `traces.mjs` | Lists every trace in the saved output, query by query, for review |

Each template lists its variants in a `VARIANTS` block, one per line: a name followed by m4
flags. The main flag groups are:
- `SCN_*` selects the scenario.
- `LEAK_*` gives the attacker a secret.
- `MUT_*` deliberately breaks one protocol mechanism.
- The rest set options, described where they are used: `NOPRF`, `DUALMODE`, `STRIPLOGIN`, `STORE`, `RCV`, `UNIQUSER`,
  `NOBT`, `PRECISE`, `KEY_UI`, `REACH_ONLY`, `MAL_RECOVERY`, `LEGACY_CLIENT`, `USE_V7`, and
  `FIX_*` in `fixes/`.

The expected results for each variant sit at the end of the template in ProVerif's own
`EXPECTPV … END` comment format, so each generated `.pv` file is self-checking.

**To add or change a query:**
1. Edit the template.
2. Run with `--print`.
3. Read every trace in each variant the change affects, not only the results that changed.
   `node formal/proverif/traces.mjs --compact <variant>` lists each trace's events, the messages
   received, and the writes to the `users`, `recov`, `creds` and `pins` tables. The filter
   matches output file names such as `account-login-tls` or `fixes-v1-account-malicious-fixui`.
   Confirm three things:
   - **Attack traces:** each one is the attack the variant names, and uses only steps the real
     system allows.
   - **Reachability traces:** each one is the honest run the related proof is about, for example
     Alice's own sign-in rather than one on the attacker's account. A proof without such a trace
     may hold only because the path it covers never runs.
   - **"cannot be proved" results:** each one has a written reason, and another variant shows the
     trace.
4. Paste the new block.
5. Record what each trace shows in this README, or in the `fixes/<version>/` README for a fix
   model.

A result that matches its `EXPECTPV` line is not evidence on its own. The expected line can encode
a mistake, so never paste a result whose trace you have not read and explained.

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

**Encodings.** Every byte concatenation is modeled as an unambiguous tuple.
`conformance.md` §4 argues that each real encoding is injective, which is what makes this
sound.

**Bounds.**
- Messages have at most 3 blocks, and loops are at most 2 deep.
- The two-loop model uses one block per loop.
- Proofs are for unbounded sessions within those shapes.

**Not covered:**
- computational strength, including PBKDF2 cost, nonce-collision bounds and length leaks;
- side channels;
- the browser running anything other than the published code.

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
the inner layer of a two-loop message (I-17). In both traces the inner layer, and so the
plaintext, is still hers. The reachability traces in this variant use a message the attacker
built under the leaked outer password. `loops-uc` shows honest acceptance for the same processes.

### Mutations

Each mutation removes one mechanism, and each must turn a proof into an attack:

| Variant | Mechanism removed | Attack found |
|---|---|---|
| `commit-v8-nokc` | Comparing the stored k_C | Two passwords accepted for one ciphertext (GCM, XChaCha) |
| `integrity-uc-nof` | f in the AEAD AD (kept in the MAC) | An attacker holding u_c flips f on block 0 and truncates a 3-block message |
| `integrity-uc-non` | Block number in the k_MN derivation | A later block replayed one position early, dropping the block before it: block 2 of a three-block message, or the empty final block of a two-block message |
| `integrity-net-emptymid` | The encryptor writing an empty block only as the last one | Truncation with no secret leaked (I-14) |
| `loops-uc-pout-nolple` | The outermost lp = le check | The inner layer of a two-loop message accepted on its own |

### Findings from this model (see `conformance.md`)

- **I-14, hardening.** The decryptor ends the stream on an empty block without checking that
  block's f. That is safe only because the encryptor never writes an empty block before the
  last one.
- **I-17, low.** Nothing compares the inner le with the outer le. An attacker holding u_c and
  the outer password can wrap a one-loop message as the inner layer of a two-loop message. The
  plaintext is still authentic.

## Account model (`account.pv.m4`)

### What is modeled

**Scenarios:**
- **`SCN_LOGIN`:** registration, sign-in, authorized requests, and adding passkeys.
- **`SCN_RECOVERY`:** registration, replacing recovery words, and recovery.
- **`SCN_MALICIOUS`:** registration and sign-in against a malicious server. `MAL_RECOVERY` adds
  recovery, both from the registering browser and from a browser with no pin.

**Account modes.** Accounts are in PRF mode unless `NOPRF` is set. With `NOPRF`, Alice's
authenticator has no PRF and the server takes the code's no-PRF branches:
- reg/verify draws u_c and keeps it under a main and a backup KMS key;
- sign-in, recover3 and recover/verify return u_c in plaintext (the last is I-10);
- passkeys/verify and recover/verify refuse a cd_p, and replace words ignores a cd_r (I-11).

Each variant's server serves one mode, for every account. An account's mode never changes, and
the server never decrypts a ciphertext a client supplied, so the attacker gains nothing from
accounts of the other mode. The exception is reg/verify itself: the server picks the mode from
which fields the request carries (`srv:438`), so with TLS broken the attacker picks Alice's mode.
`DUALMODE` gives `login-tls-dualmode` a server that accepts both request shapes, with Alice's
PRF registration halting on a no-PRF reply (I-29). The no-PRF → PRF upgrade is not modeled yet.

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
  - `STORE`: each challenge and each replay nonce is used once (the atomic delete-on-read and
    conditional put).
  - `RCV`: each private request is received by one server session.
  - `UNIQUSER`: each user id is registered once.

  Without them, the attacker gets more traces, so a proof made without them also holds with them.
  The variants that look for an attack or for reachability turn them on (see "Attack and
  reachability variants" below). So do the `replay` variants, where `STORE` stands for the
  nonce store under test.
- **Not modeled:** timestamps, the skew window, TTLs, and `authCount`. Recovery's challenge
  binding is carried as pk_R but never compared. The code binds H(pk_R : authCount) and
  re-derives it at confirm and recover/verify, so a sign-in, a logout, another recover3 or new
  words void the challenge, and recover/verify also requires an empty `lastCredentialId`.
  Leaving these out only adds attacker runs.
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
from a u_c she created (`new ucA`). With TLS broken, the attacker can copy that pk_U into an
account of its own, since a PRF registration takes pk_U from the client. So the `KEY_UI`
variants identify Alice's accounts by the user id her browser received at registration
instead. A database leak also gives the attacker pk_U, so the PRF `db` variants use `KEY_UI`
too.

In no-PRF mode the server draws u_c. Alice's accounts are then the ones whose pk_U is derived
from the u_c the server drew when it registered her passkey: the registration whose user id,
credential id and public key match a passkey she created (`ServerUc` with `AliceCredCreated`).
The same pairing gives the no-PRF u_c secrecy query, and the attacker cannot copy pk_U, because
the server derives it.

### Results: honest server

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-L1 | The server signs Alice in only with a passkey she approved, for that challenge | `net`, `session`, `cdu`, `device` | `device-nouv` (an unlocked device without UV); `unbound-trace`, `session-noproof` (each via the passkey A-R1 lets the attacker bind); `tls` (registration race) |
| A-R1 | Every passkey bound to Alice's account is one she created | `net`, `session`, `cdu`, `device` | `unbound-trace` (C1); `session-noproof`; `device-nouv` (once u_c leaks); `tls` |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | `net`, `session`, `cdu`, `device`, **and** `unbound` | `session-noproof` (cookie and CSRF alone); `device-nouv` (once u_c leaks); `tls` (the attacker holds Alice's user id) |
| A-S1, A-K1 | Alice's u_c stays secret, including when cd_u or the session cookie leaks, or TLS is broken | every variant except `device-nouv` | `device-nouv` (sign-in without UV yields cd_p, and the device yields the PRF output) |

**What the mutations and leaks show:**
- **`login-unbound-trace` rediscovers C1** (a bug fixed earlier, `vibes/security_review.md`), as
  a full trace. A signed-in attacker posts
  `passkeys/verify` with a body naming Alice's u_i and any outstanding challenge. The mutated
  server takes the user from the body and binds the attacker's passkey to Alice's account, and
  the attacker then signs in to her account with it. Even then, A-Z1 holds and u_c stays secret:
  the proof of userCred contains the damage. `login-unbound` proves those two properties with no
  restrictions.
- **`login-tls` and `recovery-tls` show the registration race (I-29).**
  - With TLS broken, the attacker sees the reply to Alice's registration options. It submits
    `reg/verify` first, with her user id and challenge but its own passkey, pk_U and recovery
    key.
  - With attestation `none`, nothing in a registration response says who built it. The attacker
    then holds Alice's user id and can sign in, make requests, and recover on it.
  - Alice's u_c and words stay secret, and her own proofs fail, so she notices.
  - Registration integrity rests on TLS.
  - With TLS broken, the attacker can also act as the server toward Alice's browser, so the
    malicious-server results apply. Through I-01 it can sign her browser in to an account it
    chose.
- **`login-tls-dualmode` and `login-tls-stripped` show the attacker choosing Alice's account
  mode (I-29).** The server picks the mode from which fields reg/verify carries, so the
  attacker strips the PRF fields from her request.
  - `login-tls-dualmode` traces the registration: the honest server registers her own user id
    and passkey as a no-PRF account and sends its u_c in the reply, which the attacker sees. Her
    browser never completes the registration, so it pins nothing.
  - `login-tls-stripped` traces the rest. Alice later signs in with that passkey, with no
    attacker involved. The honest server's auth/verify answers her assertion with that u_c, and
    her browser, with no pin, accepts it and signs in to her own user id holding a u_c the
    attacker knows. The query ties the reply her browser accepted to that server session by
    its cookie, which only that session can make. Without the tie, ProVerif satisfies the
    browser half with a reply the attacker builds, and reconstruction fails.
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
| A-V1 | recover3 accepts a proof on Alice's account only from her browser recovering it | `net`, `session`, every `replay` variant except the one below | `words` (words leaked); `tls` (registration race); `replay-legacy-splitnonce` |
| A-V2 | recover/confirm on Alice's account is one her browser signed, for that challenge | every variant except `words` and `tls` | `words`; `tls` (registration race) |
| A-V3 | New recovery words on Alice's account are ones her browser created | every variant except `words` and `tls` | `words` (the original words give recovery, then a session); `tls` |
| A-R1 | Every passkey bound to Alice's account, including by recovery, is one she created | every variant except `words` and `tls` | `words`; `tls` (registration race) |
| A-S1 | u_c, the original words, and replaced words stay secret | every variant, except u_c and the original words in `words` | `words` |

**Cross-use of recovery proofs (I-04).** The `replay` variants give the attacker Alice's
replace-words request, as a log or a TLS-terminating proxy would, and turn the `STORE`
restriction on:

| Variant | Client signs with | Replace and recover nonces | A-V1 |
|---|---|---|---|
| `replay` | per-operation contexts | one shared store | true |
| `replay-splitnonce` | per-operation contexts | separate stores | true |
| `replay-legacy` | the legacy context, for both | one shared store | true |
| `replay-legacy-splitnonce` | the legacy context, for both | separate stores | **attack** |

Each of the two layers is enough on its own:
- **Per-operation contexts** stop the cross-use for current clients.
- **The shared `'nonce'` store** stops it for legacy clients.

The trace for the last row replays a legacy replace-words signature to recover3 after the
replace completed, which the shared store would have refused. Once the legacy context is
removed, the shared store stops being load-bearing.

**Reachability.** `recovery-reach` shows each step of Alice's own recovery:
- her recover3, with her nonce;
- her confirm;
- `recover/verify` binding a passkey she created;
- her browser finishing with her own u_c.

It also shows her replacing her words. As in `login-reach`, each server event is paired with
Alice's client event, and the uniqueness restrictions are on. By the same argument, each trace
is also a run of every other recovery variant except the two `replay-legacy` variants.
`LEGACY_CLIENT` changes the context Alice's browser signs with, so `recovery-reach-legacy` checks
the same five runs with that flag.

### Results: malicious server

These variants model the code as it is. Models of proposed fixes are kept apart, in `fixes/`
(`fixes/v1/README.md`).

| ID | Property | `malicious` | `malicious-recovery` |
|---|---|---|---|
| A-S2 | In PRF mode the server never learns Alice's u_c | **true** | **true** |
| A-S3 | Once registration has completed in a browser, that browser never adopts a u_c the server knows | attack (I-01) | attack (I-01, by sign-in) |
| A-S3R | The same, by recovery alone | — | attack (I-01, at registration) |
| A-S3R, own id | A-S3R, when the reg/verify reply named Alice's user id | — | **true** |
| A-S4 | The same, for a browser with no pin that signs in | attack | attack |
| A-S4R | The same, for a browser with no pin that recovers | — | attack |
| — | A passkey Alice adds carries the user id of the session she added it in | attack (I-01) | attack (I-01) |

In both variants, registration follows the code: the browser pins and signs in under the user
id the reg/verify reply names (`auth:1545-1557`). The recovery words and the passkey's user
handle carry the user id from the registration options.

`malicious-recovery` adds recovery from both browsers (`MAL_RECOVERY`). The browser's recovery
follows the code:
- **recover3:** accepts "no-PRF" with a plaintext u_c, checked only against an existing pin for
  the words' user id.
- **New passkey:** takes its user handle from the `recover/confirm` options.
- **recover/verify:** pins and signs in under the user id the server names.

The model gives Alice her words only once registration completes, since they are shown only in
a signed-in session (`auth:530-541`).

What the traces show:
- **A-S3 (I-01).** Alice signs in on the browser that registered her account. The server
  replies with a different user id (`sui` in the model), "no-PRF", and its own u_c. The browser
  has no pin for that user id, so it accepts, and every message Alice then encrypts in that
  session rests on her password alone. `conformance.md` I-01 has the code paths.
- **A-S4.** A browser with no pin accepts the server's "no-PRF" and u_c at sign-in.
- **Add passkey (I-01).** Alice signs in to her own account, holding her own u_c, and adds a
  passkey. The `passkeys/options` reply names another user id, which becomes the new passkey's
  user handle (`auth:1576`). A later sign-in with that passkey then starts from the account the
  server named. The planned fix checks that user id before the ceremony (`conformance.md` §7.1).
- **A-S4R (trust on first use in recovery).**
  - On a browser with no pin, recover3 accepts "no-PRF" and a u_c the server chose, and pins it
    under Alice's own user id from the words.
  - The server then names a different user at `recover/verify` (I-01).
  - The words carry the user id, but nothing about the account mode or u_c.
- **A-S3R (I-01, at registration).**
  - At registration the server's reg/verify reply names a different user id. The browser pins
    that one, holding Alice's own u_c, and has no pin for the user id in her words and passkey.
  - Later, on the same browser, Alice recovers with her words. recover3 answers "no-PRF" with
    the server's u_c. The browser has no pin for that user id, so it accepts, and the recovery
    ends holding the server's u_c.
  - From recover3 on, this is the trust on first use of A-S4R (I-03): the browser that
    registered is in the position of one with no pin for Alice's account. The planned fixes
    target it twice: the registration user-id check (`conformance.md` §7.1), and the account
    tag in the recovery words (§7.2).
- **A-S3R when reg/verify named Alice's user id, proved.**
  - At recover3 that browser compares the u_c it receives with the pk_U it pinned at
    registration. So the server must return Alice's own cd_r, which it cannot forge without the
    words.
  - The server can still name another user in the `recover/confirm` options and at
    `recover/verify` (I-01). The browser then signs in to that account, but holds Alice's own
    u_c.
  - Earlier I-01 sign-ins on the same browser do not change this, because they pin under other
    user ids.

**Reachability.**
- **Sign-ins:** in both variants, an honest sign-in is reachable on the registering browser and
  on a browser with no pin. Each one signs in holding Alice's own u_c, and the query requires
  the browser and the u_c to come from the same Alice. In each trace the server answers "PRF"
  for Alice's own user id, with her cd_p. A sign-in that ends in the I-01 attack does not
  satisfy these queries, because the browser then holds the server's u_c.
- **Recoveries:** in `malicious-recovery`, a recovery that ends holding Alice's own u_c is
  reachable on both browsers. In those traces the server names a different user at
  `recover/verify`. That is the I-01 effect in recovery: the u_c is still hers.
- **The registering browser:** its two queries also require a registration whose reg/verify
  reply named Alice's user id, so their traces are the runs the A-S3R proof covers. Both take
  the positive-lookup branch described below.

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

Leaving out any one of the four (either positive lookup, either `[precise]`) leaves A-S3R, for a
registration that pinned Alice's user id, at "cannot be proved".

### Results: no-PRF accounts

The `noprf` variants repeat the login and recovery variants in no-PRF mode. The `replay`
variants are not repeated, since recovery proofs and the nonce stores do not depend on the
account mode. Results in bold differ from PRF mode.

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-L1, A-R1 | Sign-in only with a passkey Alice approved; only passkeys she created are bound | `login-noprf-net`, `-session`, `-cdu`, `-device` | `-device-nouv`, `-unbound`, `-session-noproof`, `-tls` |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | `login-noprf-net`, `-session`, `-cdu`, `-device` | `-device-nouv`, **`-unbound`**, `-session-noproof`, `-tls` |
| A-S1, A-K1 | Alice's u_c stays secret: the u_c the server drew when it registered her passkey, and the u_c her browser received | `login-noprf-net`, `-session`, `-cdu`, `-device` | `-device-nouv`, **`-unbound`**, **`-session-noproof`**, **`-tls`** |
| A-V1-3, A-R1 | Recovery steps and new words on Alice's account are her browser's | `recovery-noprf-net`, `-session` | `-words`, `-tls` |
| A-S1 | u_c, in both forms, and both word sets stay secret | `recovery-noprf-net`, `-session`; the replaced words in every variant | `-words` (u_c, original words); **`-tls`** (u_c) |
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
- **`login-noprf-tls`.** For the correspondence queries, the attacker, acting as the server,
  gives Alice's browser the user id of an account it registered (I-29). For the u_c the server
  drew for her passkey, the server's reg/verify reply to her own registration carries it in
  plaintext. For the u_c her browser received, the attacker answers her reg/verify itself with
  a u_c of its own, which a no-PRF registration takes from whoever replies.
- **`recovery-noprf-words`.** recover3 returns u_c itself to anyone holding the words. The
  attacker then confirms, binds its own passkey at recover/verify, and replaces the words. The
  replaced words stay secret.
- **`recovery-noprf-tls`.** The correspondence traces, and the trace for the u_c her browser
  received, are as in `login-noprf-tls`. The trace for the u_c the server drew is a
  registration race:
  1. The attacker answers Alice's own reg/verify itself, so her registration challenge stays
     unused.
  2. It answers her recover/confirm with registration options it requested itself, so the
     passkey she creates has the attacker's user id as its handle.
  3. It pairs that passkey's credential id and public key with her registration challenge and
     user id in a reg/verify of its own. Unsigned attestation allows this.
  4. The server registers the account and sends the attacker the u_c it drew.

  The account is one the attacker completed and Alice cannot sign in to, since her passkey's
  handle names another account. `login-noprf-tls` shows the direct exposure.
- **`malicious-noprf`.** The server's reg/verify reply supplies u_c.

**Reachability.** `login-noprf-reach` and `recovery-noprf-reach` show the same runs of Alice's as
`login-reach` and `recovery-reach`. Her sign-in and her recovery each end holding the u_c her
browser received at registration.

### Results: database leak

`LEAK_DB` gives the attacker a copy of the server's account tables:
- users, with pk_U;
- recovery keys, with pk_R and cd_r;
- passkeys, with the credential id, public key and cd_p;
- for a no-PRF account, u_c under both KMS keys.

Replay nonces are not in the copy. `LEAK_CHAL` adds live reads of the challenge table, whose
entries last 300 s (`consts.ts:63`). `LEAK_KMS_NEW` and `LEAK_KMS_OLD` add the use of the main or
the backup KMS key. PRF mode keeps nothing under KMS, so the PRF variants leave the keys out.

| Variant | Mode | Leaked | u_c | Sign-in, binding, requests, recovery |
|---|---|---|---|---|
| `login-db` | PRF | tables | secret | hold |
| `recovery-db` | PRF | tables | secret, as are both word sets | hold |
| `login-noprf-db` | no-PRF | tables | secret | hold |
| `login-noprf-db-kms` | no-PRF | tables and the main KMS key | **exposed** | hold |
| `login-noprf-db-kmsold` | no-PRF | tables and the backup KMS key | **exposed** | hold |
| `login-db-chal` | PRF | tables and live challenges | secret | **attack** (I-30) |
| `recovery-db-chal` | PRF | tables and live challenges | secret, as are both word sets | **attack** (I-30) |
| `recovery-db-chalrec` | PRF | tables and live recover/verify challenges only | secret, as are both word sets | A-R1 **attack** (I-30); recover3, confirm and new words hold |

In both exposure traces the attacker decrypts the copy of u_c under the key it holds. The
correspondence properties still hold there, because signing in still takes one of Alice's
passkeys.

The `db-chal` traces are a registration hijack without breaking TLS. The attacker reads
Alice's registration challenge, with her user id, from the table, and submits reg/verify with
them and its own passkey and keys before she does. It then holds her user id: it signs in, makes
requests, recovers, and replaces the words.

`recovery-db-chalrec` leaks only recover/verify challenges, so the registration hijack cannot
hide anything later. Alice runs recover3 and recover/confirm. The attacker reads the challenge
recover/confirm stored for her, and submits recover/verify with its own passkey before she does,
since recover/verify carries no u_c proof. The server binds that passkey to her account. Its cd_p
is the attacker's own, so signing in with it reveals nothing about her u_c, and every authorized
request still needs her proof.

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
| `login-session-noproof` | `STORE` |
| `login-device-nouv` | `RCV`, `STORE` |
| `login-unbound` | none |
| `login-unbound-trace` | `UNIQUSER` |
| `recovery-words` | `RCV` |
| `login-tls` | `STORE`, `UNIQUSER` |
| `recovery-tls` | `UNIQUSER` |
| `login-reach`, `recovery-reach`, `recovery-reach-legacy` | `RCV`, `STORE`, `UNIQUSER` |
| `recovery-replay`, `recovery-replay-splitnonce`, `recovery-replay-legacy`, `recovery-replay-legacy-splitnonce` | `STORE` |
| `login-noprf-session-noproof` | `STORE` |
| `login-noprf-device-nouv` | `RCV`, `STORE` |
| `login-noprf-unbound` | `RCV`, `STORE`, `UNIQUSER`, and `PRECISE` |
| `login-noprf-tls` | `STORE`, `UNIQUSER` |
| `login-noprf-reach` | `RCV`, `STORE`, `UNIQUSER` |
| `recovery-noprf-words` | `RCV`, `STORE`, `UNIQUSER`, and `PRECISE` |
| `recovery-noprf-tls` | `STORE`, `UNIQUSER`, and `PRECISE` |
| `recovery-noprf-reach` | `RCV`, `STORE`, `UNIQUSER`, and `PRECISE` |
| `login-db-chal`, `recovery-db-chal`, `recovery-db-chalrec`, `login-tls-dualmode` | `STORE`, `UNIQUSER` |
| `login-tls-stripped` | `STORE`, `UNIQUSER`, and `STRIPLOGIN`'s `[precise]` on Register's two inputs and the reg/verify input |

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
The exception is broken TLS: `login-tls` and `recovery-tls` are the only variants with TLS
public, so u_c and recovery-word secrecy under broken TLS is proved only under their
restrictions. The `replay` variants are the other exception: their results, with Alice's
replace request leaked, hold only under `STORE`, the shared nonce store they test.

## Remaining work

As of 2026-10-09.

The work runs as separate steps:
- model the current code;
- document the findings;
- model the fixes;
- implement the fixes and their tests;
- document the outcomes.

A fix model goes in its own `fixes/<version>/` directory, with its own variants and README, and
never replaces a current-code model, so each finding keeps its evidence until its fix ships.

**Current code:**

1. **Done: recovery on the registering browser, under a malicious server.** In
   `malicious-recovery`, A-S3R is an attack through I-01 at registration, and holds when the
   reg/verify reply named Alice's user id ("Results: malicious server").
2. **Done: no-PRF accounts and database leaks** ("Results: no-PRF accounts", "Results: database
   leak"). The no-PRF → PRF upgrade is item 5.

For the current code, A-S5 is expected to fail, through I-01 alone. A-S5 says that messages Alice
encrypts while her browser holds a pin for her account stay secret from a server that does not
know her password. I-01 lets the server switch even a pinned browser to an account whose u_c it
chose, and from then on Alice's messages rest on her password alone. So A-S5 is modeled with the
fixes (item 3), where it shows end-to-end message secrecy.

**Planned fixes, as a separate step after items 1-2:**

3. **Model the planned fix** (`conformance.md` §7) as `fixes/v2`, in its own variants, next to
   the current-code ones. Its headline goals, for PRF accounts:
   - **An attacker that controls the network, as if every call were plain HTTP:** Alice's
     browser never holds a u_c the attacker knows, and her account's u_c stays secret. The
     registration race (I-29) remains, but Alice detects it.
   - **Live read access to every server table:** opens no attack. The current code fails this
     through the challenge table (I-30).

   This covers:
   - **User-id checks:** the I-01 checks at sign-in, registration, add passkey and recovery,
     with a mutation for each check to show it is needed.
   - **Account tags:** in passkey handles and recovery words, for PRF and no-PRF accounts,
     written only from a u_c that was checked. The handle tag must also close the stripped
     registration of I-29.
   - **Read-access fixes:** the candidates in `conformance.md` §7.3 for I-30.
   - **Transition:** a variant where old untagged passkeys and 24-word sets are still in use.
   - **A-S5, end to end:** with the fixes, messages Alice encrypts under a pinned account stay
     secret from a server that does not know her password. This needs the cipher and account
     models together. If the combined model does not terminate, A-S5 becomes a two-part
     argument: the account model shows u_c stays secret, and the cipher model shows messages stay
     secret while u_c is secret.

   `fixes/v1` already checks the user-id checks at sign-in and recovery, and an early form of
   the tag: a u_c id in the passkey handle only. This step adds a new version for the planned
   design.
4. **After remediation:**
   - make the fixed behavior the default;
   - keep current behavior as variants that must still find their attacks;
   - model the I-14 and I-17 changes, if those fixes are made.
5. **The one-way no-PRF → PRF upgrade**, modeled and then implemented once the fixes in item 3
   are implemented for new accounts. The upgrade replaces every passkey and recovery word set.
   The server held u_c before the upgrade, so the PRF guarantees can hold only against a server
   compromised after the upgrade, with no copy of u_c kept.

Not planned: the legacy `/v1/recover` path (I-05).

The approved tex notation changes (`conformance.md` §6) follow items 1-2. The tex for the planned
fix goes in with the code, so the published protocol never describes behavior that has not
shipped.

**Independent reviews.** A sub-agent reviews the models, traces and claims at five points:
- after items 1 and 2, together with the malicious-server recovery results above, where new
  findings are most likely;
- after item 3, including A-S5, before the fix design goes to remediation;
- after the `main.tex` changes;
- after item 4;
- after item 5.
