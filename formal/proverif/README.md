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
  - Per-request proofs limit the damage of the C1 unbound-challenge bug.
  - Recovery requires the recovery words.
  - u_c stays secret against the network, a leaked cd_u, a leaked session, and broken TLS. The
    broken-TLS result assumes the server's uniqueness guarantees (single-use challenges, one
    registration per user id).
- **Malicious server:** in PRF mode, the server never learns u_c (A-S2).

**What does not hold, or holds only through a dependency.** Each item was confirmed against the
code. `conformance.md` §5 has the details and code locations:

| Issue | Finding | Evidence | Status |
|---|---|---|---|
| I-01 | The browser accepts whatever user id the server names at sign-in, registration, add passkey and recovery. A malicious server can switch Alice's browser to an account whose u_c it chose, so messages she then encrypts rest on her password alone. This breaks the tex's claim that PRF accounts protect u_c from the server. | `malicious`: A-S3 attack; `malicious-fixui` proves the fix | fix planned (`conformance.md` §7) |
| I-03 | Account mode and u_c are trusted on first use in each browser. Even with the I-01 fix, a browser with no pin for the account accepts "no-PRF" and a u_c the server chose. | `malicious-fixui`: A-S4 attack; `malicious-fixhandle` proves a passkey-handle id | fix planned (§7) |
| I-04 | Recovery and replace-words signatures are kept apart by two layers: per-operation contexts, and the shared nonce store for the legacy context. Either one alone is enough. | `recovery-replay-*` | the store stops being needed once the legacy context is removed |
| I-14 | Truncation resistance depends on the encryptor never writing an empty block before the last one, because the decryptor does not check f on an empty block. | `integrity-net-emptymid` | hardening, pending |
| I-17 | The inner le is not compared with the outer le. An attacker holding u_c and the outer password can wrap a one-loop message as the inner layer of a two-loop message. The plaintext is still authentic. | `loops-uc-pout` | low, pending |
| I-29 | With TLS broken, an attacker can win the registration race and hold Alice's user id. Her u_c and words stay secret, and her browser notices on first use. | `login-tls`, `recovery-tls` | accepted |
| — | The externally reported V7 key-commitment incompleteness, reproduced. V8 closes it. | `commit-v7` | known |

The other issue-log entries are gaps in the tex, or ordering differences between the tex and the
code. None of them has a security effect the models found. The approved notation changes
(`conformance.md` §6) address most of them.

## Running

```bash
# One time. The opam package needs GTK2 for ProVerif's interactive simulator.
sudo apt install opam m4 graphviz libgtk2.0-dev pkg-config
opam init -y --no-setup && opam install -y proverif

pnpm verify:proverif               # every variant; non-zero exit on any mismatch
node formal/proverif/run.mjs loops # only variants whose name contains "loops"
node formal/proverif/run.mjs --print commit   # show actual results as EXPECTPV blocks
```

The runner finds `proverif` on `PATH`, or in `~/.opam/default/bin`, or in `$PROVERIF`.
`QC_PROVERIF_TIMEOUT` sets the timeout for each variant in seconds; the default is 900.
`QC_PROVERIF_JOBS` sets how many variants run at once; the default allows 4 GB of RAM per run.
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
| `conformance.md` | Tex ↔ code ↔ model trace, encoding-injectivity arguments, issue log, notation proposal, planned fixes |
| `remediation-tests.md` | Failing unit tests for planned code fixes, kept out of the source tree until each fix ships |
| `run.mjs` | Builds each variant with `m4 -P` and checks its results |
| `traces.mjs` | Lists every trace in the saved output, query by query, for review |

Each template lists its variants in a `VARIANTS` block, one per line: a name followed by m4
flags. The flags fall into three groups:
- `SCN_*` selects the scenario.
- `LEAK_*` gives the attacker a secret.
- `MUT_*` deliberately breaks one protocol mechanism.

The expected results for each variant sit at the end of the template in ProVerif's own
`EXPECTPV … END` comment format, so each generated `.pv` file is self-checking.

**To add or change a query:**
1. Edit the template.
2. Run with `--print`.
3. Read every trace in each variant the change affects, not only the results that changed.
   `node formal/proverif/traces.mjs --compact <variant>` lists each trace's events, requests and
   state changes. Confirm three things:
   - **Attack traces:** each one is the attack the variant names, and uses only steps the real
     system allows.
   - **Reachability traces:** each one is the honest run the related proof is about, for example
     Alice's own sign-in rather than one on the attacker's account. A proof without such a trace
     may hold only because the path it covers never runs.
   - **"cannot be proved" results:** each one has a written reason, and another variant shows the
     trace.
4. Paste the new block.
5. Record in this README what each trace shows.

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
| C-I1/2 | An accepted 1-, 2- or 3-block message is exactly one honest encryption: no truncation, extension, reorder or splice | p is secret, even when u_c leaks | — |
| C-I2 | Each block released while streaming is a prefix of an honest message | p is secret, even when u_c leaks | — |
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
- **`SCN_MALICIOUS`:** registration and sign-in against a malicious server.

**Who the attacker is.** The attacker is a full client of the server, with its own accounts. In
`SCN_MALICIOUS` it is the server. The browser and the static site that serves its code are
always honest.

**Channels.** TLS is a private channel with a fresh reply channel per request. `LEAK_TLS` makes
it public.

**Abstractions, each chosen so the attacker is at least as strong as in the real system:**
- **Server state lives in tables, which can only grow.** Deleted passkeys and replaced recovery
  keys therefore stay usable.
- **Uniqueness restrictions are opt-in, and off wherever a variant proves something.** Each
  mirrors a guarantee of the real system:
  - `STORE`: each challenge and each replay nonce is used once (the atomic delete-on-read and
    conditional put).
  - `RCV`: each private request is received by one server session.
  - `UNIQUSER`: each user id is registered once.

  Without them, the attacker gets more traces, so a proof made without them also holds with them.
  The variants that look for an attack, or for reachability, turn them on (see "Attack and
  reachability variants" below).
- **Not modeled:** timestamps, the skew window, TTLs, and `authCount`. Recovery's challenge
  binding is modeled as binding to pk_R only.
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
account of its own. So the `KEY_UI` variants identify Alice's accounts by the user id her browser
received at registration instead.

### Results: honest server

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-L1 | The server signs Alice in only with a passkey she approved, for that challenge | `net`, `session`, `cdu`, `device` | `device-nouv` (an unlocked device without UV); `unbound-trace`, `session-noproof` (each via the passkey A-R1 lets the attacker bind); `tls` (registration race) |
| A-R1 | Every passkey bound to Alice's account is one she created | `net`, `session`, `cdu`, `device` | `unbound-trace` (C1); `session-noproof`; `device-nouv` (once u_c leaks); `tls` |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | `net`, `session`, `cdu`, `device`, **and** `unbound` | `session-noproof` (cookie and CSRF alone); `device-nouv` (once u_c leaks); `tls` (the attacker holds Alice's user id) |
| A-S1, A-K1 | Alice's u_c stays secret, including when cd_u or the session cookie leaks, or TLS is broken | every variant except `device-nouv` | `device-nouv` (sign-in without UV yields cd_p, and the device yields the PRF output) |

**What the mutations and leaks show:**
- **`login-unbound-trace` rediscovers C1**, as a full trace. A signed-in attacker posts
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
replace-words request, as a log or a TLS-terminating proxy would, and turn the uniqueness
restrictions on:

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

| ID | Property | `malicious` | `malicious-fixui` (I-01 fix) | `malicious-fixhandle` (I-01 and I-03 fix) |
|---|---|---|---|---|
| A-S2 | In PRF mode the server never learns Alice's u_c | **true** | **true** | **true** |
| A-S3 | Once registration has completed in a browser, that browser never adopts a u_c the server knows | **attack (I-01)** | **true** | **true** |
| A-S4 | The same, for a browser that holds no pin for the account | attack | attack (trust on first use) | **true** |

**Reachability.** In all three variants, an honest sign-in is reachable on the registering
browser and on a browser with no pin. Each one signs in holding Alice's own u_c, and the query
requires the browser and the u_c to come from the same Alice. In each trace the server answers
"PRF" for Alice's own user id, with her cd_p. These traces show the proofs do not hold only
because the sign-in path never runs. A sign-in that ends in the I-01 attack does not satisfy
these queries, because the browser then holds the server's u_c.

**About `malicious-fixhandle`.** Each passkey's user handle also carries an id derived from u_c
(`hidOf`), and the browser checks the u_c it resolves against it. The authenticator returns the
handle to the browser directly, so the server cannot alter it.

The variant models the u_c-id half of the planned account tag (`conformance.md` §7) in passkey
handles only. The other parts are not modeled yet:
- the mode bit;
- the tag in recovery words;
- no-PRF accounts;
- old untagged passkeys and 24-word sets still in use.

The model treats the id as an unguessable hash. The planned real id is 31 bits, derived with its
own KDF purpose, and that is enough for three reasons:
- **It never reaches the server.** The browser strips it from the handle before sending, and
  builds `user.id` itself rather than taking it from the server's options.
- **Guessing is blind and costly.** Pk_U is public, but u_c is not, so in a PRF account a
  malicious server can only guess the id. Each guess costs a fresh-device sign-in or a recovery
  by Alice.
- **A wrong guess shows.** The browser halts on a mismatch, so the first failure exposes the
  attack. A successful attack has probability about 2^-31.

**About A-S3 in `malicious`.** Alice signs in on the browser that registered her account. The
server replies with a different user id (`sui` in the model), "no-PRF", and its own u_c. The
browser has no pin for that user id, so it accepts, and every message Alice then encrypts in
that session rests on her password alone. `conformance.md` I-01 has the code paths.

**About A-S3 in `malicious-fixui`.** In this variant the browser checks that the server's u_i
equals the passkey's user handle. The registered-browser pin check is written as a positive
lookup of the pin registration stored. ProVerif treats the "no entry" branch of any table lookup
as always possible, so it cannot prove anything through the negative form the code uses.

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

Reconstructing a trace from such a derivation searches away from it, and a single attempt ran
past 20 minutes. Under the restrictions the derivations are executable, so traces come back in
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
restrictions.

## Remaining work

As of 2026-10-09:

1. **Recovery against a malicious server.** `SCN_MALICIOUS` models only sign-in. Recovery has the
   same I-01 pattern: the browser pins and encrypts under the server's user id. Recovery also
   has its own trust-on-first-use point, because the words carry u_i but neither the account
   mode nor anything that identifies u_c.
2. **No-PRF accounts.** Everything so far is PRF mode. This adds:
   - a no-PRF variant of each scenario;
   - a passive database-leak variant, where u_c is expected to stay secret in PRF mode and to be
     exposed in no-PRF mode;
   - the one-way no-PRF → PRF upgrade. That server held u_c before the upgrade, so the PRF
     guarantees can hold only against a server compromised after the upgrade with no copy of u_c
     kept.
3. **A-S5: messages Alice encrypts under a pinned account stay secret from a server that does
   not know her password.** This needs the cipher and account models together. If the combined
   model does not terminate, A-S5 becomes a two-part argument: the account model shows u_c stays
   secret, and the cipher model shows messages stay secret while u_c is secret.
4. **The planned fix, next to current behavior** (`conformance.md` §7). This covers:
   - the I-01 user-id check;
   - account tags in passkey handles and recovery words, for PRF and no-PRF accounts;
   - a transition variant where old untagged passkeys and 24-word sets are still in use.
5. **After remediation:**
   - make the fixed behavior the default;
   - keep current behavior as variants that must still find their attacks;
   - model the I-14 and I-17 changes, if those fixes are made.

Not planned: the legacy `/v1/recover` path (I-05).

The approved tex notation changes (`conformance.md` §6) follow items 1-4. The tex for the planned
fix goes in with the code, so the published protocol never describes behavior that has not
shipped.

**Independent reviews.** A sub-agent reviews the models, traces and claims at four points:
- after items 1 and 2, where new findings are most likely;
- after item 4, before the fix design goes to remediation;
- after the `main.tex` changes;
- after item 5.
