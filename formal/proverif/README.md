# ProVerif models of the Quick Crypt protocol

These are symbolic (Dolev-Yao) models of the protocol in `apps/web/src/assets-src/main.tex`,
checked with [ProVerif](https://bblanche.gitlabpages.inria.fr/proverif/) 2.05. The models follow
the **code** wherever it differs from the tex. `conformance.md` maps every tex step to its code
and model, and keeps the issue log.

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
| `conformance.md` | Tex ↔ code ↔ model trace, encoding-injectivity arguments, issue log, notation proposal |
| `run.mjs` | Builds each variant with `m4 -P` and checks its results |

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
3. Read the trace for every result that changed.
4. Paste the new block.

Never paste a result you have not explained.

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

### Mutations

Each mutation removes one mechanism, and each must turn a proof into an attack:

| Variant | Mechanism removed | Attack found |
|---|---|---|
| `commit-v8-nokc` | Comparing the stored k_C | Two passwords accepted for one ciphertext (GCM, XChaCha) |
| `integrity-uc-nof` | f in the AEAD AD (kept in the MAC) | An attacker holding u_c flips f on block 0 and truncates a 3-block message |
| `integrity-uc-non` | Block number in the k_MN derivation | Block 2 replayed at position 1, dropping the middle block |
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
- **Two uniqueness restrictions are opt-in (`STORE`).** One makes each challenge single-use,
  modeling the atomic delete-on-read. The other makes each replay nonce single-use. Without them,
  replays are unrestricted.
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
from a u_c she created (`new ucA`).

### Results: honest server

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-L1 | The server signs Alice in only with a passkey she approved, for that challenge | `net`, `session`, `cdu`, `device` | `device-nouv` (an unlocked device without UV); `unbound`, `session-noproof`, `tls` (each via the passkey A-R1 lets the attacker bind) |
| A-R1 | Every passkey bound to Alice's account is one she created | `net`, `session`, `cdu`, `device` | `unbound` (C1); `session-noproof`; `tls` |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | every variant except `session-noproof` and `device-nouv`, **including** `unbound` and `tls` | `session-noproof` (cookie and CSRF alone) |
| A-S1, A-K1 | Alice's u_c stays secret, including when cd_u or the session cookie leaks, or TLS is broken | every variant except `device-nouv` | `device-nouv` (sign-in without UV yields cd_p, and the device yields the PRF output) |

**What the mutations and leaks show:**
- **`login-unbound` rediscovers C1**, as a full trace. A signed-in attacker posts
  `passkeys/verify` with a body naming Alice's u_i and any outstanding challenge. The mutated
  server takes the user from the body and binds the attacker's passkey to Alice's account. Even
  then, A-Z1 holds and u_c stays secret: the proof of userCred contains the damage.
- **`login-tls`.** With TLS broken, the attacker sees Alice's registration challenge and submits
  `reg/verify` first, with her u_i, challenge and pk_U but its own passkey. With attestation
  `none`, nothing in a registration response says who built it. A-Z1 and u_c secrecy still hold.

### Results: recovery

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-V1 | recover3 accepts a proof on Alice's account only from her browser recovering it | `net`, `session`, every `replay` variant except the one below | `words` (words leaked); `tls` (registration race); `replay-legacy-splitnonce` |
| A-V2 | recover/confirm on Alice's account is one her browser signed, for that challenge | every variant except `words` | `words` |
| A-V3 | New recovery words on Alice's account are ones her browser created | every variant except `words` | `words` (the original words give recovery, then a session) |
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

**Reachability.** Each step of Alice's recovery is reachable in every non-`NOTRACE` variant.
The final step (`ServerRecovered`) is checked in `recovery-tls-reach`, because reconstructing
that trace with TLS private runs for hours.

### Results: malicious server

| ID | Property | `malicious` | `malicious-fixui` (I-01 fix) |
|---|---|---|---|
| A-S2 | In PRF mode the server never learns Alice's u_c | **true** | **true** |
| A-S3 | Once registration has completed in a browser, that browser never adopts a u_c the server knows | **attack (I-01)** | **true** |
| A-S4 | The same, for a browser that holds no pin for the account | attack | attack (trust on first use) |

**About A-S3 in `malicious`.** Alice signs in on the browser that registered her account. The
server replies with a different account id, "no-PRF", and its own u_c. The browser has no pin
for that id, so it accepts, and every message Alice then encrypts in that session rests on her
password alone. `conformance.md` I-01 has the code paths.

**About A-S3 in `malicious-fixui`.** In this variant the browser checks that the server's u_i
equals the passkey's user handle. The registered-browser pin check is written as a positive
lookup of the pin registration stored. ProVerif treats the "no entry" branch of any table lookup
as always possible, so it cannot prove anything through the negative form the code uses.

### Evidence for NOTRACE variants

In `login-session-noproof`, `login-device-nouv`, `login-tls`, `recovery-words` and
`recovery-tls`, one trace-reconstruction attempt takes over 20 minutes. These variants set
`NOTRACE`, so their attacks read "cannot be proved". The evidence is the derivation ProVerif
prints, and each was read. The two recovery variants show the expected consequence of leaked
words, and the registration race confirmed as a trace in an earlier run. The login variants:
- **`session-noproof` (A-R1, A-Z1):** the attacker sends Alice's stolen cookie and CSRF token
  with an arbitrary signature to `passkeys/options`, `passkeys/verify`, and the generic
  endpoint.
- **`device-nouv` (A-L1, A-S1):** the attacker submits an assertion the device made without UV,
  is signed in, and decrypts the returned cd_p with the device's PRF output.
- **`tls` (A-L1, A-R1):** the registration race described above. It was confirmed as a full
  trace before `NOTRACE` was added.
