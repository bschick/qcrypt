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
Generated `.pv` files and the full ProVerif output, including attack traces, go to
`dist/proverif/`.

`verify:proverif` is not part of any aggregate build or test script, because it needs opam.
Run it after any change to the protocol code, the tex, or a model.

## Layout

| File | Contents |
|---|---|
| `lib/qcrypt.pvl` | Primitives shared by every model |
| `cipher.pv.m4` | The V8 message format: block 0, block N, loops, hint, and the V7 decode path |
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

All 18 variants pass. Each takes under 15 s.

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

**About `commit-v7`.** It reproduces the externally reported V7 key-commitment attack: one u_c,
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
