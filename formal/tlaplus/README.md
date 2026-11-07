# TLA+ models of the server's state

These are models of what the API server in `apps/server` does to its DynamoDB tables, one step
per database operation, checked with [TLC](https://lamport.azurewebsites.net/tla/tools.html),
the TLA+ model checker. They answer questions the ProVerif models in `../proverif` cannot:
what happens when two requests interleave at the database, including with eventually
consistent reads. They have no attacker model and no cryptography; the ProVerif models keep
those.

## Running

```bash
# One time: any Java 11 or later runtime
sudo apt install -y openjdk-21-jre-headless      # Ubuntu
brew install openjdk                             # macOS

pnpm verify:tlaplus                              # every variant; non-zero exit on any mismatch
node formal/tlaplus/run.mjs state/shipped        # only variants whose "model/name" contains the filter
node formal/tlaplus/run.mjs --print revoke       # show actual outcomes as VARIANTS lines
```

The runner uses `$JAVA` if set, then `$JAVA_HOME/bin/java`, then `java` on `PATH`. On its first
run it downloads `tla2tools.jar` 1.7.4 into `$XDG_CACHE_HOME/qcrypt/`, by default
`~/.cache/qcrypt/`, or it uses the jar `QC_TLC_JAR` points at, and it checks the jar's SHA-256
on every run. The GitHub release tagged v1.8.0 is a nightly whose jar changes daily, so the pin
stays on the fixed release. `QC_TLC_TIMEOUT` sets the timeout for each TLC run in seconds; the
default is 600. `QC_TLC_WORKERS` sets TLC's worker threads; the default is half the CPU count.
`QC_TLC_HEAP` sets the JVM heap; the default is `2g`. Translated modules, the TLC configuration
and the full output of every run, including counterexample traces, go to `dist/tlaplus/`.

`verify:tlaplus` is not part of any aggregate build or test script, because it needs Java. Run
it after any change to a handler's sequence of database operations, or to a model.

## Layout

| File | Contents |
|---|---|
| `Revoke.tla` | Sign-in racing a passkey deletion: whether a session on a deleted passkey can be used |
| `State.tla` | Sign-in, logout, add passkey, replace words, delete passkey, user delete, the three recovery handlers; switches select alternative write disciplines: conditional writes, sign-in refused during a recovery, a versioned passkey sweep |
| `run.mjs` | Translates each model's PlusCal, runs TLC per variant and property, and checks the outcomes |
| `RESULTS.md` | Each variant's outcomes and what each counterexample shows |

Each model ends with a `VARIANTS` block: one line per variant with the constants that select
it and the expected outcome of each property, `holds` or `violated`. A `DEFAULTS` line gives
the constants every variant starts from. The runner writes one TLC configuration per variant
and property, so the block is the whole specification of a run.

## How the models are built

- The models are PlusCal, with one label per DynamoDB operation, so every interleaving of
  operations across handlers is explored. The committed file holds the PlusCal only; the runner
  translates a copy under `dist/tlaplus/`.
- A record is a variable holding its latest value, plus a sequence of every value it has held.
  A consistent read is the variable; an eventually consistent read is any of the last
  `STALE_WINDOW` values. A conditional write is a step whose enabling condition is the
  condition expression, evaluated against the latest value, as DynamoDB evaluates it.
- Handlers that only read, such as an authorized GET, are single-step observers that record
  flags. They write nothing, so one observer per token, scheduled anywhere, covers every
  placement, and a loop would only multiply interleavings. TLC has no partial-order reduction;
  the number of free-running steps is what sets the cost.
- Properties are invariants over flag sets that the steps fill in. Each invariant that should
  hold is paired with a witness: an invariant that should be violated, whose counterexample
  shows that the behavior the proof is about is reachable. A variant whose witnesses stop being
  violated has lost coverage, not gained safety.
- Variants that are expected to be violated stay in the block as regressions. They show that
  the model sees the behavior another variant's switch removes, which is what the ProVerif
  `MUT_*` variants do for the protocol.
- Every run is bounded: one in-flight instance of each handler, a fixed set of passkeys and
  word sets. The guarantee is for every interleaving within those bounds, which is where a
  race between one request and one state change appears.

**To add or change a property or variant:**
1. Edit the model and its `VARIANTS` block.
2. Run with `--print` and compare the lines with the block.
3. Read every counterexample the change affects, in the `.out` files under `dist/tlaplus/`,
   and confirm each is the behavior its property names, not an artifact of the encoding.
4. Keep each variant's run under a minute. A variant with more than about ten free-running
   processes grows past what a laptop's disk holds for TLC's state queue; split it by the
   handlers each property needs instead.

## Revocation model (`Revoke.tla`)

### What is modeled

One account with two passkeys, P_old and P_cur, and one live session on P_cur. Mallory signs
in with P_old: the passkey lookup, then the Users write and the lookup with the exists
condition in either order, then the token. Alice deletes P_old: the cookie check against an
eventually consistent read, the Authenticators delete, then the session write when the
snapshot's lastCredentialId is the deleted id; a retry that finds no item returns at the
not-found check. One GET and one mutating request per principal verify consistently.
`ROUTE_CHECK` sets which routes also look up the session's passkey item. `TX` makes the
sign-in's Users write and the delete transactions that check the other item.

## State model (`State.tla`)

### What is modeled

The account's session, passkey and recovery flows, one step per DynamoDB operation: sign-in,
logout, add passkey, replace recovery words, delete passkey including the last-passkey user
delete, recover3, confirm and recover/verify, with the confirm and recover challenges bound to
(recoveryPubKey, authCount) as buildChallenge computes them, and one consistent observer per
token. `ACTIVE` picks the handlers of a variant. Three switches select write disciplines:
- `COND_WRITES`: the add-passkey create, the replace write and the passkey delete are
  conditioned on the Users record still holding the lastCredentialId and authCount the cookie
  was verified against.
- `BLOCK_SIGNIN`: no sign-in Users write between recover3's write and recover/verify's write.
- `VERSION_SWEEP`: a passkey version on the Users record that every create and delete bumps;
  confirm's delete-all and session clear are one transaction conditioned on the version seen
  at its query, retried from the query when the condition fails.

## Summary of results

`RESULTS.md` gives each variant's outcome and what each counterexample shows. The headline
properties:

| ID | Property | Holds in | Violated, as expected, in |
|---|---|---|---|
| A-X1, A-X2 | No cookie made from a deleted passkey verifies, once the delete returned or once the item is gone | `lookup-all-routes` (the shipped code), `transactions` | `no-lookup`; GET routes in `lookup-mutating` |
| S-L1 | The cookie that performed a logout never verifies again | `shipped-session` | — |
| S-R1 | No session on a passkey a confirm deleted verifies | every variant that runs recovery | — |
| S-B1, S-B2 | A confirm or recover challenge is consumed only against the record state it was bound to | every variant that runs recovery | — |
| S-W1 | A recovery started with the old words does not complete after a replace by a session on an evicted passkey | every variant with `COND_WRITES` | the shipped variants and `versioned-sweep` |
| S-W2 | Old words are not accepted after a replace | every variant that runs recovery | — |
| S-R2 | A completed recovery leaves no passkey added by a session on an evicted passkey | `conditional-writes-block-signin`, `versioned-sweep-conditional-writes` | `shipped-recovery`, `conditional-writes`, `versioned-sweep` |
| S-B3 | A recovery does not complete once a later recover3 was accepted | — | `shipped-two-recoveries`; harmless, every consume is still guarded by S-B1 and S-B2 |
