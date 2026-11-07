# TLA+ results

What each variant of the models in `README.md` proves or finds. **holds** means TLC explored
every reachable state within the variant's bounds and the invariant held in all of them.
**violated** means TLC found a counterexample, and each counterexample was read to confirm it
is the behavior its property names. Witnesses are invariants that are expected to be violated:
their counterexamples show the behavior the proofs are about is reachable. Each variant's
constants and expected outcomes are in the `VARIANTS` block of its model.

All 11 variants pass. The whole run takes about 90 s with two TLC workers; no single TLC run
exceeds 100,000 distinct states. Every outcome below is the same with `STALE_WINDOW = 0`,
consistent reads only, because a stale verifyCookie read of an older record value produces the
same state as a read taken before the later writes.

## Revocation model (`Revoke.tla`)

One account with two passkeys. Mallory signs in with P_old while Alice, whose session is on
P_cur, deletes P_old. The question is whether a session on P_old can be used after the delete.

| Variant | What it models |
|---|---|
| `no-lookup` | verifyCookie checks only the cookie against the Users record |
| `lookup-mutating` | verifyCookie also checks that the session's passkey item exists, on non-GET routes only |
| `lookup-all-routes` | the same check on every authorized route, which is the shipped code |
| `transactions` | no passkey check; the sign-in's Users write and the passkey delete are transactions with a condition check on the other item |

| ID | Property | Holds in | Violated in |
|---|---|---|---|
| sanity | At most one cookie matches the Users record | all | — |
| A-X1 | Once a delete of P_old has returned, no cookie made from P_old verifies, GET or mutating | `lookup-all-routes`, `transactions`; mutating routes also in `lookup-mutating` | `no-lookup`; GET in `lookup-mutating` |
| A-X2 | No cookie made from P_old verifies once its Authenticators item is gone, GET or mutating | as A-X1 | as A-X1 |
| A-X3 witness | Alice's P_cur session is accepted after a delete of P_old has returned | — | all, as expected |
| A-X4 witness | A P_old session verifies at all | — | all, as expected |

**The A-X1 counterexample (`no-lookup`).** Mallory's sign-in completes: the Users record
becomes (P_old, 1) and a token is issued. Alice's delete verifies her cookie against the older
record (P_cur, 0), deletes P_old, and keeps the session because its snapshot's lastCredentialId
is P_cur. The delete returns. Mallory's GET verifies against (P_old, 1). With consistent reads
the same shape appears with Alice's verification ordered before Mallory's Users write: the race
is an ordering, not a replication lag.

**The A-X2 counterexample.** The same trace stopped after the delete's Authenticators write
and before it returns: a request on P_old verifies in that window. On GET routes this persists
in `lookup-mutating`, which is why the shipped check covers every route.

**`transactions`.** With the sign-in's write conditioned on the passkey item and the delete
conditioned on the Users record still holding the verified pair, whichever commits first makes
the other fail, and every property holds without a per-request lookup.

## State model (`State.tla`)

Sign-in, logout, add passkey, replace recovery words, delete passkey with the last-passkey user
delete, recover3, confirm, recover/verify, and one consistent observer per token. Each variant
activates the handlers its properties need. The handler set `recovery` below is sign-in, add
passkey, replace words, recover3, confirm, recover/verify and all three observers.

| Variant | Handlers | Switches | What it models |
|---|---|---|---|
| `shipped-session` | sign-in, logout, add, replace, delete, two observers | — | the shipped code |
| `shipped-recovery` | `recovery` | — | the shipped code |
| `shipped-two-recoveries` | replace, two recover3, two confirm, recover/verify, two observers | — | the shipped code |
| `conditional-writes` | `recovery` | COND_WRITES | the add-passkey create, the replace write and the passkey delete conditioned on the Users record still holding the verified (lastCredentialId, authCount) |
| `conditional-writes-block-signin` | `recovery` | COND_WRITES, BLOCK_SIGNIN | plus sign-in refused while a recovery is in progress |
| `versioned-sweep` | `recovery` | VERSION_SWEEP | a passkey version on Users bumped by every create and delete; confirm's delete-all and session clear as one transaction conditioned on the version seen at its query, retried on failure |
| `versioned-sweep-conditional-writes` | `recovery` | VERSION_SWEEP, COND_WRITES | both |

| ID | Property | Holds in | Violated in |
|---|---|---|---|
| sanity | At most one cookie matches the Users record | all | — |
| S-L1 | The cookie that performed a logout never verifies again | `shipped-session` | — |
| S-R1 | Once a confirm has deleted the passkeys, no session on one of them verifies | every `recovery` variant | — |
| S-B1, S-B2 | A confirm or recover challenge is consumed only if the Users record was not written between its store and its consumption | every variant that runs recovery | — |
| S-B3 | A recovery does not complete once a later recover3 has been accepted | — | `shipped-two-recoveries`, harmless, see below |
| S-W1 | A recovery started with the old words does not complete after a replace made by a session whose passkey it evicted | every variant with COND_WRITES | `shipped-recovery`, `shipped-two-recoveries`, `versioned-sweep` |
| S-W2 | Old words are not accepted after a replace | every `recovery` variant | — |
| S-R2 | When a recovery completes, no passkey added by a session whose passkey it evicted remains | `conditional-writes-block-signin`, `versioned-sweep-conditional-writes` | `shipped-recovery`, `conditional-writes`, `versioned-sweep` |
| witnesses | logout done; user deleted; a passkey deleted with the session ended; a passkey deleted with the session kept; sign-in token verified; recovery done; done with new words; done after a partial confirm; recovered token verified | — | all, as expected |

The user-delete revocation property is structural in this encoding, since a consistent read of
a deleted record fails, so it is covered by its witness only.

**The S-R2 counterexample (`shipped-recovery`).** An add-passkey request is authorized while
the attacker's session is live. recover3 runs. Confirm consumes its challenge and queries the
passkeys. The add request's create lands. Confirm deletes the queried set, clears the session
and stores the recover challenge, and recover/verify completes with two passkeys: the one it
created and the one added. The added passkey was never in the queried set, and the create is
not conditioned on the session that authorized it.

**The S-W1 counterexample (`shipped-recovery`).** A replace-words request is authorized at the
start and writes its key after recover/verify has consumed the recover challenge, so the
recovery completes with the replacement's words. The write is not conditioned on the session
that authorized it.

**S-B3.** The later recover3 has passed its proof check but not written, or writes between a
consume and the write that follows it, while the earlier recovery completes. Every consume is
guarded by S-B1 and S-B2, so this is harmless; the property stays in the block to record it.

**In `conditional-writes`, S-R2 still fails** because a sign-in with the passkey about to be
deleted can land between confirm's consume and its query, and that session is current when the
add request writes. The passkeys still exist until confirm's delete, so sign-in is possible in
that gap.

**`versioned-sweep` alone** leaves S-R2 open because a create authorized earlier lands
unconditionally after the sweep. **With conditional writes** a create before the query is in
the deleted set, a create between the query and the sweep's transaction bumps the version and
the sweep retries, and a create after the transaction fails its own condition because the
transaction changed authCount. That variant holds every property.

## Bounds

Each variant has one in-flight instance of each active handler, two recover3 and two confirm
instances in `shipped-two-recoveries`, three passkey identities and two word sets. A variant
with all thirteen handlers active is not in the block: its plain breadth-first search passes
one hundred million states, which exceeds the disk a laptop gives TLC's state queue, and the
properties above are about one request interleaving with one state change, which the bounded
variants cover.
