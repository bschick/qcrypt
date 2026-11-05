# ProVerif results

What each variant of the models in `README.md` proves or finds. **true** or "holds" means the
property holds. **attack** means ProVerif found a trace, and each trace was read to confirm it is
the attack its variant names. Each variant's flags, including the restrictions it runs under, are
in the `VARIANTS` block of its template.

## Message format (`cipher.pv.m4`)

All 22 variants pass. Each takes under 20 s.

### Properties

| ID | Property | Holds when | Attack, as expected, when |
|---|---|---|---|
| C-S1 | Message blocks stay secret | the attacker lacks p or u_c | it has both (`secrecy-both`) |
| C-W1 | p cannot be guessed offline | u_c is secret | u_c leaks (`secrecy-uc`): k_C and the AEAD give an offline test |
| C-H1 | The hint stays secret | u_c is secret | u_c leaks |
| C-H2 | A shown hint is one Alice wrote | u_c is secret | u_c leaks: the hint is authenticated only under u_c |
| C-I1/2 | An accepted 1-, 2- or 3-block message is exactly one honest encryption: no truncation, extension, reorder or splice | p or u_c is secret (`integrity-uc`, `integrity-p`) | — |
| C-I2 | Each block released while streaming is a prefix of an honest message | p or u_c is secret (`integrity-uc`, `integrity-p`) | — |
| C-I2 (loops) | No loop is stripped from a two-loop message, and no one-loop message is accepted as an inner layer | the inner password is secret, even when u_c and the outer password leak | — |
| C-K1 | No block 0 is accepted under two different (p, u_c) | V8: always, for all three algorithms | — |
| C-K1-v7 | The same game on V7 | AEGIS-256 | AES-GCM and XChaCha20-Poly1305 (`commit-v7`) |
| C-D1 | A V8 message is never accepted through the V7 decode path, and the reverse | u_c leaks, p secret | — |
| C-A1 | u_c at rest stays secret, and an accepted blob was encrypted under k for that same u_i | k is secret (`atrest-net`) | — |
| C-A2 | The at-rest format commits to (k, u_i) | always (`commit-*`) | — |
| C-A3 | No block is accepted both as a message and as u_c at rest | always, under any keys (`commit-*`) | — |

**About `commit-v7`.** It decodes through the V7 block 0 (`USE_V7`), and reproduces the
externally reported V7 key-commitment incompleteness: one u_c, two passwords, and one block 0
accepted under both. It fails for exactly the algorithms the report names, and holds for AEGIS.
V8 closes it for every algorithm.

**About `loops-uc-pout`.** The attacker holds u_c and the outer password, so as expected it can
replace the outer layer of Alice's two-loop message. In that trace the inner layer, and so the
plaintext, is still hers. It cannot wrap her one-loop message as an inner layer, because the
inner layer's le must equal the outer layer's, and the outermost layer must have lp = le. The
reachability traces in this variant use a message the attacker built under the leaked outer
password. `loops-uc` shows honest acceptance for the same processes.

### Mutations

Each mutation removes one mechanism, and each must turn a proof into an attack. Where two
mechanisms each block the same attack, removing one alone must still hold, and removing both
must find the attack:

| Variant | Mechanism removed | Attack found |
|---|---|---|
| `commit-v8-nokc` | Comparing the stored k_C | Two passwords accepted for one ciphertext (GCM, XChaCha) |
| `integrity-uc-nof` | f in the AEAD AD (kept in the MAC) | An attacker holding u_c flips f on block 0 and truncates a 3-block message |
| `integrity-uc-non` | Block number in the k_MN derivation | A later block replayed one position early, dropping the block before it: block 2 of a three-block message, or the empty final block of a two-block message |
| `integrity-net-emptymid` | The encryptor writing an empty block only as the last one | None: the decryptor rejects an empty block without f = 1 |
| `integrity-net-noemptyf` | The decryptor checking f on an empty block | None: the encryptor writes an empty block only as the last one |
| `integrity-net-emptymid-noemptyf` | Both of the above | Truncation with no secret leaked: an empty middle block ends a 3-block message after block 0 |
| `loops-uc-pout-nolple` | The outermost lp = le check | The inner layer of a two-loop message accepted on its own, and a one-loop message wrapped under an outer layer with lp = 2 and le = 1 |
| `loops-uc-pout-nole` | Comparing the inner layer's le with the outer layer's | A one-loop message wrapped as the inner layer of a two-loop message |

## Account model (`account.pv.m4`)

### Sign-in and passkeys (`login-*`)

Variant names in the table drop the `login-` prefix.

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-L1 | The server signs Alice in only with a passkey she approved, for that challenge | `net`, `session`, `cdu`, `device` | `device-nouv` (an unlocked device without UV); `unbound-trace`, `session-noproof` (each via the passkey A-R1 lets the attacker bind); `tls` (registration race) |
| A-R1 | Every passkey bound to Alice's account is one she created | `net`, `session`, `cdu`, `device` | `unbound-trace` (C1); `session-noproof`; `device-nouv` (once u_c leaks); `tls` |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | `net`, `session`, `cdu`, `device`, **and** `unbound` | `session-noproof` (cookie and CSRF alone); `device-nouv` (once u_c leaks); `tls` (the attacker holds Alice's user id) |
| A-K2 | The server stores Alice's pk_U or pk_R only from a reg/verify her browser signed, for that challenge | every variant except `device-nouv` | `device-nouv` (once u_c leaks); the mutations `tls-regsigr-nopku`, `db-chal-noregsigu` and `db-noregsigr` |
| A-S1, A-K1 | Alice's u_c stays secret, including when cd_u or the session cookie leaks, or TLS is broken | every variant except `device-nouv` | `device-nouv` (sign-in without UV yields cd_p, and the device yields the PRF output) |

**What the mutations and leaks show:**
- **`login-unbound-trace` rediscovers C1**, a bug fixed before the models, as a full trace. A
  signed-in attacker posts `passkeys/verify` with a body naming Alice's u_i and any outstanding
  challenge. The mutated server takes the user from the body and binds the attacker's passkey to
  Alice's account, and the attacker then signs in to her account with it. Even then, A-Z1 holds
  and u_c stays secret: the proof of userCred contains the damage. `login-unbound` proves those
  two properties with no restrictions.
- **`login-session-noproof`:** the attacker sends Alice's stolen cookie and CSRF token, with an
  arbitrary signature, to `passkeys/options`, `passkeys/verify`, and the generic endpoint. It
  then signs in with the passkey it bound.
- **`login-device-nouv`:** the attacker feeds an auth challenge to the unlocked device, posts the
  assertion it made without UV, is signed in, and decrypts the returned cd_p with the device's
  PRF output.
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
  - `STRIPLOGIN` sets up these two variants. It leaves out API requests and added passkeys, on
    both sides, because with them saturation does not finish. Leaving out honest processes only
    removes runs, so its trace is a trace of the full system. It also marks Register's two inputs
    and the reg/verify input `[precise]`.

  Her own PRF u_c stays secret throughout.

**Reachability.** `login-reach` (`REACH_ONLY`, which runs only the reachability queries) shows
Alice's own runs reaching the server:
- her sign-in with her passkey;
- a request she signed;
- a passkey she added through `passkeys/verify`;
- her browser completing a sign-in while holding her own u_c.

Each server-side query pairs the server's event with an event that only Alice's browser or
authenticator emits, so the attacker's own account cannot satisfy it. The browser query requires
the browser and the u_c to come from the same Alice (`!1 = alice`).

The variant turns on the uniqueness restrictions (`README.md`, "What is modeled"), which only
remove traces. The other login variants only add
attacker knowledge (`LEAK_*`), relax server checks (`MUT_*`), change queries (`KEY_UI`), or make
TLS public, and with TLS public the attacker can forward Alice's messages unchanged. So each trace
is also a run of every other login variant, apart from the `Rcv` events that `RCV` records.

### Recovery (`recovery-*`)

Variant names in the table drop the `recovery-` prefix.

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-V1 | recover3 accepts a proof on Alice's account only from her browser recovering it | every variant except these three | `words` (words leaked); `tls` (registration race); `log-onectx-noreplnonce` (a replace-words proof under one shared context) |
| A-V2 | recover/confirm on Alice's account is one her browser signed, for that challenge | every variant except `words` and `tls` | `words`; `tls` (registration race) |
| A-V3 | New recovery words on Alice's account are ones her browser created | every variant except `words` and `tls` | `words` (the original words give recovery, then a session); `tls` |
| A-R1 | Every passkey bound to Alice's account, including by recovery, is one she created | every variant except these five | `words`; `tls` (registration race); `log-noconfirmchal-nobind-noproof`, `log-norecoverchal-nobind-noproof` (a reused challenge with no binding check and no recover/verify proof, see "Replay"); `db-chalrec-norecverifyproof` (see "Database leak") |
| A-S1 | u_c, the original words, and replaced words stay secret | every variant, except u_c and the original words in `words` | `words` |

**`recovery-words`:** leaked words, then recover3, then confirm with the u_c from cd_r, then
recover/verify with the attacker's passkey.

**Reachability.** `recovery-reach` shows each step of Alice's own recovery:
- her recover3, with her nonce;
- her confirm;
- `recover/verify` binding a passkey she created;
- her browser finishing with her own u_c.

It also shows her replacing her words. As in `login-reach`, each server event is paired with
Alice's client event, and the uniqueness restrictions are on. By the same argument, each trace
is also a run of every other recovery variant.

### Replay

`LEAK_LOG` copies each request the server accepts to the attacker, as a request log or a proxy
that records traffic would. The copy is made after the server accepts the request. A copy made
on receipt could be forwarded and accepted before the original, which is the race that broken TLS
already covers, not a replay. GET requests are not logged, since the server lets them repeat
(`utils.ts:verifyUserCredNonceProof`). Nor are reg/options and auth/options, which need no
credentials, so the attacker can send its own.

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
| `recovery-log-norecnonce` | PRF | `'words'`, used by recover3 and replace words | **attack**: recover3 | hold |
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
| `recovery-noprf-log-norecnonce` | no-PRF | `'words'` | **attack**: all but registration | all **attack** except word secrecy |
| `recovery-noprf-log-noconfirmchal` | no-PRF | confirm challenge | holds: the authCount binding blocks it | hold |
| `recovery-noprf-log-noconfirmchal-nobind` | no-PRF | confirm challenge, and no binding check | **attack**: confirm | hold: recover/verify needs a proof made with u_c |
| `recovery-noprf-log-noconfirmchal-nobind-noproof` | no-PRF | confirm challenge, no binding check, and no recover/verify proof | **attack**: all but registration | all **attack** except word secrecy |
| `recovery-noprf-log-onectx-noreplnonce` | no-PRF | replace words' nonce, with one context | **attack**: all but registration | all **attack** except word secrecy |

The logged requests also carry the session cookie, CSRF token and pk_U, so the PRF base variants
show that a full request log breaks none of the other properties.

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
and every authorized request still needs Alice's proof. In the no-PRF mutations marked "all but
registration", the replayed request's reply carries u_c: auth/verify's, recover3's, or
recover/verify's for the passkey the attacker binds. With u_c the attacker signs requests of its
own, so the other A-N1 attacks in those variants are its own requests, not replays.
`recovery-noprf-log-norecoverchal-nobind` is left out, since its reconstruction does not finish
in 300 s, and `recovery-log-norecoverchal-nobind` shows the same reuse.

**Cross-use of recovery proofs.** The per-operation contexts alone keep a replace-words
proof from passing recover3: `recovery-log-noreplnonce` holds without replace words' nonce store.
The `onectx` variants sign and verify replace words under sc_R, as with one context for both
operations. The shared nonce store then keeps the two apart, and without it the logged
replace-words proof passes recover3. The tex shows the store in both stanzas to match the code,
although the replace-words request also has its own `'api'` nonce.

**What A-N1 does not cover.**
- **GET requests,** which may repeat. A recorded `GET passkeys/options`, sent again within the
  120 s skew window, gives the attacker a new add challenge for Alice's account
  (`server.ts:getPasskeyOptions`). Using that challenge takes a passkeys/verify request with a
  new proof over its body, which needs u_c.
- **Rejected requests,** which are not logged. A replay of one is rejected again, unless the
  first attempt failed from a transient error, such as a failed database read, before its
  challenge was consumed or its nonce stored. That replay can be accepted once, within the skew
  window or the challenge's lifetime, and it carries only what Alice sent.
- **Replies,** since each goes to a fresh private reply channel.
- **The timestamp check,** since the stores never forget (`README.md`, "What is modeled").
- **A replay inside one handler,** sent after recover/confirm or recover/verify reads authCount
  and before it increments, which the model makes one step. It can pass only with that
  challenge's store off (`README.md`, "What is modeled").

**Why not injective queries.** An `inj-event` correspondence states one-to-one acceptance
directly, but on the login queries saturation had not finished after 300 s. Queries that a
request is accepted at most once end in "cannot be proved", from derivations where one server
session receives two requests. The log query needs neither, and each variant finishes in under a
second, apart from the no-PRF mutations.

### Database leak

`LEAK_DB` gives the attacker a copy of the server's account tables:
- users and unverified users, each with pk_U;
- recovery keys, with pk_R and cd_r;
- passkeys, with the credential id, public key and cd_p;
- for a no-PRF account, u_c under both KMS keys.

Replay nonces are not in the copy. `LEAK_CHAL` adds live reads of the challenge table, whose
entries last 300 s (`CHALLENGE_TTL_SECS`), and `LEAK_CHAL_RECOVER` of only its recover/verify
challenges. `LEAK_KMS_NEW` and `LEAK_KMS_OLD` add the use of the
main or the backup KMS key. PRF mode keeps nothing under KMS, so the PRF variants leave the keys
out.

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

### No-PRF accounts

The `noprf` variants repeat the login and recovery variants in no-PRF mode. The no-PRF `log` and
`db` variants are in "Replay" and "Database leak". Results in bold differ from PRF mode.

| ID | Property | Holds in | Attack, as expected, in |
|---|---|---|---|
| A-L1, A-R1 | Sign-in only with a passkey Alice approved; only passkeys she created are bound | `login-noprf-net`, `-session`, `-cdu`, `-device` | `-device-nouv`, `-unbound`, `-session-noproof`, `-tls` |
| A-Z1 | Every authorized request on Alice's account is one her browser signed | `login-noprf-net`, `-session`, `-cdu`, `-device` | `-device-nouv`, **`-unbound`**, `-session-noproof`, `-tls` |
| A-K2 | Alice's pk_U and pk_R are stored only from a reg/verify her browser signed | `login-noprf-net`, `-session`, `-cdu`, `-device` | `-device-nouv`, **`-unbound`**, **`-session-noproof`**, **`-tls`**: each gives the attacker u_c, which signs a registration under her pk_U |
| A-S1, A-K1 | Alice's u_c stays secret: the u_c the server stored when it registered her passkey, and the u_c her browser holds | `login-noprf-net`, `-session`, `-cdu`, `-device` | `-device-nouv`, **`-unbound`**, **`-session-noproof`**, **`-tls`** |
| A-V1 to A-V3, A-R1 | Recovery steps and new words on Alice's account are her browser's | `recovery-noprf-net`, `-session` | `-words`, `-tls` |
| A-S1 | u_c, in both forms, and both word sets stay secret | `recovery-noprf-net`, `-session`; the replaced words in every variant | `-words` (u_c, original words); **`-tls`** (u_c) |

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

### Malicious server

The attacker is the server. It answers every request and holds the database, the KMS keys and
the session keys, so Alice's browser has only its own checks (`README.md`, "The browser's
checks").

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

### Results that rest on restrictions

Every attack in the account model is reported as a concrete trace ("is false"). The one exception
is `login-unbound`. It runs without restrictions so that its A-Z1 and u_c secrecy proofs hold for
every run, and without backtracking (`NOBT`). Its two attack queries therefore end in "cannot be
proved". `login-unbound-trace` adds `UNIQUSER`, and returns those as traces. A restriction only
removes traces, so each of those traces is also a trace of `login-unbound`. `login-noprf-unbound`
has no unrestricted counterpart: its counterpart in PRF mode exists to prove A-Z1 and u_c
secrecy, and in no-PRF mode both are attacks.

A "true" result in a restricted variant holds for runs that respect the real server's uniqueness
guarantees (`README.md`, "What is modeled"). Most such results also have an unrestricted proof in
a base variant. Three groups have none, so their results hold only under the restrictions:
- **Broken TLS:** every `tls` variant is restricted (`login-tls`, `recovery-tls`, the two no-PRF
  `tls` variants, `login-tls-dualmode`, `login-tls-stripped`, and the mutations
  `login-tls-regsigr-nopku` and `login-tls-stripped-nohandletag`). So u_c and
  recovery-word secrecy under broken TLS is proved only under their restrictions.
- **Live challenge reads:** every result of the `db-chal` variants.
- **Replay:** the `log` variants' results, with every accepted request leaked, hold only under
  `STORE`, the stores and authCount binding they test.

Two variants need a restriction for a reason of their own:
- `login-log-noregchal` needs `UNIQUSER`. Without it, a derivation registers Alice's user id
  twice, and the existing-user check never applies.
- `malicious-existing-nowordstag` needs `RCV`, `STORE` and `UNIQUSER`. Without them, the attack
  query ends in "cannot be proved" or does not finish in 900 s.
