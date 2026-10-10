# Fix models, version 1

These models check proposed fixes against a malicious server. They are separate from the models
of the current code in the parent directory (`../../README.md`), which keep the evidence for each
finding until its fix ships. `pnpm verify:proverif` runs both.

`account.pv.m4` is the parent's `account.pv.m4` as of 2026-10-09, with two fixes added under
flags. It is a snapshot, not kept in step with the parent model.

| Flag | Fix | Design |
|---|---|---|
| `FIX_UI` | I-01 user-id checks. At sign-in, the account the server names must be the passkey's user handle. At recovery, the `recover/confirm` options and `recover/verify` must name the recovery words' user. | `conformance.md` §7.1 |
| `FIX_HANDLE` | An early form of the I-03 tag. Each passkey's user handle also carries an id derived from u_c, and the browser compares it with the u_c it resolves at sign-in. There is no account-mode bit and no tag in the recovery words. | `conformance.md` §7.2 |

The `fixhandle` variants set both flags.

The planned design (`conformance.md` §7.2) goes further than `FIX_HANDLE`. Its tag carries an
account-mode bit as well as the u_c id, appears in the recovery words too, and is written only
from a u_c that was checked. A later version models that design.

## Results

The queries are the same as in the parent's malicious-server variants.

| ID | Property | `malicious-fixui` | `malicious-fixhandle` | `malicious-recovery-fixui` | `malicious-recovery-fixhandle` |
|---|---|---|---|---|---|
| A-S2 | In PRF mode the server never learns Alice's u_c | **true** | **true** | **true** | **true** |
| A-S3 | Once registration has completed in a browser, that browser never adopts a u_c the server knows, by sign-in or recovery | **true** | **true** | **true** | **true** |
| A-S4 | The same, for a browser with no pin that signs in | attack | **true** | attack | **attack** |
| A-S4R | The same, for a browser with no pin that recovers | — | — | attack | attack |

What the traces show:
- **The user-id checks close I-01 (A-S3).** The registering browser keeps Alice's own account and
  u_c at sign-in. With recovery, its pin blocks "no-PRF" at recover3, so the server must return
  Alice's cd_r. The two recovery checks then keep the new passkey and the session on her account.
- **The user-id checks leave trust on first use open (A-S4, A-S4R with `FIX_UI`).** A browser
  with no pin accepts "no-PRF" and the server's u_c for Alice's own user id, at sign-in or at
  recover3.
- **A u_c id in the passkey handle closes A-S4 only while recovery is left out.** In
  `malicious-fixhandle` A-S4 is proved. With recovery it is an attack:
  1. A recovery on a browser with no pin accepts the server's u_c.
  2. That recovery creates a new passkey whose handle carries the id of the server's u_c, before
     recovery even finishes.
  3. A later sign-in on another browser with no pin uses that passkey. The server again answers
     "no-PRF" with its u_c, the ids match, and the browser accepts.

  So the tag must also be in the recovery words, and a tag may be written only from a u_c that
  was checked (`conformance.md` §7.2).
- **A-S4R stays an attack in both recovery variants.** The recovery words carry no tag in this
  version.

**Reachability.** In every variant honest sign-ins, and in the recovery variants honest
recoveries, are reachable on both the registering browser and a browser with no pin. Each ends holding Alice's own u_c, on her own
user id. The queries require the browser and the u_c to come from the same Alice.

**Modeling note.** Under `FIX_UI`, the registering browser signs in through `LoginRegistered`
and recovers through `RecoveryRegistered`. Both read that browser's pin with a positive lookup.
With the negative form the code uses, A-S3 cannot be proved, because ProVerif treats the
"no entry" branch of a table lookup as always possible. The two forms are equivalent there,
because that browser's pin exists before Alice has her words.

**Registration.** This snapshot's `Register` accepts a reg/verify reply only when it names the
user id from the registration options. So every variant here includes the registration row of
the user-id checks (`conformance.md` §7.1), whatever its flags. The current-code model pins
whatever user id the reply names, and there A-S3R is an attack (`../../README.md`, "Results:
malicious server").

**Why the id can be modeled as an unguessable hash:** see `conformance.md` §7.2, "Why 31 bits
are enough".
