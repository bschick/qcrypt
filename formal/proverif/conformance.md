# Quick Crypt protocol: spec, code, and model conformance

This file ties three descriptions of the protocol together:

- the specification in `apps/web/src/assets-src/main.tex` ("tex");
- the code that implements it;
- the ProVerif models in this directory.

It also holds the issue log for every difference found between them, the proposed changes to the
tex notation, and the design of the planned fixes.

**References.** Tex references name the `main.tex` stanza, so they survive edits to the tex. Code
`file:line` references are as of commit `48c26a6`. The model column names the model function or
process for each step.

**Code paths** are abbreviated as follows.

| Abbrev | Path |
|---|---|
| `cur` | `libs/crypto/src/lib/ciphers-current.ts` |
| `ciph` | `libs/crypto/src/lib/ciphers.ts` |
| `cs` | `libs/crypto/src/lib/cipher-streams.ts` |
| `keys` | `libs/crypto/src/lib/keys.ts` |
| `cproof` | `libs/crypto/src/lib/proof.ts` |
| `aproof` | `libs/api/src/lib/proof.ts` |
| `auth` | `apps/web/src/app/services/authenticator.service.ts` |
| `ks` | `apps/web/src/app/services/keystore.service.ts` |
| `prf` | `apps/web/src/app/services/prf.ts` |
| `srv` | `apps/server/src/server.ts` |
| `sutil` | `apps/server/src/utils.ts` |

---

## 1. Message format (V8)

| Tex | Step | Code | Model |
|---|---|---|---|
| Message Encryption by A | n_IVH = D_H(2, kp_H, H_{n_IV}(n_S,a,v,lp,e_l)) | `keys:742`, called at `cur:461` and `cur:1072` | `mkNIVH` |
| Message Encryption by A | k_H = D_H(1, kp_H, H_{u_c}(…)) | `keys:741` | `mkKH` |
| Message Encryption by A | k_S = D_H(1, kp_S, H_{u_c}(…)) | `keys:721-726` | `mkKS` |
| Message Encryption by A | k_M0 = D_P(p_l‖p‖u_c‖a‖v‖lp‖e_l, n_S, i) | `keys:686-719`, material from `keys:829-836`, PBKDF2 at `keys:280-314` | `mkKM0`, `pwmat8` |
| Message Encryption by A | k_C = D_H(1, kp_C, H_{k_M0}(n_S)) | `keys:746-749` | `mkKC` |
| cd_0 Encryption by B | h_E = E_a(PAD(h), n_IVH, ∅, k_H); empty hint means no h_E | `cur:444-461` | `mkBlock0L` |
| cd_0 Encryption by B | ad_F for block 0 | `cur:472-482`, `cur:251-300` | `ad0` |
| cd_0 Encryption by B | m_E = E_a(m_0, n_IV, ad_F, k_M0) | `encryptBlock0` `cur:419-504` | `mkBlock0L` |
| cd_0 Encryption by B | t = H_{k_S}(v‖l‖ad_F‖m_E‖t_L) | `_createHeader` `cur:622-647` | `mac`, `macin` |
| cd_N Encryption by B | ad_F = f‖a‖n_IV; k_MN = D_H(N, kp_B, H_{k_M0}(…)) | `cur:535-539`, `keys:838-842` | `adN`, `mkKMN`, `mkBlockN` |
| Message Encryption by A, Message Decryption by A | t_L = 0x00 at the start of each loop | `cur:394` (encrypt), `cur:929` (decrypt), with a fresh instance per loop at `cs:73` and `cs:173` | `TL0` |
| Message Decryption by A | MAC verify | `_verifyMAC` `cur:1223-1256`, called at `cur:1061` | `Dec`, `BlockN1`, `BlockN2` |
| Message Decryption by A | k_Cl == 32 after the MAC, and i ≥ 420,000 just before k_M0 | k_Cl: `cur:1063-1069`; before the MAC, unpacking accepts only k_Cl ∈ {0, 32} (`cur:1324-1330`). i: before the MAC, `setCipherDataInfo` applies the floor to a nonzero i (`keys:93`); the complete check, which also rejects i = 0, is in `_pbkdf2CipherKey` (`keys:284`). See I-13 | `Dec`: `kC <> NOKC`, `i <> IC0` |
| Message Decryption by A | lp sequencing across loops | `cs:176-185`, after the hint is decrypted | `Dec`: `lp = le`; `open0` |
| Message Decryption by A | Hint decrypt | `cur:1071-1084` | `Dec`: `HintShown` |
| Message Decryption by A | k_M0, then the k_C compare | `decryptBlock0` `cur:717-772`; compare at `cur:745-750` | `Dec`: `kC = mkKC(...)` |
| Message Decryption by A, m_N Decryption by B | TERM flag checks | `_decodeBlockN` `cur:1155-1221`. See I-14 | `Dec`, `BlockN1`, `BlockN2` |
| m_N Decryption by B | a and v equal block 0's values | `cur:1207-1213` | `BlockN1`, `BlockN2` |
| m_N Decryption by B | Block N AEAD decrypt | `cur:1110-1140` | `BlockN1`, `BlockN2` |
| Message Decryption by A | Recurse while lp > 1 | `cs:221-223` | `DecL` |
| — | V7 decode path (I-16) | `keys:632-793`, `cur:948-967` | `DecV`, `DecK` with `USE_V7` |

## 2. u_c at rest

| Tex | Step | Code | Model |
|---|---|---|---|
| Session Start by B | k_KS = G(); B → B.key[s] : k_KS; k_L = D_S(s‖pkId, k_KS)[256:512) | `keystore.create` `ks:74-83`, `ks:113-152`; called from `_loginUser` `auth:755` | account: `StartSession` (`dsl`) |
| Authorization by B, Add Passkey by A, Replace Recovery Words by A | B ← B.key[s] : k_KS, then k_L derived again | `keystore.get` `ks:54-71`; called from `_decryptUserCredEnc` `auth:360` | abstracted: `sessions` holds u_c itself |
| u_c Encryption Under k by B | u_c encryption under k | `MasterKeyKeyProvider` `keys:469-630`; `encryptBlock0` | cipher: `mkAR`; account: `ar_enc` |
| u_c Encryption Under k by B | k_M and k_S from H_k(n_S,a,v,lp,e_l,e) | `keys:542-551`, `keys:585-629` | cipher: `mkAR`, `openAR` |
| cd_x Decryption Under k by B | cd_x decryption | `_decodeBlock0Impl` `cur:1007-1095`. Callers, with the source of e = u_i: `auth:355-376` (cd_u, from `B.sess`), `auth:719` (cd_p, from S's reply), `auth:1391` (cd_r, from the words) | cipher: `openAR`; account: `openAtRest` |

## 3. Account protocol

| Tex | Step | Client | Server | Model |
|---|---|---|---|---|
| Registration by A | Registration options | `newUser` `auth:1500-1563` | `postRegOptions` `srv:807-877`, `registrationOptions` `srv:879-936` | `Register`, `SRegOptions` |
| Registration by A | Ceremony, u_r, pk_R, u_c, cd_p, cd_r, pk_U | `auth:1520-1555`, `_newRecoverySecret` `auth:545-561` | | `Register` |
| Registration by A | Registration verify | `makeRegVerifyRequest` | `postRegVerify` `srv:422-564`, `_createAuthenticator` `srv:608-691` | `SRegVerify` |
| Registration by A, Session Start by B | Pin, cd_u, BIP39 words | `_loginUser` `auth:736-785` | | `Register`, `StartSession` |
| Authentication by A | Auth options | `_startAuthentication` `auth:1293-1338` | `postAuthOptions` `srv:727-795` | `LoginWith`, `SAuthOptions` |
| Authentication by A | Auth verify | `_createSessionImpl` `auth:1268-1291` | `postAuthVerify` `srv:284-396` | `SAuthVerify` |
| Authentication by A, Session Start by B | cd_p decrypt, pk_U pin, cd_u | `_resolveUserCred` `auth:701-733`, `_pinAccount` `auth:302-311` | | `LoginWith`, `LoginRegistered` |
| Authorization by B | Per-request proof | `_doFetch` `auth:385-459`; `aproof:49-97` | | `ApiRequests`, `mkProof` |
| Authorization by B | Cookie, CSRF, skew, proof verify | | `handler` `srv:1826-1836`, `verifyProof` `srv:1737-1791` | `authorized`, `SApi` (no skew) |
| Authorization by B | Replay nonce for non-GET requests | | `storeSingleUseNonce` `sutil:162-176`, called at `srv:1781-1790` | `NonceStored` + `STORE` restriction |
| Add Passkey by A | Add passkey | `addPasskey` `auth:1565-1604` | `getPasskeyOptions` `srv:797-805`, `postPasskeyVerify` `srv:398-420` | `AddPasskey`, `SPasskeyOptions`, `SPasskeyVerify` |
| Replace Recovery Words by A | Replace recovery words | `changeRecoveryWords` `auth:599-646`, `_putRecoveryKey` `auth:564-595` | `putRecover3Key` `srv:1107-1149`, `verifyRecoverProof` `sutil:123-159` | `ReplaceWords`, `SReplaceWords` |
| Recovery from Lost Passkey by A | recover3 | `recover3` `auth:1361-1436` | `postRecover3` `srv:1457-1512` | `Recovery`, `SRecover3` |
| Recovery from Lost Passkey by A | recover/confirm | `auth:1399-1421` | `postRecoverConfirm` `srv:1514-1585` | `Recovery`, `SRecoverConfirm` |
| Recovery from Lost Passkey by A | recover/verify | `_finishRecovery` `auth:1456-1495` | `postRecoverVerify` `srv:566-606` | `Recovery`, `SRecoverVerify` |
| Recovery from Lost Passkey by A, Persisted State | Recovery challenge binding | | `_recoveryBinding` `srv:267-269`, `consumeChallenge` `sutil:86-111` | binding carried as pk_R, never compared; `authCount` and the empty-`lastCredentialId` check (`srv:573`) not modeled |

---

## 4. Encoding injectivity

The models treat every concatenation as an unambiguous tuple. That is sound only if each byte
encoding can be parsed back into its fields in exactly one way. The argument for each encoding:

- **E1. H_k(n_S‖a‖v‖lp‖e_l‖e).** Fields are 16, 2, 2 and 1 bytes, then the e_l byte, then e.
  e_l gives the length of e. For messages e_l = 0, so e is empty. For data at rest, e_l = |u_i|.
  The `u_i` length is capped at 255 but not fixed at 16; that is still injective because e_l
  records it. Source: `keys:519-540`, `keys:807-823`.
- **E2. PBKDF2 material (V8).** p_l (4 bytes, LE) ‖ p ‖ u_c (32) ‖ a ‖ v ‖ lp ‖ e_l ‖ e. p_l
  delimits p, the next fields have fixed widths, and e_l delimits e. Source: `keys:829-836`.
  V7 had no p_l, but the web app always passes an empty e, so V7 parses uniquely from the end.
- **E3. k_C input.** H_{k_M0}(n_S): a single fixed-width field.
- **E4. MAC input.** v (2) ‖ l (3) ‖ ad_F ‖ m_E ‖ t_L.
  - l fixes |ad_F‖m_E|.
  - Inside block 0's ad_F, a fixes the n_IV width, and h_El and k_Cl delimit h_E and k_C. m_E is
    whatever remains of l.
  - t_L is the rest of the input: 1 byte for block 0 and 32 bytes for every later block. So the
    two kinds of block can never be confused. This justifies using separate constructors for
    block-0 and block-N associated data in the model.
- **E5. m_U.** Fields are joined with `\n`, and no field can contain a `\n`:
  - u_i and n_P are base64url;
  - the method is uppercase letters;
  - the path and query string are percent-encoded;
  - ts is decimal;
  - the body hash is lowercase hex.

  The optional query string turns 6 fields into 7, which is also unambiguous. Ordinary API proofs
  and recover/confirm proofs share a key and context, and are told apart by the path. Source:
  `aproof:49-67`.
- **E6. m_R.** u_i, ts and n_P joined with `\n`, by the same reasoning as E5. It uses a different
  key derivation (kp_R) and a different context from m_U. Source: `aproof:125-134`.
- **E7. D_H.** `crypto_kdf_derive_from_key` puts the 8-byte purpose in the BLAKE2b
  personalization and the subkey id in the salt. These are separate fields, so (id, purpose,
  key) is injective. In particular, `Cmit_Key` can never collide with any `Blck_Key` block
  number.
- **E8. k_L input.** s (the fixed 13-byte string `user-cred-key`) ‖ pkId. Source:
  `ks:113-134`.
- **E9. Recovery secret.** u_r (16) ‖ u_i (16), taken from 32 bytes of BIP39 entropy.
- **E10. Recovery binding.** H(pk_R ‖ ":" ‖ authCount), where pk_R is base64url and so contains
  no ":". Source: `srv:267-269`.

---

## 5. Issue log

**Class values:**
- **candidate:** a possible weakness, to be settled by the model and confirmed against the code.
- **confirmed:** a weakness the models show and the code confirms.
- **no effect found:** examined in the models, with no security effect found.
- **doc:** the tex is missing something or is wrong.
- **divergence:** the code and tex differ in ordering or detail, with no known security effect.
- **model:** a note about how the model represents something.

**Decision values:** *pending*, *fix code*, *fix tex*, *accept*.

| ID | Observation | Code / tex | Class | Model impact | Decision |
|---|---|---|---|---|---|
| I-01 | B never compares the server-returned u_i with the authenticator's userHandle, with the u_i it asked for, or (before pinning and encrypting) with the u_i decoded from the recovery words. The pk_U pin is keyed by that server-asserted u_i. A malicious API server could therefore assert an unpinned u_i. Once a session exists, `_updateLoggedInUser` does compare a reply's user id with the session's (`auth:948`), but never the reply that starts the session. <br>**Confirmed by `account/malicious` (A-S3).** Alice signs in on the browser that registered her account. The server replies with a different user id (`sui` in the model), "no-PRF", and a u_c of its choosing. The browser has no pin for that user id, so it accepts, pins it, and starts a session with the server's u_c. Every message Alice then encrypts in that session is protected by her password alone, against a server that can guess it offline. The trace matches the code: the user handle is passed to the server and never compared (`auth:1326-1329`), and both pin checks are keyed by the server's `userId` (`auth:290-311`, `auth:712`). <br>**Recovery (`account/malicious-recovery`).** The server can name a different user in the `recover/confirm` options, which become the new passkey's user handle, and at `recover/verify`, where the browser pins and signs in under it. In the traces, the recovering browser still holds Alice's own u_c. <br>**Registration (`account/malicious-recovery`, A-S3R).** The browser pins and signs in under the user id the reg/verify reply names, without comparing it with the user id in the options (`auth:1545-1557`). The server names another user there, so the browser that registered holds no pin for Alice's user id, which her words and passkey carry. A later recovery with her words on that browser then accepts "no-PRF" and the server's u_c at recover3. From recover3 on, this is the trust on first use of I-03 (A-S4R), so the account tag in the recovery words (§7.2) targets it as well as the registration check (§7.1). When the reply named Alice's user id, recovery on that browser always keeps her u_c, because recover3 compares the u_c with the pk_U pinned at registration (`auth:1399`). <br>**Add passkey (`account/malicious`).** The user id in the `passkeys/options` reply becomes the new passkey's user handle (`auth:1576`), and the browser never compares it with the session's. A passkey Alice adds can therefore name an account the server chose. | `auth:712-724`, `auth:1326-1329`, `auth:1486-1488`, `auth:1545-1557`, `auth:1576`; tex: shown as `u_i^*` in Registration, Authentication, Add Passkey and Recovery | **confirmed** weakness (malicious server) | A-S3: attack; A-S3R: attack, and true when reg/verify named Alice's user id; add-passkey handle: attack | **fix code (planned):** the user-id check in §7.1, at sign-in, registration, add passkey and recovery. Failing unit tests are in [remediation-tests.md](remediation-tests.md). |
| I-02 | pkId, an input to k_L, is supplied by the server and never compared with the credential id the authenticator actually used. <br>Under a malicious server choosing pkId, u_c stays secret (`account/malicious`, A-S2), because k_KS never leaves IndexedDB. | `auth:755`, `ks:113-134`; tex: `pkId^*` in the Registration, Authentication and Recovery replies | no effect found | A-S2, A-K1 | accept, or bind as hygiene |
| I-03 | Account mode is trusted on first use per browser. A no-PRF→PRF pin upgrade is allowed. A missing PRF output on a PRF account is an ordinary error, not a halt. <br>**Trust on first use** (`account/malicious`, A-S4; `account/malicious-recovery`, A-S4R). A browser holding no pin for the account accepts the server's "no-PRF" plus a server-chosen u_c. In the recovery trace this happens under Alice's own user id, at recover3 (`auth:1387-1399`), so a user-id check alone cannot close it. That browser could be a new device, a new profile, or cleared storage. Closing this needs the account mode and an id for u_c to reach the browser through a channel the server cannot alter. The WebAuthn user handle is one such channel, because the authenticator returns it to the browser directly. The recovery words are another. | `auth:290-311`, `auth:716-718`, `auth:1546-1555`, `auth:1387-1399`; tex: the pin checks in Session Start and Recovery accept `∅` | **confirmed** weakness (malicious server); fixable with a tag the server never sees | A-S4: attack; A-S4R: attack | **fix code (planned):** account tags (§7.2), holding the account mode and a 31-bit u_c id, in passkey handles and recovery words, for PRF and no-PRF accounts. Design constraints and open compatibility questions are in §7.2. |
| I-04 | The legacy context `qcrypt/recovery/nonce/v1` is accepted for both recover and replace. With it, separation rests only on the shared `'nonce'` replay store. <br>**Confirmed by the `account/recovery-log-*` variants,** where the attacker holds every accepted request. Either layer alone prevents the cross-use: the per-operation contexts without the replace-words nonce store (`recovery-log-noreplnonce`), and the shared store with one context for both operations, as the legacy context gives (`recovery-log-onectx`). With one context and no replace-words store, the proof from Alice's logged replace-words request is accepted by recover3 (`recovery-log-onectx-noreplnonce`). Removing the legacy context, as the code's BACKWARD COMPAT note plans, leaves the contexts as the guard. | `aproof:38-40`, `aproof:170-175`, `sutil:152`; tex: Authentication Variables (sc_R, sc_W) | doc (known backward compatibility) | A-V1 in `recovery-log-noreplnonce`, `recovery-log-onectx`, `recovery-log-onectx-noreplnonce` | **accept: treated as removed** (decided 2026-10-12). No client creates the legacy context, and `14f4511` on `prf-phase4` removes it from the server. The tex omits it, and the models no longer contain it. |
| I-05 | Legacy `POST /v1/recover` takes a plaintext u_c. It works only for accounts without a recovery key. | `srv:1389-1454`, `auth:1438-1452` | doc | not modeled (decided 2026-10-09) | **accept:** left out of the tex (decided 2026-10-12) |
| I-06 | `authCount` and `lastCredentialId` rotation, and the `deleteSession` calls inside recover3 and confirm, are absent from the tex. The tex's sign-in count c_A is `authCount`. | `srv:246-282`, `srv:1491`, `srv:1581`, `srv:588`; tex: Authentication, Recovery | doc | abstracted; not provable in ProVerif | **fixed in tex:** c_A + 1 at auth/verify, recover3, recover/confirm and recover/verify, and b built from it. lastCredentialId stays out: it keys only the session tokens (I-27) and the recover/verify check that no model `if` relies on. |
| I-07 | An auth challenge created without a u_i matches any user. The tex said "for that purpose and user". | `sutil:102`, `srv:731`, `srv:784`; tex: Authentication | doc | A-L1 models the discoverable flow | **fixed in tex:** S stores `[u_i]` and checks `u_i' ∈ {∅, u_i}` |
| I-08 | Challenges are consumed before the WebAuthn or signature check. The tex says "verify; remove ch". | `sutil:86-111` | divergence (fails closed) | single-use session names | **fixed in tex:** ↞ consumes the challenge before the WebAuthn and signature checks |
| I-09 | GET requests carry proofs, but their nonces are not single-use. This includes `GET passkeys/options`, which creates an `add` challenge. | `srv:1781-1783`; tex: Authorization | doc | not a query; `SApi` stores no nonce for GET | **fixed in tex:** S stores n_P in S.nonce only if mth ≠ GET |
| I-10 | No-PRF recover/verify returns u_c a second time. | `srv:596`, `srv:960-968`; tex: Recovery No-PRF note | doc | modeled under `NOPRF`. No variant shows an exposure through it beyond recover3's reply, which also carries u_c. | pending |
| I-11 | No-PRF replace words silently ignores a cd_r in the body instead of rejecting it. | `srv:1107-1149` | divergence | modeled under `NOPRF`, where `SReplaceWords` stores no cd_r | pending |
| I-12 | Origin and rpId are built from headers that CloudFront sets. The tex fixes o. | `urls.ts:134-150`; tex: Authentication Variables (o) | model (infrastructure trust) | origin constant | pending |
| I-13 | Decrypt-side check ordering differs from the tex: <br>• i and k_Cl are checked before the MAC; <br>• i = 0 is rejected only inside PBKDF2, after the password prompt; <br>• lp/le is checked after the hint is decrypted; <br>• the info path skips lp/le entirely. | `keys:86-106`, `keys:284`, `cur:1326`, `cs:176-185`, `cs:135-149`; tex: Message Decryption by A | divergence | decrypter follows the code's order | **fixed in tex:** k_Cl == 32 after the MAC, lp/le after the hint, and i ≥ 420,000 just before k_M0, where the code completes each check. The checks made while unpacking, before the MAC, stay out (N2). The info path decrypts nothing and is not in the tex. |
| I-14 | A block that decrypts to empty ends the stream without checking its own f. An empty block 0 with no `onDone` ends quietly. Producing either requires k_M0. <br>Truncation resistance therefore depends on an encryptor invariant: only the terminal block may be empty, which holds because `encryptBlockN` keeps reading until it has data or the stream ends (`cur:520-530`). The `integrity-net-emptymid` variant drops that invariant, and ProVerif then truncates a three-block message to one block with no secret leaked. Checking f = 1 on an empty block in the decryptor would remove the dependency. | `cur:1137-1140`, `cs:195-204` | candidate (hardening) | C-I1/2 holds; `integrity-net-emptymid` (`MUT_EMPTYMID`) shows the dependency | pending |
| I-15 | Plaintext is released block by block, before the final TERM check. The tex treats the checks and the output as one atomic step. | `cs:191-200`; tex: Message Decryption by A | model | per-block release events plus a final accept event | pending |
| I-16 | v1 and v4-v7 are still decodable. The version is picked from an unauthenticated v field. The tex describes only v8. | `ciph:87-100`, `keys:386-394` | doc | V7 path for C-D1 and C-K1-v7 | pending |
| I-17 | Nothing checks that v or le stay the same across loops; only lp is chained. <br>The `loops-uc-pout` variant shows a consequence. An attacker who holds u_c and the **outer** password can wrap an honest one-loop message (le = 1) in a new outer layer, and the decryptor accepts it as the inner layer of a two-loop message. The plaintext is still authentic Alice content; only the layering is forged. Comparing the inner le with the outer le would close it. | `cs:181-185` | candidate (low) | loop queries in `cipher.pv.m4` | pending |
| I-18 | The tex calls D_H a "BLAKE2b-512 KDF". It is `crypto_kdf_derive_from_key` with 32-byte output; n_IVH for AES-GCM derives 16 bytes and cuts them to 12. | `keys:783-791`; tex: Browser and Libsodium Functions | doc | — | **fixed in tex (N7)** |
| I-19 | The tex writes H(data…, key) with the key last, so it reads like another data argument. For example, n_IVH uses n_IV as the key. | tex: Browser and Libsodium Functions, Message Encryption by A, u_c Encryption Under k by B | doc (notation N1) | — | **fixed in tex (N1)** |
| I-20 | Hint details the tex doesn't capture: <br>• an empty hint produces no h_E at all; <br>• the hint is silently cut to 223 bytes; <br>• PAD⁻¹ strips any number of 0xFF bytes and fails on an empty result. | `cur:447-456`, `cur:1076-1082`; tex: Browser and Libsodium Functions (PAD), cd_0 Encryption by B, Message Decryption by A | doc | — | **fix doc:** a callout on the protocol page's Encrypted Hint row, not in the tex (pending) |
| I-21 | cd_x decryption does not enforce the fixed at-rest profile: it accepts v6-v8, any algorithm, lpEnd up to 16, a hint, and multiple blocks. u_c is checked to be 32 bytes only on some paths. | `ciph:89`, `keys:604-609`, `auth:411`, `auth:750`, `auth:1462` | divergence | at-rest decrypter accepts any algorithm, loop count and hint (V8 only) | pending |
| I-22 | The pin is stored after reg/verify. The tex stored pk_U before the B→S message. | `auth:1557`, `auth:753`; tex: Registration, Session Start | doc | — | **fixed in tex:** Session Start stores the pin, after the reply |
| I-23 | The WebAuthn user handle is base64url(UTF-8(base64url(u_i))). This is permanent for compatibility. | `auth:139-145` | doc (notation) | — | **accept:** recorded here only; the tex treats the handle as u_i |
| I-24 | The tex draws one r = R(384) and splits it. The code draws n_S and n_IV separately. | `ciph:53`, `cur:443`, `cur:531` | divergence | fresh names | pending |
| I-25 | Step order differs from the tex: <br>• add passkey decrypts u_c after the ceremony; <br>• replace words encrypts cd_r before signing m_R; <br>• registration creates u_r, pk_R and u_c before the ceremony. | `auth:1587`, `auth:599-646`, `auth:1520-1522`; tex: Add Passkey, Replace Recovery Words, Registration | doc | follows the code | **fixed in tex:** each stanza follows the code's order |
| I-26 | WebAuthn sign counters are ignored (`counter: 0`), so there is no clone detection. | `srv:343` | model | — | pending |
| I-27 | Session cookie and CSRF derivation (HKDF over lastCredentialId and jwtMaterial) is not in the tex, which says only "create ck, cs". | `srv:1613-1683` | doc | tokens are server-keyed MACs | **accept:** server-internal; the tex keeps "S create ck, cs" |
| I-28 | Endpoints not in the tex: <br>• GET and DELETE session; <br>• DELETE passkeys/:id (deleting the last passkey deletes the account); <br>• PATCH passkey and user; <br>• GET user; <br>• invitables; <br>• internal v0 routes. | `srv:1884-1993` | doc | not modeled | pending |
| I-29 | **Registration race when TLS is broken** (`account/login-tls`, `account/recovery-tls`, traces). <br>WebAuthn registration with attestation `none` carries no signature. An attacker who sees the reply to Alice's registration options can submit `reg/verify` first, with her user id and challenge but its own passkey, pk_U and recovery key. The server registers Alice's user id to the attacker's keys, and the attacker can then sign in and make authorized requests on it. <br>Alice's u_c and recovery words stay secret, and her browser notices on first use, because its proofs fail. <br>Registration integrity rests on TLS alone. A u_c proof at `reg/verify` would not change that, because the attacker uses its own u_c. <br>**Stripping the PRF fields** (`account/login-tls-dualmode`). The server picks the account mode from which fields `reg/verify` carries (`srv:438`). The attacker strips `userCredPubKey`, `passkeyUserCredEnc` and `recoveryUserCredEnc` from Alice's request, so the server registers her own user id and passkey as a no-PRF account and returns its u_c in plaintext. Her browser halts on the no-PRF reply (`auth:1546-1549`) without pinning. A later sign-in with that passkey, over intact TLS, receives that u_c, and with no pin her browser accepts it (`auth:712-724`). Both halves are traced: the registration by `login-tls-dualmode`, and the later sign-in, answered by the honest server, by `account/login-tls-stripped`. The §7.1 registration check would not stop this, since the reply names her own user id; the §7.2 handle tag would. | `srv:422-564`, `srv:438`, `auth:1546-1549`; tex: Registration (Account mode note) | model (requires TLS compromise) | A-L1, A-R1, A-Z1 and A-V1-3 keyed on Alice's user id; stripped registration: attack | race: accept; stripping: pending. The tex's Account mode note stays, under the Agents stanza's assumption of honest parties and intact TLS. |
| I-30 | **A live read of the challenge table hijacks registration** (`account/login-db-chal`, `account/recovery-db-chal`). A challenge entry holds its purpose, the challenge, the user id and the binding, and lasts 300 s (`consts.ts:63`). An attacker who can read the table while Alice registers submits `reg/verify` with her user id and challenge, and its own passkey, pk_U and recovery key, before she does. It then holds her user id, as in I-29, without breaking TLS. <br>**Recovery** (`account/recovery-db-chalrec`). A read of the challenge recover/confirm stores lets the attacker submit recover/verify with its own passkey before Alice does, since recover/verify carries no u_c proof (`srv:566-606`). The server binds that passkey to her account. <br>Alice's u_c and words stay secret in both. A copy of the account tables without the challenge table gives none of this. | `sutil:86-111`, `consts.ts:63`, `srv:422-564`, `srv:566-606` | **confirmed** weakness (needs live database read access) | A-L1, A-R1, A-Z1 and A-V1-3 keyed on Alice's user id: attack; recover/verify alone: A-R1 attack | **fix code (candidate):** §7.3 |

---

## 6. Tex notation proposal

**Status:**
- N1-N9 were approved on 2026-10-08 and applied from 2026-10-10 to 2026-10-12, each `main.tex`
  diff reviewed on its own.
- They describe the protocol as it runs today. The tex for the planned fixes in §7 goes in with
  the code.

**Outcomes:**
- **N1:** applied. H_key takes the key as a subscript, with key ∅ for unkeyed.
- **N2:** applied. Each check reads `check <cond> else err` where the code completes it. `==`
  compares and `=` assigns. Only checks a security property depends on appear.
- **N3:** applied as a Persisted State stanza: S.chal, S.nonce, S.user, S.pk, B.pin, B.sess and
  B.key. A store is a passive party: → stores and ← reads, ↞ reads and deletes in one step, and
  ↠ stores only a key that is absent. A value read from a store is primed when the stanza
  compares it; a value B takes from S without a comparison is starred (u_i^*, prf^*). The stanza
  gives the 300 s lifetime of challenges and nonces (I-30) and the no-PRF u_c under two KMS keys.
- **N4:** the Encodings note covers m_U and m_R, and the Byte layout note points to the protocol
  page's table and the Hex Fiend template. The hint details (I-20) go in a callout on the
  protocol page. The user-handle encoding (I-23) stays here.
- **N5:** session rotation appears through c_A, and a Session Start stanza serves registration,
  sign-in and recovery. Not added: getSession and the other endpoints in I-28, the legacy
  recovery context (treated as removed, I-04) and `/v1/recover` (left out, I-05).
- **N6:** each reply that starts a session or carries u_c lists the fields B uses, and the checks
  B makes on them appear. A field B uses without a check is starred. The Add Passkey and Replace
  Words replies are left out: B only refreshes its account state and signals the passkey list to M
  from them (`auth:1601`), after checking that their user id equals the session's (`auth:948`), a
  check no model `if` relies on.
- **N7:** applied (I-18). D_H is "BLAKE2b KDF (`crypto_kdf_derive_from_key`)" with 256-bit output,
  except n_IVH, which is as long as n_IV: derived as at least 128 bits, then truncated
  (`keys:783-791`).
- **N8:** the name table is in the README and uses the models' current names. Renaming a
  misleading name waits for `fixes/v2`.
- **N9:** one Assumptions line in the Agents stanza (honest parties over intact TLS, with a link
  to these models) replaces the per-stanza headers. The First use note, which claimed more than
  the code gives (I-01, I-03), is gone. The Account mode note stays under that assumption
  (I-29).

The aim is a tex that reads almost line for line as the model, so `conformance.md` stays
mechanical. Each change also notes whether it would affect the flow SVGs. Those are Lucidchart
exports, so any change there means re-exporting from Lucidchart and then running
`pnpm svgo:flow`.

- **N1. Write the H key as a subscript.**
  - Change H(d_1, …, d_n, key) to H_{key}(d_1, …, d_n). For example,
    k_S = D_H(1, kp_S, H_{u_c}(n_S, a, v, lp, e_l)) and t = H_{k_S}(v‖l‖ad_F‖m_E‖t_L).
  - Fixes I-19.
  - Flow SVGs: the cipher diagrams show these derivations, so check them; v7 diagrams are pinned.
- **N2. Name each check and place it where the code runs it.**
  - Write each check as `check <cond> else err`, placed where the code guarantees it, and
    named for its party (`B check`, `S check`) only in stanzas where several parties act. For
    block 0 decryption, lp/le moves after the hint, and i ≥ 420,000 moves to just before k_M0,
    since i = 0 is rejected only inside D_P.
  - The tex holds only checks a security property depends on, which are the checks the model
    has as an `if`. Range checks while unpacking (a, f, v, field lengths) are well-formedness,
    covered by the MAC, and stay out (decided 2026-10-10).
  - Fixes I-13.
  - Flow SVGs: none.
- **N3. Name the state stores and their operations.**
  - Define these once in a "State" stanza:
    - **Server:** `S.chal[purpose, ch] → (u_i, binding, exp)`, `S.nonce[purpose, n_P]`,
      `S.user[u_i]` (with `authCount` and `lastCredentialId`), `S.cred[u_i, pkId]`.
    - **Browser:** `B.pin[u_i]` (localStorage), `B.ks` (IndexedDB), `B.sess` (sessionStorage).
  - Use explicit **store**, **consume** (an atomic delete that returns the record) and
    **lookup** operations. For example: `S consume chal[recover, ch] with (u_i, H(pk_R:authCount))`.
  - Fixes I-06, I-07, I-08 and I-22.
  - Flow SVGs: none.
- **N4. Add an encodings stanza.**
  - Define once: field widths and endianness, the m_U/m_R delimiter rules, PAD and PAD⁻¹, and the
    user-handle encoding.
  - Fixes I-20 and I-23, and records section 4 above.
  - Flow SVGs: none.
- **N5. Add the missing flows.**
  - Session rotation on auth/verify, recover3, confirm, recover/verify and logout.
  - getSession.
  - The legacy recovery context, plus the legacy `/v1/recover` path, either documented or marked
    deprecated.
  - Fixes I-04, I-05, I-06, I-09 and I-28.
  - Flow SVGs: none.
- **N6. List every field in each server response, and say which ones B checks.**
  - For example: `B ← S: u_i, prf, pkId, cd_p` followed by `B check u_i = userHandle`, if I-01 is
    fixed.
  - Makes the trust in each server-asserted field visible.
  - Flow SVGs: none.
- **N7. Correct the primitive names.**
  - D_H becomes "BLAKE2b KDF (`crypto_kdf_derive_from_key`), 256-bit output".
  - V becomes "recompute MAC and constant-time compare".
  - Fixes I-18.
  - Flow SVGs: none.
- **N8. Use one ASCII name per symbol.**
  - Give each symbol a fixed ASCII spelling and use it in the models (k_{M0} → `kM0`,
    n_{IVH} → `nIVH`, and so on), listed in a table in `README.md`.
  - Flow SVGs: none.
- **N9. State the trust assumptions in each stanza.**
  - Add a short header saying which parties the stanza assumes honest: for example, B and the
    static site are honest, S may be malicious for the u_c-at-rest claims, and M is honest.
  - Gives the threat model the claims are made under.
  - Flow SVGs: none.

---

## 7. Planned fixes: user-id check, account tags, and table-read hardening (I-01, I-03, I-30)

**Status:**
- Proposed 2026-10-09 and not implemented.
- The code changes happen separately, and the tex for them goes in with the code.
- This section records the design for the fix models (README, "Remaining work", item 3).
- Headline goals for the fix models, for PRF accounts: against an attacker that controls the
  network, as if every call were plain HTTP, Alice's browser never holds a u_c the attacker
  knows; and live read access to every server table opens no attack.

### 7.1 User-id check (I-01)

The browser halts when the server names a user id other than the one the browser already holds:

| Flow | Server value | Compared with |
|---|---|---|
| Sign-in and reauthentication | user id from `auth/verify` | the passkey's user handle |
| Registration | user id from `reg/verify` | the user id in the registration options |
| Add passkey | user id in the `passkeys/options` reply, before the ceremony | the session's user id |
| Recovery | user id in the `recover/confirm` reply, before the ceremony, then the user id from `recover/verify` | the user id in the recovery words |

[remediation-tests.md](remediation-tests.md) has failing unit tests for every row except the
`recover/verify` comparison. `fixes/v1` models the sign-in and recovery rows, and they close
I-01 there (`fixes/v1/README.md`).

### 7.2 Account tags (I-03)

A tag is 4 bytes: 1 bit for the account mode (PRF or no-PRF), and a 31-bit u_c id. The id is
derived from u_c with D_H under its own purpose, then truncated.

- **Where tags are written:**
  - in the user handle of every new passkey, in PRF and no-PRF accounts;
  - in every new recovery word set. 27 words carry 288 bits: u_r (16 bytes), u_i (16 bytes) and
    the tag. Existing 24-word sets stay valid.
- **Where tags are checked.** Wherever the browser resolves u_c:
  - after sign-in, against the tag in the passkey's user handle;
  - after recover3, against the tag in the words.

  The browser halts when the server's account mode or the resolved u_c does not match the tag.
- **The tag never reaches the server.**
  - The browser builds `user.id` for a registration itself.
  - It strips the tag from the user handle before sending an assertion.
  - The assertion signature does not cover the user handle, so the server's verification does
    not change.
- **When a tag changes:**
  - u_c never changes. Replacing recovery words re-encrypts the same u_c (`srv:1128-1132`).
  - The account mode is set at registration (`srv:544`). It changes only through the one-way
    no-PRF → PRF upgrade, which replaces every passkey and recovery word set and so writes new
    tags. There is no PRF → no-PRF path.
- **Why 31 bits are enough.** A model can treat the id as an unguessable hash, because:
  - **It never reaches the server.** The browser strips it from the handle before sending, and
    builds `user.id` itself rather than taking it from the server's options.
  - **Guessing is blind and costly.** pk_U is public, but u_c is not, so in a PRF account a
    malicious server can only guess the id. Each guess costs a fresh-device sign-in or a
    recovery by Alice.
  - **A wrong guess shows.** The browser halts on a mismatch, so the first failure exposes the
    attack. A successful attack has probability about 2^-31.

**Design constraints:**
- **Write a tag only from a u_c and mode that were checked.**
  - A browser can resolve u_c on trust: through an untagged passkey or a 24-word set, with no pin
    for the account. The u_c in that session may be one the server chose.
  - If that session writes tags into new passkeys or recovery words, the server's u_c then passes
    every later check.
  - So a session writes tags only when its u_c and mode were checked against a tag or a pin. The
    mode bit comes from that same check, never from the server's `prf` field.
  - Recovery is one such session. On a browser with no pin, recover3 accepts the server's u_c
    (`account/malicious-recovery`, A-S4R) and then creates a new passkey before recovery
    finishes. A tag written into that passkey would carry the server's u_c id, and a later
    sign-in with it would accept the server's u_c.
  - `fixes/v1` shows this with a u_c id in the passkey handle only
    (`malicious-recovery-fixhandle`, A-S4).
  - Later fix models and the transition variant test the full design against it.
- **Old credentials remain a fallback path.**
  - A server can still accept an untagged passkey, including one it removed from its own records
    but that an authenticator still holds. It can steer sign-in to that passkey through
    `allowCredentials`.
  - A fresh browser using such a passkey falls back to trust on first use.
  - An account is fully covered only once no authenticator holds an untagged credential for it.
    Removing old credentials through the Signal API (`signalAllAcceptedCredentials`) narrows the
    gap.
- **Upgraded accounts.**
  - Before the upgrade, the server can decrypt u_c. A no-PRF registration stores it twice, under
    the main and the backup KMS keys (`userCredEnc` and `userCredEncOld`, `srv:476-487`).
  - The PRF guarantees for an upgraded account hold only against a server compromised after the
    upgrade, and only if the upgrade deletes every server copy of u_c.

**Open compatibility questions, for remediation:**
- **Encoding:** the byte format of a tagged user handle, and how the browser tells it apart from
  an untagged one.
- **Signal API:** `signalAllAcceptedCredentials` and `signalCurrentUserDetails` name one exact
  user handle. An account whose passkeys use both formats needs a call for each.
- **Duplicate passkeys:** CTAP 2 overwrites a discoverable credential only when the user handle
  matches. A new tagged passkey therefore does not replace an untagged one on the same
  authenticator, and the passkey picker can show both.

### 7.3 Read access to the server's tables (I-30)

**Status:** candidates from the 2026-10-10 review, not yet designed in detail. The fix models
test them against a live read of every table.

Only two kinds of challenge give a table reader anything. An auth challenge also needs a
signature from Alice's passkey, and an add or confirm challenge needs a proof made with her u_c.
The two that need neither:
- **Registration challenge:** bind it to a secret the browser holds. At reg/options the browser
  sends H(s) for a fresh s, the server stores H(s) with the challenge, and reg/verify must carry
  s. A reader of the table sees only H(s). A network attacker sees s in transit, so the
  registration race (I-29) remains against it.
- **recover/verify challenge:** require a u_c proof at recover/verify, as recover/confirm
  already does, covering the challenge and the new passkey's registration response. A reader of
  the table has no u_c, so it cannot bind a passkey. Because the proof covers the body, a network
  attacker cannot swap in its own passkey either.
