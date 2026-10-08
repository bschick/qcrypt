# Quick Crypt protocol: spec, code, and model conformance

This file ties three descriptions of the protocol together:

- the specification in `apps/web/src/assets-src/main.tex` ("tex");
- the code that implements it;
- the ProVerif models in this directory.

It also holds the issue log for every difference found between them, and the proposed changes to
the tex notation.

**References.** Tex line numbers and code `file:line` references are as of commit `48c26a6`. The
model column is filled in as each model is written.

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
| 167 | n_IVH = D_H(2, kp_H, H_{n_IV}(n_S,a,v,lp,e_l)) | `keys:742`, called at `cur:461` and `cur:1072` | `mkNIVH` |
| 168 | k_H = D_H(1, kp_H, H_{u_c}(…)) | `keys:741` | `mkKH` |
| 169 | k_S = D_H(1, kp_S, H_{u_c}(…)) | `keys:721-726` | `mkKS` |
| 170 | k_M0 = D_P(p_l‖p‖u_c‖a‖v‖lp‖e_l, n_S, i) | `keys:686-719`, material from `keys:829-836`, PBKDF2 at `keys:280-314` | `mkKM0`, `pwmat8` |
| 171 | k_C = D_H(1, kp_C, H_{k_M0}(n_S)) | `keys:746-749` | `mkKC` |
| 185 | h_E = E_a(PAD(h), n_IVH, ∅, k_H); empty hint means no h_E | `cur:444-461` | `mkBlock0L` |
| 188 | ad_F for block 0 | `cur:472-482`, `cur:251-300` | `ad0` |
| 189 | m_E = E_a(m_0, n_IV, ad_F, k_M0) | `encryptBlock0` `cur:419-504` | `mkBlock0L` |
| 191 | t = H_{k_S}(v‖l‖ad_F‖m_E‖t_L) | `_createHeader` `cur:622-647` | `mac`, `macin` |
| 205-206 | ad_F = f‖a‖n_IV; k_MN = D_H(N, kp_B, H_{k_M0}(…)) | `cur:535-539`, `keys:838-842` | `adN`, `mkKMN`, `mkBlockN` |
| 224 | t_L = 0x00 at the start of each loop | `cur:394` (encrypt), `cur:929` (decrypt), with a fresh instance per loop at `cs:73` and `cs:173` | `TL0` |
| 229 | MAC verify | `_verifyMAC` `cur:1223-1256`, called at `cur:1061` | `Dec`, `BlockN1`, `BlockN2` |
| 233 | k_Cl = 32 and i ≥ 420,000 | Runs **before** the MAC: `cur:1324-1330`, `keys:86-106`. See I-13 | `Dec`: `kC <> NOKC`, `i <> IC0` |
| 234 | lp sequencing across loops | `cs:176-185`, after the hint is decrypted. See I-13 | `Dec`: `lp = le`; `open0` |
| 235-237 | Hint decrypt | `cur:1071-1084` | `Dec`: `HintShown` |
| 240-241 | k_M0, then the k_C compare | `decryptBlock0` `cur:717-772`; compare at `cur:745-750` | `Dec`: `kC = mkKC(...)` |
| 245, 264 | TERM flag checks | `_decodeBlockN` `cur:1155-1221`. See I-14 | `Dec`, `BlockN1`, `BlockN2` |
| 271 | a and v equal block 0's values | `cur:1207-1213` | `BlockN1`, `BlockN2` |
| 273 | Block N AEAD decrypt | `cur:1110-1140` | `BlockN1`, `BlockN2` |
| 247 | Recurse while lp > 1 | `cs:221-223` | `DecL` |
| — | V7 decode path (I-16) | `keys:632-793`, `cur:948-967` | `DecV`, `DecK` with `USE_V7` |

## 2. u_c at rest

| Tex | Step | Code | Model |
|---|---|---|---|
| 330-332 | k_KS = G(); k_L = D_S(s‖pkId, k_KS)[256:512) | `ks:74-83`, `ks:113-152`; called from `_loginUser` `auth:755` | |
| 341-351 | u_c encryption under k | `MasterKeyKeyProvider` `keys:469-630`; `encryptBlock0` | |
| 344-345 | k_M and k_S from H_k(n_S,a,v,lp,e_l,e) | `keys:542-551`, `keys:585-629` | |
| 361-368 | cd_x decryption | `_decodeBlock0Impl` `cur:1007-1095`. Callers: `auth:355-376` (cd_u), `auth:719` (cd_p), `auth:1391` (cd_r) | |

## 3. Account protocol

| Tex | Step | Client | Server | Model |
|---|---|---|---|---|
| 434-437 | Registration options | `newUser` `auth:1500-1563` | `postRegOptions` `srv:807-877`, `registrationOptions` `srv:879-936` | |
| 438-447 | Ceremony, u_r, pk_R, u_c, cd_p, cd_r, pk_U | `auth:1520-1555`, `_newRecoverySecret` `auth:545-561` | | |
| 448-451 | Registration verify | `makeRegVerifyRequest` | `postRegVerify` `srv:422-564`, `_createAuthenticator` `srv:608-691` | |
| 452-453 | cd_u, BIP39 words | `_loginUser` `auth:736-785` | | |
| 469-471 | Auth options | `_startAuthentication` `auth:1293-1338` | `postAuthOptions` `srv:727-795` | |
| 476-479 | Auth verify | `_createSessionImpl` `auth:1268-1291` | `postAuthVerify` `srv:284-396` | |
| 480-483 | cd_p decrypt, pk_U pin, cd_u | `_resolveUserCred` `auth:701-733`, `_pinAccount` `auth:302-311` | | |
| 499-505 | Per-request proof | `_doFetch` `auth:385-459`; `aproof:49-97` | | |
| 506-513 | Cookie, CSRF, skew, proof verify | | `handler` `srv:1826-1836`, `verifyProof` `srv:1737-1791` | |
| 518 | Replay nonce for non-GET requests | | `storeSingleUseNonce` `sutil:162-176`, called at `srv:1781-1790` | |
| 527-537 | Add passkey | `addPasskey` `auth:1565-1604` | `getPasskeyOptions` `srv:797-805`, `postPasskeyVerify` `srv:398-420` | |
| 551-569 | Replace recovery words | `changeRecoveryWords` `auth:599-646`, `_putRecoveryKey` `auth:564-595` | `putRecover3Key` `srv:1107-1149`, `verifyRecoverProof` `sutil:123-159` | |
| 581-596 | recover3 | `recover3` `auth:1361-1436` | `postRecover3` `srv:1457-1512` | |
| 597-611 | recover/confirm | `auth:1399-1421` | `postRecoverConfirm` `srv:1514-1585` | |
| 612-621 | recover/verify | `_finishRecovery` `auth:1456-1495` | `postRecoverVerify` `srv:566-606` | |
| 626 | Recovery challenge binding | | `_recoveryBinding` `srv:267-269`, `consumeChallenge` `sutil:86-111` | |

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
- **doc:** the tex is missing something or is wrong.
- **divergence:** the code and tex differ in ordering or detail, with no known security effect.
- **model:** a note about how the model represents something.

**Decision values:** *pending*, *fix code*, *fix tex*, *accept*.

| ID | Observation | Code / tex | Class | Model impact | Decision |
|---|---|---|---|---|---|
| I-01 | B never compares the server-returned u_i with the authenticator's userHandle, with the u_i it asked for, or (before pinning and encrypting) with the u_i decoded from the recovery words. The pk_U pin is keyed by that server-asserted u_i. A malicious API server could therefore assert an unpinned u_i. | `auth:712-724`, `auth:1326-1329`, `auth:1486-1488`; tex 492 | candidate | A-S3, A-S4 | pending |
| I-02 | pkId, an input to k_L, is supplied by the server and never compared with the credential id the authenticator actually used. | `auth:755`, `ks:113-134` | candidate (likely benign: k_KS stays secret) | A-K1 | pending |
| I-03 | Account mode is trusted on first use per browser. A no-PRF→PRF pin upgrade is allowed. A missing PRF output on a PRF account is an ordinary error, not a halt. | `auth:290-311`, `auth:716-718`, `auth:1546-1555`; tex 462 | candidate (tied to I-01) | A-S4 | pending |
| I-04 | The legacy context `qcrypt/recovery/nonce/v1` is accepted for both recover and replace. With it, separation rests only on the shared `'nonce'` replay store. | `aproof:38-40`, `aproof:170-175`, `sutil:152`; tex 404-406 | doc (known backward compatibility) | A-V3 variant | pending |
| I-05 | Legacy `POST /v1/recover` takes a plaintext u_c. It works only for accounts without a recovery key. | `srv:1389-1454`, `auth:1438-1452` | doc | optional variant | pending |
| I-06 | `authCount` and `lastCredentialId` rotation, and the `deleteSession` calls inside recover3 and confirm, are absent from the tex. The tex's "sign-in count" (626) is `authCount`. | `srv:246-282`, `srv:1491`, `srv:1581`, `srv:588` | doc | abstracted; not provable in ProVerif | pending |
| I-07 | An auth challenge created without a u_i matches any user. Tex 427 says "for that purpose and user". | `sutil:102`, `srv:731`, `srv:784` | doc | A-L1 models the discoverable flow | pending |
| I-08 | Challenges are consumed before the WebAuthn or signature check. The tex says "verify; remove ch". | `sutil:86-111` | divergence (fails closed) | single-use session names | pending |
| I-09 | GET requests carry proofs, but their nonces are not single-use. This includes `GET passkeys/options`, which creates an `add` challenge. | `srv:1781-1783`; tex 518 | doc | A-Z2 | pending |
| I-10 | No-PRF recover/verify returns u_c a second time. | `srv:596`, `srv:960-968`; tex 630 | doc | — | pending |
| I-11 | No-PRF replace words silently ignores a cd_r in the body instead of rejecting it. | `srv:1107-1149` | divergence | — | pending |
| I-12 | Origin and rpId are built from headers that CloudFront sets. The tex fixes o. | `urls.ts:134-150`; tex 393 | model (infrastructure trust) | origin constant | pending |
| I-13 | Decrypt-side check ordering differs from the tex: <br>• i and k_Cl are checked before the MAC; <br>• i = 0 is rejected only inside PBKDF2, after the password prompt; <br>• lp/le is checked after the hint is decrypted; <br>• the info path skips lp/le entirely. | `keys:86-106`, `keys:284`, `cur:1326`, `cs:176-185`, `cs:135-149`; tex 233-234 | divergence | decrypter follows the code's order | pending |
| I-14 | A block that decrypts to empty ends the stream without checking its own f. An empty block 0 with no `onDone` ends quietly. Producing either requires k_M0. <br>Truncation resistance therefore depends on an encryptor invariant: only the terminal block may be empty, which holds because `encryptBlockN` keeps reading until it has data or the stream ends (`cur:520-530`). The `integrity-net-emptymid` variant drops that invariant, and ProVerif then truncates a three-block message to one block with no secret leaked. Checking f = 1 on an empty block in the decryptor would remove the dependency. | `cur:1137-1140`, `cs:195-204` | candidate (hardening) | C-I2 holds today; `MUT_EMPTYMID` shows the dependency | pending |
| I-15 | Plaintext is released block by block, before the final TERM check. The tex treats the checks and the output as one atomic step. | `cs:191-200`; tex 244-245 | model | per-block release events plus a final accept event | pending |
| I-16 | v1 and v4-v7 are still decodable. The version is picked from an unauthenticated v field. The tex describes only v8. | `ciph:87-100`, `keys:386-394` | doc | V7 path for C-D1 and C-K1-v7 | pending |
| I-17 | Nothing checks that v or le stay the same across loops; only lp is chained. <br>The `loops-uc-pout` variant shows a consequence. An attacker who holds u_c and the **outer** password can wrap an honest one-loop message (le = 1) in a new outer layer, and the decryptor accepts it as the inner layer of a two-loop message. The plaintext is still authentic Alice content; only the layering is forged. Comparing the inner le with the outer le would close it. | `cs:181-185` | candidate (low) | loop queries in `cipher.pv.m4` | pending |
| I-18 | The tex calls D_H a "BLAKE2b-512 KDF". It is `crypto_kdf_derive_from_key` with 32-byte output; n_IVH for AES-GCM derives 16 bytes and cuts them to 12. | `keys:783-791`; tex 54 | doc | — | pending |
| I-19 | The tex writes H(data…, key) with the key last, so it reads like another data argument. For example, n_IVH uses n_IV as the key. | tex 69, 167-171, 344-345 | doc (notation N1) | — | pending |
| I-20 | Hint details the tex doesn't capture: <br>• an empty hint produces no h_E at all; <br>• the hint is silently cut to 223 bytes; <br>• PAD⁻¹ strips any number of 0xFF bytes and fails on an empty result. | `cur:447-456`, `cur:1076-1082`; tex 72, 185, 237 | doc | — | pending |
| I-21 | cd_x decryption does not enforce the fixed at-rest profile: it accepts v6-v8, any algorithm, lpEnd up to 16, a hint, and multiple blocks. u_c is checked to be 32 bytes only on some paths. | `ciph:89`, `keys:604-609`, `auth:411`, `auth:750`, `auth:1462` | divergence | at-rest decrypter accepts any parameters the attacker picks | pending |
| I-22 | The pin is stored after reg/verify. Tex 447 stores pk_U before the B→S message. | `auth:1557`, `auth:753`; tex 447 | doc | — | pending |
| I-23 | The WebAuthn user handle is base64url(UTF-8(base64url(u_i))). This is permanent for compatibility. | `auth:139-145` | doc (notation) | — | pending |
| I-24 | The tex draws one r = R(384) and splits it. The code draws n_S and n_IV separately. | `ciph:53`, `cur:443`, `cur:531` | divergence | fresh names | pending |
| I-25 | Step order differs from the tex: <br>• add passkey decrypts u_c after the ceremony; <br>• replace words encrypts cd_r before signing m_R; <br>• registration creates u_r, pk_R and u_c before the ceremony. | `auth:1587`, `auth:599-646`, `auth:1520-1522`; tex 530, 552-559, 442-447 | doc | follows the code | pending |
| I-26 | WebAuthn sign counters are ignored (`counter: 0`), so there is no clone detection. | `srv:343` | model | — | pending |
| I-27 | Session cookie and CSRF derivation (HKDF over lastCredentialId and jwtMaterial) is not in the tex, which says only "create ck, cs". | `srv:1613-1683` | doc | tokens are server-keyed MACs | pending |
| I-28 | Endpoints not in the tex: <br>• GET and DELETE session; <br>• DELETE passkeys/:id (deleting the last passkey deletes the account); <br>• PATCH passkey and user; <br>• GET user; <br>• invitables; <br>• internal v0 routes. | `srv:1884-1993` | doc | getSession and logout only | pending |

---

## 6. Tex notation proposal

**Status:** N1-N9 approved 2026-10-08. They will be applied after the account models (Phases
3-4), so the auth stanzas are rewritten once, with each `main.tex` diff reviewed individually.

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
  - Write every check as `B check <cond> else err`, in the order the code runs it. For block 0
    decryption, the parameter checks move before the MAC and lp/le moves after the hint.
  - Each check maps to one model `if`.
  - Fixes I-13.
  - Flow SVGs: none.
- **N3. Name the state stores and their operations.**
  - Define these once in an "State" stanza:
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
