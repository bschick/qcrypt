m4_changequote({{,}})m4_dnl
(* Quick Crypt accounts, with an honest or a malicious server: the main.tex stanzas from u_c
   Encryption at Rest Variables through Recovery from Lost Passkey by A. Accounts are in PRF
   mode, or in no-PRF mode with NOPRF, where Alice's authenticator has no PRF and the server
   keeps the u_c her browser created.

   Each honest user (Alice) registers once from her browser, then logs in with any passkey she
   holds, sends authorized requests, adds passkeys, replaces her recovery words, and recovers.
   Her browser checks the user id in every server reply, and checks the u_c it resolves against
   the tag in her passkey's user handle or her recovery words (vibes/user-id-checks.md,
   vibes/credential-tags.md). Every challenge that creates a passkey is bound to pk_U and
   answered with a proof under sk_U (vibes/challenge-binding.md).
   The server keeps its state in tables, which in ProVerif can only grow. So deletions are not
   modeled: old passkeys and recovery keys stay usable, which only helps the attacker.
   Single-use challenges, replay nonces and authCount values are uniqueness restrictions; they
   stand for the atomic DynamoDB delete-on-read in consumeChallenge (sutil:86-111), the
   conditional put in storeSingleUseNonce (sutil:162-176) and the atomic add in
   _setLastCredential (srv:245-265). Timestamps and the skew window are not modeled.

   TLS is a private channel, with a fresh reply channel per request. Every server handler also
   runs on the public channel, where the attacker is a client like any other and chooses its own
   reply channel; LEAK_TLS makes the private channel public too.

   WebAuthn registration is unsigned, as with attestation 'none': the server checks the
   challenge, origin, rpId and flags in the response, and nothing proves who built it.

{{   VARIANTS:
     login-net            SCN_LOGIN
     login-session        SCN_LOGIN LEAK_SESSION
     login-session-noproof  SCN_LOGIN LEAK_SESSION MUT_NOPROOF STORE NOBT
     login-cdu            SCN_LOGIN LEAK_CDU
     login-device         SCN_LOGIN LEAK_DEVICE
     login-device-nouv    SCN_LOGIN LEAK_DEVICE MUT_NOUV RCV STORE NOBT
     login-unbound        SCN_LOGIN MUT_UNBOUND NOBT
     login-unbound-trace  SCN_LOGIN MUT_UNBOUND UNIQUSER NOBT
     login-tls            SCN_LOGIN LEAK_TLS KEY_UI STORE UNIQUSER NOBT
     login-tls-regsigr-nopku  SCN_LOGIN LEAK_TLS KEY_UI STORE UNIQUSER NOBT MUT_REGSIGR_NOPKU
     login-reach          SCN_LOGIN REACH_ONLY RCV STORE UNIQUSER NOBT
     login-log            SCN_LOGIN LEAK_LOG KEY_UI STORE
     login-log-sharedctx  SCN_LOGIN LEAK_LOG KEY_UI STORE MUT_SHAREDCTX
     login-log-noapinonce  SCN_LOGIN LEAK_LOG KEY_UI STORE MUT_NOSTORE_NAPI RCV UNIQUSER NOBT
     login-log-noauthchal  SCN_LOGIN LEAK_LOG KEY_UI STORE MUT_NOSTORE_PAUTH RCV UNIQUSER NOBT
     login-log-noaddchal  SCN_LOGIN LEAK_LOG KEY_UI STORE MUT_NOSTORE_PADD
     login-log-noapinonce-noaddchal  SCN_LOGIN LEAK_LOG KEY_UI STORE MUT_NOSTORE_NAPI MUT_NOSTORE_PADD RCV UNIQUSER NOBT
     login-log-noregchal  SCN_LOGIN LEAK_LOG KEY_UI STORE MUT_NOSTORE_PREG UNIQUSER
     malicious            SCN_MALICIOUS
     malicious-recovery   SCN_MALICIOUS MAL_RECOVERY
     recovery-net         SCN_RECOVERY
     recovery-session     SCN_RECOVERY LEAK_SESSION
     recovery-words       SCN_RECOVERY LEAK_WORDS RCV NOBT
     recovery-tls         SCN_RECOVERY LEAK_TLS KEY_UI UNIQUSER NOBT
     recovery-reach       SCN_RECOVERY REACH_ONLY RCV STORE UNIQUSER NOBT
     recovery-log         SCN_RECOVERY LEAK_LOG KEY_UI STORE
     recovery-log-api     SCN_RECOVERY LEAK_LOG KEY_UI STORE GENERIC_API
     recovery-log-api-sharedctx  SCN_RECOVERY LEAK_LOG LOG_NOREGVER KEY_UI STORE GENERIC_API MUT_SHAREDCTX
     recovery-log-norecnonce  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOSTORE_NREC RCV UNIQUSER NOBT
     recovery-log-noconfirmchal  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOSTORE_PCONFIRM RCV UNIQUSER NOBT
     recovery-log-noconfirmchal-nobind  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOSTORE_PCONFIRM MUT_NOBIND RCV UNIQUSER NOBT
     recovery-log-norecoverchal  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOSTORE_PRECOVER RCV UNIQUSER NOBT
     recovery-log-norecoverchal-nobind  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOSTORE_PRECOVER MUT_NOBIND RCV UNIQUSER NOBT
     recovery-log-noapinonce  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOSTORE_NAPI
     recovery-log-noreplnonce  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOREPLNONCE
     recovery-log-noreplnonce-noapinonce  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOREPLNONCE MUT_NOSTORE_NAPI RCV UNIQUSER NOBT
     recovery-log-onectx  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_ONECTX
     recovery-log-onectx-noreplnonce  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_ONECTX MUT_NOREPLNONCE RCV UNIQUSER NOBT
     login-db             SCN_LOGIN LEAK_DB KEY_UI
     recovery-db          SCN_RECOVERY LEAK_DB KEY_UI
     login-noprf-net      SCN_LOGIN NOPRF
     login-noprf-session  SCN_LOGIN NOPRF LEAK_SESSION
     login-noprf-session-noproof  SCN_LOGIN NOPRF LEAK_SESSION MUT_NOPROOF STORE NOBT
     login-noprf-cdu      SCN_LOGIN NOPRF LEAK_CDU
     login-noprf-device   SCN_LOGIN NOPRF LEAK_DEVICE
     login-noprf-device-nouv  SCN_LOGIN NOPRF LEAK_DEVICE MUT_NOUV RCV STORE NOBT
     login-noprf-unbound  SCN_LOGIN NOPRF MUT_UNBOUND RCV STORE UNIQUSER NOBT PRECISE
     login-noprf-tls      SCN_LOGIN NOPRF LEAK_TLS KEY_UI STORE UNIQUSER NOBT
     login-noprf-reach    SCN_LOGIN NOPRF REACH_ONLY RCV STORE UNIQUSER NOBT
     login-noprf-log      SCN_LOGIN NOPRF LEAK_LOG KEY_UI STORE RCV UNIQUSER NOBT
     login-noprf-log-noregver  SCN_LOGIN NOPRF LEAK_LOG LOG_NOREGVER KEY_UI STORE
     login-noprf-log-noauthchal  SCN_LOGIN NOPRF LEAK_LOG LOG_NOREGVER KEY_UI STORE MUT_NOSTORE_PAUTH RCV UNIQUSER NOBT
     login-noprf-db       SCN_LOGIN NOPRF LEAK_DB
     login-noprf-db-kms   SCN_LOGIN NOPRF LEAK_DB LEAK_KMS_NEW KEY_UI
     login-noprf-db-kmsold  SCN_LOGIN NOPRF LEAK_DB LEAK_KMS_OLD KEY_UI
     recovery-noprf-net   SCN_RECOVERY NOPRF
     recovery-noprf-session  SCN_RECOVERY NOPRF LEAK_SESSION
     recovery-noprf-words  SCN_RECOVERY NOPRF LEAK_WORDS RCV STORE UNIQUSER NOBT PRECISE
     recovery-noprf-tls   SCN_RECOVERY NOPRF LEAK_TLS KEY_UI STORE UNIQUSER NOBT PRECISE
     recovery-noprf-reach  SCN_RECOVERY NOPRF REACH_ONLY RCV STORE UNIQUSER NOBT PRECISE
     recovery-noprf-log   SCN_RECOVERY NOPRF LEAK_LOG LOG_NOREGVER KEY_UI STORE
     recovery-noprf-log-norecnonce  SCN_RECOVERY NOPRF LEAK_LOG LOG_NOREGVER KEY_UI STORE MUT_NOSTORE_NREC RCV UNIQUSER NOBT PRECISE
     recovery-noprf-log-noconfirmchal  SCN_RECOVERY NOPRF LEAK_LOG LOG_NOREGVER KEY_UI STORE MUT_NOSTORE_PCONFIRM RCV UNIQUSER NOBT PRECISE
     recovery-noprf-log-noconfirmchal-nobind  SCN_RECOVERY NOPRF LEAK_LOG LOG_NOREGVER KEY_UI STORE MUT_NOSTORE_PCONFIRM MUT_NOBIND RCV UNIQUSER NOBT PRECISE
     recovery-noprf-log-onectx-noreplnonce  SCN_RECOVERY NOPRF LEAK_LOG LOG_NOREGVER KEY_UI STORE MUT_ONECTX MUT_NOREPLNONCE RCV UNIQUSER NOBT
     malicious-noprf      SCN_MALICIOUS NOPRF
     login-db-chal        SCN_LOGIN LEAK_DB LEAK_CHAL KEY_UI STORE UNIQUSER NOBT
     recovery-db-chal     SCN_RECOVERY LEAK_DB LEAK_CHAL KEY_UI STORE UNIQUSER NOBT
     login-tls-dualmode   SCN_LOGIN LEAK_TLS KEY_UI DUALMODE STORE UNIQUSER NOBT
     recovery-db-chalrec  SCN_RECOVERY LEAK_DB LEAK_CHAL_RECOVER KEY_UI STORE UNIQUSER NOBT
     login-tls-stripped   SCN_LOGIN LEAK_TLS KEY_UI DUALMODE STORE UNIQUSER NOBT STRIPLOGIN
     login-tls-stripped-nohandletag  SCN_LOGIN LEAK_TLS KEY_UI DUALMODE STORE UNIQUSER NOBT STRIPLOGIN MUT_NOHANDLETAG
     recovery-log-noconfirmchal-nobind-noproof  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOSTORE_PCONFIRM MUT_NOBIND MUT_NORECVERIFYPROOF RCV UNIQUSER NOBT
     recovery-log-norecoverchal-nobind-noproof  SCN_RECOVERY LEAK_LOG KEY_UI STORE MUT_NOSTORE_PRECOVER MUT_NOBIND MUT_NORECVERIFYPROOF RCV UNIQUSER NOBT
     recovery-noprf-log-noconfirmchal-nobind-noproof  SCN_RECOVERY NOPRF LEAK_LOG LOG_NOREGVER KEY_UI STORE MUT_NOSTORE_PCONFIRM MUT_NOBIND MUT_NORECVERIFYPROOF RCV UNIQUSER NOBT PRECISE
     login-db-chal-noregbind  SCN_LOGIN LEAK_DB LEAK_CHAL KEY_UI STORE UNIQUSER NOBT MUT_NOREGBIND
     login-db-chal-noregsigu  SCN_LOGIN LEAK_DB LEAK_CHAL KEY_UI STORE UNIQUSER MUT_NOREGSIG_U
     login-db-noregsigr   SCN_LOGIN LEAK_DB KEY_UI STORE UNIQUSER NOBT MUT_NOREGSIG_R
     recovery-db-chalrec-norecverifyproof  SCN_RECOVERY LEAK_DB LEAK_CHAL_RECOVER KEY_UI STORE UNIQUSER NOBT MUT_NORECVERIFYPROOF
     recovery-noprf-db-chalrec  SCN_RECOVERY NOPRF LEAK_DB LEAK_CHAL_RECOVER KEY_UI STORE UNIQUSER NOBT PRECISE
     recovery-noprf-db-chalrec-norecverifyproof  SCN_RECOVERY NOPRF LEAK_DB LEAK_CHAL_RECOVER KEY_UI STORE UNIQUSER PRECISE MUT_NORECVERIFYPROOF
     malicious-nohandletag  SCN_MALICIOUS MUT_NOHANDLETAG
     malicious-noprf-nohandletag  SCN_MALICIOUS NOPRF MUT_NOHANDLETAG
     malicious-recovery-nowordstag  SCN_MALICIOUS MAL_RECOVERY MUT_NOWORDSTAG
     malicious-recovery-serverhandle  SCN_MALICIOUS MAL_RECOVERY MUT_SERVERHANDLE
     malicious-nouicheck-login  SCN_MALICIOUS MUT_NOUICHECK_LOGIN
     malicious-recovery-nouicheck-reg  SCN_MALICIOUS MAL_RECOVERY MUT_NOUICHECK_REG
     malicious-recovery-nouicheck-recoververify  SCN_MALICIOUS MAL_RECOVERY MUT_NOUICHECK_RECOVERVERIFY
     malicious-twoaccounts  SCN_MALICIOUS TWOACCOUNTS REAUTH
     malicious-twoaccounts-nouicheck-reauth  SCN_MALICIOUS TWOACCOUNTS REAUTH MUT_NOUICHECK_REAUTH
     malicious-existing   SCN_MALICIOUS EXISTING MAL_RECOVERY PRECISE
     malicious-existing-nohandletag  SCN_MALICIOUS EXISTING MAL_RECOVERY PRECISE MUT_NOHANDLETAG
     malicious-existing-nowordstag  SCN_MALICIOUS EXISTING MAL_RECOVERY MUT_NOWORDSTAG STORE RCV UNIQUSER
     malicious-existing-noprf  SCN_MALICIOUS EXISTING MAL_RECOVERY NOPRF
     malicious-existing-firstuse  SCN_MALICIOUS EXISTING FIRSTUSE MAL_RECOVERY
     malicious-existing-firstuse-nouicheck-login  SCN_MALICIOUS EXISTING FIRSTUSE MUT_NOUICHECK_LOGIN
   END VARIANTS}} *)

(* NOBT turns off backtracking in trace reconstruction. Under the restrictions, a derivation can
   be followed without backtracking, and when one cannot, ProVerif stops at once and prints the
   partial trace up to the step that blocked. *)
m4_ifdef({{NOBT}}, {{
set traceBacktracking = false.
}})

(* PRECISE marks three actions [precise]: the inputs of auth/verify and recover3, and the lookup
   of the words a recovery uses. Each receives or reads one value per run, so this adds no
   assumption. In no-PRF mode, recover3's reply does not depend on the words, and without it
   some reconstructions combine two requests in one server session, or two sets of words in one
   recovery. Marking every action precise does not finish in practical time. *)
m4_ifdef({{PRECISE}}, {{m4_define({{PREC}}, {{ [precise]}})}}, {{m4_define({{PREC}}, {{}})}})

(* With a malicious server there is no honest server process: the attacker answers on the public
   channel and learns every reply channel from the requests. EXISTING starts from an account
   that exists when the release deploys. Then the server is honest in phase 0 and the attacker
   takes it over in phase 1 (PHASED), or with FIRSTUSE the attacker is the server from the start. *)
m4_ifdef({{EXISTING}}, {{m4_ifdef({{FIRSTUSE}}, {{}}, {{m4_define({{PHASED}})}})}})
m4_ifdef({{LEAK_TLS}}, {{m4_define({{TLS_PUBLIC}})}})
m4_ifdef({{SCN_MALICIOUS}}, {{m4_ifdef({{PHASED}}, {{}}, {{m4_define({{TLS_PUBLIC}})}})}})
m4_ifdef({{TLS_PUBLIC}}, {{
free tls: channel.
}}, {{
free tls: channel [private].
}})

(* Server secret behind the session cookie and CSRF token (srv:1613-1683) *)
free skJWT: key [private].

(* ---------------------------------------------------------------------------------------- *)
(* Wire constants *)

const REGOPT, REGVER, AUTHOPT, AUTHVER, API, PKOPT, PKVER, OK: bitstring [data].
const REPLACE, REC3, CONFIRM, RECVER: bitstring [data].
const GET, POST, PUT: bitstring [data].
const PATH_API, PATH_PKOPT, PATH_PKVER, PATH_REPLACE, PATH_CONFIRM, PATH_REGVER, PATH_RECVER: bitstring [data].
const PREG, PADD, PAUTH, PCONFIRM, PRECOVER: bitstring [data].

(* Replay-nonce namespaces: 'api' for authorized requests, 'nonce' for both recovery proofs *)
const NAPI, NREC: bitstring [data].

(* Recovery signature contexts: sc_R, sc_W, and sc_G for the proof of sk_R at registration. The
   code also accepts a legacy context for recover and replace, which no client creates; it is
   treated as removed (I-04). *)
const SCR, SCW, SCG: bitstring [data].

(* m_R = u_i, n_P; the timestamp is not modeled *)
fun mrc(bitstring, bitstring): bitstring [data].
(* The message of the proof under sk_R at registration: u_i, the registration challenge and pk_U *)
fun mrg(bitstring, bitstring, bitstring): bitstring [data].
m4_ifdef({{MUT_REGSIGR_NOPKU}}, {{
(* MUTATION: the proof under sk_R leaves out pk_U *)
m4_define({{REGSIGR_PKU}}, {{EMPTY}})
}}, {{
m4_define({{REGSIGR_PKU}}, {{$1}})
}})
(* reg/options stores pk_U on the new account and binds the challenge to it, and reg/verify
   checks against that stored pk_U. REGBIND is the value reg/options stores, REGSTORED the name
   reg/verify reads it into, and BODY_PKU adds pk_U to the reg/verify body. *)
m4_ifdef({{MUT_NOREGBIND}}, {{
(* MUTATION: reg/options stores no pk_U and binds the challenge to the user id alone, so
   reg/verify takes pk_U from its body *)
m4_define({{REGBIND}}, {{NOBIND}})
m4_define({{REGSTORED}}, {{upk}})
m4_define({{BODY_PKU}}, {{$1, }})
}}, {{
m4_define({{REGBIND}}, {{$1}})
m4_define({{REGSTORED}}, {{pkU}})
m4_define({{BODY_PKU}}, {{}})
}})
const UNKNOWN, NOBIND: bitstring [data].
const PRF0, PRF1: bitstring [data].
const ORIGIN, RPID, UV0, UV1, WA_CREATE, WA_GET: bitstring [data].
const SLOT: bitstring [data].

(* p_S, the fixed PRF salt, the proof signature context sc_U for the nonce form, and sc_P for the
   challenge form. The challenge form signs a server-issued challenge: at reg/verify,
   recover/confirm and recover/verify, which carry no session, and at passkeys/verify, which
   does. With sc_P, no challenge-form proof verifies as a nonce-form request, whatever path a
   request carries. *)
const PS: bitstring [data].
const SCU: bitstring [data].
m4_ifdef({{MUT_SHAREDCTX}}, {{
(* MUTATION: the challenge form uses sc_U *)
m4_define({{SCP}}, {{SCU}})
}}, {{
const SCP: bitstring [data].
}})

(* WebAuthn clientDataJSON (type, challenge, origin) and authenticator data (rpId, UV flag) *)
fun cdj(bitstring, bitstring, bitstring): bitstring [data].
fun adata(bitstring, bitstring): bitstring [data].

(* Registration response: credential id, public key, authenticator data, clientDataJSON *)
fun regr(bitstring, bitstring, bitstring, bitstring): bitstring [data].

(* Recovery secret u_r || u_i *)
fun rsec(bitstring, bitstring): key [data].

(* m_U = u_i, method, path, n_P, H_2(body); the timestamp is not modeled *)
fun muc(bitstring, bitstring, bitstring, bitstring, bitstring): bitstring [data].

(* Session cookie: u_i, session id, and a MAC under the server key. CSRF token: a second MAC. *)
fun ckmac(key, bitstring, bitstring): bitstring.
fun csmac(key, bitstring, bitstring): bitstring.
letfun cookie(ui: bitstring, sid: bitstring) = (ui, sid, ckmac(skJWT, ui, sid)).

(* ---------------------------------------------------------------------------------------- *)
(* u_c at rest under k (tex: u_c Encryption Under k by B, cd_x Decryption Under k by B), with
   e = u_i. This is an abstract authenticated encryption that commits to k and e. The real V8
   format is modeled in cipher.pv.m4, where the atrest-net and commit-* variants prove the three
   properties this abstraction assumes: secrecy and integrity under a secret k for a given u_i,
   commitment to (k, u_i), and that no block is accepted both as a message and as u_c at rest.
   Expanding the real format here exhausts memory during saturation. *)

fun ar_enc(key, bitstring, bitstring, bitstring): bitstring.
reduc forall k: key, e: bitstring, n: bitstring, m: bitstring; ar_dec(k, e, ar_enc(k, e, n, m)) = m.

letfun mkAtRest(k: key, e: bitstring, n: bitstring, m: bitstring) = ar_enc(k, e, n, m).
letfun openAtRest(k: key, e: bitstring, cd: bitstring) = bs2key(ar_dec(k, e, cd)).

letfun proofKey(uc: key) = kdf(ID1, kpU, uc).
letfun recoveryKey(ur: bitstring, ui: bitstring) = kdf(ID1, kpR, rsec(ur, ui)).

(* The account tag in a passkey's user handle and in a recovery word set: the u_c id, D_H keyed
   with u_c under its own purpose and truncated to 32 bits (vibes/credential-tags.md). Modeled as
   a one-way function of u_c with no inverse, so the attacker computes a tag only from a u_c it
   knows; the 2^-32 chance of a guess matching is outside the model. NOTAG marks an untagged
   handle or a 24-word set. *)
fun ucid(key): bitstring.
const NOTAG: bitstring [data].

(* KMS (srv:152-198): encryption under a key only the server's role can use, with the user id
   as encryption context. A no-PRF account keeps u_c under a main and a backup key. *)
fun kms_enc(key, bitstring, key): bitstring.
reduc forall k: key, ctx: bitstring, m: key; kms_dec(k, ctx, kms_enc(k, ctx, m)) = m.
free kmsNew, kmsOld: key [private].

(* ---------------------------------------------------------------------------------------- *)
(* State *)

(* Server. unverified holds a user id from reg/options and the pk_U stored with it. *)
table unverified(bitstring, bitstring).
table users(bitstring, bitstring).
table recov(bitstring, bitstring, bitstring).
table creds(bitstring, bitstring, bitstring, bitstring).
table chal(bitstring, bitstring, bitstring, bitstring).

(* A no-PRF account's u_c under the main and the backup KMS keys (srv:475-490). The server
   decrypts only the main copy. *)
table ucenc(bitstring, bitstring, bitstring).

(* Per-browser pin: browser, u_i, account mode, pk_U (auth:302-311) *)
table pins(bitstring, bitstring, bitstring, bitstring).

(* ---------------------------------------------------------------------------------------- *)
(* Events and restrictions *)

event AliceCredCreated(bitstring, bitstring, bitstring).
event UserApproves(bitstring, bitstring, bitstring).
event ClientSigned(bitstring, bitstring, bitstring, bitstring, bitstring).
event ClientLoggedIn(bitstring, bitstring, key).
event ClientSignedIn(bitstring, bitstring, key).
(* Server events end with the account's pk_U, which is how the queries pick out Alice's
   accounts: hers are the ones whose pk_U comes from her own u_c. *)
event ServerCredAdded(bitstring, bitstring, bitstring, bitstring).
event ServerLogin(bitstring, bitstring, bitstring, bitstring).
event ServerAccept(bitstring, bitstring, bitstring, bitstring, bitstring, bitstring).
event Consumed(bitstring, bitstring, bitstring).
event NonceStored(bitstring, bitstring, bitstring).
event Incremented(bitstring, bitstring).

event ClientRecoverIntent(bitstring, bitstring).
event ClientConfirm(bitstring, bitstring).
event ClientReplace(bitstring, bitstring).
event ClientRecovered(bitstring, bitstring, key).
event ServerRecover3(bitstring, bitstring, bitstring).
event ServerConfirm(bitstring, bitstring, bitstring).
event ServerReplaced(bitstring, bitstring, bitstring).
event ServerRecovered(bitstring, bitstring, bitstring).

(* The user id Alice's browser received at registration *)
event AliceUi(bitstring).

(* Registration completed in a browser: the user id in the options, and the user id in the
   reg/verify reply *)
event Registered(bitstring, bitstring, bitstring).

(* No-PRF: the u_c the server drew at a registration, with the user id, credential id and
   passkey public key it registered; and the u_c Alice's browser received in the reply *)
event ServerUc(bitstring, bitstring, bitstring, key).
event AliceUc(bitstring, key).

(* A passkey Alice created in a session or a recovery: the session's or the words' user id, and
   the passkey's user handle *)
event PasskeyHandle(bitstring, bitstring).

(* A browser session starts: browser, user id, the u_c it holds, the tag of the credential it
   started from (NOTAG for an untagged one, the browser's own tag at registration), and the
   account mode the server returned *)
event Adopted(bitstring, bitstring, key, bitstring, bitstring).

(* A server reply's user id passed the browser's checks: the user id the browser already held
   for the flow (the passkey handle's, the one from reg/options, or the recovery words'), and the
   reply's *)
event SessionUser(bitstring, bitstring).

(* reg/verify: Alice's browser signed it with sk_U and sk_R, and the server registered it. User
   id, challenge, pk_U, pk_R. *)
event RegSigned(bitstring, bitstring, bitstring, bitstring).
event ServerRegistered(bitstring, bitstring, bitstring, bitstring).

m4_ifdef({{STRIPLOGIN}}, {{
(* A browser sign-in that passed the pin checks: browser, the user id the server returned, the
   passkey and challenge the assertion used, the cookie the reply carried, and the u_c the
   session holds *)
event SignedInWith(bitstring, bitstring, bitstring, bitstring, bitstring, key).
(* auth/verify answered an assertion with u_c in plaintext: user, passkey, challenge, the
   session cookie of the reply, and that u_c *)
event ServerReplyUc(bitstring, bitstring, bitstring, bitstring, key).
(* One request per reg/verify session, and one options message and one reply per registration.
   Without them, reconstruction of the stripped sign-in merges two runs that no execution can
   join. They add no assumption. *)
m4_define({{PREC_STRIP}}, {{ [precise]}})
}}, {{
m4_define({{PREC_STRIP}}, {{}})
}})

(* Restrictions mirror what the real system guarantees. The base variants, whose results are
   proofs, run without them: leaving them off gives the attacker more traces, so a property
   proved without them also holds with them. Variants that look for an attack or for
   reachability turn them on, and so do the log variants, whose replay queries test the stores.
   Without them, ProVerif finds derivations no real run can follow, such as one private request
   received by two server sessions, or one user id registered twice. Reconstructing a trace from
   such a derivation then runs for hours, while a trace found under the restrictions is a trace
   of the real system.

   STORE: a challenge is consumed at most once, and a replay nonce is stored at most once
   (sutil:86-111, sutil:162-176). A MUT_NOSTORE_<purpose> mutation lifts this for one challenge
   purpose or nonce namespace, at every handler that uses it: MUT_NOSTORE_NREC opens both
   recover3 and replace words, while MUT_NOREPLNONCE removes only replace words' nonce.

   STORE also increments each authCount value at most once, as the code's atomic add does
   (srv:245-265). recover3 and recover/confirm bind the challenge they create to the value their
   own increment produced (srv:267-269). recover/confirm and recover/verify increment the value
   their challenge is bound to, so a second use of one challenge fails. The code reads authCount
   before it consumes the challenge and increments at the end of the handler; the model makes
   these one step. MUT_NOBIND removes the binding check.

   Without STORE these mutations would change nothing, so m4 stops with an error instead. *)
m4_define({{REUSE}}, {{m4_ifdef({{MUT_NOSTORE_$1}}, {{ || pu = $1 }})}})
m4_define({{REUSABLE}},
   REUSE(NAPI)REUSE(NREC)REUSE(PREG)REUSE(PAUTH)REUSE(PADD)REUSE(PCONFIRM)REUSE(PRECOVER))
m4_ifdef({{STORE}}, {{
restriction pu: bitstring, ch: bitstring, s1: bitstring, s2: bitstring;
   event(Consumed(pu, ch, s1)) && event(Consumed(pu, ch, s2)) ==> s1 = s2 REUSABLE.
restriction pu: bitstring, n: bitstring, s1: bitstring, s2: bitstring;
   event(NonceStored(pu, n, s1)) && event(NonceStored(pu, n, s2)) ==> s1 = s2 REUSABLE.
restriction n: bitstring, s1: bitstring, s2: bitstring;
   event(Incremented(n, s1)) && event(Incremented(n, s2)) ==> s1 = s2.
}}, {{
m4_ifelse(REUSABLE, {{}}, {{}}, {{m4_errprint({{MUT_NOSTORE_<purpose> needs STORE
}})m4_m4exit(1)}})
m4_ifdef({{MUT_NOBIND}}, {{m4_errprint({{MUT_NOBIND needs STORE
}})m4_m4exit(1)}})
m4_ifdef({{MUT_NOREPLNONCE}}, {{m4_errprint({{MUT_NOREPLNONCE needs STORE
}})m4_m4exit(1)}})
}})

(* RCV: each request, identified by its fresh reply channel, is received by one server session.
   Over the private TLS channel that is exactly what happens; on the public channel the attacker
   can always choose a new reply channel. *)
event Rcv(channel, bitstring).
m4_ifdef({{RCV}}, {{
restriction rc: channel, s1: bitstring, s2: bitstring;
   event(Rcv(rc, s1)) && event(Rcv(rc, s2)) ==> s1 = s2.
m4_define({{RECEIVED}}, {{event Rcv(rc, rq);}})
}}, {{
m4_define({{RECEIVED}}, {{}})
}})

(* LEAK_LOG: each request a handler accepts is then copied to the attacker, as by a request log
   or a proxy that records traffic. A copy made on receipt instead could be forwarded and
   accepted before the original, which is the race LEAK_TLS covers, not a replay. GET requests
   are not logged, since repeating one is allowed. Nor are reg/options and auth/options, which
   need no credentials. The copies carry cookies and CSRF tokens. These variants use KEY_UI,
   which picks out Alice's accounts by user id whatever pk_U values the attacker learns. The
   no-PRF ones use it too, so both modes answer the same queries.

   A-N1: the attacker cannot produce Alice's signatures or passkey assertions, so her account
   accepts a request on the public channel only when a logged request is used again, at the
   same endpoint or another. One query per request type shows which endpoint a mutation opens.

   A no-PRF reg/verify carries u_c in its body, so a full log hands the attacker u_c and then
   the account (login-noprf-log). LOG_NOREGVER leaves that request out of the log, so the other
   no-PRF log variants test the stores instead. recovery-log-api-sharedctx also sets it, so the
   attack it finds must reuse a recovery proof rather than the reg/verify proof. *)
m4_ifdef({{LEAK_LOG}}, {{
event Accepted(channel, bitstring, bitstring).
m4_define({{LOGGED}}, {{event Accepted(net, $1, $2); out(c, req);}})
query ui: bitstring; event(Accepted(c, REGVER, ui)) && event(AliceUi(ui)).
m4_ifdef({{SCN_LOGIN}}, {{
query ui: bitstring; event(Accepted(c, AUTHVER, ui)) && event(AliceUi(ui)).
query ui: bitstring; event(Accepted(c, API, ui)) && event(AliceUi(ui)).
query ui: bitstring; event(Accepted(c, PKVER, ui)) && event(AliceUi(ui)).
}})
m4_ifdef({{SCN_RECOVERY}}, {{
query ui: bitstring; event(Accepted(c, REPLACE, ui)) && event(AliceUi(ui)).
query ui: bitstring; event(Accepted(c, REC3, ui)) && event(AliceUi(ui)).
query ui: bitstring; event(Accepted(c, CONFIRM, ui)) && event(AliceUi(ui)).
query ui: bitstring; event(Accepted(c, RECVER, ui)) && event(AliceUi(ui)).
m4_ifdef({{GENERIC_API}}, {{
query ui: bitstring; event(Accepted(c, API, ui)) && event(AliceUi(ui)).
}})
}})
}}, {{
m4_define({{LOGGED}}, {{}})
}})

(* UNIQUSER:a user id is registered at most once, as the server's check for an existing
   verified user ensures (srv:426-434) *)
event UserCreated(bitstring, bitstring).
m4_ifdef({{UNIQUSER}}, {{
restriction ui: bitstring, s1: bitstring, s2: bitstring;
   event(UserCreated(ui, s1)) && event(UserCreated(ui, s2)) ==> s1 = s2.
}})

(* ---------------------------------------------------------------------------------------- *)
(* Server endpoints (srv:1884-1993).

   Each handler creates its fresh names before its input. ProVerif parameterizes a name by the
   inputs received before it, so a name created after an attacker-chosen request can be fed back
   into the next request, and saturation never terminates. Creating the names first gives the
   same one-fresh-value-per-request semantics. *)

(* POST reg/options: a new unverified user that stores the pk_U in the request, and a challenge
   bound to that user and pk_U (srv:postRegOptions, srv:registrationOptions) *)
let SRegOptions(net: channel) =
   new ui: bitstring; new ch: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=REGOPT, pkU: bitstring) = req in
   insert unverified(ui, REGBIND(pkU));
   insert chal(PREG, ch, ui, REGBIND(pkU));
   out(rc, (ch, ui)).

(* The checks both reg/verify handlers make on the body bd, which carries the user id ui, the
   challenge ch, pk_R and the proof under sk_R (srv:postRegVerify). pk_U is the one reg/options
   stored for ui. First the proof under sk_U, over the user id, the challenge and the whole body,
   and the proof under sk_R, over the user id, the challenge and pk_U. A proof under sk_R that
   left out pk_U would let an attacker with TLS broken pair it with its own pk_U, on an account
   it opened with that pk_U. Then the challenge is consumed only if it is bound to that user id
   and pk_U, as one conditional delete, so a request that fails either check leaves the challenge
   for Alice. *)
m4_define({{REGCHECKS}}, {{
m4_ifdef({{MUT_NOREGSIG_U}}, {{
   (* MUTATION: the proof under sk_U is not checked *)
}}, {{
   if sig_verify(pkU, muc(ui, POST, PATH_REGVER, ch, sha256(bd)), sigU, SCP) then
}})
m4_ifdef({{MUT_NOREGSIG_R}}, {{
   (* MUTATION: the proof under sk_R is not checked *)
}}, {{
   if sig_verify(pkR, mrg(ui, ch, REGSIGR_PKU(pkU)), sigR, SCG) then
}})
m4_ifdef({{MUT_UNBOUND}}, {{
   get chal(pu: bitstring, =ch, cu: bitstring, bnd: bitstring) in
   event Consumed(pu, ch, st);
}}, {{
   get chal(=PREG, =ch, =ui, =REGBIND(pkU)) in
   event Consumed(PREG, ch, st);
}})
}})

(* POST reg/verify for a PRF registration, which carries cd_p and cd_r (srv:postRegVerify,
   srv:_createAuthenticator) *)
let SRegVerify(net: channel) =
   new st: bitstring; new sid: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel))PREC_STRIP;
   RECEIVED
   let (=REGVER, bd: bitstring, sigU: bitstring) = req in
   let (rr: bitstring, ui: bitstring, ch: bitstring, pkR: bitstring, BODY_PKU({{pkU: bitstring}})cdp: bitstring, cdr: bitstring, sigR: bitstring) = bd in
   get unverified(=ui, REGSTORED: bitstring) in
   get users(=ui, pkU0: bitstring) in 0 else
REGCHECKS
   let regr(credId: bitstring, credPk: bitstring, adata(=RPID, =UV1), cdj(=WA_CREATE, =ch, =ORIGIN)) = rr in
   event UserCreated(ui, st);
   event ServerRegistered(ui, ch, pkU, pkR);
   insert users(ui, pkU);
   insert recov(ui, pkR, cdr);
   insert creds(ui, credId, credPk, cdp);
   event ServerCredAdded(ui, credId, credPk, pkU);
m4_ifdef({{LOG_NOREGVER}}, {{}}, {{
   LOGGED(REGVER, ui)
}})
m4_ifdef({{DUALMODE}}, {{
   out(rc, (ui, PRF1, EMPTY, cookie(ui, sid), csmac(skJWT, ui, sid))).
}}, {{
   out(rc, (ui, cookie(ui, sid), csmac(skJWT, ui, sid))).
}})

(* POST reg/verify for a no-PRF registration, which carries u_c itself in place of cd_p and
   cd_r. The server keeps u_c under both KMS keys and returns it in the reply, which the browser
   does not read (srv:postRegVerify). The server picks the mode from which fields the request
   carries. *)
let SRegVerifyNoPrf(net: channel) =
   new st: bitstring; new sid: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel))PREC_STRIP;
   RECEIVED
   let (=REGVER, bd: bitstring, sigU: bitstring) = req in
   let (rr: bitstring, ui: bitstring, ch: bitstring, pkR: bitstring, BODY_PKU({{pkU: bitstring}})ucbs: bitstring, sigR: bitstring) = bd in
   get unverified(=ui, REGSTORED: bitstring) in
   get users(=ui, pkU0: bitstring) in 0 else
REGCHECKS
   let regr(credId: bitstring, credPk: bitstring, adata(=RPID, =UV1), cdj(=WA_CREATE, =ch, =ORIGIN)) = rr in
   event UserCreated(ui, st);
   event ServerRegistered(ui, ch, pkU, pkR);
   let uc = bs2key(ucbs) in
   insert users(ui, pkU);
   insert ucenc(ui, kms_enc(kmsNew, ui, uc), kms_enc(kmsOld, ui, uc));
   insert recov(ui, pkR, EMPTY);
   insert creds(ui, credId, credPk, EMPTY);
   event ServerUc(ui, credId, credPk, uc);
   event ServerCredAdded(ui, credId, credPk, pkU);
m4_ifdef({{LOG_NOREGVER}}, {{}}, {{
   LOGGED(REGVER, ui)
}})
   out(rc, (ui, PRF0, ucbs, cookie(ui, sid), csmac(skJWT, ui, sid))).

(* POST auth/options: an auth challenge, bound to a user only if the request carries one
   (srv:727-795) *)
let SAuthOptions(net: channel) =
   new ch: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=AUTHOPT, cu: bitstring) = req in
   insert chal(PAUTH, ch, cu, NOBIND);
   out(rc, ch).

(* POST auth/verify (srv:284-396). The user is the assertion's userHandle; UNKNOWN matches any. *)
let SAuthVerify(net: channel) =
   new st: bitstring; new sid: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel))PREC;
   RECEIVED
   let (=AUTHVER, credId: bitstring, uh: bitstring, ad: bitstring, cd: bitstring, sig: bitstring, ch: bitstring) = req in
   let cdj(=WA_GET, =ch, =ORIGIN) = cd in
m4_ifdef({{MUT_NOUV}}, {{
   (* MUTATION: user verification is not required *)
   let adata(=RPID, uvf: bitstring) = ad in
}}, {{
   let adata(=RPID, =UV1) = ad in
}})
   get chal(=PAUTH, =ch, cu: bitstring, =NOBIND) in
   if cu = UNKNOWN || cu = uh then
   event Consumed(PAUTH, ch, st);
   get creds(=uh, =credId, credPk: bitstring, cdp: bitstring) in
   if wa_verify(credPk, (ad, cd), sig) then
   get users(=uh, pkU: bitstring) in
   event ServerLogin(uh, credId, ch, pkU);
   LOGGED(AUTHVER, uh)
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF reply carries u_c, decrypted with the main KMS key (srv:960-967) *)
   get ucenc(=uh, enc: bitstring, encOld: bitstring) in
   out(rc, (uh, PRF0, credId, key2bs(kms_dec(kmsNew, uh, enc)), cookie(uh, sid), csmac(skJWT, uh, sid))).
}}, {{
m4_ifdef({{DUALMODE}}, {{
   (* Only a no-PRF account has a KMS copy of u_c *)
m4_ifdef({{STRIPLOGIN}}, {{
   get ucenc(=uh, enc: bitstring, encOld: bitstring) in (
      event ServerReplyUc(uh, credId, ch, (uh, sid, ckmac(skJWT, uh, sid)), kms_dec(kmsNew, uh, enc));
      out(rc, (uh, PRF0, credId, key2bs(kms_dec(kmsNew, uh, enc)), cookie(uh, sid), csmac(skJWT, uh, sid)))
   ) else out(rc, (uh, PRF1, credId, cdp, cookie(uh, sid), csmac(skJWT, uh, sid))).
}}, {{
   get ucenc(=uh, enc: bitstring, encOld: bitstring) in
   out(rc, (uh, PRF0, credId, key2bs(kms_dec(kmsNew, uh, enc)), cookie(uh, sid), csmac(skJWT, uh, sid)))
   else out(rc, (uh, PRF1, credId, cdp, cookie(uh, sid), csmac(skJWT, uh, sid))).
}})
}}, {{
   out(rc, (uh, PRF1, credId, cdp, cookie(uh, sid), csmac(skJWT, uh, sid))).
}})
}})

(* Cookie, CSRF, and proof checks for every authorized request (srv:handler). The caller has
   taken u_i from the cookie and looked up its pk_U. nP is the nonce or the challenge the proof
   signs, and ctx the context of that proof form. The caller makes nP single use: a non-GET nonce
   through the nonce store, a challenge by consuming it. *)
letfun authorized(ck: bitstring, cs: bitstring, pkU: bitstring, mth: bitstring, pth: bitstring, bd: bitstring, nP: bitstring, sig: bitstring, ctx: bitstring) =
   let (ui: bitstring, sid: bitstring, tag: bitstring) = ck in
m4_ifdef({{MUT_NOPROOF}}, {{
   (* MUTATION: the cookie and CSRF token are enough *)
   tag = ckmac(skJWT, ui, sid) && cs = csmac(skJWT, ui, sid).
}}, {{
   tag = ckmac(skJWT, ui, sid) && cs = csmac(skJWT, ui, sid) &&
   sig_verify(pkU, muc(ui, mth, pth, nP, sha256(bd)), sig, ctx).
}})

letfun cookieUser(ck: bitstring) = let (ui: bitstring, sid: bitstring, tag: bitstring) = ck in ui.

(* Any authorized endpoint, as an opaque method, path and body. It accepts any path, so the model
   does not rely on the server's routing to keep other proofs out. *)
let SApi(net: channel) =
   new st: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=API, ck: bitstring, cs: bitstring, mth: bitstring, pth: bitstring, bd: bitstring, nP: bitstring, sig: bitstring) = req in
   let ui = cookieUser(ck) in
   get users(=ui, pkU: bitstring) in
   if authorized(ck, cs, pkU, mth, pth, bd, nP, sig, SCU) then
   if mth = GET then (
      event ServerAccept(ui, mth, pth, bd, nP, pkU);
      out(rc, OK)
   ) else (
      event NonceStored(NAPI, nP, st);
      event ServerAccept(ui, mth, pth, bd, nP, pkU);
      LOGGED(API, ui)
      out(rc, OK)
   ).

(* GET passkeys/options, authorized (srv:797-805) *)
let SPasskeyOptions(net: channel) =
   new ch: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=PKOPT, ck: bitstring, cs: bitstring, nP: bitstring, sig: bitstring) = req in
   let ui = cookieUser(ck) in
   get users(=ui, pkU: bitstring) in
   if authorized(ck, cs, pkU, GET, PATH_PKOPT, EMPTY, nP, sig, SCU) then
   event ServerAccept(ui, GET, PATH_PKOPT, EMPTY, nP, pkU);
   insert chal(PADD, ch, ui, pkU);
   (* Registration options, whose user.id becomes the new passkey's user handle *)
   out(rc, (ch, ui)).

(* POST passkeys/verify, authorized, with a challenge-form proof over the add challenge. The user
   is the session's, never the body's (srv:postPasskeyVerify). Consuming the challenge makes the
   proof single use, so no nonce is stored. *)
let SPasskeyVerify(net: channel) =
   new st: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=PKVER, ck: bitstring, cs: bitstring, sig: bitstring, bd: bitstring) = req in
   let (rr: bitstring, ch: bitstring, cdp: bitstring, bui: bitstring) = bd in
   let sui = cookieUser(ck) in
   get users(=sui, pkU: bitstring) in
   if authorized(ck, cs, pkU, POST, PATH_PKVER, bd, ch, sig, SCP) then
   event ServerAccept(sui, POST, PATH_PKVER, bd, ch, pkU);
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF account takes no cd_p (srv:407-409) *)
   if cdp = EMPTY then
}})
m4_ifdef({{MUT_UNBOUND}}, {{
   (* MUTATION: the pre-fix server took the user from the body and matched the challenge alone *)
   let ui = bui in
   get chal(pu: bitstring, =ch, cu: bitstring, bnd: bitstring) in
   event Consumed(pu, ch, st);
}}, {{
   let ui = sui in
   get chal(=PADD, =ch, =ui, =pkU) in
   event Consumed(PADD, ch, st);
}})
   let regr(credId: bitstring, credPk: bitstring, adata(=RPID, =UV1), cdj(=WA_CREATE, =ch, =ORIGIN)) = rr in
   insert creds(ui, credId, credPk, cdp);
   get users(=ui, pkUi: bitstring) in
   event ServerCredAdded(ui, credId, credPk, pkUi);
   LOGGED(PKVER, ui)
   out(rc, OK).

(* A recovery proof verifies under the operation's own context (aproof:158-176) *)
letfun recoveryProofOK(pkR: bitstring, ui: bitstring, nP: bitstring, sig: bitstring, ctx: bitstring) =
   sig_verify(pkR, mrc(ui, nP), sig, ctx).

(* PUT recover3/key, authorized: new recovery words, proved by a signature under the submitted
   key (srv:1107-1149, sutil:123-159) *)
let SReplaceWords(net: channel) =
   new st: bitstring; new st2: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=REPLACE, ck: bitstring, cs: bitstring, nP: bitstring, sig: bitstring, bd: bitstring) = req in
   let (pkR: bitstring, nPR: bitstring, sigR: bitstring, cdr: bitstring) = bd in
   let ui = cookieUser(ck) in
   get users(=ui, pkU: bitstring) in
   if authorized(ck, cs, pkU, PUT, PATH_REPLACE, bd, nP, sig, SCU) then
   event ServerAccept(ui, PUT, PATH_REPLACE, bd, nP, pkU);
   event NonceStored(NAPI, nP, st);
m4_ifdef({{MUT_ONECTX}}, {{
   (* MUTATION: replace words verifies under sc_R, as with one context for both operations, so
      only the nonce stores keep its proof from passing recover3 (I-04) *)
   if recoveryProofOK(pkR, ui, nPR, sigR, SCR) then
}}, {{
   if recoveryProofOK(pkR, ui, nPR, sigR, SCW) then
}})
m4_ifdef({{MUT_NOREPLNONCE}}, {{
   (* MUTATION: the replace proof's nonce is not stored *)
}}, {{
   event NonceStored(NREC, nPR, st2);
}})
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF account ignores the cd_r in the body (srv:1126-1133, I-11) *)
   insert recov(ui, pkR, EMPTY);
}}, {{
   insert recov(ui, pkR, cdr);
}})
   event ServerReplaced(ui, pkR, pkU);
   LOGGED(REPLACE, ui)
   out(rc, OK).

(* POST recover3: proof of the recovery words, then a confirm challenge and cd_r
   (srv:1457-1512). Every recovery key ever stored for the user is accepted, since tables only
   grow. The challenge is bound to pk_R and cnt, the authCount value this handler's increment
   produces (srv:1489-1495). Only cnt is compared, so unlike the code, the model lets a sign-in,
   a logout, another recover3 or new words leave the challenge valid. Leaving that out only adds
   attacker runs. *)
let SRecover3(net: channel) =
   new st: bitstring; new chR: bitstring; new cnt: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel))PREC;
   RECEIVED
   let (=REC3, ui: bitstring, nPR: bitstring, sigR: bitstring) = req in
   get recov(=ui, pkR: bitstring, cdr: bitstring) in
   if recoveryProofOK(pkR, ui, nPR, sigR, SCR) then
   event NonceStored(NREC, nPR, st);
   get users(=ui, pkU: bitstring) in
   event ServerRecover3(ui, nPR, pkU);
   LOGGED(REC3, ui)
   insert chal(PCONFIRM, chR, ui, (pkR, cnt));
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF reply carries u_c itself, decrypted with the main KMS key (srv:1501-1507) *)
   get ucenc(=ui, enc: bitstring, encOld: bitstring) in
   out(rc, (PRF0, chR, key2bs(kms_dec(kmsNew, ui, enc)))).
}}, {{
   out(rc, (PRF1, chR, cdr)).
}})

(* POST recover/confirm: a proof under sk_U over the user id, ch_R and the body, then a
   registration challenge (srv:postRecoverConfirm). The proof comes before the consume, as at
   recover/verify, so a request that fails it leaves the challenge for Alice. *)
let SRecoverConfirm(net: channel) =
   new st: bitstring; new ch: bitstring; new st2: bitstring; new cnt: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=CONFIRM, bd: bitstring, sigU: bitstring) = req in
   let (ui: bitstring, chR: bitstring) = bd in
   get users(=ui, pkU: bitstring) in
   if sig_verify(pkU, muc(ui, POST, PATH_CONFIRM, chR, sha256(bd)), sigU, SCP) then
   get chal(=PCONFIRM, =chR, =ui, bnd: bitstring) in
   event Consumed(PCONFIRM, chR, st);
   let (pkRb: bitstring, cntb: bitstring) = bnd in
m4_ifdef({{MUT_NOBIND}}, {{
   (* MUTATION: the binding is not compared *)
}}, {{
   (* The binding check and the increment, as one step (srv:1537, srv:1581) *)
   event Incremented(cntb, st2);
}})
   event ServerConfirm(ui, chR, pkU);
   LOGGED(CONFIRM, ui)
   insert chal(PRECOVER, ch, ui, (pkRb, cnt, pkU));
   (* Registration options, whose user.id becomes the new passkey's user handle *)
   out(rc, (ch, ui)).

(* POST recover/verify: the new passkey, with a proof under sk_U over the user id, the challenge
   and the body (srv:postRecoverVerify, srv:_createAuthenticator). The challenge is bound to the
   account's pk_R, authCount and pk_U. The check for an empty lastCredentialId is left out: the
   write that sets it also increments authCount (srv:_setLastCredential), so it fails only where
   the binding check already fails. *)
let SRecoverVerify(net: channel) =
   new st: bitstring; new sid: bitstring; new st2: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=RECVER, bd: bitstring, sigU: bitstring) = req in
   let (rr: bitstring, ui: bitstring, ch: bitstring, cdp: bitstring) = bd in
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF account takes no cd_p (srv:postRecoverVerify) *)
   if cdp = EMPTY then
}})
   get users(=ui, pkU: bitstring) in
m4_ifdef({{MUT_NORECVERIFYPROOF}}, {{
   (* MUTATION: the recover/verify proof is not checked *)
}}, {{
   if sig_verify(pkU, muc(ui, POST, PATH_RECVER, ch, sha256(bd)), sigU, SCP) then
}})
   (* The proof comes first, so a request that fails it leaves the challenge for Alice. The
      server consumes the challenge with one conditional delete on the whole binding. Here the
      pk_U part is checked with the consume, and the authCount part with the increment below,
      which differs only in whether a failed request uses up the challenge. *)
   get chal(=PRECOVER, =ch, =ui, bnd: bitstring) in
   let (pkRb: bitstring, cntb: bitstring, pkUb: bitstring) = bnd in
   if pkUb = pkU then
   event Consumed(PRECOVER, ch, st);
   let regr(credId: bitstring, credPk: bitstring, adata(=RPID, =UV1), cdj(=WA_CREATE, =ch, =ORIGIN)) = rr in
m4_ifdef({{MUT_NOBIND}}, {{
   (* MUTATION: the authCount binding is not compared *)
}}, {{
   (* The authCount binding check and the increment, as one step (srv:_createAuthenticator,
      srv:_setLastCredential) *)
   event Incremented(cntb, st2);
}})
   insert creds(ui, credId, credPk, cdp);
   event ServerCredAdded(ui, credId, credPk, pkU);
   event ServerRecovered(ui, credId, pkU);
   LOGGED(RECVER, ui)
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF reply carries u_c again (srv:596, I-10) *)
   get ucenc(=ui, enc: bitstring, encOld: bitstring) in
   out(rc, (ui, PRF0, cookie(ui, sid), csmac(skJWT, ui, sid), key2bs(kms_dec(kmsNew, ui, enc)))).
}}, {{
   out(rc, (ui, PRF1, cookie(ui, sid), csmac(skJWT, ui, sid))).
}})

(* Each endpoint serves honest browsers over TLS and the attacker's own client on c. Forwarding
   attacker requests into the TLS channel through a relay process gives the same access but
   makes query solving take hours. *)
(* Each variant's server serves one account mode, or with DUALMODE both, picked at reg/verify *)
m4_ifdef({{NOPRF}}, {{m4_define({{REGVERIFY}}, {{!SRegVerifyNoPrf(net)}})}},
   {{m4_ifdef({{DUALMODE}}, {{m4_define({{REGVERIFY}}, {{!SRegVerify(net) | !SRegVerifyNoPrf(net)}})}},
   {{m4_define({{REGVERIFY}}, {{!SRegVerify(net)}})}})}})
m4_ifdef({{PHASED}}, {{
(* The honest server of phase 0, for an account that already exists: no registration *)
let Endpoints(net: channel) =
   !SAuthOptions(net) | !SAuthVerify(net) | !SPasskeyOptions(net) | !SPasskeyVerify(net) |
   !SReplaceWords(net) | !SRecover3(net) | !SRecoverConfirm(net) | !SRecoverVerify(net).
}}, {{
m4_ifdef({{SCN_RECOVERY}}, {{
(* GENERIC_API adds the generic authorized endpoint, which Alice's recovery never calls, so the
   log variants can test whether a recovery proof passes there *)
let Endpoints(net: channel) =
   !SRegOptions(net) | REGVERIFY | !SReplaceWords(net) | !SRecover3(net) | !SRecoverConfirm(net) |
   !SRecoverVerify(net)m4_ifdef({{GENERIC_API}}, {{ | !SApi(net)}}).
}}, {{
m4_ifdef({{STRIPLOGIN}}, {{
(* Registration and sign-in only: with requests and added passkeys present, saturation of the
   stripped sign-in does not finish. Leaving out honest processes only removes runs. *)
let Endpoints(net: channel) =
   !SRegOptions(net) | REGVERIFY | !SAuthOptions(net) | !SAuthVerify(net).
}}, {{
let Endpoints(net: channel) =
   !SRegOptions(net) | REGVERIFY | !SAuthOptions(net) | !SAuthVerify(net) | !SApi(net) |
   !SPasskeyOptions(net) | !SPasskeyVerify(net).
}})
}})
}})

(* With the TLS channel public, the attacker already reaches every endpoint through it, and the
   copy on c only multiplies clauses *)
m4_ifdef({{TLS_PUBLIC}}, {{
let Server() = Endpoints(tls).
}}, {{
let Server() = Endpoints(tls) | Endpoints(c).
}})

(* ---------------------------------------------------------------------------------------- *)
(* Alice's browser and authenticator.

   Each activity is its own replicated process that creates its fresh names first, then reads
   Alice's state from the tables below, and only then talks to the server. ProVerif
   parameterizes a name by the inputs and table reads before it, so a name created after an
   attacker-influenced value can nest through the attacker without bound, and saturation does
   not terminate. Keeping state in tables also lets every passkey Alice holds be used to sign
   in, including ones added later or created by recovery.

   aid identifies one Alice, with her authenticator; bid identifies one of her browsers. Her
   first browser has bid = aid. *)

(* Alice's passkeys: authenticator, the user handle's user id and tag, credential id, and key *)
table passkeys(bitstring, bitstring, bitstring, bitstring, key).
(* Browser, the user id in the registration options, and the user id in the reg/verify reply,
   which is the one registration pinned *)
table registered(bitstring, bitstring, bitstring).
(* Alice's recovery word sets: u_i, u_r, and the tag (NOTAG for a 24-word set) *)
table words(bitstring, bitstring, bitstring, bitstring).
table sessions(bitstring, bitstring, bitstring, key, bitstring, bitstring, bitstring).

(* A signed authorized request, as _doFetch builds it (auth:385-459) *)
letfun mkProof(uc: key, ui: bitstring, mth: bitstring, pth: bitstring, bd: bitstring, nP: bitstring, r: bitstring) =
   sig_sign(proofKey(uc), muc(ui, mth, pth, nP, sha256(bd)), SCU, r).

(* Records a signed-in browser session. k_KS is replaced at every login (auth:755), and cd_u
   is u_c under k_L. ctag is the tag of the credential the session started from, and sprf the
   account mode the server returned. *)
let StartSession(aid: bitstring, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring, kKS: key, nS: bitstring, ctag: bitstring, sprf: bitstring) =
   insert sessions(aid, bid, ui, uc, pkId, ck, cs);
   event ClientLoggedIn(bid, ui, uc);
   event Adopted(bid, ui, uc, ctag, sprf);
   let cdu = mkAtRest(dsl(kKS, (SLOT, pkId)), ui, nS, key2bs(uc)) in
m4_ifdef({{LEAK_SESSION}}, {{   out(c, (ck, cs)); }})
m4_ifdef({{LEAK_CDU}}, {{   out(c, (cdu, pkId)); }})
   0.

(* Alice sends a request to an endpoint other than the ones modeled separately, with a method
   and body the attacker suggests: a body can carry user-supplied text, such as a passkey name.
   The app picks the path, and the path is signed, so the attacker cannot steer Alice into
   signing an add-passkey request. *)
let ApiRequests(aid: bitstring) =
   !new nP: bitstring; new r: bitstring; new rc: channel;
   get sessions(=aid, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring) in
   in(c, (mth: bitstring, bd: bitstring));
   let pth = PATH_API in
   event ClientSigned(ui, mth, pth, bd, nP);
   out(tls, ((API, ck, cs, mth, pth, bd, nP, mkProof(uc, ui, mth, pth, bd, nP, r)), rc));
   in(rc, resp: bitstring).

(* The user id in a new passkey's handle (auth:_startRegistration). The browser stops before the
   ceremony unless the options carry the user id it already holds, and builds the handle from
   that user id. MUT_SERVERHANDLE takes the options' user id instead, unchecked. *)
m4_define({{HANDLEUSER}}, {{
m4_ifdef({{MUT_SERVERHANDLE}}, {{
   (* MUTATION: the handle carries the options' user id *)
   let hui = $1 in
}}, {{
   if $1 = $2 then
   let hui = $2 in
}})
}})

(* addPasskey (auth:addPasskey). The authenticator keeps the passkey once created. Its handle
   carries the session's user id and the tag of the session's u_c. passkeys/options carries a
   nonce-form proof, and passkeys/verify a challenge-form proof over the add challenge. *)
let AddPasskey(aid: bitstring) =
   !new nP1: bitstring; new r1: bitstring; new rc1: channel;
   new credKey: key; new credId: bitstring; new nS: bitstring;
   new r2: bitstring; new rc2: channel;
   get sessions(=aid, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring) in
   event ClientSigned(ui, GET, PATH_PKOPT, EMPTY, nP1);
   out(tls, ((PKOPT, ck, cs, nP1, mkProof(uc, ui, GET, PATH_PKOPT, EMPTY, nP1, r1)), rc1));
   in(rc1, (ch: bitstring, oui: bitstring));
HANDLEUSER(oui, ui)
   let credPk = wa_pk(credKey) in
   event AliceCredCreated(ui, credId, credPk);
   event PasskeyHandle(ui, hui);
   insert passkeys(aid, hui, ucid(uc), credId, credKey);
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF account sends no cd_p (auth:1575-1598) *)
   let bd = (rr, ch, EMPTY, ui) in
}}, {{
   let bd = (rr, ch, mkAtRest(wa_prf(credKey, PS), ui, nS, key2bs(uc)), ui) in
}})
   event ClientSigned(ui, POST, PATH_PKVER, bd, ch);
   out(tls, ((PKVER, ck, cs, sig_sign(proofKey(uc), muc(ui, POST, PATH_PKVER, ch, sha256(bd)), SCP, r2), bd), rc2));
   in(rc2, resp: bitstring).

(* The tag check on a credential with tag $2, for the u_c $3 the browser resolved: a tagged
   credential's tag must be that u_c's id. MUT_NO$1TAG removes it. On a mismatch the process
   stops. The browser then completes the flow it was in (vibes/credential-tags.md, "A halt must
   tell the server nothing"), but those messages carry only the server's own u_c and fresh
   values, so the model leaves them out. *)
m4_define({{TAGCHECK}}, {{
m4_ifdef({{MUT_NO$1TAG}}, {{
   (* MUTATION: the tag is not checked *)
}}, {{
   if $2 = NOTAG || ucid($3) = $2 then
}})
}})

(* The user-id check on a server reply: the reply's user id $3 must be the one the browser
   already holds for the flow, $2. MUT_NOUICHECK_$1 removes it. *)
m4_define({{UICHECK}}, {{
m4_ifdef({{MUT_NOUICHECK_$1}}, {{
   (* MUTATION: the reply's user id is not compared *)
}}, {{
   if $3 = $2 then
}})
}})

(* Sign in from browser bid with the given passkey, whose handle carries ui and the tag tg
   (auth:createSession, auth:_resolveUserCred, auth:_loginUser) *)
let LoginWith(aid: bitstring, bid: bitstring, ui: bitstring, tg: bitstring, credId: bitstring, credKey: key, rc1: channel, rc2: channel, kKS: key, nS: bitstring) =
   out(tls, ((AUTHOPT, UNKNOWN), rc1));
   in(rc1, ch: bitstring);
   event UserApproves(ui, credId, ch);
   let ad = adata(RPID, UV1) in
   let cd = cdj(WA_GET, ch, ORIGIN) in
   out(tls, ((AUTHVER, credId, ui, ad, cd, wa_sign(credKey, (ad, cd)), ch), rc2));
   in(rc2, (sui: bitstring, sprf: bitstring, spkId: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
UICHECK({{LOGIN}}, ui, sui)
   (* _checkAccountPinPrf, then _resolveUserCred: a PRF account sends cd_p, a no-PRF account
      sends u_c itself. Then the tag check, and _pinAccount. *)
   get pins(=bid, =sui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
   let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
TAGCHECK({{HANDLE}}, tg, uc)
   get pins(=bid, =sui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
   insert pins(bid, sui, sprf, sig_pk(proofKey(uc)));
m4_ifdef({{STRIPLOGIN}}, {{   event SignedInWith(bid, sui, credId, ch, ck, uc);}})
   event SessionUser(ui, sui);
   event ClientSignedIn(bid, sui, uc);
   StartSession(aid, bid, sui, uc, spkId, ck, cs, kKS, nS, tg, sprf).

(* Sign in from browser bid, at any time, with any passkey Alice holds *)
let Login(aid: bitstring, bid: bitstring) =
   new rc1: channel; new rc2: channel; new kKS: key; new nS: bitstring;
   get passkeys(=aid, ui: bitstring, tg: bitstring, credId: bitstring, credKey: key) in
   LoginWith(aid, bid, ui, tg, credId, credKey, rc1, rc2, kKS, nS).

(* Sign in from the browser that registered, once registration has completed there. When the
   reply carries the user id registration pinned, the pin checks read that pin with a positive
   lookup, which drops no run because the pin exists from registration on. That lookup is what
   lets A-S3 be proved for an untagged credential: ProVerif treats the "no entry" branch of a
   negative lookup as always possible, and through it a sign-in could pin a u_c the server chose
   under that user id. When the reply carries another user id, which takes a user-id check
   mutation, the checks are the code's negative lookups. *)
let LoginRegistered(aid: bitstring) =
   new rc1: channel; new rc2: channel; new kKS: key; new nS: bitstring;
   get registered(=aid, ui: bitstring, rui: bitstring) in
   get passkeys(=aid, =ui, tg: bitstring, credId: bitstring, credKey: key) in
   out(tls, ((AUTHOPT, UNKNOWN), rc1));
   in(rc1, ch: bitstring);
   event UserApproves(ui, credId, ch);
   let ad = adata(RPID, UV1) in
   let cd = cdj(WA_GET, ch, ORIGIN) in
   out(tls, ((AUTHVER, credId, ui, ad, cd, wa_sign(credKey, (ad, cd)), ch), rc2));
   in(rc2, (sui: bitstring, sprf: bitstring, spkId: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
UICHECK({{LOGIN}}, ui, sui)
   (* _checkAccountPinPrf, then _resolveUserCred: a PRF account sends cd_p, a no-PRF account
      sends u_c itself. Then the tag check, and _pinAccount. *)
   if sui = rui then (
      get pins(=aid, =rui, pprf: bitstring, ppk: bitstring) in
      if pprf = PRF1 && sprf = PRF0 then 0 else
      let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
TAGCHECK({{HANDLE}}, tg, uc)
      if ppk = sig_pk(proofKey(uc)) then
      insert pins(aid, rui, sprf, sig_pk(proofKey(uc)));
      event SessionUser(ui, rui);
      event ClientSignedIn(aid, rui, uc);
      StartSession(aid, aid, rui, uc, spkId, ck, cs, kKS, nS, tg, sprf)
   ) else (
      get pins(=aid, =sui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
      let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
TAGCHECK({{HANDLE}}, tg, uc)
      get pins(=aid, =sui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
      insert pins(aid, sui, sprf, sig_pk(proofKey(uc)));
      event SessionUser(ui, sui);
      event ClientSignedIn(aid, sui, uc);
      StartSession(aid, aid, sui, uc, spkId, ck, cs, kKS, nS, tg, sprf)
   ).

(* The rest of a recovery, once the u_c from recover3 has passed the browser's pin checks under
   the words' u_i: recover/confirm, the new passkey, and recover/verify *)
let FinishRecovery(aid: bitstring, bid: bitstring, ui: bitstring, uc: key, sprf: bitstring, chR: bitstring,
                   r2: bitstring, r3: bitstring, credKey: key, credId: bitstring, nS: bitstring, rc2: channel,
                   rc3: channel, kKS: key, nS2: bitstring, wtg: bitstring) =
   insert pins(bid, ui, sprf, sig_pk(proofKey(uc)));
   event ClientConfirm(ui, chR);
   let cbd = (ui, chR) in
   out(tls, ((CONFIRM, cbd, sig_sign(proofKey(uc), muc(ui, POST, PATH_CONFIRM, chR, sha256(cbd)), SCP, r2)), rc2));
   (* Registration options. The new passkey's handle carries the words' user id and the tag of
      the u_c that passed the checks. *)
   in(rc2, (ch: bitstring, oui: bitstring));
HANDLEUSER(oui, ui)
   let credPk = wa_pk(credKey) in
   event AliceCredCreated(ui, credId, credPk);
   event PasskeyHandle(ui, hui);
   insert passkeys(aid, hui, ucid(uc), credId, credKey);
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
   (* cd_p is sent only for a PRF account (auth:_finishRecovery) *)
   let cdp = (if sprf = PRF1 then mkAtRest(wa_prf(credKey, PS), ui, nS, key2bs(uc)) else EMPTY) in
   let bd = (rr, ui, ch, cdp) in
   out(tls, ((RECVER, bd, sig_sign(proofKey(uc), muc(ui, POST, PATH_RECVER, ch, sha256(bd)), SCP, r3)), rc3));
m4_ifdef({{NOPRF}}, {{
   (* The browser does not read the u_c a no-PRF reply also carries (auth:1485-1488) *)
   in(rc3, (sui: bitstring, sprf2: bitstring, ck: bitstring, cs: bitstring, sdata2: bitstring)) [precise];
}}, {{
   in(rc3, (sui: bitstring, sprf2: bitstring, ck: bitstring, cs: bitstring)) [precise];
}})
   (* The browser reads prf as a boolean (auth:290-311), so the mode it pins is one of the two.
      [precise] keeps that constraint from breaking trace reconstruction. *)
   if sprf2 = PRF0 || sprf2 = PRF1 then
UICHECK({{RECOVERVERIFY}}, ui, sui)
   (* The account-mode pin check under the words' u_i (auth:_finishRecovery), then _loginUser,
      which pins under the reply's u_i (auth:_loginUser, auth:_pinAccount). The pin under the
      words' u_i is the one inserted above, so its mode is compared directly: ProVerif's negative
      lookup also allows a run where that entry is missing. *)
   if sprf = PRF1 && sprf2 = PRF0 then 0 else
   get pins(=bid, =ui, =PRF1, ppk2: bitstring) suchthat sprf2 = PRF0 in 0 else
   get pins(=bid, =sui, =PRF1, ppk3: bitstring) suchthat sprf2 = PRF0 in 0 else
   get pins(=bid, =sui, pprf4: bitstring, ppk4: bitstring) suchthat ppk4 <> sig_pk(proofKey(uc)) in 0 else
   insert pins(bid, sui, sprf2, sig_pk(proofKey(uc)));
   event SessionUser(ui, sui);
   event ClientRecovered(bid, sui, uc);
   StartSession(aid, bid, sui, uc, credId, ck, cs, kKS, nS2, wtg, sprf2).

(* recover3, recover/confirm, then recover/verify with a new passkey (auth:recover3), using any
   recovery words Alice has written down *)
let Recovery(aid: bitstring, bid: bitstring) =
   new nPR: bitstring; new r1: bitstring; new r2: bitstring; new r3: bitstring;
   new credKey: key; new credId: bitstring; new nS: bitstring;
   new rc1: channel; new rc2: channel; new rc3: channel;
   new kKS: key; new nS2: bitstring;
   get words(=aid, ui: bitstring, ur: bitstring, wtg: bitstring)PREC in
   event ClientRecoverIntent(ui, nPR);
   out(tls, ((REC3, ui, nPR, sig_sign(recoveryKey(ur, ui), mrc(ui, nPR), SCR, r1)), rc1));
   in(rc1, (sprf: bitstring, chR: bitstring, sdata: bitstring));
   (* A PRF account sends cd_r, a no-PRF account sends u_c itself (auth:recover3). Then the
      words' tag check, and _pinAccount under the words' u_i: the account-mode pin check, then
      the userCred compare. *)
   let uc = (if sprf = PRF1 then openAtRest(rsec(ur, ui), ui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
TAGCHECK({{WORDS}}, wtg, uc)
   get pins(=bid, =ui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
   get pins(=bid, =ui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
   FinishRecovery(aid, bid, ui, uc, sprf, chR, r2, r3, credKey, credId, nS, rc2, rc3, kKS, nS2, wtg).

(* Recovery from the browser that registered, once registration has completed there. When
   registration pinned the words' user id, the recover3 pin checks read that pin with a positive
   lookup, as in LoginRegistered. Otherwise registration left this browser no pin for that user
   id, and the checks are the code's negative lookups. The recover/verify checks are the code's
   in both cases: u_c is fixed at recover3, so their "no entry" branch pins the u_c that passed
   the recover3 check. *)
let RecoveryRegistered(aid: bitstring) =
   new nPR: bitstring; new r1: bitstring; new r2: bitstring; new r3: bitstring;
   new credKey: key; new credId: bitstring; new nS: bitstring;
   new rc1: channel; new rc2: channel; new rc3: channel;
   new kKS: key; new nS2: bitstring;
   get registered(=aid, ui: bitstring, rui: bitstring) in
   get words(=aid, =ui, ur: bitstring, wtg: bitstring) in
   event ClientRecoverIntent(ui, nPR);
   out(tls, ((REC3, ui, nPR, sig_sign(recoveryKey(ur, ui), mrc(ui, nPR), SCR, r1)), rc1));
   in(rc1, (sprf: bitstring, chR: bitstring, sdata: bitstring));
   (* A PRF account sends cd_r, a no-PRF account sends u_c itself (auth:recover3). Then the
      words' tag check, and _pinAccount under the words' u_i: the account-mode pin check, then
      the userCred compare. *)
   let uc = (if sprf = PRF1 then openAtRest(rsec(ur, ui), ui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
TAGCHECK({{WORDS}}, wtg, uc)
   if rui = ui then (
      get pins(=aid, =ui, pprf: bitstring, ppk: bitstring) in
      if pprf = PRF1 && sprf = PRF0 then 0 else
      if ppk = sig_pk(proofKey(uc)) then
      FinishRecovery(aid, aid, ui, uc, sprf, chR, r2, r3, credKey, credId, nS, rc2, rc3, kKS, nS2, wtg)
   ) else (
      get pins(=aid, =ui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
      get pins(=aid, =ui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
      FinishRecovery(aid, aid, ui, uc, sprf, chR, r2, r3, credKey, credId, nS, rc2, rc3, kKS, nS2, wtg)
   ).

(* changeRecoveryWords (auth:564-646). The words are shown, and so written down, even when the
   server does not confirm them (auth:639-641). *)
let ReplaceWords(aid: bitstring) =
   !new ur2: bitstring; new nPR: bitstring; new rR: bitstring; new nP: bitstring; new r: bitstring;
   new nS: bitstring; new rc: channel;
   get sessions(=aid, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring) in
   (* 27 words, tagged with the session's u_c *)
   insert words(aid, ui, ur2, ucid(uc));
   let skR = recoveryKey(ur2, ui) in
m4_ifdef({{MUT_ONECTX}}, {{
   (* MUTATION: the replace proof is signed under sc_R *)
   let sigR = sig_sign(skR, mrc(ui, nPR), SCR, rR) in
}}, {{
   let sigR = sig_sign(skR, mrc(ui, nPR), SCW, rR) in
}})
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF account sends no cd_r (auth:609-619) *)
   let bd = (sig_pk(skR), nPR, sigR, EMPTY) in
}}, {{
   let bd = (sig_pk(skR), nPR, sigR, mkAtRest(rsec(ur2, ui), ui, nS, key2bs(uc))) in
}})
   event ClientReplace(ui, sig_pk(skR));
   event ClientSigned(ui, PUT, PATH_REPLACE, bd, nP);
   out(tls, ((REPLACE, ck, cs, nP, mkProof(uc, ui, PUT, PATH_REPLACE, bd, nP, r), bd), rc));
   in(rc, resp: bitstring).

(* The account mode the browser pins at registration *)
m4_ifdef({{NOPRF}}, {{m4_define({{ACCTMODE}}, {{PRF0}})}}, {{m4_define({{ACCTMODE}}, {{PRF1}})}})

(* Registration (tex: Registration by A; auth:newUser). The browser creates u_c in both modes and
   sends pk_U in reg/options. The passkey's handle and the words carry the tag of that u_c, and
   reg/verify carries proofs under sk_U and sk_R. u_i is public: it is in the recovery words and
   in URLs. *)
let Register(aid: bitstring) =
   new rc1: channel; new rc2: channel;
   new credKey: key; new credId: bitstring; new ur: bitstring; new ucA: key;
   new nS1: bitstring; new nS2: bitstring; new kKS: key; new nS3: bitstring;
   new rU: bitstring; new rR: bitstring;
   let uc = ucA in
   let pkU = sig_pk(proofKey(uc)) in
   out(tls, ((REGOPT, pkU), rc1));
m4_ifdef({{SCN_MALICIOUS}}, {{
   (* [precise], here and on the reg/verify reply, tells ProVerif that one registration receives
      one options message and one reply. Without it, the Horn-clause abstraction can combine two
      registrations of this browser, under different user ids the server chose, into one
      derivation that no run follows. It adds no assumption, and only the malicious-server
      variants need it. *)
   in(rc1, (ch: bitstring, ui: bitstring)) [precise];
}}, {{
   in(rc1, (ch: bitstring, ui: bitstring))PREC_STRIP;
}})
   event AliceUi(ui);
   let tg = ucid(uc) in
   let credPk = wa_pk(credKey) in
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
   event AliceCredCreated(ui, credId, credPk);
   insert passkeys(aid, ui, tg, credId, credKey);
m4_ifdef({{LEAK_WORDS}}, {{   out(c, ur); }})
   let skR = recoveryKey(ur, ui) in
   let sigR = sig_sign(skR, mrg(ui, ch, REGSIGR_PKU(pkU)), SCG, rR) in
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF registration sends u_c itself in place of cd_p and cd_r *)
   event AliceUc(aid, uc);
   let bd = (rr, ui, ch, sig_pk(skR), BODY_PKU(pkU)key2bs(uc), sigR) in
}}, {{
   let cdp = mkAtRest(wa_prf(credKey, PS), ui, nS1, key2bs(uc)) in
   let cdr = mkAtRest(rsec(ur, ui), ui, nS2, key2bs(uc)) in
   let bd = (rr, ui, ch, sig_pk(skR), BODY_PKU(pkU)cdp, cdr, sigR) in
}})
   event RegSigned(ui, ch, pkU, sig_pk(skR));
   out(tls, ((REGVER, bd, sig_sign(proofKey(uc), muc(ui, POST, PATH_REGVER, ch, sha256(bd)), SCP, rU)), rc2));
m4_ifdef({{NOPRF}}, {{
   (* The browser does not read the u_c a no-PRF reply carries *)
m4_ifdef({{SCN_MALICIOUS}}, {{
   in(rc2, (sui: bitstring, sprf: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring)) [precise];
}}, {{
   in(rc2, (sui: bitstring, sprf: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
}})
   if sprf = PRF0 then
}}, {{
   (* newUser halts when the reply to a PRF registration says no-PRF (auth:newUser). The model
      reads that field only under DUALMODE, where an honest server can send it; elsewhere,
      ignoring it only adds runs. *)
m4_ifdef({{SCN_MALICIOUS}}, {{
   in(rc2, (sui: bitstring, ck: bitstring, cs: bitstring)) [precise];
}}, {{
m4_ifdef({{DUALMODE}}, {{
   in(rc2, (sui: bitstring, sprf: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring))PREC_STRIP;
   if sprf = PRF1 then
}}, {{
   in(rc2, (sui: bitstring, ck: bitstring, cs: bitstring));
}})
}})
}})
   (* newUser stops unless the reply carries the user id from reg/options. _loginUser then pins
      and signs in under it. This browser holds no pin before it registers, so _pinAccount's
      checks pass. *)
UICHECK({{REG}}, ui, sui)
   event Registered(aid, ui, sui);
   insert pins(aid, sui, ACCTMODE, pkU);
   insert registered(aid, ui, sui);
   (* The words are shown only in a signed-in session, so Alice has them only once registration
      completes (auth:530-541) *)
   insert words(aid, ui, ur, tg);
   out(c, ui);
   event SessionUser(ui, sui);
   StartSession(aid, aid, sui, uc, credId, ck, cs, kKS, nS3, tg, ACCTMODE).

m4_ifdef({{EXISTING}}, {{
(* An account that exists when the release deploys. It is data, not a protocol run: the
   server's records, Alice's untagged passkey and 24-word set, and the pin on the browser that
   registered the account. *)
let Existing(aid: bitstring) =
   new ui: bitstring; new ucA: key; new ur: bitstring; new credKey: key; new credId: bitstring;
   new nS1: bitstring; new nS2: bitstring;
   let pkU = sig_pk(proofKey(ucA)) in
   let pkR = sig_pk(recoveryKey(ur, ui)) in
   let credPk = wa_pk(credKey) in
   event AliceUi(ui);
   event AliceCredCreated(ui, credId, credPk);
   insert users(ui, pkU);
m4_ifdef({{NOPRF}}, {{
   event AliceUc(aid, ucA);
   insert ucenc(ui, kms_enc(kmsNew, ui, ucA), kms_enc(kmsOld, ui, ucA));
   insert recov(ui, pkR, EMPTY);
   insert creds(ui, credId, credPk, EMPTY);
}}, {{
   insert recov(ui, pkR, mkAtRest(rsec(ur, ui), ui, nS2, key2bs(ucA)));
   insert creds(ui, credId, credPk, mkAtRest(wa_prf(credKey, PS), ui, nS1, key2bs(ucA)));
}})
   insert passkeys(aid, ui, NOTAG, credId, credKey);
   insert words(aid, ui, ur, NOTAG);
   insert registered(aid, ui, ui);
   insert pins(aid, ui, ACCTMODE, pkU);
   out(c, ui).

(* Once the attacker controls the server, it reads every server table and holds the server's
   keys. It needs no write access: it answers every request itself. *)
let DbDump() =
   (!get users(ui: bitstring, pkU: bitstring) in out(c, (ui, pkU)))
   | (!get recov(ui: bitstring, pkR: bitstring, cdr: bitstring) in out(c, (ui, pkR, cdr)))
   | (!get creds(ui: bitstring, credId: bitstring, credPk: bitstring, cdp: bitstring) in out(c, (ui, credId, credPk, cdp)))
   | (!get ucenc(ui: bitstring, enc: bitstring, encOld: bitstring) in out(c, (ui, enc, encOld)))
   | (!get chal(pu: bitstring, ch: bitstring, cu: bitstring, bnd: bitstring) in out(c, (pu, ch, cu, bnd)))
   | out(c, (skJWT, kmsNew, kmsOld)).
}})

m4_ifdef({{TWOACCOUNTS}}, {{
(* A second PRF account that Alice registered earlier from the same browser and authenticator:
   her tagged passkey and words for it, its pin, and the records the malicious server received
   at that registration. A second run of Register, under replication, does not terminate. *)
let SecondAccount(aid: bitstring) =
   new ui: bitstring; new ucB: key; new ur: bitstring; new credKey: key; new credId: bitstring;
   new nS1: bitstring; new nS2: bitstring;
   let pkU = sig_pk(proofKey(ucB)) in
   let credPk = wa_pk(credKey) in
   event AliceUi(ui);
   event AliceCredCreated(ui, credId, credPk);
   insert passkeys(aid, ui, ucid(ucB), credId, credKey);
   insert words(aid, ui, ur, ucid(ucB));
   insert registered(aid, ui, ui);
   insert pins(aid, ui, PRF1, pkU);
   out(c, (ui, pkU, sig_pk(recoveryKey(ur, ui)), credId, credPk,
           mkAtRest(wa_prf(credKey, PS), ui, nS1, key2bs(ucB)), mkAtRest(rsec(ur, ui), ui, nS2, key2bs(ucB)))).
}})

m4_ifdef({{REAUTH}}, {{
(* reauthenticate (auth:reauthenticate): a browser with a session signs in again, as it does
   before operations such as replacing the recovery words. The reply's user id must be the
   passkey handle's and the session's. *)
event Reauthenticated(bitstring, bitstring, key).

let Reauth(aid: bitstring) =
   !new rc1: channel; new rc2: channel; new kKS: key; new nS: bitstring;
   get sessions(=aid, bid: bitstring, sui0: bitstring, uc0: key, pkId0: bitstring, ck0: bitstring, cs0: bitstring) in
   get passkeys(=aid, ui: bitstring, tg: bitstring, credId: bitstring, credKey: key) in
   out(tls, ((AUTHOPT, sui0), rc1));
   in(rc1, ch: bitstring);
   event UserApproves(ui, credId, ch);
   let ad = adata(RPID, UV1) in
   let cd = cdj(WA_GET, ch, ORIGIN) in
   out(tls, ((AUTHVER, credId, ui, ad, cd, wa_sign(credKey, (ad, cd)), ch), rc2));
   in(rc2, (sui: bitstring, sprf: bitstring, spkId: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
UICHECK({{LOGIN}}, ui, sui)
UICHECK({{REAUTH}}, sui0, sui)
   get pins(=bid, =sui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
   let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
TAGCHECK({{HANDLE}}, tg, uc)
   get pins(=bid, =sui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
   insert pins(bid, sui, sprf, sig_pk(proofKey(uc)));
   event SessionUser(ui, sui);
   event SessionUser(sui0, sui);
   event Reauthenticated(bid, sui, uc);
   event ClientSignedIn(bid, sui, uc);
   StartSession(aid, bid, sui, uc, spkId, ck, cs, kKS, nS, tg, sprf).
}})

(* An unlocked device without the user: assertions without UV, and PRF output *)
let DeviceAccess(aid: bitstring) =
   !get passkeys(=aid, ui: bitstring, tg: bitstring, credId: bitstring, credKey: key) in
   in(c, dch: bitstring);
   out(c, (credId, wa_sign(credKey, (adata(RPID, UV0), cdj(WA_GET, dch, ORIGIN))), wa_prf(credKey, PS))).

m4_ifdef({{LEAK_DB}}, {{
(* A copy of the server's account tables. Replay nonces are not in it. LEAK_CHAL adds live reads
   of the challenge table, and LEAK_CHAL_RECOVER of only its recover/verify challenges.
   LEAK_KMS_NEW and LEAK_KMS_OLD add the use of a KMS key. *)
let DbLeak() =
   (!get users(ui: bitstring, pkU: bitstring) in out(c, (ui, pkU)))
   | (!get unverified(ui: bitstring, pkU: bitstring) in out(c, (ui, pkU)))
   | (!get recov(ui: bitstring, pkR: bitstring, cdr: bitstring) in out(c, (ui, pkR, cdr)))
   | (!get creds(ui: bitstring, credId: bitstring, credPk: bitstring, cdp: bitstring) in out(c, (ui, credId, credPk, cdp)))
   | (!get ucenc(ui: bitstring, enc: bitstring, encOld: bitstring) in out(c, (ui, enc, encOld)))
m4_ifdef({{LEAK_CHAL}}, {{   | (!get chal(pu: bitstring, ch: bitstring, cu: bitstring, bnd: bitstring) in out(c, (pu, ch, cu, bnd)))}})
m4_ifdef({{LEAK_CHAL_RECOVER}}, {{   | (!get chal(=PRECOVER, ch: bitstring, cu: bitstring, bnd: bitstring) in out(c, (ch, cu, bnd)))}})
m4_ifdef({{LEAK_KMS_NEW}}, {{   | out(c, kmsNew)}})
m4_ifdef({{LEAK_KMS_OLD}}, {{   | out(c, kmsOld)}})
   .
}})

(* What Alice does against a malicious server *)
m4_define({{MALICIOUS_ACTIVITY}}, {{
    !LoginRegistered(aid) | AddPasskey(aid)
    (* Sign-ins from browsers with no pin: a new device or profile, cleared storage, or the
       registering browser before registration completed *)
    | (!new bidF: bitstring; Login(aid, bidF))
m4_ifdef({{EXISTING}}, {{
    | ReplaceWords(aid)
}})
m4_ifdef({{REAUTH}}, {{
    | Reauth(aid)
}})
m4_ifdef({{MAL_RECOVERY}}, {{
    (* Recovery from the registering browser, and from a browser with no pin, the usual case
       after losing every passkey *)
    | !RecoveryRegistered(aid)
    | (!new bidR: bitstring; Recovery(aid, bidR))
}})
}})

(* One Alice: she registers, then does everything the scenario covers, any number of times.
   With TWOACCOUNTS her browser also holds a second account. With EXISTING her account already
   exists. *)
let Alice() =
   new aid: bitstring;
   (
m4_ifdef({{EXISTING}}, {{
    Existing(aid)
}}, {{
    Register(aid)
m4_ifdef({{TWOACCOUNTS}}, {{
    | SecondAccount(aid)
}})
}})
m4_ifdef({{SCN_RECOVERY}}, {{
    | ReplaceWords(aid) | !Recovery(aid, aid)
}})
m4_ifdef({{SCN_LOGIN}}, {{
m4_ifdef({{STRIPLOGIN}}, {{
    | !Login(aid, aid)
}}, {{
    | !Login(aid, aid) | ApiRequests(aid) | AddPasskey(aid)
}})
}})
m4_ifdef({{SCN_MALICIOUS}}, {{
m4_ifdef({{PHASED}}, {{
    (* Phase 0, with the server honest: sign-ins from the registering browser and from browsers
       with no pin, and the passkeys and words Alice adds, tagged from the u_c the honest server
       returns *)
    | !LoginRegistered(aid) | (!new bidF0: bitstring; Login(aid, bidF0)) | AddPasskey(aid)
    | ReplaceWords(aid)
    (* Phase 1, with the attacker controlling the server *)
    | (phase 1; (MALICIOUS_ACTIVITY))
}}, {{
    | MALICIOUS_ACTIVITY
}})
}})
m4_ifdef({{LEAK_DEVICE}}, {{
    | DeviceAccess(aid)
}})
   ).

m4_ifdef({{SCN_LOGIN}}, {{
(* ======================================================================================== *)
(* A-L1, A-R1, A-Z1, A-K1, A-S1 *)

m4_ifdef({{REACH_ONLY}}, {{}}, {{
m4_ifdef({{STRIPLOGIN}}, {{
(* The rest of the stripped registration: Alice's own browser signs in with that passkey, the
   honest server's auth/verify answers her assertion with the account's u_c, and her browser
   accepts that reply. The cookie ties the two: only that server session can make it. *)
query b: bitstring, u: bitstring, id: bitstring, ch: bitstring, ck: bitstring, pk: bitstring, x: key;
   event(SignedInWith(b, u, id, ch, ck, x)) && event(ServerReplyUc(u, id, ch, ck, x))
   && event(ServerUc(u, id, pk, x)) && event(AliceCredCreated(u, id, pk)) && attacker(x).
}}, {{
m4_ifdef({{KEY_UI}}, {{
(* With TLS broken the attacker can copy Alice's pk_U into an account of its own, so Alice's
   accounts are the ones with the user id her browser received at registration *)

(* A-L1: the server signs Alice in only with a passkey she approved, for that challenge *)
query u: bitstring, id: bitstring, ch: bitstring, pkU: bitstring;
   event(ServerLogin(u, id, ch, pkU)) && event(AliceUi(u)) ==> event(UserApproves(u, id, ch)).

(* A-R1: every passkey the server binds to Alice's account is one she created *)
query u: bitstring, id: bitstring, pk: bitstring, pkU: bitstring;
   event(ServerCredAdded(u, id, pk, pkU)) && event(AliceUi(u)) ==> event(AliceCredCreated(u, id, pk)).

(* A-Z1: an authorized request on Alice's account is one her browser signed *)
query u: bitstring, m: bitstring, p: bitstring, b: bitstring, n: bitstring, pkU: bitstring;
   event(ServerAccept(u, m, p, b, n, pkU)) && event(AliceUi(u)) ==> event(ClientSigned(u, m, p, b, n)).
}}, {{
m4_ifdef({{NOPRF}}, {{
(* Alice's accounts are the ones whose pk_U is derived from the u_c the server drew when it
   registered her passkey *)

(* A-L1: the server signs Alice in only with a passkey she approved, for that challenge *)
query u: bitstring, id: bitstring, ch: bitstring, au: bitstring, aid: bitstring, apk: bitstring, x: key;
   event(ServerLogin(u, id, ch, sig_pk(kdf(ID1, kpU, x)))) && event(ServerUc(au, aid, apk, x)) && event(AliceCredCreated(au, aid, apk))
   ==> event(UserApproves(u, id, ch)).

(* A-R1: every passkey the server binds to Alice's account is one she created *)
query u: bitstring, id: bitstring, pk: bitstring, au: bitstring, aid: bitstring, apk: bitstring, x: key;
   event(ServerCredAdded(u, id, pk, sig_pk(kdf(ID1, kpU, x)))) && event(ServerUc(au, aid, apk, x)) && event(AliceCredCreated(au, aid, apk))
   ==> event(AliceCredCreated(u, id, pk)).

(* A-Z1: an authorized request on Alice's account is one her browser signed *)
query u: bitstring, m: bitstring, p: bitstring, b: bitstring, n: bitstring, au: bitstring, aid: bitstring, apk: bitstring, x: key;
   event(ServerAccept(u, m, p, b, n, sig_pk(kdf(ID1, kpU, x)))) && event(ServerUc(au, aid, apk, x)) && event(AliceCredCreated(au, aid, apk))
   ==> event(ClientSigned(u, m, p, b, n)).
}}, {{
(* Alice's accounts are the ones whose pk_U is derived from a u_c created by "new ucA" *)

(* A-L1: the server signs Alice in only with a passkey she approved, for that challenge *)
query u: bitstring, id: bitstring, ch: bitstring;
   event(ServerLogin(u, id, ch, sig_pk(kdf(ID1, kpU, new ucA)))) ==> event(UserApproves(u, id, ch)).

(* A-R1: every passkey the server binds to Alice's account is one she created *)
query u: bitstring, id: bitstring, pk: bitstring;
   event(ServerCredAdded(u, id, pk, sig_pk(kdf(ID1, kpU, new ucA)))) ==> event(AliceCredCreated(u, id, pk)).

(* A-Z1: an authorized request on Alice's account is one her browser signed *)
query u: bitstring, m: bitstring, p: bitstring, b: bitstring, n: bitstring;
   event(ServerAccept(u, m, p, b, n, sig_pk(kdf(ID1, kpU, new ucA)))) ==> event(ClientSigned(u, m, p, b, n)).
}})
}})

(* A-K2: the server stores Alice's pk_U or pk_R only from a reg/verify her browser signed, for
   that user id and challenge *)
query u: bitstring, ch: bitstring, pr: bitstring;
   event(ServerRegistered(u, ch, sig_pk(kdf(ID1, kpU, new ucA)), pr))
   ==> event(RegSigned(u, ch, sig_pk(kdf(ID1, kpU, new ucA)), pr)).
query u: bitstring, ch: bitstring, pu: bitstring, v: bitstring;
   event(ServerRegistered(u, ch, pu, sig_pk(kdf(ID1, kpR, rsec(new ur, v)))))
   ==> event(RegSigned(u, ch, pu, sig_pk(kdf(ID1, kpR, rsec(new ur, v))))).

(* A-S1, A-K1: u_c stays secret. In no-PRF mode it is the u_c the server registered with Alice's
   passkey, and the u_c her browser created. With TLS broken the attacker can register her
   passkey with a u_c of its own, so only the second is about her account. *)
m4_ifdef({{NOPRF}}, {{
query u: bitstring, id: bitstring, pk: bitstring, x: key;
   event(ServerUc(u, id, pk, x)) && event(AliceCredCreated(u, id, pk)) && attacker(x).
query a: bitstring, x: key; event(AliceUc(a, x)) && attacker(x).
}}, {{
query attacker(new ucA).
}})

m4_ifdef({{DUALMODE}}, {{
(* Alice registers in PRF mode, yet the honest server registers her user id and passkey as a
   no-PRF account whose u_c the attacker knows *)
query u: bitstring, id: bitstring, pk: bitstring, x: key;
   event(AliceUi(u)) && event(ServerUc(u, id, pk, x)) && event(AliceCredCreated(u, id, pk)) && attacker(x).
}})
}})
}})

m4_ifdef({{REACH_ONLY}}, {{
(* Reachability of Alice's own runs. Each server event is paired with an event that only Alice's
   browser or authenticator emits, so a run on an attacker's account does not satisfy the query.
   Without the uniqueness restrictions, trace reconstruction for these runs does not finish, so
   they are checked only in the REACH_ONLY variant. Restrictions only remove traces, and the other
   login variants only add attacker knowledge, relax server checks, change queries, or make TLS
   public. So each trace found here, less the Rcv events that RCV records, is also a trace of
   every other login variant. *)
query user: bitstring, credId: bitstring, chal: bitstring, pkU: bitstring;
   event(ServerLogin(user, credId, chal, pkU)) && event(UserApproves(user, credId, chal)).
query user: bitstring, method: bitstring, body: bitstring, nonce: bitstring, pkU: bitstring;
   event(ServerAccept(user, method, PATH_API, body, nonce, pkU))
   && event(ClientSigned(user, method, PATH_API, body, nonce)).
(* The added passkey is the one in Alice's signed passkeys/verify body, not her registration
   passkey *)
query user: bitstring, credId: bitstring, credPk: bitstring, pkU: bitstring, authData: bitstring,
      clientData: bitstring, chal: bitstring, cdp: bitstring, bodyUser: bitstring, nonce: bitstring;
   event(ServerCredAdded(user, credId, credPk, pkU))
   && event(ClientSigned(user, POST, PATH_PKVER, (regr(credId, credPk, authData, clientData), chal, cdp, bodyUser), nonce)).
(* Alice's browser signs in holding her own u_c. "!1 = alice" requires both names to come from
   the same Alice. *)
m4_ifdef({{NOPRF}}, {{
query user: bitstring, alice: sid, x: key;
   event(ClientSignedIn(new aid[!1 = alice], user, x)) && event(AliceUc(new aid[!1 = alice], x)).
}}, {{
query user: bitstring, alice: sid; event(ClientSignedIn(new aid[!1 = alice], user, new ucA[!1 = alice])).
}})
}})

process
   Server() | !Alice()
m4_ifdef({{LEAK_DB}}, {{   | DbLeak()}})
}})

m4_ifdef({{SCN_RECOVERY}}, {{
(* ======================================================================================== *)
(* A-V1, A-V2, A-V3, A-R1, A-S1 for recovery and replacing recovery words *)

m4_ifdef({{REACH_ONLY}}, {{}}, {{
m4_ifdef({{KEY_UI}}, {{
(* Alice's accounts are the ones with the user id her browser received at registration *)

(* A-V1: recover3 accepts a proof on Alice's account only from a browser recovering it *)
query u: bitstring, n: bitstring, pkU: bitstring;
   event(ServerRecover3(u, n, pkU)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u, n)).

(* A-V2: recover/confirm on Alice's account is one her browser signed, for that challenge *)
query u: bitstring, ch: bitstring, pkU: bitstring;
   event(ServerConfirm(u, ch, pkU)) && event(AliceUi(u)) ==> event(ClientConfirm(u, ch)).

(* A-V3: new recovery words on Alice's account are ones her browser created *)
query u: bitstring, pk: bitstring, pkU: bitstring;
   event(ServerReplaced(u, pk, pkU)) && event(AliceUi(u)) ==> event(ClientReplace(u, pk)).

(* A-R1: every passkey bound to Alice's account, including by recovery, is one she created *)
query u: bitstring, id: bitstring, pk: bitstring, pkU: bitstring;
   event(ServerCredAdded(u, id, pk, pkU)) && event(AliceUi(u)) ==> event(AliceCredCreated(u, id, pk)).
}}, {{
m4_ifdef({{NOPRF}}, {{
(* Alice's accounts are the ones whose pk_U is derived from the u_c the server drew when it
   registered her passkey *)

(* A-V1: recover3 accepts a proof on Alice's account only from a browser recovering it *)
query u: bitstring, n: bitstring, au: bitstring, aid: bitstring, apk: bitstring, x: key;
   event(ServerRecover3(u, n, sig_pk(kdf(ID1, kpU, x)))) && event(ServerUc(au, aid, apk, x)) && event(AliceCredCreated(au, aid, apk))
   ==> event(ClientRecoverIntent(u, n)).

(* A-V2: recover/confirm on Alice's account is one her browser signed, for that challenge *)
query u: bitstring, ch: bitstring, au: bitstring, aid: bitstring, apk: bitstring, x: key;
   event(ServerConfirm(u, ch, sig_pk(kdf(ID1, kpU, x)))) && event(ServerUc(au, aid, apk, x)) && event(AliceCredCreated(au, aid, apk))
   ==> event(ClientConfirm(u, ch)).

(* A-V3: new recovery words on Alice's account are ones her browser created *)
query u: bitstring, pk: bitstring, au: bitstring, aid: bitstring, apk: bitstring, x: key;
   event(ServerReplaced(u, pk, sig_pk(kdf(ID1, kpU, x)))) && event(ServerUc(au, aid, apk, x)) && event(AliceCredCreated(au, aid, apk))
   ==> event(ClientReplace(u, pk)).

(* A-R1: every passkey bound to Alice's account, including by recovery, is one she created *)
query u: bitstring, id: bitstring, pk: bitstring, au: bitstring, aid: bitstring, apk: bitstring, x: key;
   event(ServerCredAdded(u, id, pk, sig_pk(kdf(ID1, kpU, x)))) && event(ServerUc(au, aid, apk, x)) && event(AliceCredCreated(au, aid, apk))
   ==> event(AliceCredCreated(u, id, pk)).
}}, {{
(* A-V1: recover3 accepts a proof on Alice's account only from a browser recovering it *)
query u: bitstring, n: bitstring;
   event(ServerRecover3(u, n, sig_pk(kdf(ID1, kpU, new ucA)))) ==> event(ClientRecoverIntent(u, n)).

(* A-V2: recover/confirm on Alice's account is one her browser signed, for that challenge *)
query u: bitstring, ch: bitstring;
   event(ServerConfirm(u, ch, sig_pk(kdf(ID1, kpU, new ucA)))) ==> event(ClientConfirm(u, ch)).

(* A-V3: new recovery words on Alice's account are ones her browser created *)
query u: bitstring, pk: bitstring;
   event(ServerReplaced(u, pk, sig_pk(kdf(ID1, kpU, new ucA)))) ==> event(ClientReplace(u, pk)).

(* A-R1: every passkey bound to Alice's account, including by recovery, is one she created *)
query u: bitstring, id: bitstring, pk: bitstring;
   event(ServerCredAdded(u, id, pk, sig_pk(kdf(ID1, kpU, new ucA)))) ==> event(AliceCredCreated(u, id, pk)).
}})
}})

(* A-S1: u_c and both sets of recovery words stay secret *)
m4_ifdef({{NOPRF}}, {{
query u: bitstring, id: bitstring, pk: bitstring, x: key;
   event(ServerUc(u, id, pk, x)) && event(AliceCredCreated(u, id, pk)) && attacker(x).
query a: bitstring, x: key; event(AliceUc(a, x)) && attacker(x).
}}, {{
query attacker(new ucA).
}})
query attacker(new ur).
query attacker(new ur2).
}})

m4_ifdef({{REACH_ONLY}}, {{
(* Reachability of each step of Alice's own recovery, and of replacing her words. Each server
   event is paired with an event that only Alice's browser emits, and the passkey recover/verify
   binds must be one she created. Without the uniqueness restrictions, trace reconstruction for
   these runs does not finish, so they are checked only in the REACH_ONLY variants. Restrictions
   only remove traces, and the other recovery variants only add attacker knowledge, relax server
   checks, change queries, or make TLS public. So each trace found here, less the Rcv events that
   RCV records, is also a trace of every other recovery variant. *)
query user: bitstring, recoveryPk: bitstring, pkU: bitstring;
   event(ServerReplaced(user, recoveryPk, pkU)) && event(ClientReplace(user, recoveryPk)).
query user: bitstring, nonce: bitstring, pkU: bitstring;
   event(ServerRecover3(user, nonce, pkU)) && event(ClientRecoverIntent(user, nonce)).
query user: bitstring, chal: bitstring, pkU: bitstring;
   event(ServerConfirm(user, chal, pkU)) && event(ClientConfirm(user, chal)).
query user: bitstring, credId: bitstring, credPk: bitstring, pkU: bitstring;
   event(ServerRecovered(user, credId, pkU)) && event(AliceCredCreated(user, credId, credPk)).
m4_ifdef({{NOPRF}}, {{
query user: bitstring, alice: sid, x: key;
   event(ClientRecovered(new aid[!1 = alice], user, x)) && event(AliceUc(new aid[!1 = alice], x)).
}}, {{
query user: bitstring, alice: sid; event(ClientRecovered(new aid[!1 = alice], user, new ucA[!1 = alice])).
}})
}})

process
   Server() | !Alice()
m4_ifdef({{LEAK_DB}}, {{   | DbLeak()}})
}})

m4_ifdef({{SCN_MALICIOUS}}, {{
(* ======================================================================================== *)
(* A-S2..A-S4: a malicious server answers every request Alice's browser makes. The browser and
   the static site that serves its code are honest. *)

m4_ifdef({{NOPRF}}, {{
(* In no-PRF mode the server holds u_c, so it knows the u_c Alice's browser holds *)
query a: bitstring, x: key; event(AliceUc(a, x)) && attacker(x).
}}, {{
(* A-S2: in PRF mode the server never learns Alice's u_c *)
query attacker(new ucA).
m4_ifdef({{TWOACCOUNTS}}, {{
query attacker(new ucB).
}})
m4_ifdef({{REAUTH}}, {{
(* Reachability of reauthentication: on the registering browser for each account, and on a
   browser with no pin, each ending with that account's own u_c *)
query u: bitstring, alice: sid; event(Reauthenticated(new aid[!1 = alice], u, new ucA[!1 = alice])).
m4_ifdef({{TWOACCOUNTS}}, {{
query u: bitstring, alice: sid; event(Reauthenticated(new aid[!1 = alice], u, new ucB[!1 = alice])).
}})
query u: bitstring, alice: sid; event(Reauthenticated(new bidF[!1 = alice], u, new ucA[!1 = alice])).
}})

m4_ifdef({{EXISTING}}, {{
(* A-E1 for an account that existed before the release. A credential tagged with Alice's own u_c,
   written while the server was honest, never lets a browser adopt a u_c the server knows. An
   untagged one does, on a browser with no pin: the gap until untagged credentials are
   migrated. *)
query b: bitstring, u: bitstring, x: key, m: bitstring; event(Adopted(b, u, x, ucid(new ucA), m)) && attacker(x).
query b: bitstring, u: bitstring, x: key, m: bitstring; event(Adopted(b, u, x, NOTAG, m)) && attacker(x).
m4_ifdef({{FIRSTUSE}}, {{
(* With the server dishonest from the start, a session that trusted it on first use writes tags
   from the server's u_c, and a later sign-in with such a credential accepts that u_c *)
query b: bitstring, u: bitstring, x: key, y: key, m: bitstring; event(Adopted(b, u, x, ucid(y), m)) && attacker(x).
}})

(* A-S3 for the browser that registered the account: its pin and the user-id checks protect even
   the untagged credentials *)
query u: bitstring, x: key; event(ClientLoggedIn(new aid, u, x)) && attacker(x).

m4_ifdef({{PHASED}}, {{
(* Reachability: in phase 0, with the server honest, a browser with no pin signs in with the
   untagged passkey and holds Alice's own u_c. In phase 1, a browser with no pin signs in with a
   tagged passkey and holds Alice's own u_c. *)
query u: bitstring, m: bitstring, alice: sid;
   event(Adopted(new bidF0[!1 = alice], u, new ucA[!1 = alice], NOTAG, m)).
query u: bitstring, m: bitstring, alice: sid;
   event(Adopted(new bidF[!1 = alice], u, new ucA[!1 = alice], ucid(new ucA[!1 = alice]), m)).

(* Reachability of recoveries, which run only in phase 1: on a browser with no pin, with tagged
   words and with the untagged words, and on the registering browser, each ending with Alice's
   own u_c *)
query u: bitstring, m: bitstring, alice: sid;
   event(Adopted(new bidR[!1 = alice], u, new ucA[!1 = alice], ucid(new ucA[!1 = alice]), m)).
query u: bitstring, m: bitstring, alice: sid;
   event(Adopted(new bidR[!1 = alice], u, new ucA[!1 = alice], NOTAG, m)).
query u: bitstring, alice: sid; event(ClientRecovered(new aid[!1 = alice], u, new ucA[!1 = alice])).
}})
}}, {{
(* A-E1: every u_c any of Alice's browsers adopts stays secret from the server *)
query b: bitstring, u: bitstring, x: key, t: bitstring, m: bitstring; event(Adopted(b, u, x, t, m)) && attacker(x).

(* A-D1: a browser never treats Alice's PRF account as no-PRF when it uses a credential tagged
   with her u_c *)
query b: bitstring, u: bitstring, x: key; event(Adopted(b, u, x, ucid(new ucA), PRF0)).

(* A-S3: once registration has completed in a browser, that browser never adopts a u_c the
   server knows, whether it signs in or, with MAL_RECOVERY, recovers *)
query u: bitstring, x: key; event(ClientLoggedIn(new aid, u, x)) && attacker(x).

(* A-S4: a browser with no pin for the account never adopts a u_c the server knows *)
query u: bitstring, x: key; event(ClientLoggedIn(new bidF, u, x)) && attacker(x).

(* Reachability of honest sign-ins: the registering browser, after a registration whose reply
   carried Alice's own user id, and a browser with no pin, each sign in holding Alice's own u_c.
   "!1 = alice" requires the browser and u_c to come from the same Alice. *)
query user: bitstring, ui: bitstring, alice: sid;
   event(ClientSignedIn(new aid[!1 = alice], user, new ucA[!1 = alice])) && event(Registered(new aid[!1 = alice], ui, ui)).
query user: bitstring, alice: sid; event(ClientSignedIn(new bidF[!1 = alice], user, new ucA[!1 = alice])).

m4_ifdef({{MAL_RECOVERY}}, {{
(* A-S4R: a browser with no pin that recovers never adopts a u_c the server knows *)
query user: bitstring, userCred: key; event(ClientLoggedIn(new bidR, user, userCred)) && attacker(userCred).

(* A-S3R: recovery on the browser that registered never adopts a u_c the server knows. Without
   the registration user-id check, the reg/verify reply can carry another user id, the browser
   pins that one, and only the words' tag then protects recover3 under the words' user id. *)
query user: bitstring, userCred: key; event(ClientRecovered(new aid, user, userCred)) && attacker(userCred).

(* A-S3R, for a registration whose reg/verify reply carried Alice's own user id. At recover3 the
   browser then compares the u_c it receives with the pk_U it pinned at registration. *)
query alice: sid, ui: bitstring, user: bitstring, userCred: key;
   event(ClientRecovered(new aid[!1 = alice], user, userCred)) && event(Registered(new aid[!1 = alice], ui, ui))
   && attacker(userCred).

(* Reachability of honest recoveries, on the registering browser after a registration whose reply
   carried Alice's own user id, and on a browser with no pin, each ending with Alice's own u_c *)
query user: bitstring, ui: bitstring, alice: sid;
   event(ClientRecovered(new aid[!1 = alice], user, new ucA[!1 = alice])) && event(Registered(new aid[!1 = alice], ui, ui)).
query user: bitstring, alice: sid; event(ClientRecovered(new bidR[!1 = alice], user, new ucA[!1 = alice])).
}})
}})
}})

(* A-T1: a session started from a tagged credential holds the u_c the tag was made from. In
   no-PRF mode this is all the tag gives. *)
query b: bitstring, u: bitstring, x: key, y: key, m: bitstring; event(Adopted(b, u, x, ucid(y), m)) ==> x = y.

(* A-U1: a browser accepts a server reply only with the user id it already holds for the flow *)
query expected: bitstring, actual: bitstring; event(SessionUser(expected, actual)) ==> expected = actual.

(* A passkey Alice creates carries the user id of the session she added it in, or of her
   recovery words *)
query u: bitstring, h: bitstring; event(PasskeyHandle(u, h)) ==> u = h.

process
   !Alice()
m4_ifdef({{PHASED}}, {{
   (* The honest server, until the attacker takes it over in phase 1 *)
   | Server() | (phase 1; out(c, tls); DbDump())
}})
m4_ifdef({{FIRSTUSE}}, {{
   | DbDump()
}})
}})

(* ======================================================================================== *)
(* Expected results, one block per variant. On a reachability query, "is false" means a run
   reaches the events; the README says what each of those traces shows. Every other "is false" is
   an attack the variant exists to show, and ProVerif reconstructed a trace for each one. *)

m4_ifdef({{VARIANT_login_net}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_session}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_session_noproof}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_cdu}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_device}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_device_nouv}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is false.
END *)}})
m4_ifdef({{VARIANT_login_unbound}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) cannot be proved.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) cannot be proved.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu_4,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu_4,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_unbound_trace}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu_4,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu_4,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_tls}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_9,pkU_7)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_9)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_7)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_7)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT event(ServerRegistered(u,ch_9,sig_pk(kdf(ID1,kpU,ucA[!1 = v_13])),pr)) ==> event(RegSigned(u,ch_9,sig_pk(kdf(ID1,kpU,ucA[!1 = v_14])),pr)) is true.
RESULT event(ServerRegistered(u,ch_9,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_13],v_14))))) ==> event(RegSigned(u,ch_9,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_15],v_14))))) is true.
RESULT not attacker(ucA[!1 = v_13]) is true.
END *)}})
m4_ifdef({{VARIANT_login_tls_regsigr_nopku}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_9,pkU_7)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_9)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_7)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_7)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT event(ServerRegistered(u,ch_9,sig_pk(kdf(ID1,kpU,ucA[!1 = v_13])),pr)) ==> event(RegSigned(u,ch_9,sig_pk(kdf(ID1,kpU,ucA[!1 = v_14])),pr)) is true.
RESULT event(ServerRegistered(u,ch_9,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_13],v_14))))) ==> event(RegSigned(u,ch_9,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_15],v_14))))) is false.
RESULT not attacker(ucA[!1 = v_13]) is true.
END *)}})
m4_ifdef({{VARIANT_login_reach}}, {{(* EXPECTPV
RESULT not (event(ServerLogin(user,credId_9,chal_1,pkU_13)) && event(UserApproves(user,credId_9,chal_1))) is false.
RESULT not (event(ServerAccept(user,method,PATH_API,body,nonce,pkU_13)) && event(ClientSigned(user,method,PATH_API,body,nonce))) is false.
RESULT not (event(ServerCredAdded(user,credId_9,credPk_8,pkU_13)) && event(ClientSigned(user,POST,PATH_PKVER,(regr(credId_9,credPk_8,authData,clientData),chal_1,cdp_7,bodyUser),nonce))) is false.
RESULT not event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) is false.
END *)}})
m4_ifdef({{VARIANT_login_log}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_sharedctx}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noapinonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noauthchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noaddchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noapinonce_noaddchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noregchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_net}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_session}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_words}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientRecoverIntent(u,n_3)) is false.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientConfirm(u,ch_10)) is false.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_10])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_10]) is false.
RESULT not attacker(ur[!1 = v_10]) is false.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_tls}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,pkU_7)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is false.
RESULT event(ServerConfirm(u,ch_6,pkU_7)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_6)) is false.
RESULT event(ServerReplaced(u,pk,pkU_7)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_7)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_6]) is true.
RESULT not attacker(ur[!1 = v_6]) is true.
RESULT not attacker(ur2[!2 = v_6,!1 = v_7]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_reach}}, {{(* EXPECTPV
RESULT not (event(ServerReplaced(user,recoveryPk,pkU_13)) && event(ClientReplace(user,recoveryPk))) is false.
RESULT not (event(ServerRecover3(user,nonce,pkU_13)) && event(ClientRecoverIntent(user,nonce))) is false.
RESULT not (event(ServerConfirm(user,chal_1,pkU_13)) && event(ClientConfirm(user,chal_1))) is false.
RESULT not (event(ServerRecovered(user,credId_7,pkU_13)) && event(AliceCredCreated(user,credId_7,credPk_6))) is false.
RESULT not event(ClientRecovered(aid[!1 = alice],user,ucA[!1 = alice])) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_log}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_api}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],REC3,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],API,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_15)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_15)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_18]) is true.
RESULT not attacker(ur[!1 = v_18]) is true.
RESULT not attacker(ur2[!2 = v_18,!1 = v_19]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_api_sharedctx}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],REC3,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_25)) && event(AliceUi(ui_25))) is true.
RESULT not (event(Accepted(c[],API,ui_25)) && event(AliceUi(ui_25))) is false.
RESULT event(ServerRecover3(u,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_15)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_15)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_18]) is true.
RESULT not attacker(ur[!1 = v_18]) is true.
RESULT not attacker(ur2[!2 = v_18,!1 = v_19]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_norecnonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_noconfirmchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_noconfirmchal_nobind}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_norecoverchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_norecoverchal_nobind}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_noapinonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_noreplnonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_noreplnonce_noapinonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_onectx}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_onectx_noreplnonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is false.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_malicious}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_3]) is true.
RESULT not (event(Adopted(b,u,x,t,m)) && attacker(x)) is true.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_3]),PRF0)) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_3],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_3,!1 = v_4],u,x)) && attacker(x)) is true.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_4,ui_4))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_3,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_recovery}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not (event(Adopted(b,u,x,t,m)) && attacker(x)) is true.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_8]),PRF0)) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_8],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_8,!1 = v_9],u,x)) && attacker(x)) is true.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT not (event(ClientLoggedIn(bidR[!2 = v_8,!1 = v_9],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = v_8],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,userCred)) && event(Registered(aid[!1 = alice],ui_6,ui_6)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientRecovered(bidR[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_login_db}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,pkU_15)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_db}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_15)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_15)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_net}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_session}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_session_noproof}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_cdu}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_device}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_device_nouv}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_unbound}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_15,pu_4,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu_4,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_tls}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_9,pkU_7)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_9)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_7)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,pkU_7)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT event(ServerRegistered(u,ch_9,sig_pk(kdf(ID1,kpU,ucA[!1 = v_13])),pr)) ==> event(RegSigned(u,ch_9,sig_pk(kdf(ID1,kpU,ucA[!1 = v_14])),pr)) is false.
RESULT event(ServerRegistered(u,ch_9,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_13],v_14))))) ==> event(RegSigned(u,ch_9,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_15],v_14))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_reach}}, {{(* EXPECTPV
RESULT not (event(ServerLogin(user,credId_9,chal_1,pkU_13)) && event(UserApproves(user,credId_9,chal_1))) is false.
RESULT not (event(ServerAccept(user,method,PATH_API,body,nonce,pkU_13)) && event(ClientSigned(user,method,PATH_API,body,nonce))) is false.
RESULT not (event(ServerCredAdded(user,credId_9,credPk_8,pkU_13)) && event(ClientSigned(user,POST,PATH_PKVER,(regr(credId_9,credPk_8,authData,clientData),chal_1,cdp_4,bodyUser),nonce))) is false.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,x)) && event(AliceUc(aid[!1 = alice],x))) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_log}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_log_noauthchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_db}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_db_kms}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,pkU_15)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,pkU_15)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_db_kmsold}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,pkU_15)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,pkU_15)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_net}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientRecoverIntent(u,n)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_session}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientRecoverIntent(u,n)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_words}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientConfirm(u,ch_10)) is false.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_4,apk,x)) && event(AliceCredCreated(au,aid_4,apk)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT not attacker(ur[!1 = v_10]) is false.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_tls}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n,pkU_7)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_6,pkU_7)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_6)) is false.
RESULT event(ServerReplaced(u,pk,pkU_7)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_7)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT not attacker(ur[!1 = v_6]) is true.
RESULT not attacker(ur2[!2 = v_6,!1 = v_7]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_reach}}, {{(* EXPECTPV
RESULT not (event(ServerReplaced(user,recoveryPk,pkU_13)) && event(ClientReplace(user,recoveryPk))) is false.
RESULT not (event(ServerRecover3(user,nonce,pkU_13)) && event(ClientRecoverIntent(user,nonce))) is false.
RESULT not (event(ServerConfirm(user,chal_1,pkU_13)) && event(ClientConfirm(user,chal_1))) is false.
RESULT not (event(ServerRecovered(user,credId_7,pkU_13)) && event(AliceCredCreated(user,credId_7,credPk_6))) is false.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,x)) && event(AliceUc(aid[!1 = alice],x))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_log}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_log_norecnonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT event(ServerRecover3(u,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is false.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_log_noconfirmchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_log_noconfirmchal_nobind}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_log_onectx_noreplnonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT event(ServerRecover3(u,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is false.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_malicious_noprf}}, {{(* EXPECTPV
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_login_db_chal}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_16,pkU_15)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_16)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_16,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_16,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_16,pu_1,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_16,pu_1,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_db_chal}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_11,pkU_15)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_11)) is true.
RESULT event(ServerReplaced(u,pk,pkU_15)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_login_tls_dualmode}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_10,pkU_8)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_10)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_8)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_8)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT event(ServerRegistered(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_13])),pr)) ==> event(RegSigned(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_14])),pr)) is true.
RESULT event(ServerRegistered(u,ch_10,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_13],v_14))))) ==> event(RegSigned(u,ch_10,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_15],v_14))))) is true.
RESULT not attacker(ucA[!1 = v_13]) is true.
RESULT not (event(AliceUi(u)) && event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_tls_stripped}}, {{(* EXPECTPV
RESULT not (event(SignedInWith(b,u,id,ch_7,ck_2,x)) && event(ServerReplyUc(u,id,ch_7,ck_2,x)) && event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_tls_stripped_nohandletag}}, {{(* EXPECTPV
RESULT not (event(SignedInWith(b,u,id,ch_7,ck_2,x)) && event(ServerReplyUc(u,id,ch_7,ck_2,x)) && event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_db_chalrec}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_11,pkU_15)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_11)) is true.
RESULT event(ServerReplaced(u,pk,pkU_15)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_log_noregver}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_13)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_noconfirmchal_nobind_noproof}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_norecoverchal_nobind_noproof}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT event(ServerRecover3(u,n_3,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_log_noconfirmchal_nobind_noproof}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT event(ServerRecover3(u,n,pkU_13)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_10,pkU_13)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is false.
RESULT event(ServerReplaced(u,pk,pkU_13)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_13)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_login_db_chal_noregbind}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_16,pkU_15)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_16)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT event(ServerRegistered(u,ch_16,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_16,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_16,pu_1,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_16,pu_1,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_db_chal_noregsigu}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_16,pkU_15)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_16)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_16,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_16,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is false.
RESULT event(ServerRegistered(u,ch_16,pu_1,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_16,pu_1,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_db_noregsigr}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,pkU_15)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT event(ServerRegistered(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])),pr)) ==> event(RegSigned(u,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_26])),pr)) is true.
RESULT event(ServerRegistered(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_25],v_26))))) ==> event(RegSigned(u,ch_15,pu,sig_pk(kdf(ID1,kpR,rsec(ur[!1 = v_27],v_26))))) is false.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_db_chalrec_norecverifyproof}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,pkU_15)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_11,pkU_15)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_11)) is true.
RESULT event(ServerReplaced(u,pk,pkU_15)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_db_chalrec}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n,pkU_15)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is true.
RESULT event(ServerConfirm(u,ch_11,pkU_15)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_11)) is true.
RESULT event(ServerReplaced(u,pk,pkU_15)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_db_chalrec_norecverifyproof}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n,pkU_15)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_11,pkU_15)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_11)) is false.
RESULT event(ServerReplaced(u,pk,pkU_15)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_15)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_malicious_nohandletag}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_3]) is true.
RESULT not (event(Adopted(b,u,x,t,m)) && attacker(x)) is false.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_3]),PRF0)) is false.
RESULT not (event(ClientLoggedIn(aid[!1 = v_3],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_3,!1 = v_4],u,x)) && attacker(x)) is false.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_4,ui_4))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_3,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is false.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_noprf_nohandletag}}, {{(* EXPECTPV
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is false.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_recovery_nowordstag}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not (event(Adopted(b,u,x,t,m)) && attacker(x)) is false.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_8]),PRF0)) is false.
RESULT not (event(ClientLoggedIn(aid[!1 = v_8],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_8,!1 = v_9],u,x)) && attacker(x)) is false.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT not (event(ClientLoggedIn(bidR[!2 = v_8,!1 = v_9],user,userCred)) && attacker(userCred)) is false.
RESULT not (event(ClientRecovered(aid[!1 = v_8],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,userCred)) && event(Registered(aid[!1 = alice],ui_6,ui_6)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientRecovered(bidR[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is false.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_recovery_serverhandle}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not (event(Adopted(b,u,x,t,m)) && attacker(x)) is true.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_8]),PRF0)) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_8],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_8,!1 = v_9],u,x)) && attacker(x)) is true.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT not (event(ClientLoggedIn(bidR[!2 = v_8,!1 = v_9],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = v_8],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,userCred)) && event(Registered(aid[!1 = alice],ui_6,ui_6)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientRecovered(bidR[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is false.
END *)}})
m4_ifdef({{VARIANT_malicious_nouicheck_login}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_3]) is true.
RESULT not (event(Adopted(b,u,x,t,m)) && attacker(x)) is true.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_3]),PRF0)) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_3],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_3,!1 = v_4],u,x)) && attacker(x)) is true.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_4,ui_4))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_3,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_recovery_nouicheck_reg}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not (event(Adopted(b,u,x,t,m)) && attacker(x)) is true.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_8]),PRF0)) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_8],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_8,!1 = v_9],u,x)) && attacker(x)) is true.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT not (event(ClientLoggedIn(bidR[!2 = v_8,!1 = v_9],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = v_8],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,userCred)) && event(Registered(aid[!1 = alice],ui_6,ui_6)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientRecovered(bidR[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is false.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_recovery_nouicheck_recoververify}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not (event(Adopted(b,u,x,t,m)) && attacker(x)) is true.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_8]),PRF0)) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_8],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_8,!1 = v_9],u,x)) && attacker(x)) is true.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT not (event(ClientLoggedIn(bidR[!2 = v_8,!1 = v_9],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = v_8],user,userCred)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,userCred)) && event(Registered(aid[!1 = alice],ui_6,ui_6)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientRecovered(bidR[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is false.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_twoaccounts}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_4]) is true.
RESULT not attacker(ucB[!1 = v_4]) is true.
RESULT not event(Reauthenticated(aid[!1 = alice],u,ucA[!1 = alice])) is false.
RESULT not event(Reauthenticated(aid[!1 = alice],u,ucB[!1 = alice])) is false.
RESULT not event(Reauthenticated(bidF[!2 = v_4,!1 = alice],u,ucA[!1 = alice])) is false.
RESULT not (event(Adopted(b,u,x,t,m_2)) && attacker(x)) is true.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_4]),PRF0)) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_4],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_4,!1 = v_5],u,x)) && attacker(x)) is true.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_7,ui_7))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_4,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m_2)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_twoaccounts_nouicheck_reauth}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_4]) is true.
RESULT not attacker(ucB[!1 = v_4]) is true.
RESULT not event(Reauthenticated(aid[!1 = alice],u,ucA[!1 = alice])) is false.
RESULT not event(Reauthenticated(aid[!1 = alice],u,ucB[!1 = alice])) is false.
RESULT not event(Reauthenticated(bidF[!2 = v_4,!1 = alice],u,ucA[!1 = alice])) is false.
RESULT not (event(Adopted(b,u,x,t,m_2)) && attacker(x)) is true.
RESULT not event(Adopted(b,u,x,ucid(ucA[!1 = v_4]),PRF0)) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_4],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_4,!1 = v_5],u,x)) && attacker(x)) is true.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_7,ui_7))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_4,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m_2)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is false.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_existing}}, {{(* EXPECTPV
RESULT not attacker_p1(ucA[!1 = v_35]) is true.
RESULT not (event(Adopted(b,u,x,ucid(ucA[!1 = v_35]),m_2)) && attacker_p1(x)) is true.
RESULT not (event(Adopted(b,u,x,NOTAG,m_2)) && attacker_p1(x)) is false.
RESULT not (event(ClientLoggedIn(aid[!1 = v_35],u,x)) && attacker_p1(x)) is true.
RESULT not event(Adopted(bidF0[!2 = v_35,!1 = alice],u,ucA[!1 = alice],NOTAG,m_2)) is false.
RESULT not event(Adopted(bidF[!2 = v_35,!1 = alice],u,ucA[!1 = alice],ucid(ucA[!1 = alice]),m_2)) is false.
RESULT not event(Adopted(bidR[!2 = v_35,!1 = alice],u,ucA[!1 = alice],ucid(ucA[!1 = alice]),m_2)) is false.
RESULT not event(Adopted(bidR[!2 = v_35,!1 = alice],u,ucA[!1 = alice],NOTAG,m_2)) is false.
RESULT not event(ClientRecovered(aid[!1 = alice],u,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m_2)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_existing_nohandletag}}, {{(* EXPECTPV
RESULT not attacker_p1(ucA[!1 = v_35]) is true.
RESULT not (event(Adopted(b,u,x,ucid(ucA[!1 = v_35]),m_2)) && attacker_p1(x)) is false.
RESULT not (event(Adopted(b,u,x,NOTAG,m_2)) && attacker_p1(x)) is false.
RESULT not (event(ClientLoggedIn(aid[!1 = v_35],u,x)) && attacker_p1(x)) is true.
RESULT not event(Adopted(bidF0[!2 = v_35,!1 = alice],u,ucA[!1 = alice],NOTAG,m_2)) is false.
RESULT not event(Adopted(bidF[!2 = v_35,!1 = alice],u,ucA[!1 = alice],ucid(ucA[!1 = alice]),m_2)) is false.
RESULT not event(Adopted(bidR[!2 = v_35,!1 = alice],u,ucA[!1 = alice],ucid(ucA[!1 = alice]),m_2)) is false.
RESULT not event(Adopted(bidR[!2 = v_35,!1 = alice],u,ucA[!1 = alice],NOTAG,m_2)) is false.
RESULT not event(ClientRecovered(aid[!1 = alice],u,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m_2)) ==> x = y is false.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_existing_nowordstag}}, {{(* EXPECTPV
RESULT not attacker_p1(ucA[!1 = v_35]) is true.
RESULT not (event(Adopted(b,u,x,ucid(ucA[!1 = v_35]),m_2)) && attacker_p1(x)) is false.
RESULT not (event(Adopted(b,u,x,NOTAG,m_2)) && attacker_p1(x)) is false.
RESULT not (event(ClientLoggedIn(aid[!1 = v_35],u,x)) && attacker_p1(x)) is true.
RESULT not event(Adopted(bidF0[!2 = v_35,!1 = alice],u,ucA[!1 = alice],NOTAG,m_2)) is false.
RESULT not event(Adopted(bidF[!2 = v_35,!1 = alice],u,ucA[!1 = alice],ucid(ucA[!1 = alice]),m_2)) is false.
RESULT not event(Adopted(bidR[!2 = v_35,!1 = alice],u,ucA[!1 = alice],ucid(ucA[!1 = alice]),m_2)) is false.
RESULT not event(Adopted(bidR[!2 = v_35,!1 = alice],u,ucA[!1 = alice],NOTAG,m_2)) is false.
RESULT not event(ClientRecovered(aid[!1 = alice],u,ucA[!1 = alice])) is false.
RESULT event(Adopted(b,u,x,ucid(y),m_2)) ==> x = y is false.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_existing_noprf}}, {{(* EXPECTPV
RESULT not (event(AliceUc(a,x)) && attacker_p1(x)) is false.
RESULT event(Adopted(b,u,x,ucid(y),m)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_existing_firstuse}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not (event(Adopted(b,u,x,ucid(ucA[!1 = v_8]),m_2)) && attacker(x)) is true.
RESULT not (event(Adopted(b,u,x,NOTAG,m_2)) && attacker(x)) is false.
RESULT not (event(Adopted(b,u,x,ucid(y),m_2)) && attacker(x)) is false.
RESULT not (event(ClientLoggedIn(aid[!1 = v_8],u,x)) && attacker(x)) is true.
RESULT event(Adopted(b,u,x,ucid(y),m_2)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is true.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
m4_ifdef({{VARIANT_malicious_existing_firstuse_nouicheck_login}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_3]) is true.
RESULT not (event(Adopted(b,u,x,ucid(ucA[!1 = v_3]),m_2)) && attacker(x)) is true.
RESULT not (event(Adopted(b,u,x,NOTAG,m_2)) && attacker(x)) is false.
RESULT not (event(Adopted(b,u,x,ucid(y),m_2)) && attacker(x)) is false.
RESULT not (event(ClientLoggedIn(aid[!1 = v_3],u,x)) && attacker(x)) is false.
RESULT event(Adopted(b,u,x,ucid(y),m_2)) ==> x = y is true.
RESULT event(SessionUser(expected,actual)) ==> expected = actual is false.
RESULT event(PasskeyHandle(u,h)) ==> u = h is true.
END *)}})
