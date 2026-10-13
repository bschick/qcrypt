m4_changequote({{,}})m4_dnl
(* Quick Crypt accounts, with an honest or a malicious server: the main.tex stanzas from u_c
   Encryption at Rest Variables through Recovery from Lost Passkey by A. Accounts are in PRF
   mode, or in no-PRF mode with NOPRF, where Alice's authenticator has no PRF and the server
   draws and keeps u_c.

   Each honest user (Alice) registers once from her browser, then logs in with any passkey she
   holds, sends authorized requests, adds passkeys, replaces her recovery words, and recovers.
   The server keeps its state in tables, which in ProVerif can only grow. So deletions are not
   modeled: old passkeys and recovery keys stay usable, which only helps the attacker.
   Single-use challenges, replay nonces and authCount values are uniqueness restrictions; they
   stand for the atomic DynamoDB delete-on-read in consumeChallenge (sutil:86-111), the
   conditional put in storeSingleUseNonce (sutil:162-176) and the atomic add in
   _setLastCredential (srv:245-265). Timestamps and the skew window are not modeled.

   TLS is a private channel, with a fresh reply channel per request. Every server handler also
   runs on the public channel, where the attacker is a client like any other and names its own
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
     login-reach          SCN_LOGIN REACH_ONLY RCV STORE UNIQUSER NOBT
     login-log            SCN_LOGIN LEAK_LOG KEY_UI STORE
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
     login-noprf-log      SCN_LOGIN NOPRF LEAK_LOG KEY_UI STORE
     login-noprf-log-noauthchal  SCN_LOGIN NOPRF LEAK_LOG KEY_UI STORE MUT_NOSTORE_PAUTH RCV UNIQUSER NOBT
     login-noprf-db       SCN_LOGIN NOPRF LEAK_DB
     login-noprf-db-kms   SCN_LOGIN NOPRF LEAK_DB LEAK_KMS_NEW
     login-noprf-db-kmsold  SCN_LOGIN NOPRF LEAK_DB LEAK_KMS_OLD
     recovery-noprf-net   SCN_RECOVERY NOPRF
     recovery-noprf-session  SCN_RECOVERY NOPRF LEAK_SESSION
     recovery-noprf-words  SCN_RECOVERY NOPRF LEAK_WORDS RCV STORE UNIQUSER NOBT PRECISE
     recovery-noprf-tls   SCN_RECOVERY NOPRF LEAK_TLS KEY_UI STORE UNIQUSER NOBT PRECISE
     recovery-noprf-reach  SCN_RECOVERY NOPRF REACH_ONLY RCV STORE UNIQUSER NOBT PRECISE
     recovery-noprf-log   SCN_RECOVERY NOPRF LEAK_LOG KEY_UI STORE
     recovery-noprf-log-norecnonce  SCN_RECOVERY NOPRF LEAK_LOG KEY_UI STORE MUT_NOSTORE_NREC RCV UNIQUSER NOBT PRECISE
     recovery-noprf-log-noconfirmchal  SCN_RECOVERY NOPRF LEAK_LOG KEY_UI STORE MUT_NOSTORE_PCONFIRM RCV UNIQUSER NOBT PRECISE
     recovery-noprf-log-noconfirmchal-nobind  SCN_RECOVERY NOPRF LEAK_LOG KEY_UI STORE MUT_NOSTORE_PCONFIRM MUT_NOBIND RCV UNIQUSER NOBT PRECISE
     malicious-noprf      SCN_MALICIOUS NOPRF
     login-db-chal        SCN_LOGIN LEAK_DB LEAK_CHAL KEY_UI STORE UNIQUSER NOBT
     recovery-db-chal     SCN_RECOVERY LEAK_DB LEAK_CHAL KEY_UI STORE UNIQUSER NOBT
     login-tls-dualmode   SCN_LOGIN LEAK_TLS KEY_UI DUALMODE STORE UNIQUSER NOBT
     recovery-db-chalrec  SCN_RECOVERY LEAK_DB LEAK_CHAL_RECOVER KEY_UI STORE UNIQUSER NOBT
     login-tls-stripped   SCN_LOGIN LEAK_TLS KEY_UI DUALMODE STORE UNIQUSER NOBT STRIPLOGIN
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
   channel and learns every reply channel from the requests. *)
m4_ifdef({{LEAK_TLS}}, {{m4_define({{TLS_PUBLIC}})}})
m4_ifdef({{SCN_MALICIOUS}}, {{m4_define({{TLS_PUBLIC}})}})
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
const PATH_API, PATH_PKOPT, PATH_PKVER, PATH_REPLACE, PATH_CONFIRM: bitstring [data].
const PREG, PADD, PAUTH, PCONFIRM, PRECOVER: bitstring [data].

(* Replay-nonce namespaces: 'api' for authorized requests, 'nonce' for both recovery proofs *)
const NAPI, NREC: bitstring [data].

(* Recovery signature contexts: sc_R, sc_W. The code also accepts a legacy context for both,
   which no client creates; it is treated as removed (I-04). *)
const SCR, SCW: bitstring [data].

(* m_R = u_i, n_P; the timestamp is not modeled *)
fun mrc(bitstring, bitstring): bitstring [data].
const UNKNOWN, NOBIND: bitstring [data].
const PRF0, PRF1: bitstring [data].
const ORIGIN, RPID, UV0, UV1, WA_CREATE, WA_GET: bitstring [data].
const SLOT: bitstring [data].

(* p_S, the fixed PRF salt, and the proof signature context sc_U *)
const PS: bitstring [data].
const SCU: bitstring [data].

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

(* KMS (srv:152-198): encryption under a key only the server's role can use, with the user id
   as encryption context. A no-PRF account keeps u_c under a main and a backup key. *)
fun kms_enc(key, bitstring, key): bitstring.
reduc forall k: key, ctx: bitstring, m: key; kms_dec(k, ctx, kms_enc(k, ctx, m)) = m.
free kmsNew, kmsOld: key [private].

(* ---------------------------------------------------------------------------------------- *)
(* State *)

(* Server *)
table unverified(bitstring).
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

(* Registration completed in a browser: the user id in the options, and the user id the
   reg/verify reply named *)
event Registered(bitstring, bitstring, bitstring).

(* No-PRF: the u_c the server drew at a registration, with the user id, credential id and
   passkey public key it registered; and the u_c Alice's browser received in the reply *)
event ServerUc(bitstring, bitstring, bitstring, key).
event AliceUc(bitstring, key).

(* A passkey Alice added in a session: the session's user id, and the passkey's user handle *)
event PasskeyHandle(bitstring, bitstring).

m4_ifdef({{STRIPLOGIN}}, {{
(* A browser sign-in that passed the pin checks: browser, the user id the server named, the
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
   are not logged, since repeating one is allowed. The copies carry cookies, CSRF tokens and
   pk_U, which is why these variants use KEY_UI.

   A-N1: the attacker cannot produce Alice's signatures or passkey assertions, so her account
   accepts a request on the public channel only when a logged request is used again, at the
   same endpoint or another. One query per request type shows which endpoint a mutation opens. *)
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

(* POST reg/options: a new unverified user and a challenge bound to it (srv:807-936) *)
let SRegOptions(net: channel) =
   new ui: bitstring; new ch: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   if req = REGOPT then
   insert unverified(ui);
   insert chal(PREG, ch, ui, NOBIND);
   out(rc, (ch, ui)).

(* POST reg/verify for a PRF registration, which carries pk_U, cd_p and cd_r (srv:422-564,
   608-691) *)
let SRegVerify(net: channel) =
   new st: bitstring; new sid: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel))PREC_STRIP;
   RECEIVED
   let (=REGVER, rr: bitstring, ui: bitstring, ch: bitstring, pkR: bitstring, pkU: bitstring, cdp: bitstring, cdr: bitstring) = req in
   get unverified(=ui) in
   get users(=ui, pkU0: bitstring) in 0 else
m4_ifdef({{MUT_UNBOUND}}, {{
   get chal(pu: bitstring, =ch, cu: bitstring, bnd: bitstring) in
   event Consumed(pu, ch, st);
}}, {{
   get chal(=PREG, =ch, =ui, =NOBIND) in
   event Consumed(PREG, ch, st);
}})
   let regr(credId: bitstring, credPk: bitstring, adata(=RPID, =UV1), cdj(=WA_CREATE, =ch, =ORIGIN)) = rr in
   event UserCreated(ui, st);
   insert users(ui, pkU);
   insert recov(ui, pkR, cdr);
   insert creds(ui, credId, credPk, cdp);
   event ServerCredAdded(ui, credId, credPk, pkU);
   LOGGED(REGVER, ui)
m4_ifdef({{DUALMODE}}, {{
   out(rc, (ui, PRF1, EMPTY, cookie(ui, sid), csmac(skJWT, ui, sid))).
}}, {{
   out(rc, (ui, cookie(ui, sid), csmac(skJWT, ui, sid))).
}})

(* POST reg/verify for a no-PRF registration, which carries none of them. The server draws u_c,
   keeps it under both KMS keys, and returns it in the reply (srv:475-490, srv:556). The server
   picks the mode from which fields the request carries (srv:438). *)
let SRegVerifyNoPrf(net: channel) =
   new st: bitstring; new sid: bitstring;
   new rq: bitstring;
   new ucS: key;
   in(net, (req: bitstring, rc: channel))PREC_STRIP;
   RECEIVED
   let (=REGVER, rr: bitstring, ui: bitstring, ch: bitstring, pkR: bitstring) = req in
   get unverified(=ui) in
   get users(=ui, pkU0: bitstring) in 0 else
m4_ifdef({{MUT_UNBOUND}}, {{
   get chal(pu: bitstring, =ch, cu: bitstring, bnd: bitstring) in
   event Consumed(pu, ch, st);
}}, {{
   get chal(=PREG, =ch, =ui, =NOBIND) in
   event Consumed(PREG, ch, st);
}})
   let regr(credId: bitstring, credPk: bitstring, adata(=RPID, =UV1), cdj(=WA_CREATE, =ch, =ORIGIN)) = rr in
   event UserCreated(ui, st);
   let pkU = sig_pk(proofKey(ucS)) in
   insert users(ui, pkU);
   insert ucenc(ui, kms_enc(kmsNew, ui, ucS), kms_enc(kmsOld, ui, ucS));
   insert recov(ui, pkR, EMPTY);
   insert creds(ui, credId, credPk, EMPTY);
   event ServerUc(ui, credId, credPk, ucS);
   event ServerCredAdded(ui, credId, credPk, pkU);
   LOGGED(REGVER, ui)
   out(rc, (ui, PRF0, key2bs(ucS), cookie(ui, sid), csmac(skJWT, ui, sid))).

(* POST auth/options: an auth challenge, bound to a user only if one was named (srv:727-795) *)
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

(* Cookie, CSRF, and proof checks for every authorized request (srv:1826-1836, 1737-1791). The
   caller has taken u_i from the cookie and looked up its pk_U. Non-GET nonces are made single
   use by the caller. *)
letfun authorized(ck: bitstring, cs: bitstring, pkU: bitstring, mth: bitstring, pth: bitstring, bd: bitstring, nP: bitstring, sig: bitstring) =
   let (ui: bitstring, sid: bitstring, tag: bitstring) = ck in
m4_ifdef({{MUT_NOPROOF}}, {{
   (* MUTATION: the cookie and CSRF token are enough *)
   tag = ckmac(skJWT, ui, sid) && cs = csmac(skJWT, ui, sid).
}}, {{
   tag = ckmac(skJWT, ui, sid) && cs = csmac(skJWT, ui, sid) &&
   sig_verify(pkU, muc(ui, mth, pth, nP, sha256(bd)), sig, SCU).
}})

letfun cookieUser(ck: bitstring) = let (ui: bitstring, sid: bitstring, tag: bitstring) = ck in ui.

(* Any authorized endpoint, as an opaque method, path and body *)
let SApi(net: channel) =
   new st: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=API, ck: bitstring, cs: bitstring, mth: bitstring, pth: bitstring, bd: bitstring, nP: bitstring, sig: bitstring) = req in
   let ui = cookieUser(ck) in
   get users(=ui, pkU: bitstring) in
   if authorized(ck, cs, pkU, mth, pth, bd, nP, sig) then
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
   if authorized(ck, cs, pkU, GET, PATH_PKOPT, EMPTY, nP, sig) then
   event ServerAccept(ui, GET, PATH_PKOPT, EMPTY, nP, pkU);
   insert chal(PADD, ch, ui, NOBIND);
   (* Registration options, whose user.id becomes the new passkey's user handle *)
   out(rc, (ch, ui)).

(* POST passkeys/verify, authorized. The user is the session's, never the body's (srv:398-420). *)
let SPasskeyVerify(net: channel) =
   new st0: bitstring; new st: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=PKVER, ck: bitstring, cs: bitstring, nP: bitstring, sig: bitstring, bd: bitstring) = req in
   let (rr: bitstring, ch: bitstring, cdp: bitstring, bui: bitstring) = bd in
   let sui = cookieUser(ck) in
   get users(=sui, pkU: bitstring) in
   if authorized(ck, cs, pkU, POST, PATH_PKVER, bd, nP, sig) then
   event ServerAccept(sui, POST, PATH_PKVER, bd, nP, pkU);
   event NonceStored(NAPI, nP, st0);
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
   get chal(=PADD, =ch, =ui, =NOBIND) in
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
   if authorized(ck, cs, pkU, PUT, PATH_REPLACE, bd, nP, sig) then
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

(* POST recover/confirm: a userCred proof over ch_R, then a registration challenge
   (srv:1514-1585) *)
let SRecoverConfirm(net: channel) =
   new st: bitstring; new ch: bitstring; new st2: bitstring; new cnt: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=CONFIRM, ui: bitstring, chR: bitstring, sigU: bitstring) = req in
   get chal(=PCONFIRM, =chR, =ui, bnd: bitstring) in
   event Consumed(PCONFIRM, chR, st);
   get users(=ui, pkU: bitstring) in
   if sig_verify(pkU, muc(ui, POST, PATH_CONFIRM, chR, sha256(EMPTY)), sigU, SCU) then
   let (pkRb: bitstring, cntb: bitstring) = bnd in
m4_ifdef({{MUT_NOBIND}}, {{
   (* MUTATION: the binding is not compared *)
}}, {{
   (* The binding check and the increment, as one step (srv:1537, srv:1581) *)
   event Incremented(cntb, st2);
}})
   event ServerConfirm(ui, chR, pkU);
   LOGGED(CONFIRM, ui)
   insert chal(PRECOVER, ch, ui, (pkRb, cnt));
   (* Registration options, whose user.id becomes the new passkey's user handle *)
   out(rc, (ch, ui)).

(* POST recover/verify: the new passkey (srv:566-606, 608-691). The check for an empty
   lastCredentialId (srv:573) is left out: the write that sets it also increments authCount
   (srv:245-265), so it fails only where the binding check already fails. *)
let SRecoverVerify(net: channel) =
   new st: bitstring; new sid: bitstring; new st2: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=RECVER, rr: bitstring, ui: bitstring, ch: bitstring, cdp: bitstring) = req in
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF account takes no cd_p (srv:582-584) *)
   if cdp = EMPTY then
}})
   get chal(=PRECOVER, =ch, =ui, bnd: bitstring) in
   event Consumed(PRECOVER, ch, st);
   let regr(credId: bitstring, credPk: bitstring, adata(=RPID, =UV1), cdj(=WA_CREATE, =ch, =ORIGIN)) = rr in
   let (pkRb: bitstring, cntb: bitstring) = bnd in
m4_ifdef({{MUT_NOBIND}}, {{
   (* MUTATION: the binding is not compared *)
}}, {{
   (* The binding check and the increment, as one step (srv:630-634, srv:588) *)
   event Incremented(cntb, st2);
}})
   get users(=ui, pkU: bitstring) in
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
m4_ifdef({{SCN_RECOVERY}}, {{
let Endpoints(net: channel) =
   !SRegOptions(net) | REGVERIFY | !SReplaceWords(net) | !SRecover3(net) | !SRecoverConfirm(net) |
   !SRecoverVerify(net).
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

table passkeys(bitstring, bitstring, bitstring, key).
(* Browser, the user id in the registration options, and the user id the reg/verify reply named,
   which is the one registration pinned *)
table registered(bitstring, bitstring, bitstring).
table words(bitstring, bitstring, bitstring).
table sessions(bitstring, bitstring, bitstring, key, bitstring, bitstring, bitstring).

(* A signed authorized request, as _doFetch builds it (auth:385-459) *)
letfun mkProof(uc: key, ui: bitstring, mth: bitstring, pth: bitstring, bd: bitstring, nP: bitstring, r: bitstring) =
   sig_sign(proofKey(uc), muc(ui, mth, pth, nP, sha256(bd)), SCU, r).

(* Records a signed-in browser session. k_KS is replaced at every login (auth:755), and cd_u
   is u_c under k_L. *)
let StartSession(aid: bitstring, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring, kKS: key, nS: bitstring) =
   insert sessions(aid, bid, ui, uc, pkId, ck, cs);
   event ClientLoggedIn(bid, ui, uc);
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

(* addPasskey (auth:1565-1604). The authenticator keeps the passkey once created. Its user handle
   is the user.id in the passkeys/options reply (auth:1576), which the browser never compares
   with the session's user id (I-01). *)
let AddPasskey(aid: bitstring) =
   !new nP1: bitstring; new r1: bitstring; new rc1: channel;
   new credKey: key; new credId: bitstring; new nS: bitstring;
   new nP2: bitstring; new r2: bitstring; new rc2: channel;
   get sessions(=aid, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring) in
   event ClientSigned(ui, GET, PATH_PKOPT, EMPTY, nP1);
   out(tls, ((PKOPT, ck, cs, nP1, mkProof(uc, ui, GET, PATH_PKOPT, EMPTY, nP1, r1)), rc1));
   in(rc1, (ch: bitstring, hui: bitstring));
   let credPk = wa_pk(credKey) in
   event AliceCredCreated(ui, credId, credPk);
   event PasskeyHandle(ui, hui);
   insert passkeys(aid, hui, credId, credKey);
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF account sends no cd_p (auth:1575-1598) *)
   let bd = (rr, ch, EMPTY, ui) in
}}, {{
   let bd = (rr, ch, mkAtRest(wa_prf(credKey, PS), ui, nS, key2bs(uc)), ui) in
}})
   event ClientSigned(ui, POST, PATH_PKVER, bd, nP2);
   out(tls, ((PKVER, ck, cs, nP2, mkProof(uc, ui, POST, PATH_PKVER, bd, nP2, r2), bd), rc2));
   in(rc2, resp: bitstring).

(* Sign in from browser bid with the given passkey (auth:1256-1338, 701-785) *)
let LoginWith(aid: bitstring, bid: bitstring, ui: bitstring, credId: bitstring, credKey: key, rc1: channel, rc2: channel, kKS: key, nS: bitstring) =
   out(tls, ((AUTHOPT, UNKNOWN), rc1));
   in(rc1, ch: bitstring);
   event UserApproves(ui, credId, ch);
   let ad = adata(RPID, UV1) in
   let cd = cdj(WA_GET, ch, ORIGIN) in
   out(tls, ((AUTHVER, credId, ui, ad, cd, wa_sign(credKey, (ad, cd)), ch), rc2));
   in(rc2, (sui: bitstring, sprf: bitstring, spkId: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
   (* _checkAccountPinPrf, then _resolveUserCred: a PRF account sends cd_p, a no-PRF account
      sends u_c itself. Then _pinAccount. *)
   get pins(=bid, =sui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
   let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
   get pins(=bid, =sui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
   insert pins(bid, sui, sprf, sig_pk(proofKey(uc)));
m4_ifdef({{STRIPLOGIN}}, {{   event SignedInWith(bid, sui, credId, ch, ck, uc);}})
   event ClientSignedIn(bid, sui, uc);
   StartSession(aid, bid, sui, uc, spkId, ck, cs, kKS, nS).

(* Sign in from browser bid, at any time, with any passkey Alice holds *)
let Login(aid: bitstring, bid: bitstring) =
   new rc1: channel; new rc2: channel; new kKS: key; new nS: bitstring;
   get passkeys(=aid, ui: bitstring, credId: bitstring, credKey: key) in
   LoginWith(aid, bid, ui, credId, credKey, rc1, rc2, kKS, nS).

(* Sign in from the browser that registered, once registration has completed there. When the
   server names the account registration pinned, the pin checks read that pin with a positive
   lookup, which drops no run because the pin exists from registration on. That lookup is what
   lets A-S3R be proved for a registration that pinned Alice's own user id: ProVerif treats the
   "no entry" branch of a negative lookup as always possible, and through it a sign-in could pin
   a u_c the server chose under that user id. When the server names another account, the checks
   are the code's negative lookups. *)
let LoginRegistered(aid: bitstring) =
   new rc1: channel; new rc2: channel; new kKS: key; new nS: bitstring;
   get registered(=aid, ui: bitstring, rui: bitstring) in
   get passkeys(=aid, =ui, credId: bitstring, credKey: key) in
   out(tls, ((AUTHOPT, UNKNOWN), rc1));
   in(rc1, ch: bitstring);
   event UserApproves(ui, credId, ch);
   let ad = adata(RPID, UV1) in
   let cd = cdj(WA_GET, ch, ORIGIN) in
   out(tls, ((AUTHVER, credId, ui, ad, cd, wa_sign(credKey, (ad, cd)), ch), rc2));
   in(rc2, (sui: bitstring, sprf: bitstring, spkId: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
   (* _checkAccountPinPrf, then _resolveUserCred: a PRF account sends cd_p, a no-PRF account
      sends u_c itself. Then _pinAccount. *)
   if sui = rui then (
      get pins(=aid, =rui, pprf: bitstring, ppk: bitstring) in
      if pprf = PRF1 && sprf = PRF0 then 0 else
      let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
      if ppk = sig_pk(proofKey(uc)) then
      insert pins(aid, rui, sprf, sig_pk(proofKey(uc)));
      event ClientSignedIn(aid, rui, uc);
      StartSession(aid, aid, rui, uc, spkId, ck, cs, kKS, nS)
   ) else (
      get pins(=aid, =sui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
      let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
      get pins(=aid, =sui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
      insert pins(aid, sui, sprf, sig_pk(proofKey(uc)));
      event ClientSignedIn(aid, sui, uc);
      StartSession(aid, aid, sui, uc, spkId, ck, cs, kKS, nS)
   ).

(* The rest of a recovery, once the u_c from recover3 has passed the browser's pin checks under
   the words' u_i: recover/confirm, the new passkey, and recover/verify *)
let FinishRecovery(aid: bitstring, bid: bitstring, ui: bitstring, uc: key, sprf: bitstring, chR: bitstring,
                   r2: bitstring, credKey: key, credId: bitstring, nS: bitstring, rc2: channel, rc3: channel,
                   kKS: key, nS2: bitstring) =
   insert pins(bid, ui, sprf, sig_pk(proofKey(uc)));
   event ClientConfirm(ui, chR);
   out(tls, ((CONFIRM, ui, chR, sig_sign(proofKey(uc), muc(ui, POST, PATH_CONFIRM, chR, sha256(EMPTY)), SCU, r2)), rc2));
   (* Registration options. Their user.id becomes the new passkey's user handle (auth:1610). *)
   in(rc2, (ch: bitstring, hui: bitstring));
   let credPk = wa_pk(credKey) in
   event AliceCredCreated(ui, credId, credPk);
   insert passkeys(aid, hui, credId, credKey);
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
   (* cd_p is sent only for a PRF account (auth:1470-1477) *)
   let cdp = (if sprf = PRF1 then mkAtRest(wa_prf(credKey, PS), ui, nS, key2bs(uc)) else EMPTY) in
   out(tls, ((RECVER, rr, ui, ch, cdp), rc3));
m4_ifdef({{NOPRF}}, {{
   (* The browser does not read the u_c a no-PRF reply also carries (auth:1485-1488) *)
   in(rc3, (sui: bitstring, sprf2: bitstring, ck: bitstring, cs: bitstring, sdata2: bitstring)) [precise];
}}, {{
   in(rc3, (sui: bitstring, sprf2: bitstring, ck: bitstring, cs: bitstring)) [precise];
}})
   (* The browser reads prf as a boolean (auth:290-311), so the mode it pins is one of the two.
      [precise] keeps that constraint from breaking trace reconstruction. *)
   if sprf2 = PRF0 || sprf2 = PRF1 then
   (* The account-mode pin check under the words' u_i (auth:1486), then _loginUser, which pins
      under the server's u_i (auth:1488, auth:302-311) *)
   get pins(=bid, =ui, =PRF1, ppk2: bitstring) suchthat sprf2 = PRF0 in 0 else
   get pins(=bid, =sui, =PRF1, ppk3: bitstring) suchthat sprf2 = PRF0 in 0 else
   get pins(=bid, =sui, pprf4: bitstring, ppk4: bitstring) suchthat ppk4 <> sig_pk(proofKey(uc)) in 0 else
   insert pins(bid, sui, sprf2, sig_pk(proofKey(uc)));
   event ClientRecovered(bid, sui, uc);
   StartSession(aid, bid, sui, uc, credId, ck, cs, kKS, nS2).

(* recover3, recover/confirm, then recover/verify with a new passkey (auth:1340-1495), using
   any recovery words Alice has written down *)
let Recovery(aid: bitstring, bid: bitstring) =
   new nPR: bitstring; new r1: bitstring; new r2: bitstring;
   new credKey: key; new credId: bitstring; new nS: bitstring;
   new rc1: channel; new rc2: channel; new rc3: channel;
   new kKS: key; new nS2: bitstring;
   get words(=aid, ui: bitstring, ur: bitstring)PREC in
   event ClientRecoverIntent(ui, nPR);
   out(tls, ((REC3, ui, nPR, sig_sign(recoveryKey(ur, ui), mrc(ui, nPR), SCR, r1)), rc1));
   in(rc1, (sprf: bitstring, chR: bitstring, sdata: bitstring));
   (* A PRF account sends cd_r, a no-PRF account sends u_c itself (auth:1387-1397). Then
      _pinAccount under the words' u_i (auth:1399): the account-mode pin check, then the userCred
      compare. *)
   let uc = (if sprf = PRF1 then openAtRest(rsec(ur, ui), ui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
   get pins(=bid, =ui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
   get pins(=bid, =ui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
   FinishRecovery(aid, bid, ui, uc, sprf, chR, r2, credKey, credId, nS, rc2, rc3, kKS, nS2).

(* Recovery from the browser that registered, once registration has completed there. When
   registration pinned the words' user id, the recover3 pin checks read that pin with a positive
   lookup, as in LoginRegistered. Otherwise registration left this browser no pin for that user
   id, and the checks are the code's negative lookups. The recover/verify checks are the code's
   in both cases: u_c is fixed at recover3, so their "no entry" branch pins the u_c that passed
   the recover3 check. *)
let RecoveryRegistered(aid: bitstring) =
   new nPR: bitstring; new r1: bitstring; new r2: bitstring;
   new credKey: key; new credId: bitstring; new nS: bitstring;
   new rc1: channel; new rc2: channel; new rc3: channel;
   new kKS: key; new nS2: bitstring;
   get registered(=aid, ui: bitstring, rui: bitstring) in
   get words(=aid, =ui, ur: bitstring) in
   event ClientRecoverIntent(ui, nPR);
   out(tls, ((REC3, ui, nPR, sig_sign(recoveryKey(ur, ui), mrc(ui, nPR), SCR, r1)), rc1));
   in(rc1, (sprf: bitstring, chR: bitstring, sdata: bitstring));
   (* A PRF account sends cd_r, a no-PRF account sends u_c itself (auth:1387-1397). Then
      _pinAccount under the words' u_i (auth:1399): the account-mode pin check, then the userCred
      compare. *)
   let uc = (if sprf = PRF1 then openAtRest(rsec(ur, ui), ui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
   if rui = ui then (
      get pins(=aid, =ui, pprf: bitstring, ppk: bitstring) in
      if pprf = PRF1 && sprf = PRF0 then 0 else
      if ppk = sig_pk(proofKey(uc)) then
      FinishRecovery(aid, aid, ui, uc, sprf, chR, r2, credKey, credId, nS, rc2, rc3, kKS, nS2)
   ) else (
      get pins(=aid, =ui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
      get pins(=aid, =ui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
      FinishRecovery(aid, aid, ui, uc, sprf, chR, r2, credKey, credId, nS, rc2, rc3, kKS, nS2)
   ).

(* changeRecoveryWords (auth:564-646). The words are shown, and so written down, even when the
   server does not confirm them (auth:639-641). *)
let ReplaceWords(aid: bitstring) =
   !new ur2: bitstring; new nPR: bitstring; new rR: bitstring; new nP: bitstring; new r: bitstring;
   new nS: bitstring; new rc: channel;
   get sessions(=aid, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring) in
   insert words(aid, ui, ur2);
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

(* Registration (tex: Registration by A; auth:1500-1563). u_i is public: it is in the recovery words and
   in URLs. *)
let Register(aid: bitstring) =
   new rc1: channel; new rc2: channel;
   new credKey: key; new credId: bitstring; new ur: bitstring; new ucA: key;
   new nS1: bitstring; new nS2: bitstring; new kKS: key; new nS3: bitstring;
   out(tls, (REGOPT, rc1));
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
m4_ifdef({{NOPRF}}, {{
   let credPk = wa_pk(credKey) in
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
}}, {{
   let uc = ucA in
   let credPk = wa_pk(credKey) in
   let cdp = mkAtRest(wa_prf(credKey, PS), ui, nS1, key2bs(uc)) in
   let cdr = mkAtRest(rsec(ur, ui), ui, nS2, key2bs(uc)) in
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
}})
   event AliceCredCreated(ui, credId, credPk);
   insert passkeys(aid, ui, credId, credKey);
m4_ifdef({{LEAK_WORDS}}, {{   out(c, ur); }})
m4_ifdef({{NOPRF}}, {{
   (* A no-PRF registration sends no pk_U, cd_p or cd_r (auth:1533-1544) *)
   out(tls, ((REGVER, rr, ui, ch, sig_pk(recoveryKey(ur, ui))), rc2));
}}, {{
   out(tls, ((REGVER, rr, ui, ch, sig_pk(recoveryKey(ur, ui)), sig_pk(proofKey(uc)), cdp, cdr), rc2));
}})
   (* _loginUser pins and signs in under the user id the reply names, which the browser never
      compares with ui (I-01, auth:1545-1557). The words and the passkey's user handle carry ui. *)
m4_ifdef({{NOPRF}}, {{
m4_ifdef({{SCN_MALICIOUS}}, {{
   in(rc2, (sui: bitstring, sprf: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring)) [precise];
}}, {{
   in(rc2, (sui: bitstring, sprf: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
}})
   (* newUser requires a no-PRF reply and takes u_c from it (auth:1550-1555) *)
   if sprf = PRF0 then
   let uc = bs2key(sdata) in
   event AliceUc(aid, uc);
   event Registered(aid, ui, sui);
   insert pins(aid, sui, PRF0, sig_pk(proofKey(uc)));
}}, {{
   (* _pinAccount also halts on an existing pin for sui with another pk_U, and this browser holds
      no pin before it registers. newUser halts when the reply to a PRF registration says no-PRF
      (auth:1546-1549). The model reads that field only under DUALMODE, where an honest server
      can send it; elsewhere, ignoring it only adds runs. *)
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
   event Registered(aid, ui, sui);
   insert pins(aid, sui, PRF1, sig_pk(proofKey(uc)));
}})
   insert registered(aid, ui, sui);
   (* The words are shown only in a signed-in session, so Alice has them only once registration
      completes (auth:530-541) *)
   insert words(aid, ui, ur);
   out(c, ui);
   StartSession(aid, aid, sui, uc, credId, ck, cs, kKS, nS3).

(* An unlocked device without the user: assertions without UV, and PRF output *)
let DeviceAccess(aid: bitstring) =
   !get passkeys(=aid, ui: bitstring, credId: bitstring, credKey: key) in
   in(c, dch: bitstring);
   out(c, (credId, wa_sign(credKey, (adata(RPID, UV0), cdj(WA_GET, dch, ORIGIN))), wa_prf(credKey, PS))).

m4_ifdef({{LEAK_DB}}, {{
(* A copy of the server's account tables. Replay nonces are not in it. LEAK_CHAL adds live reads
   of the challenge table, and LEAK_CHAL_RECOVER of only its recover/verify challenges.
   LEAK_KMS_NEW and LEAK_KMS_OLD add the use of a KMS key. *)
let DbLeak() =
   (!get users(ui: bitstring, pkU: bitstring) in out(c, (ui, pkU)))
   | (!get recov(ui: bitstring, pkR: bitstring, cdr: bitstring) in out(c, (ui, pkR, cdr)))
   | (!get creds(ui: bitstring, credId: bitstring, credPk: bitstring, cdp: bitstring) in out(c, (ui, credId, credPk, cdp)))
   | (!get ucenc(ui: bitstring, enc: bitstring, encOld: bitstring) in out(c, (ui, enc, encOld)))
m4_ifdef({{LEAK_CHAL}}, {{   | (!get chal(pu: bitstring, ch: bitstring, cu: bitstring, bnd: bitstring) in out(c, (pu, ch, cu, bnd)))}})
m4_ifdef({{LEAK_CHAL_RECOVER}}, {{   | (!get chal(=PRECOVER, ch: bitstring, cu: bitstring, bnd: bitstring) in out(c, (ch, cu, bnd)))}})
m4_ifdef({{LEAK_KMS_NEW}}, {{   | out(c, kmsNew)}})
m4_ifdef({{LEAK_KMS_OLD}}, {{   | out(c, kmsOld)}})
   .
}})

(* One Alice: she registers, then does everything the scenario covers, any number of times *)
let Alice() =
   new aid: bitstring;
   (Register(aid)
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
    | !LoginRegistered(aid) | AddPasskey(aid)
    (* Sign-ins from browsers with no pin: a new device or profile, cleared storage, or the
       registering browser before registration completed *)
    | (!new bidF: bitstring; Login(aid, bidF))
m4_ifdef({{MAL_RECOVERY}}, {{
    (* Recovery from the registering browser, and from a browser with no pin, the usual case
       after losing every passkey *)
    | !RecoveryRegistered(aid)
    | (!new bidR: bitstring; Recovery(aid, bidR))
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

(* A-S1, A-K1: u_c stays secret. In no-PRF mode it is the u_c the server drew when it registered
   Alice's passkey, and the u_c her browser received. With TLS broken the attacker can send her
   browser a u_c of its own, so only the first is about her account. *)
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
(* In no-PRF mode the server draws u_c, so it knows the u_c Alice's browser holds *)
query a: bitstring, x: key; event(AliceUc(a, x)) && attacker(x).
}}, {{
(* A-S2: in PRF mode the server never learns Alice's u_c *)
query attacker(new ucA).

(* A-S3: once registration has completed in a browser, that browser never adopts a u_c the
   server knows, whether it signs in or, with MAL_RECOVERY, recovers. I-01 breaks this: the
   server names an account with no pin in this browser. *)
query u: bitstring, x: key; event(ClientLoggedIn(new aid, u, x)) && attacker(x).

(* A-S4: a browser with no pin for the account trusts the server's account mode on first use *)
query u: bitstring, x: key; event(ClientLoggedIn(new bidF, u, x)) && attacker(x).

(* A passkey Alice adds carries the user id of the session she added it in. I-01 breaks this:
   the passkeys/options reply names the handle. *)
query u: bitstring, h: bitstring; event(PasskeyHandle(u, h)) ==> u = h.

(* Reachability of honest sign-ins: the registering browser, after a registration whose reply
   named Alice's own user id, and a browser with no pin, each sign in holding Alice's own u_c.
   "!1 = alice" requires the browser and u_c to come from the same Alice. *)
query user: bitstring, ui: bitstring, alice: sid;
   event(ClientSignedIn(new aid[!1 = alice], user, new ucA[!1 = alice])) && event(Registered(new aid[!1 = alice], ui, ui)).
query user: bitstring, alice: sid; event(ClientSignedIn(new bidF[!1 = alice], user, new ucA[!1 = alice])).

m4_ifdef({{MAL_RECOVERY}}, {{
(* A-S4R: a browser with no pin that recovers trusts the server's account mode on first use *)
query user: bitstring, userCred: key; event(ClientLoggedIn(new bidR, user, userCred)) && attacker(userCred).

(* A-S3R: recovery on the browser that registered never adopts a u_c the server knows. I-01 at
   registration breaks this: when the reg/verify reply names another user id, the browser pins
   that one, and recover3 under the words' user id then trusts the server on first use. *)
query user: bitstring, userCred: key; event(ClientRecovered(new aid, user, userCred)) && attacker(userCred).

(* A-S3R, for a registration whose reg/verify reply named Alice's own user id. At recover3 the
   browser then compares the u_c it receives with the pk_U it pinned at registration. *)
query alice: sid, ui: bitstring, user: bitstring, userCred: key;
   event(ClientRecovered(new aid[!1 = alice], user, userCred)) && event(Registered(new aid[!1 = alice], ui, ui))
   && attacker(userCred).

(* Reachability of honest recoveries, on the registering browser after a registration whose reply
   named Alice's own user id, and on a browser with no pin, each ending with Alice's own u_c *)
query user: bitstring, ui: bitstring, alice: sid;
   event(ClientRecovered(new aid[!1 = alice], user, new ucA[!1 = alice])) && event(Registered(new aid[!1 = alice], ui, ui)).
query user: bitstring, alice: sid; event(ClientRecovered(new bidR[!1 = alice], user, new ucA[!1 = alice])).
}})
}})

process
   !Alice()
}})

(* ======================================================================================== *)
(* Expected results, one block per variant. On a reachability query, "is false" means a run
   reaches the events; the README says what each of those traces shows. Every other "is false" is
   an attack the variant exists to show, and ProVerif reconstructed a trace for each one. *)

m4_ifdef({{VARIANT_login_net}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_session}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_session_noproof}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_cdu}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_device}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_device_nouv}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT not attacker(ucA[!1 = v_25]) is false.
END *)}})
m4_ifdef({{VARIANT_login_unbound}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) cannot be proved.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) cannot be proved.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_unbound_trace}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_tls}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_9,pkU_5)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_9)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_5)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_5)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT not attacker(ucA[!1 = v_13]) is true.
END *)}})
m4_ifdef({{VARIANT_login_reach}}, {{(* EXPECTPV
RESULT not (event(ServerLogin(user,credId_9,chal_1,pkU_10)) && event(UserApproves(user,credId_9,chal_1))) is false.
RESULT not (event(ServerAccept(user,method,PATH_API,body,nonce,pkU_10)) && event(ClientSigned(user,method,PATH_API,body,nonce))) is false.
RESULT not (event(ServerCredAdded(user,credId_9,credPk_8,pkU_10)) && event(ClientSigned(user,POST,PATH_PKVER,(regr(credId_9,credPk_8,authData,clientData),chal_1,cdp_7,bodyUser),nonce))) is false.
RESULT not event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) is false.
END *)}})
m4_ifdef({{VARIANT_login_log}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_10)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noapinonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_10)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noauthchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_10)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noaddchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_10)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noapinonce_noaddchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT event(ServerLogin(u,id,ch_15,pkU_10)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_login_log_noregchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_10)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
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
RESULT event(ServerRecover3(u,n_3,pkU_5)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is false.
RESULT event(ServerConfirm(u,ch_6,pkU_5)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_6)) is false.
RESULT event(ServerReplaced(u,pk,pkU_5)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_5)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_6]) is true.
RESULT not attacker(ur[!1 = v_6]) is true.
RESULT not attacker(ur2[!2 = v_6,!1 = v_7]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_reach}}, {{(* EXPECTPV
RESULT not (event(ServerReplaced(user,recoveryPk,pkU_10)) && event(ClientReplace(user,recoveryPk))) is false.
RESULT not (event(ServerRecover3(user,nonce,pkU_10)) && event(ClientRecoverIntent(user,nonce))) is false.
RESULT not (event(ServerConfirm(user,chal_1,pkU_10)) && event(ClientConfirm(user,chal_1))) is false.
RESULT not (event(ServerRecovered(user,credId_7,pkU_10)) && event(AliceCredCreated(user,credId_7,credPk_6))) is false.
RESULT not event(ClientRecovered(aid[!1 = alice],user,ucA[!1 = alice])) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_log}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_norecnonce}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
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
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_log_noconfirmchal_nobind}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
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
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
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
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
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
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
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
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
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
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
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
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
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
RESULT event(ServerRecover3(u,n_3,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is false.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_malicious}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_3]) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_3],u,x)) && attacker(x)) is false.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_3,!1 = v_4],u,x)) && attacker(x)) is false.
RESULT event(PasskeyHandle(u,h)) ==> u = h is false.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_4,ui_4))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_3,!1 = alice],user,ucA[!1 = alice])) is false.
END *)}})
m4_ifdef({{VARIANT_malicious_recovery}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_8],u,x)) && attacker(x)) is false.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_8,!1 = v_9],u,x)) && attacker(x)) is false.
RESULT event(PasskeyHandle(u,h)) ==> u = h is false.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
RESULT not (event(ClientLoggedIn(bidR[!2 = v_8,!1 = v_9],user,userCred)) && attacker(userCred)) is false.
RESULT not (event(ClientRecovered(aid[!1 = v_8],user,userCred)) && attacker(userCred)) is false.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,userCred)) && event(Registered(aid[!1 = alice],ui_6,ui_6)) && attacker(userCred)) is true.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,ucA[!1 = alice])) && event(Registered(aid[!1 = alice],ui_6,ui_6))) is false.
RESULT not event(ClientRecovered(bidR[!2 = v_8,!1 = alice],user,ucA[!1 = alice])) is false.
END *)}})
m4_ifdef({{VARIANT_login_db}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,pkU_11)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_11)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_11)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_db}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,pkU_11)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_11)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_11)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_11)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_net}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_session}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_session_noproof}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_cdu}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_device}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_device_nouv}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_6,apk,x)) && event(AliceCredCreated(au,aid_6,apk)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_unbound}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_tls}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_9,pkU_5)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_9)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_5)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,pkU_5)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_reach}}, {{(* EXPECTPV
RESULT not (event(ServerLogin(user,credId_9,chal_1,pkU_10)) && event(UserApproves(user,credId_9,chal_1))) is false.
RESULT not (event(ServerAccept(user,method,PATH_API,body,nonce,pkU_10)) && event(ClientSigned(user,method,PATH_API,body,nonce))) is false.
RESULT not (event(ServerCredAdded(user,credId_9,credPk_8,pkU_10)) && event(ClientSigned(user,POST,PATH_PKVER,(regr(credId_9,credPk_8,authData,clientData),chal_1,cdp_4,bodyUser),nonce))) is false.
RESULT not (event(ClientSignedIn(aid[!1 = alice],user,x)) && event(AliceUc(aid[!1 = alice],x))) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_log}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT event(ServerLogin(u,id,ch_15,pkU_10)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,pkU_10)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_log_noauthchal}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_26)) && event(AliceUi(ui_26))) is true.
RESULT not (event(Accepted(c[],AUTHVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],API,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT not (event(Accepted(c[],PKVER,ui_26)) && event(AliceUi(ui_26))) is false.
RESULT event(ServerLogin(u,id,ch_15,pkU_10)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n,pkU_10)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_db}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
END *)}})
m4_ifdef({{VARIANT_login_noprf_db_kms}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_noprf_db_kmsold}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n,sig_pk(kdf(ID1,kpU,x)))) && event(ServerUc(au,aid_5,apk,x)) && event(AliceCredCreated(au,aid_5,apk)) ==> event(ClientSigned(u,m,p,b,n)) is true.
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
RESULT event(ServerRecover3(u,n,pkU_5)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_6,pkU_5)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_6)) is false.
RESULT event(ServerReplaced(u,pk,pkU_5)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_5)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT not attacker(ur[!1 = v_6]) is true.
RESULT not attacker(ur2[!2 = v_6,!1 = v_7]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_reach}}, {{(* EXPECTPV
RESULT not (event(ServerReplaced(user,recoveryPk,pkU_10)) && event(ClientReplace(user,recoveryPk))) is false.
RESULT not (event(ServerRecover3(user,nonce,pkU_10)) && event(ClientRecoverIntent(user,nonce))) is false.
RESULT not (event(ServerConfirm(user,chal_1,pkU_10)) && event(ClientConfirm(user,chal_1))) is false.
RESULT not (event(ServerRecovered(user,credId_7,pkU_10)) && event(AliceCredCreated(user,credId_7,credPk_6))) is false.
RESULT not (event(ClientRecovered(aid[!1 = alice],user,x)) && event(AliceUc(aid[!1 = alice],x))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_log}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT event(ServerRecover3(u,n,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
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
RESULT event(ServerRecover3(u,n,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is false.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
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
RESULT event(ServerRecover3(u,n,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is true.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is true.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_noprf_log_noconfirmchal_nobind}}, {{(* EXPECTPV
RESULT not (event(Accepted(c[],REGVER,ui_19)) && event(AliceUi(ui_19))) is true.
RESULT not (event(Accepted(c[],REPLACE,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],REC3,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],CONFIRM,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT not (event(Accepted(c[],RECVER,ui_19)) && event(AliceUi(ui_19))) is false.
RESULT event(ServerRecover3(u,n,pkU_10)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n)) is false.
RESULT event(ServerConfirm(u,ch_10,pkU_10)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_10)) is false.
RESULT event(ServerReplaced(u,pk,pkU_10)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_10)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not (event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_malicious_noprf}}, {{(* EXPECTPV
RESULT not (event(AliceUc(a,x)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_db_chal}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_16,pkU_11)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_16)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_11)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_11)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT not attacker(ucA[!1 = v_25]) is true.
END *)}})
m4_ifdef({{VARIANT_recovery_db_chal}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,pkU_11)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is false.
RESULT event(ServerConfirm(u,ch_11,pkU_11)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_11)) is false.
RESULT event(ServerReplaced(u,pk,pkU_11)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_11)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
m4_ifdef({{VARIANT_login_tls_dualmode}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_10,pkU_6)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_10)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_6)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_6)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT not attacker(ucA[!1 = v_13]) is true.
RESULT not (event(AliceUi(u)) && event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_tls_stripped}}, {{(* EXPECTPV
RESULT not (event(SignedInWith(b,u,id,ch_7,ck_2,x)) && event(ServerReplyUc(u,id,ch_7,ck_2,x)) && event(ServerUc(u,id,pk,x)) && event(AliceCredCreated(u,id,pk)) && attacker(x)) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_db_chalrec}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_3,pkU_11)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_3)) is true.
RESULT event(ServerConfirm(u,ch_11,pkU_11)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_11)) is true.
RESULT event(ServerReplaced(u,pk,pkU_11)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,pkU_11)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_10]) is true.
RESULT not attacker(ur[!1 = v_10]) is true.
RESULT not attacker(ur2[!2 = v_10,!1 = v_11]) is true.
END *)}})
