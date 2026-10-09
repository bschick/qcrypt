m4_changequote({{,}})m4_dnl
(* Quick Crypt accounts with an honest server, PRF mode: main.tex lines 277-631.

   Each honest user (Alice) registers once from her browser, then logs in with any passkey she
   holds, sends authorized requests, adds passkeys, replaces her recovery words, and recovers.
   The server keeps its state in tables, which in ProVerif can only grow. So deletions are not
   modeled: old passkeys and recovery keys stay usable, which only helps the attacker.
   Single-use challenges and replay nonces are uniqueness restrictions; they stand for the atomic
   DynamoDB delete-on-read in consumeChallenge (sutil:86-111) and the conditional put in
   storeSingleUseNonce (sutil:162-176). Timestamps and the skew window are not modeled.

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
     login-unbound        SCN_LOGIN MUT_UNBOUND
     login-tls            SCN_LOGIN LEAK_TLS KEY_UI STORE UNIQUSER NOBT
     malicious            SCN_MALICIOUS
     malicious-fixui      SCN_MALICIOUS FIX_UI
     malicious-fixhandle  SCN_MALICIOUS FIX_UI FIX_HANDLE
     recovery-net         SCN_RECOVERY
     recovery-session     SCN_RECOVERY LEAK_SESSION
     recovery-words       SCN_RECOVERY LEAK_WORDS RCV NOBT
     recovery-tls         SCN_RECOVERY LEAK_TLS KEY_UI UNIQUSER NOBT
     recovery-tls-reach   SCN_RECOVERY LEAK_TLS REACH_ONLY STORE
     recovery-replay      SCN_RECOVERY LEAK_REPLACE STORE
     recovery-replay-splitnonce  SCN_RECOVERY LEAK_REPLACE STORE MUT_SPLITNONCE
     recovery-replay-legacy  SCN_RECOVERY LEAK_REPLACE STORE LEGACY_CLIENT
     recovery-replay-legacy-splitnonce  SCN_RECOVERY LEAK_REPLACE STORE LEGACY_CLIENT MUT_SPLITNONCE
   END VARIANTS}} *)

(* NOBT turns off backtracking in trace reconstruction. Under the restrictions, a derivation can
   be followed without backtracking, and when one cannot, ProVerif stops at once and prints the
   partial trace up to the step that blocked. *)
m4_ifdef({{NOBT}}, {{
set traceBacktracking = false.
}})

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

(* Used only by the MUT_SPLITNONCE mutation *)
const NREPL: bitstring [data].

(* Recovery signature contexts: sc_R, sc_W, and the legacy context still accepted for both *)
const SCR, SCW, SCLEG: bitstring [data].

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
(* u_c at rest under k (tex 336-370), with e = u_i. This is an abstract authenticated encryption
   that commits to k and e. The real V8 format is modeled in cipher.pv.m4, where the atrest-net
   and commit-* variants prove the three properties this abstraction assumes: secrecy and
   integrity under a secret k for a given u_i, commitment to (k, u_i), and that no block is
   accepted both as a message and as u_c at rest. Expanding the real format here exhausts memory
   during saturation. *)

fun ar_enc(key, bitstring, bitstring, bitstring): bitstring.
reduc forall k: key, e: bitstring, n: bitstring, m: bitstring; ar_dec(k, e, ar_enc(k, e, n, m)) = m.

letfun mkAtRest(k: key, e: bitstring, n: bitstring, m: bitstring) = ar_enc(k, e, n, m).
letfun openAtRest(k: key, e: bitstring, cd: bitstring) = bs2key(ar_dec(k, e, cd)).

letfun proofKey(uc: key) = kdf(ID1, kpU, uc).
letfun recoveryKey(ur: bitstring, ui: bitstring) = kdf(ID1, kpR, rsec(ur, ui)).

(* ---------------------------------------------------------------------------------------- *)
(* State *)

(* Server *)
table unverified(bitstring).
table users(bitstring, bitstring).
table recov(bitstring, bitstring, bitstring).
table creds(bitstring, bitstring, bitstring, bitstring).
table chal(bitstring, bitstring, bitstring, bitstring).

(* Per-browser pin: browser, u_i, account mode, pk_U (auth:302-311) *)
table pins(bitstring, bitstring, bitstring, bitstring).

(* ---------------------------------------------------------------------------------------- *)
(* Events and restrictions *)

event AliceCredCreated(bitstring, bitstring, bitstring).
event UserApproves(bitstring, bitstring, bitstring).
event ClientSigned(bitstring, bitstring, bitstring, bitstring, bitstring).
event ClientLoggedIn(bitstring, bitstring, key).
event ClientSignedIn(bitstring, bitstring).
(* Server events end with the account's pk_U, which is how the queries pick out Alice's
   accounts: hers are the ones whose pk_U comes from her own u_c. *)
event ServerCredAdded(bitstring, bitstring, bitstring, bitstring).
event ServerLogin(bitstring, bitstring, bitstring, bitstring).
event ServerAccept(bitstring, bitstring, bitstring, bitstring, bitstring, bitstring).
event Consumed(bitstring, bitstring, bitstring).
event NonceStored(bitstring, bitstring, bitstring).

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

(* Restrictions mirror what the real system guarantees. Every variant whose results are proofs
   runs without them: leaving them off gives the attacker more traces, so a property proved
   without them also holds with them. Variants that look for an attack turn them on. Without
   them, ProVerif finds derivations no real run can follow, such as one private request received
   by two server sessions, or one user id registered twice. Reconstructing a trace from such a
   derivation then runs for hours, while a trace found under the restrictions is a trace of the
   real system.

   STORE: a challenge is consumed at most once, and a replay nonce is stored at most once
   (sutil:86-111, sutil:162-176). *)
m4_ifdef({{STORE}}, {{
restriction pu: bitstring, ch: bitstring, s1: bitstring, s2: bitstring;
   event(Consumed(pu, ch, s1)) && event(Consumed(pu, ch, s2)) ==> s1 = s2.
restriction pu: bitstring, n: bitstring, s1: bitstring, s2: bitstring;
   event(NonceStored(pu, n, s1)) && event(NonceStored(pu, n, s2)) ==> s1 = s2.
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

(* UNIQUSER: a user id is registered at most once, as the server's check for an existing
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

(* POST reg/verify (srv:422-564, 608-691) *)
let SRegVerify(net: channel) =
   new st: bitstring; new sid: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
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
   out(rc, (ui, cookie(ui, sid), csmac(skJWT, ui, sid))).

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
   in(net, (req: bitstring, rc: channel));
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
   out(rc, (uh, PRF1, credId, cdp, cookie(uh, sid), csmac(skJWT, uh, sid))).

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
   out(rc, ch).

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
   out(rc, OK).

(* A recovery proof verifies under the operation's own context or the legacy one that old
   clients use for both operations (aproof:158-176) *)
letfun recoveryProofOK(pkR: bitstring, ui: bitstring, nP: bitstring, sig: bitstring, ctx: bitstring) =
   sig_verify(pkR, mrc(ui, nP), sig, ctx) || sig_verify(pkR, mrc(ui, nP), sig, SCLEG).

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
   if recoveryProofOK(pkR, ui, nPR, sigR, SCW) then
m4_ifdef({{MUT_SPLITNONCE}}, {{
   (* MUTATION: replace proofs get their own nonce namespace *)
   event NonceStored(NREPL, nPR, st2);
}}, {{
   event NonceStored(NREC, nPR, st2);
}})
   insert recov(ui, pkR, cdr);
   event ServerReplaced(ui, pkR, pkU);
   out(rc, OK).

(* POST recover3: proof of the recovery words, then a confirm challenge and cd_r
   (srv:1457-1512). Every recovery key ever stored for the user is accepted, since tables only
   grow. The challenge binding stands for H(pk_R : authCount); authCount is not modeled. *)
let SRecover3(net: channel) =
   new st: bitstring; new chR: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=REC3, ui: bitstring, nPR: bitstring, sigR: bitstring) = req in
   get recov(=ui, pkR: bitstring, cdr: bitstring) in
   if recoveryProofOK(pkR, ui, nPR, sigR, SCR) then
   event NonceStored(NREC, nPR, st);
   get users(=ui, pkU: bitstring) in
   event ServerRecover3(ui, nPR, pkU);
   insert chal(PCONFIRM, chR, ui, pkR);
   out(rc, (PRF1, chR, cdr)).

(* POST recover/confirm: a userCred proof over ch_R, then a registration challenge
   (srv:1514-1585) *)
let SRecoverConfirm(net: channel) =
   new st: bitstring; new ch: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=CONFIRM, ui: bitstring, chR: bitstring, sigU: bitstring) = req in
   get chal(=PCONFIRM, =chR, =ui, bnd: bitstring) in
   event Consumed(PCONFIRM, chR, st);
   get users(=ui, pkU: bitstring) in
   if sig_verify(pkU, muc(ui, POST, PATH_CONFIRM, chR, sha256(EMPTY)), sigU, SCU) then
   event ServerConfirm(ui, chR, pkU);
   insert chal(PRECOVER, ch, ui, bnd);
   out(rc, ch).

(* POST recover/verify: the new passkey (srv:566-606, 608-691) *)
let SRecoverVerify(net: channel) =
   new st: bitstring; new sid: bitstring;
   new rq: bitstring;
   in(net, (req: bitstring, rc: channel));
   RECEIVED
   let (=RECVER, rr: bitstring, ui: bitstring, ch: bitstring, cdp: bitstring) = req in
   get chal(=PRECOVER, =ch, =ui, bnd: bitstring) in
   event Consumed(PRECOVER, ch, st);
   let regr(credId: bitstring, credPk: bitstring, adata(=RPID, =UV1), cdj(=WA_CREATE, =ch, =ORIGIN)) = rr in
   get users(=ui, pkU: bitstring) in
   insert creds(ui, credId, credPk, cdp);
   event ServerCredAdded(ui, credId, credPk, pkU);
   event ServerRecovered(ui, credId, pkU);
   out(rc, (ui, cookie(ui, sid), csmac(skJWT, ui, sid))).

(* Each endpoint serves honest browsers over TLS and the attacker's own client on c. Forwarding
   attacker requests into the TLS channel through a relay process gives the same access but
   makes query solving take hours. *)
m4_ifdef({{SCN_RECOVERY}}, {{
let Endpoints(net: channel) =
   !SRegOptions(net) | !SRegVerify(net) | !SReplaceWords(net) | !SRecover3(net) | !SRecoverConfirm(net) |
   !SRecoverVerify(net).
}}, {{
let Endpoints(net: channel) =
   !SRegOptions(net) | !SRegVerify(net) | !SAuthOptions(net) | !SAuthVerify(net) | !SApi(net) |
   !SPasskeyOptions(net) | !SPasskeyVerify(net).
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

(* FIX_HANDLE models the proposed fix for I-01 and I-03: each passkey's user handle also carries
   an id derived from u_c, and the browser compares it with the u_c it resolves at sign-in. The
   authenticator returns the handle to the browser, so the server cannot alter it. The id is an
   unguessable hash here; the real one is 4 bytes, and README.md states the argument for that. *)
m4_ifdef({{FIX_HANDLE}}, {{
fun hidOf(key): bitstring.
m4_define({{HID_T}}, {{, bitstring}})
m4_define({{HID_OF}}, {{, hidOf($1)}})
m4_define({{HID_VAR}}, {{, hid: bitstring}})
m4_define({{HID_ARG}}, {{, hid}})
m4_define({{HID_CHECK}}, {{if hidOf($1) = hid then}})
}}, {{
m4_define({{HID_T}}, {{}})
m4_define({{HID_OF}}, {{}})
m4_define({{HID_VAR}}, {{}})
m4_define({{HID_ARG}}, {{}})
m4_define({{HID_CHECK}}, {{}})
}})

table passkeys(bitstring, bitstring, bitstring, key HID_T).
table registered(bitstring, bitstring).
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

(* addPasskey (auth:1565-1604). The authenticator keeps the passkey once created. *)
let AddPasskey(aid: bitstring) =
   !new nP1: bitstring; new r1: bitstring; new rc1: channel;
   new credKey: key; new credId: bitstring; new nS: bitstring;
   new nP2: bitstring; new r2: bitstring; new rc2: channel;
   get sessions(=aid, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring) in
   event ClientSigned(ui, GET, PATH_PKOPT, EMPTY, nP1);
   out(tls, ((PKOPT, ck, cs, nP1, mkProof(uc, ui, GET, PATH_PKOPT, EMPTY, nP1, r1)), rc1));
   in(rc1, ch: bitstring);
   let credPk = wa_pk(credKey) in
   event AliceCredCreated(ui, credId, credPk);
   insert passkeys(aid, ui, credId, credKey HID_OF(uc));
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
   let bd = (rr, ch, mkAtRest(wa_prf(credKey, PS), ui, nS, key2bs(uc)), ui) in
   event ClientSigned(ui, POST, PATH_PKVER, bd, nP2);
   out(tls, ((PKVER, ck, cs, nP2, mkProof(uc, ui, POST, PATH_PKVER, bd, nP2, r2), bd), rc2));
   in(rc2, resp: bitstring).

(* Sign in from browser bid with the given passkey (auth:1256-1338, 701-785) *)
let LoginWith(aid: bitstring, bid: bitstring, ui: bitstring, credId: bitstring, credKey: key HID_VAR, rc1: channel, rc2: channel, kKS: key, nS: bitstring) =
   out(tls, ((AUTHOPT, UNKNOWN), rc1));
   in(rc1, ch: bitstring);
   event UserApproves(ui, credId, ch);
   let ad = adata(RPID, UV1) in
   let cd = cdj(WA_GET, ch, ORIGIN) in
   out(tls, ((AUTHVER, credId, ui, ad, cd, wa_sign(credKey, (ad, cd)), ch), rc2));
   in(rc2, (sui: bitstring, sprf: bitstring, spkId: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
m4_ifdef({{FIX_UI}}, {{
   (* PROPOSED FIX for I-01: the account signed in must be the passkey's own user handle *)
   if sui = ui then
}})
   (* _checkAccountPinPrf, then _resolveUserCred: a PRF account sends cd_p, a no-PRF account
      sends u_c itself. Then _pinAccount. *)
   get pins(=bid, =sui, =PRF1, ppk: bitstring) suchthat sprf = PRF0 in 0 else
   let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
   HID_CHECK(uc)
   get pins(=bid, =sui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
   insert pins(bid, sui, sprf, sig_pk(proofKey(uc)));
   event ClientSignedIn(bid, sui);
   StartSession(aid, bid, sui, uc, spkId, ck, cs, kKS, nS).

(* Sign in from browser bid, at any time, with any passkey Alice holds *)
let Login(aid: bitstring, bid: bitstring) =
   new rc1: channel; new rc2: channel; new kKS: key; new nS: bitstring;
   get passkeys(=aid, ui: bitstring, credId: bitstring, credKey: key HID_VAR) in
   LoginWith(aid, bid, ui, credId, credKey HID_ARG, rc1, rc2, kKS, nS).

(* Sign in from the browser that registered, once registration has completed there and so
   pinned the account *)
let LoginRegistered(aid: bitstring) =
   new rc1: channel; new rc2: channel; new kKS: key; new nS: bitstring;
   get registered(=aid, ui: bitstring) in
   get passkeys(=aid, =ui, credId: bitstring, credKey: key HID_VAR) in
m4_ifdef({{FIX_UI}}, {{
   (* With the I-01 fix the server must sign in ui itself, and registration pinned ui in this
      browser, so the pin checks become a positive lookup of that pin. ProVerif treats the
      "no entry" branch of a table lookup as always possible, so it cannot prove anything
      through the general negative form. *)
   out(tls, ((AUTHOPT, UNKNOWN), rc1));
   in(rc1, ch: bitstring);
   event UserApproves(ui, credId, ch);
   let ad = adata(RPID, UV1) in
   let cd = cdj(WA_GET, ch, ORIGIN) in
   out(tls, ((AUTHVER, credId, ui, ad, cd, wa_sign(credKey, (ad, cd)), ch), rc2));
   in(rc2, (sui: bitstring, sprf: bitstring, spkId: bitstring, sdata: bitstring, ck: bitstring, cs: bitstring));
   if sui = ui then
   get pins(=aid, =ui, pprf: bitstring, ppk: bitstring) in
   if pprf = PRF1 && sprf = PRF0 then 0 else
   let uc = (if sprf = PRF1 then openAtRest(wa_prf(credKey, PS), sui, sdata) else if sprf = PRF0 then bs2key(sdata)) in
   HID_CHECK(uc)
   if ppk = sig_pk(proofKey(uc)) then
   insert pins(aid, ui, sprf, sig_pk(proofKey(uc)));
   event ClientSignedIn(aid, ui);
   StartSession(aid, aid, ui, uc, spkId, ck, cs, kKS, nS).
}}, {{
   LoginWith(aid, aid, ui, credId, credKey HID_ARG, rc1, rc2, kKS, nS).
}})

(* recover3, recover/confirm, then recover/verify with a new passkey (auth:1340-1495), using
   any recovery words Alice has written down *)
let Recovery(aid: bitstring, bid: bitstring) =
   new nPR: bitstring; new r1: bitstring; new r2: bitstring;
   new credKey: key; new credId: bitstring; new nS: bitstring;
   new rc1: channel; new rc2: channel; new rc3: channel;
   new kKS: key; new nS2: bitstring;
   get words(=aid, ui: bitstring, ur: bitstring) in
   event ClientRecoverIntent(ui, nPR);
m4_ifdef({{LEGACY_CLIENT}}, {{
   out(tls, ((REC3, ui, nPR, sig_sign(recoveryKey(ur, ui), mrc(ui, nPR), SCLEG, r1)), rc1));
}}, {{
   out(tls, ((REC3, ui, nPR, sig_sign(recoveryKey(ur, ui), mrc(ui, nPR), SCR, r1)), rc1));
}})
   in(rc1, (sprf: bitstring, chR: bitstring, cdr: bitstring));
   let uc = openAtRest(rsec(ur, ui), ui, cdr) in
   get pins(=bid, =ui, pprf: bitstring, ppk: bitstring) suchthat ppk <> sig_pk(proofKey(uc)) in 0 else
   insert pins(bid, ui, sprf, sig_pk(proofKey(uc)));
   event ClientConfirm(ui, chR);
   out(tls, ((CONFIRM, ui, chR, sig_sign(proofKey(uc), muc(ui, POST, PATH_CONFIRM, chR, sha256(EMPTY)), SCU, r2)), rc2));
   in(rc2, ch: bitstring);
   let credPk = wa_pk(credKey) in
   event AliceCredCreated(ui, credId, credPk);
   insert passkeys(aid, ui, credId, credKey HID_OF(uc));
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
   out(tls, ((RECVER, rr, ui, ch, mkAtRest(wa_prf(credKey, PS), ui, nS, key2bs(uc))), rc3));
   in(rc3, (=ui, ck: bitstring, cs: bitstring));
   event ClientRecovered(bid, ui, uc);
   StartSession(aid, bid, ui, uc, credId, ck, cs, kKS, nS2).

(* changeRecoveryWords (auth:564-646). The words are shown, and so written down, even when the
   server does not confirm them (auth:639-641). *)
let ReplaceWords(aid: bitstring) =
   !new ur2: bitstring; new nPR: bitstring; new rR: bitstring; new nP: bitstring; new r: bitstring;
   new nS: bitstring; new rc: channel;
   get sessions(=aid, bid: bitstring, ui: bitstring, uc: key, pkId: bitstring, ck: bitstring, cs: bitstring) in
   insert words(aid, ui, ur2);
   let skR = recoveryKey(ur2, ui) in
m4_ifdef({{LEGACY_CLIENT}}, {{
   let sigR = sig_sign(skR, mrc(ui, nPR), SCLEG, rR) in
}}, {{
   let sigR = sig_sign(skR, mrc(ui, nPR), SCW, rR) in
}})
   let bd = (sig_pk(skR), nPR, sigR, mkAtRest(rsec(ur2, ui), ui, nS, key2bs(uc))) in
   event ClientReplace(ui, sig_pk(skR));
   event ClientSigned(ui, PUT, PATH_REPLACE, bd, nP);
   out(tls, ((REPLACE, ck, cs, nP, mkProof(uc, ui, PUT, PATH_REPLACE, bd, nP, r), bd), rc));
m4_ifdef({{LEAK_REPLACE}}, {{
   (* The attacker sees the recovery proof in this request, as a log or a TLS-terminating proxy
      would *)
   out(c, bd);
}})
   in(rc, resp: bitstring).

(* Registration (tex 431-463, auth:1500-1563). u_i is public: it is in the recovery words and
   in URLs. *)
let Register(aid: bitstring) =
   new rc1: channel; new rc2: channel;
   new credKey: key; new credId: bitstring; new ur: bitstring; new ucA: key;
   new nS1: bitstring; new nS2: bitstring; new kKS: key; new nS3: bitstring;
   out(tls, (REGOPT, rc1));
   in(rc1, (ch: bitstring, ui: bitstring));
   event AliceUi(ui);
   let uc = ucA in
   let credPk = wa_pk(credKey) in
   let cdp = mkAtRest(wa_prf(credKey, PS), ui, nS1, key2bs(uc)) in
   let cdr = mkAtRest(rsec(ur, ui), ui, nS2, key2bs(uc)) in
   let rr = regr(credId, credPk, adata(RPID, UV1), cdj(WA_CREATE, ch, ORIGIN)) in
   event AliceCredCreated(ui, credId, credPk);
   insert passkeys(aid, ui, credId, credKey HID_OF(uc));
   insert words(aid, ui, ur);
m4_ifdef({{LEAK_WORDS}}, {{   out(c, ur); }})
   out(tls, ((REGVER, rr, ui, ch, sig_pk(recoveryKey(ur, ui)), sig_pk(proofKey(uc)), cdp, cdr), rc2));
   in(rc2, (=ui, ck: bitstring, cs: bitstring));
   insert pins(aid, ui, PRF1, sig_pk(proofKey(uc)));
   insert registered(aid, ui);
   out(c, ui);
   StartSession(aid, aid, ui, uc, credId, ck, cs, kKS, nS3).

(* An unlocked device without the user: assertions without UV, and PRF output *)
let DeviceAccess(aid: bitstring) =
   !get passkeys(=aid, ui: bitstring, credId: bitstring, credKey: key HID_VAR) in
   in(c, dch: bitstring);
   out(c, (credId, wa_sign(credKey, (adata(RPID, UV0), cdj(WA_GET, dch, ORIGIN))), wa_prf(credKey, PS))).

(* One Alice: she registers, then does everything the scenario covers, any number of times *)
let Alice() =
   new aid: bitstring;
   (Register(aid)
m4_ifdef({{SCN_RECOVERY}}, {{
    | ReplaceWords(aid) | !Recovery(aid, aid)
}})
m4_ifdef({{SCN_LOGIN}}, {{
    | !Login(aid, aid) | ApiRequests(aid) | AddPasskey(aid)
}})
m4_ifdef({{SCN_MALICIOUS}}, {{
    | !LoginRegistered(aid)
    (* Sign-ins from browsers with no pin: a new device or profile, cleared storage, or the
       registering browser before registration completed *)
    | (!new bidF: bitstring; Login(aid, bidF))
}})
m4_ifdef({{LEAK_DEVICE}}, {{
    | DeviceAccess(aid)
}})
   ).

m4_ifdef({{SCN_LOGIN}}, {{
(* ======================================================================================== *)
(* A-L1, A-R1, A-Z1, A-K1, A-S1 *)

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

(* A-S1, A-K1: u_c stays secret *)
query attacker(new ucA).

(* Reachability *)
query u: bitstring, id: bitstring, ch: bitstring, pk: bitstring; event(ServerLogin(u, id, ch, pk)).
query u: bitstring, m: bitstring, p: bitstring, b: bitstring, n: bitstring, pk: bitstring;
   event(ServerAccept(u, m, p, b, n, pk)).
query u: bitstring, id: bitstring, pk: bitstring, pkU: bitstring; event(ServerCredAdded(u, id, pk, pkU)).
query u: bitstring, b: bitstring, x: key; event(ClientLoggedIn(b, u, x)).

process
   Server() | !Alice()
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

(* A-S1: u_c and both sets of recovery words stay secret *)
query attacker(new ucA).
query attacker(new ur).
query attacker(new ur2).
}})

(* Reachability of each step of Alice's own recovery, and of replacing her words *)
query u: bitstring, pk: bitstring; event(ServerReplaced(u, pk, sig_pk(kdf(ID1, kpU, new ucA)))).
query u: bitstring, n: bitstring; event(ServerRecover3(u, n, sig_pk(kdf(ID1, kpU, new ucA)))).
query u: bitstring, ch: bitstring; event(ServerConfirm(u, ch, sig_pk(kdf(ID1, kpU, new ucA)))).

(* The last step, recover/verify on Alice's account, follows only from confirm, which needs her
   u_c. Reconstructing its trace runs for hours unless the TLS channel is public, so it is checked
   only in the REACH_ONLY variant. *)
m4_ifdef({{REACH_ONLY}}, {{
query u: bitstring, id: bitstring; event(ServerRecovered(u, id, sig_pk(kdf(ID1, kpU, new ucA)))).
}})

process
   Server() | !Alice()
}})

m4_ifdef({{SCN_MALICIOUS}}, {{
(* ======================================================================================== *)
(* A-S2..A-S4: a malicious server answers every request Alice's browser makes. The browser and
   the static site that serves its code are honest. *)

(* A-S2: in PRF mode the server never learns Alice's u_c *)
query attacker(new ucA).

(* A-S3: once registration has completed in a browser, and so pinned the account, that browser
   never adopts a u_c the server knows. Without the I-01 fix, the server names an account with no
   pin in this browser. *)
query u: bitstring, x: key; event(ClientLoggedIn(new aid, u, x)) && attacker(x).

(* A-S4: a browser with no pin for the account trusts the server's account mode on first use *)
query u: bitstring, x: key; event(ClientLoggedIn(new bidF, u, x)) && attacker(x).

(* Reachability: the registering browser can sign in again, and so can a browser with no pin *)
query u: bitstring; event(ClientSignedIn(new aid, u)).
query u: bitstring; event(ClientSignedIn(new bidF, u)).

process
   !Alice()
}})

(* ======================================================================================== *)
(* Expected results, one block per variant. "is false" on a "not event" query means an honest
   run reaches that event. Every other "is false" is an attack the variant exists to show, and
   ProVerif reconstructed a trace for each one. *)

m4_ifdef({{VARIANT_login_net}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
RESULT not event(ServerLogin(u,id,ch_15,pk)) is false.
RESULT not event(ServerAccept(u,m,p,b,n_3,pk)) is false.
RESULT not event(ServerCredAdded(u,id,pk,pkU_10)) is false.
RESULT not event(ClientLoggedIn(b,u,x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_session}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
RESULT not event(ServerLogin(u,id,ch_15,pk)) is false.
RESULT not event(ServerAccept(u,m,p,b,n_3,pk)) is false.
RESULT not event(ServerCredAdded(u,id,pk,pkU_10)) is false.
RESULT not event(ClientLoggedIn(b,u,x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_session_noproof}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT not attacker(ucA[!1 = v_25]) is true.
RESULT not event(ServerLogin(u,id,ch_15,pk)) is false.
RESULT not event(ServerAccept(u,m,p,b,n_3,pk)) is false.
RESULT not event(ServerCredAdded(u,id,pk,pkU_10)) is false.
RESULT not event(ClientLoggedIn(b,u,x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_cdu}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
RESULT not event(ServerLogin(u,id,ch_15,pk)) is false.
RESULT not event(ServerAccept(u,m,p,b,n_3,pk)) is false.
RESULT not event(ServerCredAdded(u,id,pk,pkU_10)) is false.
RESULT not event(ClientLoggedIn(b,u,x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_device}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
RESULT not event(ServerLogin(u,id,ch_15,pk)) is false.
RESULT not event(ServerAccept(u,m,p,b,n_3,pk)) is false.
RESULT not event(ServerCredAdded(u,id,pk,pkU_10)) is false.
RESULT not event(ClientLoggedIn(b,u,x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_device_nouv}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT not attacker(ucA[!1 = v_25]) is false.
RESULT not event(ServerLogin(u,id,ch_15,pk)) is false.
RESULT not event(ServerAccept(u,m,p,b,n_3,pk)) is false.
RESULT not event(ServerCredAdded(u,id,pk,pkU_10)) is false.
RESULT not event(ClientLoggedIn(b,u,x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_unbound}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_15,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(UserApproves(u,id,ch_15)) cannot be proved.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,sig_pk(kdf(ID1,kpU,ucA[!1 = v_25])))) ==> event(ClientSigned(u,m,p,b,n_3)) is true.
RESULT not attacker(ucA[!1 = v_25]) is true.
RESULT not event(ServerLogin(u,id,ch_15,pk)) is false.
RESULT not event(ServerAccept(u,m,p,b,n_3,pk)) is false.
RESULT not event(ServerCredAdded(u,id,pk,pkU_10)) is false.
RESULT not event(ClientLoggedIn(b,u,x)) is false.
END *)}})
m4_ifdef({{VARIANT_login_tls}}, {{(* EXPECTPV
RESULT event(ServerLogin(u,id,ch_9,pkU_5)) && event(AliceUi(u)) ==> event(UserApproves(u,id,ch_9)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_5)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT event(ServerAccept(u,m,p,b,n_3,pkU_5)) && event(AliceUi(u)) ==> event(ClientSigned(u,m,p,b,n_3)) is false.
RESULT not attacker(ucA[!1 = v_13]) is true.
RESULT not event(ServerLogin(u,id,ch_9,pk)) is false.
RESULT not event(ServerAccept(u,m,p,b,n_3,pk)) is false.
RESULT not event(ServerCredAdded(u,id,pk,pkU_5)) is false.
RESULT not event(ClientLoggedIn(b,u,x)) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_net}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientRecoverIntent(u,n_4)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not attacker(ur[!1 = v_8]) is true.
RESULT not attacker(ur2[!2 = v_8,!1 = v_9]) is true.
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_session}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientRecoverIntent(u,n_4)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not attacker(ur[!1 = v_8]) is true.
RESULT not attacker(ur2[!2 = v_8,!1 = v_9]) is true.
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_words}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientRecoverIntent(u,n_4)) is false.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientConfirm(u,ch_10)) is false.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_8]) is false.
RESULT not attacker(ur[!1 = v_8]) is false.
RESULT not attacker(ur2[!2 = v_8,!1 = v_9]) is true.
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_tls}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_4,pkU_5)) && event(AliceUi(u)) ==> event(ClientRecoverIntent(u,n_4)) is false.
RESULT event(ServerConfirm(u,ch_6,pkU_5)) && event(AliceUi(u)) ==> event(ClientConfirm(u,ch_6)) is false.
RESULT event(ServerReplaced(u,pk,pkU_5)) && event(AliceUi(u)) ==> event(ClientReplace(u,pk)) is false.
RESULT event(ServerCredAdded(u,id,pk,pkU_5)) && event(AliceUi(u)) ==> event(AliceCredCreated(u,id,pk)) is false.
RESULT not attacker(ucA[!1 = v_4]) is true.
RESULT not attacker(ur[!1 = v_4]) is true.
RESULT not attacker(ur2[!2 = v_4,!1 = v_5]) is true.
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_4])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_4])))) is false.
RESULT not event(ServerConfirm(u,ch_6,sig_pk(kdf(ID1,kpU,ucA[!1 = v_4])))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_tls_reach}}, {{(* EXPECTPV
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_4])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_4])))) is false.
RESULT not event(ServerConfirm(u,ch_6,sig_pk(kdf(ID1,kpU,ucA[!1 = v_4])))) is false.
RESULT not event(ServerRecovered(u,id,sig_pk(kdf(ID1,kpU,ucA[!1 = v_4])))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_replay}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientRecoverIntent(u,n_4)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not attacker(ur[!1 = v_8]) is true.
RESULT not attacker(ur2[!2 = v_8,!1 = v_9]) is true.
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_replay_splitnonce}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientRecoverIntent(u,n_4)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not attacker(ur[!1 = v_8]) is true.
RESULT not attacker(ur2[!2 = v_8,!1 = v_9]) is true.
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_replay_legacy}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientRecoverIntent(u,n_4)) is true.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not attacker(ur[!1 = v_8]) is true.
RESULT not attacker(ur2[!2 = v_8,!1 = v_9]) is true.
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
END *)}})
m4_ifdef({{VARIANT_recovery_replay_legacy_splitnonce}}, {{(* EXPECTPV
RESULT event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientRecoverIntent(u,n_4)) is false.
RESULT event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientConfirm(u,ch_10)) is true.
RESULT event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(ClientReplace(u,pk)) is true.
RESULT event(ServerCredAdded(u,id,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) ==> event(AliceCredCreated(u,id,pk)) is true.
RESULT not attacker(ucA[!1 = v_8]) is true.
RESULT not attacker(ur[!1 = v_8]) is true.
RESULT not attacker(ur2[!2 = v_8,!1 = v_9]) is true.
RESULT not event(ServerReplaced(u,pk,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerRecover3(u,n_4,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
RESULT not event(ServerConfirm(u,ch_10,sig_pk(kdf(ID1,kpU,ucA[!1 = v_8])))) is false.
END *)}})
m4_ifdef({{VARIANT_malicious}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_2]) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_2],u,x)) && attacker(x)) is false.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_2,!1 = v_3],u,x)) && attacker(x)) is false.
RESULT not event(ClientSignedIn(aid[!1 = v_2],u)) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_2,!1 = v_3],u)) is false.
END *)}})
m4_ifdef({{VARIANT_malicious_fixui}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_2]) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_2],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_2,!1 = v_3],u,x)) && attacker(x)) is false.
RESULT not event(ClientSignedIn(aid[!1 = v_2],u)) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_2,!1 = v_3],u)) is false.
END *)}})
m4_ifdef({{VARIANT_malicious_fixhandle}}, {{(* EXPECTPV
RESULT not attacker(ucA[!1 = v_2]) is true.
RESULT not (event(ClientLoggedIn(aid[!1 = v_2],u,x)) && attacker(x)) is true.
RESULT not (event(ClientLoggedIn(bidF[!2 = v_2,!1 = v_3],u,x)) && attacker(x)) is true.
RESULT not event(ClientSignedIn(aid[!1 = v_2],u)) is false.
RESULT not event(ClientSignedIn(bidF[!2 = v_2,!1 = v_3],u)) is false.
END *)}})
