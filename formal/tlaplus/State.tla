---------------------------- MODULE State ----------------------------
(*
  Server state at DynamoDB operation granularity for the account's session, passkey and recovery
  flows, in the shipped code shape: sign-in writes in either order, deletePasskey with the
  snapshot check, and the passkey lookup in verifyCookie on every authorized route.

  Legend: L = lastCredentialId, N = authCount, P = recoveryPubKey, written as the word set it
  hashes ("w0", then "w1" after a replacement). `users` is the latest Users record and `hist`
  every value it has held: a consistent read is `users`, an eventually consistent read is any of
  the last STALE_WINDOW values. `auths` is the set of Authenticators items, read consistently.
  `chals` holds the confirm and recover challenges with the binding buildChallenge computes,
  (P, N), and the index of the Users write they were stored after; consuming one is the
  conditional delete, so it succeeds only against a record with the same (P, N). A cookie is the
  pair (L, N) it was derived from. Every token is usable by every handler: the properties are
  about server state, not about who acts.

  Handlers, one label per DynamoDB operation:
    si   sign-in          M1 lookup; M3a lookup and M3b write in either order; M4 token
    lo   logout           verifyCookie; write L = none, N + 1
    ap   add passkey      verifyCookie; create c1
    rw   replace words    verifyCookie; write P = w1
    dp   delete passkey   verifyCookie; delete; consistent count; last one: delete the user,
                          else if the snapshot's L is the deleted id: write L = none, N + 1
    r3a  recover3         consistent read, proof against P; write L = none, N + 1; store confirm
    r3b                   challenge bound to (P as read, N after the write)
    cfa  confirm          consistent read; consume confirm challenge against (P, N) as read;
    cfb                   query the passkeys; delete the queried ones; write L = none, N + 1;
                          store recover challenge bound to (P as read, N after the write)
    rv   recover/verify   consistent read with L = none; consume recover challenge; create r1;
                          write L = r1, N + 1; token
    obs_* observers       one consistent verification per token holder; a request writes nothing,
                          so one observer per token, scheduled anywhere, covers every placement
  ACTIVE selects the handlers of a variant; an inactive handler never starts.
  COND_WRITES makes the add-passkey create, the replace-words write and the passkey delete
  conditional on the Users record still holding the (L, N) pair the cookie was verified against:
  a condition expression for the Users write, a transaction with a condition check for the two
  Authenticators writes.
  BLOCK_SIGNIN refuses a sign-in's Users write while a recovery is in progress, from recover3's
  session-clearing write until recover/verify's write, as a flag on the Users record would.
  VERSION_SWEEP gives the Users record a version that every passkey create and delete bumps in
  the same transaction; confirm's delete-all and its session-clearing write are then one
  transaction conditioned on the version it saw when it queried, retried from the query when
  that condition fails. With COND_WRITES, a create after that transaction fails its own
  condition, because the transaction changed authCount.
  The variants and their expected outcomes are in the VARIANTS block at the end.
*)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS ACTIVE, STALE_WINDOW, COND_WRITES, BLOCK_SIGNIN, VERSION_SWEEP

ASSUME STALE_WINDOW \in Nat /\ {COND_WRITES, BLOCK_SIGNIN, VERSION_SWEEP} \subseteq BOOLEAN

NONE == "none"
Holders == {"a", "s", "r"}
Rec3Ids == {"r3a", "r3b"}
ConfirmIds == {"cfa", "cfb"}
ObsIds == {"obs_a", "obs_s", "obs_r"}
HolderOf == [id \in ObsIds |-> IF id = "obs_a" THEN "a" ELSE IF id = "obs_s" THEN "s" ELSE "r"]
NOTOK == [L |-> NONE, N |-> 0]
NOREC == [L |-> NONE, N |-> 0, P |-> NONE]
Matches(rec, t) == rec.L = t.L /\ rec.N = t.N

(* --algorithm state {
variables
   users = [L |-> "c0", N |-> 0, P |-> "w0"],
   userExists = TRUE,
   recovering = FALSE,
   credVersion = 0,
   hist = << [L |-> "c0", N |-> 0, P |-> "w0"] >>,
   auths = {"c0"},
   chals = {},
   tok = [a |-> [L |-> "c0", N |-> 0], s |-> NOTOK, r |-> NOTOK],
   issued = [a |-> TRUE, s |-> FALSE, r |-> FALSE],
   loggedOut = {},
   evicted = {},
   accepted = <<>>,
   recWords = [r3 \in Rec3Ids |-> NONE],
   revokedByReplace = {},
   replacedWords = {},
   deleteAllRids = {},
   c1By = NONE,
   rwBy = NONE,
   violations = {},
   seen = {};

define {
   Oldest == IF Len(hist) > STALE_WINDOW THEN Len(hist) - STALE_WINDOW ELSE 1
   StaleReads == { hist[i] : i \in Oldest..Len(hist) }
   LiveTokens == { hld \in Holders : issued[hld] }
   Consumable(purpose) == { c \in chals : c.purpose = purpose /\ c.P = users.P /\ c.N = users.N }
   SessionCurrent(auth) == ~COND_WRITES \/ (users.L = auth.t.L /\ users.N = auth.t.N)
}

\* verifyCookie: an eventually consistent read equal to the cookie, and the session's passkey item
macro VerifyCookie(auth) {
   with (h \in LiveTokens, rec \in { rr \in StaleReads : Matches(rr, tok[h]) /\ tok[h].L \in auths }) {
      auth := [t |-> tok[h], snap |-> rec];
   };
}

process (SignIn \in {"si"})
variables cred = NONE, patched = FALSE, nAfter = 0, usersFirst = TRUE;
{
M1: await self \in ACTIVE;
    with (c \in auths) { cred := c; };
    either { usersFirst := TRUE; } or { usersFirst := FALSE; };
M2: if (usersFirst) {
Mb1:   await userExists /\ (~BLOCK_SIGNIN \/ ~recovering);
       with (newRec = [L |-> cred, N |-> users.N + 1, P |-> users.P]) {
          users := newRec; hist := Append(hist, newRec); nAfter := newRec.N;
       };
Ma1:   patched := cred \in auths;
    } else {
Ma2:   patched := cred \in auths;
Mb2:   await userExists /\ (~BLOCK_SIGNIN \/ ~recovering);
       with (newRec = [L |-> cred, N |-> users.N + 1, P |-> users.P]) {
          users := newRec; hist := Append(hist, newRec); nAfter := newRec.N;
       };
    };
M4: if (patched) { tok["s"] := [L |-> cred, N |-> nAfter]; issued["s"] := TRUE; };
}

process (Logout \in {"lo"})
variables loAuth = [t |-> NOTOK, snap |-> NOREC];
{
LO1: await self \in ACTIVE;
     VerifyCookie(loAuth);
LO2: await userExists;
     with (newRec = [L |-> NONE, N |-> users.N + 1, P |-> users.P]) {
        users := newRec; hist := Append(hist, newRec);
     };
     loggedOut := loggedOut \cup {loAuth.t};
     seen := seen \cup {"logout_done"};
}

process (AddPasskey \in {"ap"})
variables apAuth = [t |-> NOTOK, snap |-> NOREC];
{
PV1: await self \in ACTIVE;
     VerifyCookie(apAuth);
PV2: await SessionCurrent(apAuth);
     auths := auths \cup {"c1"};
     c1By := apAuth.t.L;
     credVersion := credVersion + 1;
}

process (Replace \in {"rw"})
variables rwAuth = [t |-> NOTOK, snap |-> NOREC];
{
RW1: await self \in ACTIVE;
     VerifyCookie(rwAuth);
RW2: await userExists /\ SessionCurrent(rwAuth);
     with (oldP = users.P, newRec = [L |-> users.L, N |-> users.N, P |-> "w1"]) {
        users := newRec; hist := Append(hist, newRec);
        rwBy := rwAuth.t.L;
        replacedWords := replacedWords \cup {oldP};
        revokedByReplace := revokedByReplace \cup { rr3 \in Rec3Ids : recWords[rr3] = oldP };
     };
}

process (Delete \in {"dp"})
variables dpAuth = [t |-> NOTOK, snap |-> NOREC], cid = NONE, dpAction = "keep";
{
A1: await self \in ACTIVE;
    VerifyCookie(dpAuth);
    with (c \in {"c0", "c1"}) { cid := c; };
A3: await SessionCurrent(dpAuth);
    if (cid \in auths) { auths := auths \ {cid}; credVersion := credVersion + 1; } else { goto Done; };
A4: dpAction := IF auths = {} THEN "deleteUser" ELSE IF dpAuth.snap.L = cid THEN "endSession" ELSE "keep";
A5: if (dpAction = "deleteUser") {
       await userExists;
       userExists := FALSE;
       seen := seen \cup {"user_deleted"};
    } else {
       if (dpAction = "endSession") {
          await userExists;
          with (newRec = [L |-> NONE, N |-> users.N + 1, P |-> users.P]) {
             users := newRec; hist := Append(hist, newRec);
          };
          seen := seen \cup {"passkey_deleted_session_ended"};
       } else {
          seen := seen \cup {"passkey_deleted_kept"};
       };
    };
}

process (Rec3 \in Rec3Ids)
variables pRead = NONE, nAfter3 = 0;
{
R1: await self \in ACTIVE /\ userExists;
    pRead := users.P;
    recWords[self] := users.P;
    accepted := Append(accepted, self);
    violations := violations \cup (IF users.P \in replacedWords THEN {"old_words_accepted"} ELSE {});
R2: await userExists;
    with (newRec = [L |-> NONE, N |-> users.N + 1, P |-> users.P]) {
       users := newRec; hist := Append(hist, newRec); nAfter3 := newRec.N;
    };
    recovering := TRUE;
R3: chals := chals \cup {[purpose |-> "confirm", rec3 |-> self, P |-> pRead, N |-> nAfter3, len |-> Len(hist)]};
}

process (Confirm \in ConfirmIds)
variables cRid = NONE, pReadC = NONE, snapAuths = {}, snapVer = 0, nAfterC = 0;
{
C1: await self \in ACTIVE /\ userExists;
    with (ch \in Consumable("confirm")) {
       chals := chals \ {ch};
       cRid := ch.rec3;
       pReadC := users.P;
       violations := violations \cup (IF ch.len # Len(hist) THEN {"confirm_binding"} ELSE {});
    };
C2: snapAuths := auths; snapVer := credVersion;
C3: if (VERSION_SWEEP /\ credVersion # snapVer) {
       goto C2;
    } else {
       auths := auths \ snapAuths;
       credVersion := credVersion + 1;
       evicted := evicted \cup snapAuths;
       deleteAllRids := deleteAllRids \cup {cRid};
       if (VERSION_SWEEP) {
          await userExists;
          with (newRec = [L |-> NONE, N |-> users.N + 1, P |-> users.P]) {
             users := newRec; hist := Append(hist, newRec); nAfterC := newRec.N;
          };
       };
    };
C4: if (~VERSION_SWEEP) {
       await userExists;
       with (newRec = [L |-> NONE, N |-> users.N + 1, P |-> users.P]) {
          users := newRec; hist := Append(hist, newRec); nAfterC := newRec.N;
       };
    };
C5: chals := chals \cup {[purpose |-> "recover", rec3 |-> cRid, P |-> pReadC, N |-> nAfterC, len |-> Len(hist)]};
}

process (RecVerify \in {"rv"})
variables ridV = NONE;
{
V1: await self \in ACTIVE /\ userExists /\ users.L = NONE;
    with (ch \in Consumable("recover")) {
       chals := chals \ {ch};
       ridV := ch.rec3;
       violations := violations \cup (IF ch.len # Len(hist) THEN {"recover_binding"} ELSE {});
    };
V2: auths := auths \cup {"r1"};
    credVersion := credVersion + 1;
V3: await userExists;
    with (newRec = [L |-> "r1", N |-> users.N + 1, P |-> users.P]) {
       users := newRec; hist := Append(hist, newRec);
       tok["r"] := [L |-> "r1", N |-> newRec.N];
    };
    issued["r"] := TRUE;
    recovering := FALSE;
    violations := violations
       \cup (IF ridV \in revokedByReplace /\ rwBy \in evicted THEN {"replace_revokes_old_words"} ELSE {})
       \cup (IF accepted[Len(accepted)] # ridV THEN {"recoveries_interleave"} ELSE {})
       \cup (IF "c1" \in auths /\ c1By \in evicted THEN {"passkey_survives_recovery"} ELSE {});
    seen := seen
       \cup {"recovery_done"}
       \cup (IF recWords[ridV] = "w1" THEN {"recovery_done_new_words"} ELSE {})
       \cup (IF \E other \in deleteAllRids : other # ridV THEN {"recovery_done_after_partial_confirm"} ELSE {});
}

process (Obs \in ObsIds)
variables holder = HolderOf[self];
{
O1: await self \in ACTIVE /\ issued[holder] /\ userExists /\ Matches(users, tok[holder]) /\ tok[holder].L \in auths;
    violations := violations
       \cup (IF tok[holder] \in loggedOut THEN {"logout_session_verified"} ELSE {})
       \cup (IF tok[holder].L \in evicted THEN {"evicted_session_verified"} ELSE {});
    seen := seen \cup {"verified_" \o holder};
}
} *)
\* BEGIN TRANSLATION
\* END TRANSLATION

\* Sanity: at most one cookie matches the Users record
Inv_OneLive == Cardinality({hld \in Holders : issued[hld] /\ Matches(users, tok[hld])}) <= 1
\* S-L1: the cookie that performed a logout never verifies again
Inv_Logout == "logout_session_verified" \notin violations
\* S-R1: once a confirm has deleted the passkeys, no session on one of them verifies
Inv_RecoveryRevokes == "evicted_session_verified" \notin violations
\* S-B1, S-B2: a challenge is consumed only if the record was not written between store and consume
Inv_ConfirmBinding == "confirm_binding" \notin violations
Inv_RecoverBinding == "recover_binding" \notin violations
\* S-B3 as first stated: a recovery cannot complete once a later recover3 was accepted. Violated
\* and harmless: the later recover3 sits between its proof check and its write, or writes between
\* a consume and the write that follows it; every consume is still guarded by S-B1 and S-B2
Inv_NoInterleave == "recoveries_interleave" \notin violations
\* S-W1: a recovery started with the old words does not complete after a replace made by a session
\* whose passkey it evicted (the recovered owner may replace words again as soon as the new passkey exists)
Inv_ReplaceRevokes == "replace_revokes_old_words" \notin violations
\* S-W2: old words are not accepted after a replacement
Inv_OldWordsRejected == "old_words_accepted" \notin violations
\* S-R2: when a recovery completes, no passkey added by a session whose passkey it evicted remains
Inv_NoPasskeySurvives == "passkey_survives_recovery" \notin violations

\* Witnesses, expected to be violated
NoLogout == "logout_done" \notin seen
NoUserDelete == "user_deleted" \notin seen
NoDeleteEndedSession == "passkey_deleted_session_ended" \notin seen
NoDeleteKept == "passkey_deleted_kept" \notin seen
NoSigninVerified == "verified_s" \notin seen
NoRecoveryDone == "recovery_done" \notin seen
NoRecoveryNewWords == "recovery_done_new_words" \notin seen
NoRecoveryAfterPartial == "recovery_done_after_partial_confirm" \notin seen
NoRecoveryTokenVerified == "verified_r" \notin seen

(* VARIANTS
DEFAULTS STALE_WINDOW=1 COND_WRITES=FALSE BLOCK_SIGNIN=FALSE VERSION_SWEEP=FALSE
shipped-session ACTIVE={"si","lo","ap","rw","dp","obs_a","obs_s"} Inv_OneLive:holds Inv_Logout:holds NoLogout:violated NoUserDelete:violated NoDeleteEndedSession:violated NoDeleteKept:violated NoSigninVerified:violated
shipped-recovery ACTIVE={"si","ap","rw","r3a","cfa","rv","obs_a","obs_s","obs_r"} Inv_OneLive:holds Inv_RecoveryRevokes:holds Inv_ConfirmBinding:holds Inv_RecoverBinding:holds Inv_OldWordsRejected:holds Inv_ReplaceRevokes:violated Inv_NoPasskeySurvives:violated NoRecoveryDone:violated NoRecoveryNewWords:violated NoRecoveryTokenVerified:violated
shipped-two-recoveries ACTIVE={"rw","r3a","r3b","cfa","cfb","rv","obs_a","obs_r"} Inv_NoInterleave:violated Inv_ConfirmBinding:holds Inv_RecoverBinding:holds Inv_ReplaceRevokes:violated NoRecoveryDone:violated NoRecoveryAfterPartial:violated
conditional-writes ACTIVE={"si","ap","rw","r3a","cfa","rv","obs_a","obs_s","obs_r"} COND_WRITES=TRUE Inv_OneLive:holds Inv_RecoveryRevokes:holds Inv_ConfirmBinding:holds Inv_RecoverBinding:holds Inv_OldWordsRejected:holds Inv_ReplaceRevokes:holds Inv_NoPasskeySurvives:violated NoRecoveryDone:violated NoRecoveryNewWords:violated NoRecoveryTokenVerified:violated
conditional-writes-block-signin ACTIVE={"si","ap","rw","r3a","cfa","rv","obs_a","obs_s","obs_r"} COND_WRITES=TRUE BLOCK_SIGNIN=TRUE Inv_OneLive:holds Inv_RecoveryRevokes:holds Inv_ConfirmBinding:holds Inv_RecoverBinding:holds Inv_OldWordsRejected:holds Inv_ReplaceRevokes:holds Inv_NoPasskeySurvives:holds NoRecoveryDone:violated NoRecoveryNewWords:violated NoRecoveryTokenVerified:violated
versioned-sweep ACTIVE={"si","ap","rw","r3a","cfa","rv","obs_a","obs_s","obs_r"} VERSION_SWEEP=TRUE Inv_OneLive:holds Inv_RecoveryRevokes:holds Inv_ConfirmBinding:holds Inv_RecoverBinding:holds Inv_OldWordsRejected:holds Inv_ReplaceRevokes:violated Inv_NoPasskeySurvives:violated NoRecoveryDone:violated NoRecoveryNewWords:violated NoRecoveryTokenVerified:violated
versioned-sweep-conditional-writes ACTIVE={"si","ap","rw","r3a","cfa","rv","obs_a","obs_s","obs_r"} VERSION_SWEEP=TRUE COND_WRITES=TRUE Inv_OneLive:holds Inv_RecoveryRevokes:holds Inv_ConfirmBinding:holds Inv_RecoverBinding:holds Inv_OldWordsRejected:holds Inv_ReplaceRevokes:holds Inv_NoPasskeySurvives:holds NoRecoveryDone:violated NoRecoveryNewWords:violated NoRecoveryTokenVerified:violated
END VARIANTS *)
=============================================================================
