---------------------------- MODULE Revoke ----------------------------
(*
  Revocation of a session whose passkey is deleted, at DynamoDB operation granularity.

  Legend: L = lastCredentialId, N = authCount. A cookie is the pair <<L, N>> it was derived from
  and verifies when it equals the Users record, which is what getSessionKey binds. `users` is the
  latest Users record, `hist` every value it has held, so a consistent read is `users` and an
  eventually consistent read is any of the last STALE_WINDOW values. `auths` is the set of
  Authenticators items; a lookup reads it consistently.

  Sign-in (m1 with P_old, a1 with P_cur): M1 lookup, then the Users write (L = c, N + 1) and the
  lookup with the exists condition in either order, as Promise.all allows, then M4 token.
  Delete (d1, d2, both of P_old with Alice's cookie): A1 cookie check against an eventually
  consistent read, A3 delete, then A4 ends the session if the item was found and A1's snapshot
  has L = P_old; a retry whose A3 finds nothing returns at the not-found check.
  Authorized requests: one GET and one mutating request per principal. A request writes
  nothing, so one per route and principal, scheduled anywhere, covers every placement.

  Constants:
     ROUTE_CHECK   "none": no route looks up the session's passkey; "mut": non-GET routes do;
                   "all": every route does, which is what verifyCookie implements
     STALE_WINDOW  how many writes back an eventually consistent read may return
     TX            the sign-in's Users write is a transaction that also checks that the passkey
                   item exists, and A3 is a transaction that also checks that the Users record
                   still holds the pair the cookie was verified against
  The variants and their expected outcomes are in the VARIANTS block at the end.
*)
EXTENDS Naturals, Sequences, FiniteSets

CONSTANTS ROUTE_CHECK, STALE_WINDOW, TX

ASSUME ROUTE_CHECK \in {"none", "mut", "all"} /\ STALE_WINDOW \in Nat /\ TX \in BOOLEAN

POLD == "pold"
PCUR == "pcur"
NONE == "none"
SignInIds == {"m1", "a1"}
CredOf == [id \in SignInIds |-> IF id = "a1" THEN PCUR ELSE POLD]
WhoOf == [id \in SignInIds |-> IF id = "a1" THEN "a" ELSE "m"]
DeleteIds == {"d1", "d2"}
ApiIds == {"m_get", "m_mut", "a_get", "a_mut"}
ApiWho == [id \in ApiIds |-> IF id \in {"m_get", "m_mut"} THEN "m" ELSE "a"]
ApiKind == [id \in ApiIds |-> IF id \in {"m_get", "a_get"} THEN "get" ELSE "mut"]

(* --algorithm revoke {
variables
   auths = {POLD, PCUR},
   users = [L |-> PCUR, N |-> 0],
   hist = << [L |-> PCUR, N |-> 0] >>,
   tok = [m |-> [L |-> NONE, N |-> 0], a |-> [L |-> PCUR, N |-> 0]],
   issued = [m |-> FALSE, a |-> TRUE],
   deleted = {},
   returned = {},
   violations = {},
   seen = {};

define {
   Oldest == IF Len(hist) > STALE_WINDOW THEN Len(hist) - STALE_WINDOW ELSE 1
   StaleReads == { hist[i] : i \in Oldest..Len(hist) }
   NeedsLookup(kind) == ROUTE_CHECK = "all" \/ (ROUTE_CHECK = "mut" /\ kind = "mut")
}

process (SignIn \in SignInIds)
variables cred = CredOf[self], principal = WhoOf[self], patched = FALSE, nAfter = 0, usersFirst = TRUE;
{
M1: if (cred \in auths) {
       either { usersFirst := TRUE; } or { usersFirst := FALSE; };
    } else { goto Done; };
M2: if (usersFirst) {
Mb1:   await ~TX \/ cred \in auths;
       with (newN = users.N + 1) {
          users := [L |-> cred, N |-> newN];
          hist := Append(hist, [L |-> cred, N |-> newN]);
          nAfter := newN;
       };
Ma1:   patched := cred \in auths;
    } else {
Ma2:   patched := cred \in auths;
Mb2:   await ~TX \/ cred \in auths;
       with (newN = users.N + 1) {
          users := [L |-> cred, N |-> newN];
          hist := Append(hist, [L |-> cred, N |-> newN]);
          nAfter := newN;
       };
    };
M4: if (patched) {
       tok[principal] := [L |-> cred, N |-> nAfter];
       issued[principal] := TRUE;
    };
}

process (Delete \in DeleteIds)
variables snap = [L |-> NONE, N |-> 0], found = FALSE;
{
A1: with (rec \in {r \in StaleReads : r = tok["a"]}) { snap := rec; };
A3: await ~TX \/ (users.L = snap.L /\ users.N = snap.N);
    if (POLD \in auths) {
       auths := auths \ {POLD};
       deleted := deleted \cup {POLD};
       found := TRUE;
    } else {
       found := FALSE;
    };
A4: if (found /\ snap.L = POLD) {
       with (newN = users.N + 1) {
          users := [L |-> NONE, N |-> newN];
          hist := Append(hist, [L |-> NONE, N |-> newN]);
       };
    };
    returned := returned \cup {POLD};
}

process (Api \in ApiIds)
variables apiWho = ApiWho[self], apiKind = ApiKind[self];
{
R1: await issued[apiWho];
    if (users = tok[apiWho] /\ (NeedsLookup(apiKind) => tok[apiWho].L \in auths)) {
       violations := violations
          \cup (IF tok[apiWho].L \in returned THEN {"ax1_" \o apiKind} ELSE {})
          \cup (IF tok[apiWho].L \in deleted THEN {"ax2_" \o apiKind} ELSE {});
       seen := seen
          \cup (IF apiWho = "m" THEN {"mallory_verified"} ELSE {})
          \cup (IF apiWho = "a" /\ POLD \in returned THEN {"alice_after_pold_delete"} ELSE {});
    };
}
} *)
\* BEGIN TRANSLATION
\* END TRANSLATION

\* Sanity: at most one cookie matches the Users record
Inv_OneLive == Cardinality({w \in {"m", "a"} : issued[w] /\ tok[w] = users}) <= 1

\* A-X1: once a delete of P_old has returned, no cookie made from P_old verifies, on any route
Inv_AX1_get == "ax1_get" \notin violations
Inv_AX1_mut == "ax1_mut" \notin violations

\* A-X2: no cookie made from P_old verifies once its Authenticators item is gone
Inv_AX2_get == "ax2_get" \notin violations
Inv_AX2_mut == "ax2_mut" \notin violations

\* Witnesses: these are expected to be violated, which shows the model can reach the states
\* A-X4: a P_old session works at all
NoMalloryVerified == "mallory_verified" \notin seen
\* A-X3: Alice's P_cur session is accepted after a delete of P_old has returned
NoOtherSurvives == "alice_after_pold_delete" \notin seen

(* VARIANTS
DEFAULTS STALE_WINDOW=9 TX=FALSE
no-lookup ROUTE_CHECK="none" Inv_OneLive:holds Inv_AX1_get:violated Inv_AX1_mut:violated Inv_AX2_mut:violated Inv_AX2_get:violated NoOtherSurvives:violated NoMalloryVerified:violated
lookup-mutating ROUTE_CHECK="mut" Inv_OneLive:holds Inv_AX1_get:violated Inv_AX1_mut:holds Inv_AX2_mut:holds Inv_AX2_get:violated NoOtherSurvives:violated NoMalloryVerified:violated
lookup-all-routes ROUTE_CHECK="all" Inv_OneLive:holds Inv_AX1_get:holds Inv_AX1_mut:holds Inv_AX2_mut:holds Inv_AX2_get:holds NoOtherSurvives:violated NoMalloryVerified:violated
transactions ROUTE_CHECK="none" TX=TRUE Inv_OneLive:holds Inv_AX1_get:holds Inv_AX1_mut:holds Inv_AX2_mut:holds Inv_AX2_get:holds NoOtherSurvives:violated NoMalloryVerified:violated
END VARIANTS *)
=============================================================================
