m4_changequote({{,}})m4_dnl
(* Quick Crypt V8 message format: main.tex lines 152-275.

   Alice owns the password p and the user credential uc. She encrypts messages of 1 to 3 blocks
   under every AEAD algorithm, and decrypts any block stream the attacker sends her. The
   decryptor follows the order of checks in the code, not the order in the tex (conformance.md
   I-13), and releases each block as soon as it decrypts, as the streaming code does (I-15).

   Each scenario is selected by an m4 flag; run.mjs builds one .pv per entry in VARIANTS. The
   list is m4-quoted so the flag names survive into the generated files.

{{   VARIANTS:
     secrecy-net        SCN_SECRECY
     secrecy-uc         SCN_SECRECY LEAK_UC
     secrecy-p          SCN_SECRECY LEAK_P
     secrecy-both       SCN_SECRECY LEAK_UC LEAK_P
     integrity-net      SCN_INTEGRITY
     integrity-uc       SCN_INTEGRITY LEAK_UC
     integrity-p        SCN_INTEGRITY LEAK_P
     integrity-uc-nof   SCN_INTEGRITY LEAK_UC MUT_NOF
     integrity-uc-non   SCN_INTEGRITY LEAK_UC MUT_NON
     integrity-net-emptymid  SCN_INTEGRITY MUT_EMPTYMID
     commit-v8          SCN_COMMIT
     commit-v8-nokc     SCN_COMMIT MUT_NOKC
     commit-v7          SCN_COMMIT USE_V7
     loops-net          SCN_LOOPS
     loops-uc           SCN_LOOPS LEAK_UC
     loops-uc-pout      SCN_LOOPS LEAK_UC LEAK_POUT
     loops-uc-pout-nolple  SCN_LOOPS LEAK_UC LEAK_POUT MUT_NOLPLE
     downgrade-uc       SCN_DOWNGRADE LEAK_UC
   END VARIANTS}} *)

free p: password [private].
free uc: key [private].
free HINT: bitstring [private].

(* Plaintext blocks for the secrecy scenario *)
free MSG0: bitstring [private].
free MSG1: bitstring [private].
free MSG2: bitstring [private].

(* ---------------------------------------------------------------------------------------- *)
(* Key schedule, tex 165-171 and 206 *)

letfun mkX8(nS: bitstring, a: alg, lp: bitstring) = xctx8(nS, a, V8, lp, EL0, EMPTY).
letfun mkKS(u: key, x: bitstring) = kdf(ID1, kpS, hmix(u, x)).
letfun mkKH(u: key, x: bitstring) = kdf(ID1, kpH, hmix(u, x)).
letfun mkNIVH(nIV: bitstring, x: bitstring) = key2bs(kdf(ID2, kpH, hmix(bs2key(nIV), x))).
letfun mkKM0(pw: password, u: key, a: alg, lp: bitstring, nS: bitstring, i: bitstring) =
   pbkdf(pwmat8(pw, u, a, V8, lp, EL0, EMPTY), nS, i).
letfun mkKC(k0: key, nS: bitstring) = kdf(ID1, kpC, hmix(k0, nS)).

m4_ifdef({{MUT_NON}}, {{
(* MUTATION: the block number no longer selects the block key *)
letfun mkKMN(k0: key, n: bitstring, x: bitstring) = kdf(B1, kpB, hmix(k0, x)).
}}, {{
letfun mkKMN(k0: key, n: bitstring, x: bitstring) = kdf(n, kpB, hmix(k0, x)).
}})

m4_ifdef({{MUT_NOF}}, {{
(* MUTATION: f is covered by the outer MAC but left out of the AEAD AD *)
letfun aad0(adf: bitstring) =
   let ad0(f: bitstring, a: alg, n: bitstring, s: bitstring, i: bitstring, le: bitstring, lp: bitstring, h: bitstring, k: key) = adf in
   ad0(F0, a, n, s, i, le, lp, h, k)
   else adf.
letfun aadN(adf: bitstring) =
   let adN(f: bitstring, a: alg, n: bitstring) = adf in adN(F0, a, n) else adf.
}}, {{
letfun aad0(adf: bitstring) = adf.
letfun aadN(adf: bitstring) = adf.
}})

(* ---------------------------------------------------------------------------------------- *)
(* Events *)

event EncPre1(bitstring, bitstring).
event EncPre2(bitstring, bitstring, bitstring).
event Enc1(bitstring, bitstring).
event Enc2(bitstring, bitstring, bitstring).
event Enc3(bitstring, bitstring, bitstring, bitstring).
event Rel1(bitstring, bitstring).
event Rel2(bitstring, bitstring, bitstring).
event Acc1(bitstring, bitstring).
event Acc2(bitstring, bitstring, bitstring).
event Acc3(bitstring, bitstring, bitstring, bitstring).
event HintMade(bitstring, bitstring).
event HintShown(bitstring, bitstring).

(* ---------------------------------------------------------------------------------------- *)
(* Alice encrypts: tex 152-213. Block 0 and the block-N chain, with le = lp = 1. *)

letfun mkBlock0L(pw: password, a: alg, nS: bitstring, nIV0: bitstring, f0: bitstring, lp: bitstring, le: bitstring, m0: bitstring) =
   let x = mkX8(nS, a, lp) in
   let kM0 = mkKM0(pw, uc, a, lp, nS, IC) in
   let hE = aead_enc(a, mkKH(uc, x), mkNIVH(nIV0, x), EMPTY, HINT) in
   let adf0 = ad0(f0, a, nIV0, nS, IC, le, lp, hE, mkKC(kM0, nS)) in
   let mE0 = aead_enc(a, kM0, nIV0, aad0(adf0), m0) in
   blk(mac(mkKS(uc, x), macin(V8, adf0, mE0, TL0)), V8, adf0, mE0).

letfun mkBlock0(a: alg, nS: bitstring, nIV0: bitstring, f0: bitstring, m0: bitstring) =
   mkBlock0L(p, a, nS, nIV0, f0, LP1, LP1, m0).

letfun mkBlockN(a: alg, nS: bitstring, n: bitstring, nIV: bitstring, f: bitstring, m: bitstring, tL: bitstring) =
   let x = mkX8(nS, a, LP1) in
   let kM0 = mkKM0(p, uc, a, LP1, nS, IC) in
   let adf = adN(f, a, nIV) in
   let mE = aead_enc(a, mkKMN(kM0, n, x), nIV, aadN(adf), m) in
   blk(mac(mkKS(uc, x), macin(V8, adf, mE, tL)), V8, adf, mE).

letfun tagOf(b: bitstring) = let blk(t: bitstring, v: bitstring, adf: bitstring, mE: bitstring) = b in t.

(* The encryptor never writes an empty block 0 (cur:427-431), and keeps reading until a later
   block has data or the stream ends (cur:520-530). So only the terminal block can be empty, and
   an empty terminal block carries no plaintext: the message is the blocks before it. *)

let Enc1P(a: alg, m0: bitstring) =
   if m0 <> EMPTY then
   new nS: bitstring; new nIV0: bitstring;
   let b0 = mkBlock0(a, nS, nIV0, F1, m0) in
   event HintMade(nS, HINT);
   event EncPre1(nS, m0);
   event Enc1(nS, m0);
   out(c, b0).

let Enc2P(a: alg, m0: bitstring, m1: bitstring) =
   if m0 <> EMPTY then
   new nS: bitstring; new nIV0: bitstring; new nIV1: bitstring;
   let b0 = mkBlock0(a, nS, nIV0, F0, m0) in
   let b1 = mkBlockN(a, nS, B1, nIV1, F1, m1, tagOf(b0)) in
   event HintMade(nS, HINT);
   event EncPre1(nS, m0);
   if m1 = EMPTY then (
      event Enc1(nS, m0);
      out(c, (b0, b1))
   ) else (
      event EncPre2(nS, m0, m1);
      event Enc2(nS, m0, m1);
      out(c, (b0, b1))
   ).

let Enc3P(a: alg, m0: bitstring, m1: bitstring, m2: bitstring) =
   if m0 <> EMPTY then
m4_ifdef({{MUT_EMPTYMID}}, {{
   (* MUTATION: the encryptor may write an empty block that is not the last *)
}}, {{
   if m1 <> EMPTY then
}})
   new nS: bitstring; new nIV0: bitstring; new nIV1: bitstring; new nIV2: bitstring;
   let b0 = mkBlock0(a, nS, nIV0, F0, m0) in
   let b1 = mkBlockN(a, nS, B1, nIV1, F0, m1, tagOf(b0)) in
   let b2 = mkBlockN(a, nS, B2, nIV2, F1, m2, tagOf(b1)) in
   event HintMade(nS, HINT);
   event EncPre1(nS, m0);
   event EncPre2(nS, m0, m1);
   if m2 = EMPTY then (
      event Enc2(nS, m0, m1);
      out(c, (b0, b1, b2))
   ) else (
      event Enc3(nS, m0, m1, m2);
      out(c, (b0, b1, b2))
   ).

(* ---------------------------------------------------------------------------------------- *)
(* Alice decrypts: tex 216-275, in the code's order (cur:1007-1095, cur:717-772,
   cur:1155-1221, cs:165-205). A block that decrypts to empty ends the stream without checking
   its own f, as the code does (conformance.md I-14). *)

let BlockN2(a: alg, x: bitstring, kS: key, kM0: key, nS: bitstring, m0: bitstring, m1: bitstring, t1: bitstring) =
   in(c, b2: bitstring);
   let blk(t2: bitstring, v2: bitstring, adf2: bitstring, mE2: bitstring) = b2 in
   let adN(f2: bitstring, a2: alg, nIV2: bitstring) = adf2 in
   if t2 = mac(kS, macin(v2, adf2, mE2, t1)) then
   if a2 = a && v2 = V8 then
   let m2 = aead_dec(a2, mkKMN(kM0, B2, x), nIV2, aadN(adf2), mE2) in
   if m2 = EMPTY then event Acc2(nS, m0, m1)
   else if f2 = F1 then event Acc3(nS, m0, m1, m2).

let BlockN1(a: alg, x: bitstring, kS: key, kM0: key, nS: bitstring, m0: bitstring, t0: bitstring) =
   in(c, b1: bitstring);
   let blk(t1: bitstring, v1: bitstring, adf1: bitstring, mE1: bitstring) = b1 in
   let adN(f1: bitstring, a1: alg, nIV1: bitstring) = adf1 in
   if t1 = mac(kS, macin(v1, adf1, mE1, t0)) then
   if a1 = a && v1 = V8 then
   let m1 = aead_dec(a1, mkKMN(kM0, B1, x), nIV1, aadN(adf1), mE1) in
   if m1 = EMPTY then event Acc1(nS, m0)
   else (
      event Rel2(nS, m0, m1);
      if f1 = F1 then event Acc2(nS, m0, m1)
      else BlockN2(a, x, kS, kM0, nS, m0, m1, t1)
   ).

let Dec() =
   in(c, b0: bitstring);
   let blk(t0: bitstring, v0: bitstring, adf0: bitstring, mE0: bitstring) = b0 in
   let ad0(f0: bitstring, a: alg, nIV0: bitstring, nS: bitstring, i: bitstring, le: bitstring, lp: bitstring, hE: bitstring, kC: key) = adf0 in
   if v0 = V8 then
   let x = mkX8(nS, a, lp) in
   let kS = mkKS(uc, x) in
   if t0 = mac(kS, macin(v0, adf0, mE0, TL0)) then
   if kC <> NOKC then
   let h = (if hE = NOHINT then NOHINT else aead_dec(a, mkKH(uc, x), mkNIVH(nIV0, x), EMPTY, hE)) in
   event HintShown(nS, h);
   if lp = le then
   if i <> IC0 then
   let kM0 = mkKM0(p, uc, a, lp, nS, i) in
m4_ifdef({{MUT_NOKC}}, {{
   (* MUTATION: the stored k_C is never compared *)
}}, {{
   if kC = mkKC(kM0, nS) then
}})
   let m0 = aead_dec(a, kM0, nIV0, aad0(adf0), mE0) in
   if m0 <> EMPTY then (
      event Rel1(nS, m0);
      if f0 = F1 then event Acc1(nS, m0)
      else BlockN1(a, x, kS, kM0, nS, m0, t0)
   ).

(* ---------------------------------------------------------------------------------------- *)
(* Alice leaks a secret, when the scenario gives the attacker one *)

let Leaks() =
m4_ifdef({{LEAK_UC}}, {{   out(c, uc); }})
m4_ifdef({{LEAK_P}}, {{   out(c, p); }})
   0.

m4_ifdef({{SCN_SECRECY}}, {{
(* ======================================================================================== *)
(* C-S1, C-S2, C-H1, C-W1, C-W2: Alice encrypts the secret blocks MSG0..MSG2 and decrypts
   whatever she is sent. Decryption produces no output, so it gives the attacker no oracle. *)

query attacker(MSG0).
query attacker(MSG1).
query attacker(MSG2).
query attacker(HINT).
m4_ifdef({{LEAK_P}}, {{}}, {{
weaksecret p.
}})

let Alg(a: alg) =
   !Enc1P(a, MSG0) | !Enc2P(a, MSG0, MSG1) | !Enc3P(a, MSG0, MSG1, MSG2).

process
   Leaks() | Alg(GCM) | Alg(XCC) | Alg(AEGIS) | !Dec()
}})

m4_ifdef({{SCN_INTEGRITY}}, {{
(* ======================================================================================== *)
(* C-I1, C-I2, C-H2: Alice encrypts plaintexts the attacker chooses. Every message has a fresh
   n_S, so an accepted stream that matches no single honest encryption with the same n_S and
   the same block count is a forgery: truncation, extension, reorder, or splice. *)

query nS: bitstring, m0: bitstring;
   event(Acc1(nS, m0)) ==> event(Enc1(nS, m0)).
query nS: bitstring, m0: bitstring, m1: bitstring;
   event(Acc2(nS, m0, m1)) ==> event(Enc2(nS, m0, m1)).
query nS: bitstring, m0: bitstring, m1: bitstring, m2: bitstring;
   event(Acc3(nS, m0, m1, m2)) ==> event(Enc3(nS, m0, m1, m2)).

(* Streaming releases each block before the end of the stream is checked *)
query nS: bitstring, m0: bitstring;
   event(Rel1(nS, m0)) ==> event(EncPre1(nS, m0)).
query nS: bitstring, m0: bitstring, m1: bitstring;
   event(Rel2(nS, m0, m1)) ==> event(EncPre2(nS, m0, m1)).

query nS: bitstring, h: bitstring;
   event(HintShown(nS, h)) ==> event(HintMade(nS, h)).

(* Reachability: each of these must report false, meaning an honest run reaches it *)
query nS: bitstring, m0: bitstring; event(Acc1(nS, m0)).
query nS: bitstring, m0: bitstring, m1: bitstring; event(Acc2(nS, m0, m1)).
query nS: bitstring, m0: bitstring, m1: bitstring, m2: bitstring; event(Acc3(nS, m0, m1, m2)).

let Alg(a: alg) =
   (!in(c, m0: bitstring); Enc1P(a, m0)) |
   (!in(c, (m0: bitstring, m1: bitstring)); Enc2P(a, m0, m1)) |
   (!in(c, (m0: bitstring, m1: bitstring, m2: bitstring)); Enc3P(a, m0, m1, m2)).

process
   Leaks() | Alg(GCM) | Alg(XCC) | Alg(AEGIS) | !Dec()
}})

m4_ifdef({{SCN_COMMIT}}, {{
(* ======================================================================================== *)
(* C-K1: key commitment. The attacker picks every input, including both passwords and both
   credentials, and wins if one block 0 is accepted under two different (password, uc). *)

event AccK(alg, bitstring, password, key).

query b: bitstring, p1: password, u1: key, p2: password, u2: key;
   event(AccK(GCM, b, p1, u1)) && event(AccK(GCM, b, p2, u2)) ==> p1 = p2 && u1 = u2.
query b: bitstring, p1: password, u1: key, p2: password, u2: key;
   event(AccK(XCC, b, p1, u1)) && event(AccK(XCC, b, p2, u2)) ==> p1 = p2 && u1 = u2.
query b: bitstring, p1: password, u1: key, p2: password, u2: key;
   event(AccK(AEGIS, b, p1, u1)) && event(AccK(AEGIS, b, p2, u2)) ==> p1 = p2 && u1 = u2.

(* Reachability: an honest round trip is accepted *)
query a: alg, b: bitstring, p1: password, u1: key; event(AccK(a, b, p1, u1)).

m4_ifdef({{USE_V7}}, {{
(* V7 block 0 (keys.ts:632-793): no e_l in the context, no p_l in the PBKDF2 material, and k_C is
   folded into the AEAD AD instead of being stored and compared. *)
let DecK() =
   in(c, (b0: bitstring, pw: password, u: key));
   let blk(t0: bitstring, v0: bitstring, adf0: bitstring, mE0: bitstring) = b0 in
   let ad0v7(f0: bitstring, a: alg, nIV0: bitstring, nS: bitstring, i: bitstring, le: bitstring, lp: bitstring, hE: bitstring) = adf0 in
   if v0 = V7 then
   let x = xctx7(nS, a, V7, lp, EMPTY) in
   if t0 = mac(kdf(ID1, kpS, hmix(u, x)), macin(v0, adf0, mE0, TL0)) then
   if lp = le then
   if i <> IC0 then
   let kM0 = pbkdf(pwmat7(pw, u, a, V7, lp, EMPTY), nS, i) in
   let m0 = aead_dec(a, kM0, nIV0, aadv7(adf0, EMPTY, mkKC(kM0, nS)), mE0) in
   event AccK(a, b0, pw, u).

let EncK(a: alg) =
   in(c, (m0: bitstring, pw: password, u: key));
   new nS: bitstring; new nIV0: bitstring;
   let x = xctx7(nS, a, V7, LP1, EMPTY) in
   let kM0 = pbkdf(pwmat7(pw, u, a, V7, LP1, EMPTY), nS, IC) in
   let adf0 = ad0v7(F1, a, nIV0, nS, IC, LP1, LP1, NOHINT) in
   let mE0 = aead_enc(a, kM0, nIV0, aadv7(adf0, EMPTY, mkKC(kM0, nS)), m0) in
   out(c, blk(mac(kdf(ID1, kpS, hmix(u, x)), macin(V7, adf0, mE0, TL0)), V7, adf0, mE0)).
}}, {{
let DecK() =
   in(c, (b0: bitstring, pw: password, u: key));
   let blk(t0: bitstring, v0: bitstring, adf0: bitstring, mE0: bitstring) = b0 in
   let ad0(f0: bitstring, a: alg, nIV0: bitstring, nS: bitstring, i: bitstring, le: bitstring, lp: bitstring, hE: bitstring, kC: key) = adf0 in
   if v0 = V8 then
   let x = mkX8(nS, a, lp) in
   if t0 = mac(mkKS(u, x), macin(v0, adf0, mE0, TL0)) then
   if kC <> NOKC then
   if lp = le then
   if i <> IC0 then
   let kM0 = mkKM0(pw, u, a, lp, nS, i) in
m4_ifdef({{MUT_NOKC}}, {{
   (* MUTATION: the stored k_C is never compared *)
}}, {{
   if kC = mkKC(kM0, nS) then
}})
   let m0 = aead_dec(a, kM0, nIV0, adf0, mE0) in
   event AccK(a, b0, pw, u).

let EncK(a: alg) =
   in(c, (m0: bitstring, pw: password, u: key));
   new nS: bitstring; new nIV0: bitstring;
   let x = mkX8(nS, a, LP1) in
   let kM0 = mkKM0(pw, u, a, LP1, nS, IC) in
   let adf0 = ad0(F1, a, nIV0, nS, IC, LP1, LP1, NOHINT, mkKC(kM0, nS)) in
   let mE0 = aead_enc(a, kM0, nIV0, adf0, m0) in
   out(c, blk(mac(mkKS(u, x), macin(V8, adf0, mE0, TL0)), V8, adf0, mE0)).
}})

process
   !DecK() | !EncK(GCM) | !EncK(XCC) | !EncK(AEGIS)
}})

m4_ifdef({{SCN_LOOPS}}, {{
(* ======================================================================================== *)
(* C-I2, loops (tex 161-176, 223-247): a loop re-encrypts the previous loop's cipher data under
   its own password, with lp counting up to le. Decryption recurses while lp > 1 (cs:221-223),
   and only the outermost layer is checked for lp = le (cs:180-185). The inner layer is checked
   against the outer lp - 1. Each loop here is a single block.

   pIn protects one-loop messages and the inner layer of two-loop messages. pOut protects the
   outer layer. LEAK_POUT gives the attacker pOut, so it can open and rebuild outer layers. *)

free pIn: password [private].
free pOut: password [private].

event EncL1(bitstring, bitstring).
event EncL2(bitstring, bitstring, bitstring).
event AccL1(password, bitstring, bitstring).
event AccL2(password, password, bitstring, bitstring, bitstring).

(* The queries cover layers under pIn, which the attacker never learns. Anything under a
   password the attacker knows is the attacker's to forge. *)

(* A one-loop acceptance under pIn comes from a one-loop encryption: no layer was stripped *)
query nS: bitstring, m: bitstring; event(AccL1(pIn, nS, m)) ==> event(EncL1(nS, m)).
(* A two-loop acceptance matches one honest two-loop encryption exactly *)
query nSo: bitstring, nSi: bitstring, m: bitstring;
   event(AccL2(pOut, pIn, nSo, nSi, m)) ==> event(EncL2(nSo, nSi, m)).
(* An inner layer under pIn came from a two-loop encryption, even when the outer one has been
   rebuilt. This fails once the attacker knows pOut: nothing compares the inner le with the
   outer one (conformance.md I-17), so a one-loop message can be wrapped as an inner layer. *)
query pw: password, nSo: bitstring, nSi: bitstring, m: bitstring, nSo2: bitstring;
   event(AccL2(pw, pIn, nSo, nSi, m)) ==> event(EncL2(nSo2, nSi, m)).
(* The inner plaintext under pIn is always something Alice encrypted under pIn *)
query pw: password, nSo: bitstring, nSi: bitstring, m: bitstring, nSo2: bitstring;
   event(AccL2(pw, pIn, nSo, nSi, m)) ==> event(EncL2(nSo2, nSi, m)) || event(EncL1(nSi, m)).
query pw: password, nS: bitstring, m: bitstring; event(AccL1(pw, nS, m)).
query pw: password, pw2: password, nSo: bitstring, nSi: bitstring, m: bitstring; event(AccL2(pw, pw2, nSo, nSi, m)).

letfun validAlg(a: alg) = a = GCM || a = XCC || a = AEGIS.

(* Opens one single-block layer and returns (n_S, lp, m_0). The outermost layer must have
   lp = le; an inner layer must have lp = expLp. *)
letfun open0(pw: password, b0: bitstring, outermost: bool, expLp: bitstring) =
   let blk(t0: bitstring, v0: bitstring, adf0: bitstring, mE0: bitstring) = b0 in
   let ad0(f0: bitstring, a: alg, nIV0: bitstring, nS: bitstring, i: bitstring, le: bitstring, lp: bitstring, hE: bitstring, kC: key) = adf0 in
   let x = mkX8(nS, a, lp) in
   let h = (if hE = NOHINT then NOHINT else aead_dec(a, mkKH(uc, x), mkNIVH(nIV0, x), EMPTY, hE)) in
   let kM0 = mkKM0(pw, uc, a, lp, nS, i) in
   let m0 = aead_dec(a, kM0, nIV0, adf0, mE0) in
m4_ifdef({{MUT_NOLPLE}}, {{
   (* MUTATION: the outermost layer is not checked for lp = le *)
   if v0 = V8 && t0 = mac(mkKS(uc, x), macin(v0, adf0, mE0, TL0)) && kC <> NOKC &&
      (outermost || lp = expLp) &&
}}, {{
   if v0 = V8 && t0 = mac(mkKS(uc, x), macin(v0, adf0, mE0, TL0)) && kC <> NOKC &&
      ((outermost && lp = le) || (not(outermost) && lp = expLp)) &&
}})
      i <> IC0 && kC = mkKC(kM0, nS) && f0 = F1 && m0 <> EMPTY
   then (nS, lp, m0).

let DecL(pwO: password, pwI: password) =
   in(c, b: bitstring);
   let (nSo: bitstring, lpO: bitstring, mO: bitstring) = open0(pwO, b, true, EMPTY) in
   if lpO = LP1 then event AccL1(pwO, nSo, mO)
   else if lpO = LP2 then
   let (nSi: bitstring, lpI: bitstring, mI: bitstring) = open0(pwI, mO, false, LP1) in
   event AccL2(pwO, pwI, nSo, nSi, mI).

let EncL1P(pw: password) =
   in(c, (a: alg, m: bitstring));
   if validAlg(a) && m <> EMPTY then
   new nS: bitstring; new nIV: bitstring;
   event EncL1(nS, m);
   out(c, mkBlock0L(pw, a, nS, nIV, F1, LP1, LP1, m)).

let EncL2P(pwI: password, pwO: password) =
   in(c, (aI: alg, aO: alg, m: bitstring));
   if validAlg(aI) && validAlg(aO) && m <> EMPTY then
   new nSi: bitstring; new nIVi: bitstring; new nSo: bitstring; new nIVo: bitstring;
   let bi = mkBlock0L(pwI, aI, nSi, nIVi, F1, LP1, LP2, m) in
   event EncL2(nSo, nSi, m);
   out(c, mkBlock0L(pwO, aO, nSo, nIVo, F1, LP2, LP2, bi)).

process
   Leaks() |
m4_ifdef({{LEAK_POUT}}, {{   out(c, pOut) | }})
   !EncL1P(pIn) | !EncL2P(pIn, pOut) |
   !DecL(pIn, pIn) | !DecL(pIn, pOut) | !DecL(pOut, pIn) | !DecL(pOut, pOut)
}})

m4_ifdef({{SCN_DOWNGRADE}}, {{
(* ======================================================================================== *)
(* C-D1: the decryptor picks V7 or V8 from the unauthenticated v (ciph:87-100). Alice also has
   legacy V7 ciphertexts under the same p and uc. An accepted plaintext must come from an honest
   encryption of the same version with the same n_S. *)

event EncV7(bitstring, bitstring).
event EncV8(bitstring, bitstring).
event AccV7(bitstring, bitstring).
event AccV8(bitstring, bitstring).

query nS: bitstring, m0: bitstring; event(AccV7(nS, m0)) ==> event(EncV7(nS, m0)).
query nS: bitstring, m0: bitstring; event(AccV8(nS, m0)) ==> event(EncV8(nS, m0)).
query nS: bitstring, m0: bitstring; event(AccV7(nS, m0)).
query nS: bitstring, m0: bitstring; event(AccV8(nS, m0)).

letfun mkKM07(a: alg, nS: bitstring, lp: bitstring, i: bitstring) = pbkdf(pwmat7(p, uc, a, V7, lp, EMPTY), nS, i).

let EncV7P(a: alg) =
   in(c, m0: bitstring);
   new nS: bitstring; new nIV0: bitstring;
   let x = xctx7(nS, a, V7, LP1, EMPTY) in
   let kM0 = mkKM07(a, nS, LP1, IC) in
   let adf0 = ad0v7(F1, a, nIV0, nS, IC, LP1, LP1, NOHINT) in
   let mE0 = aead_enc(a, kM0, nIV0, aadv7(adf0, EMPTY, mkKC(kM0, nS)), m0) in
   event EncV7(nS, m0);
   out(c, blk(mac(kdf(ID1, kpS, hmix(uc, x)), macin(V7, adf0, mE0, TL0)), V7, adf0, mE0)).

let EncV8P(a: alg) =
   in(c, m0: bitstring);
   new nS: bitstring; new nIV0: bitstring;
   let b0 = mkBlock0(a, nS, nIV0, F1, m0) in
   event EncV8(nS, m0);
   out(c, b0).

let DecV() =
   in(c, b0: bitstring);
   let blk(t0: bitstring, v0: bitstring, adf0: bitstring, mE0: bitstring) = b0 in
   if v0 = V7 then (
      let ad0v7(f0: bitstring, a: alg, nIV0: bitstring, nS: bitstring, i: bitstring, le: bitstring, lp: bitstring, hE: bitstring) = adf0 in
      let x = xctx7(nS, a, V7, lp, EMPTY) in
      if t0 = mac(kdf(ID1, kpS, hmix(uc, x)), macin(v0, adf0, mE0, TL0)) then
      if lp = le then
      if i <> IC0 then
      let kM0 = mkKM07(a, nS, lp, i) in
      let m0 = aead_dec(a, kM0, nIV0, aadv7(adf0, EMPTY, mkKC(kM0, nS)), mE0) in
      if f0 = F1 then event AccV7(nS, m0)
   ) else if v0 = V8 then (
      let ad0(f0: bitstring, a: alg, nIV0: bitstring, nS: bitstring, i: bitstring, le: bitstring, lp: bitstring, hE: bitstring, kC: key) = adf0 in
      let x = mkX8(nS, a, lp) in
      if t0 = mac(mkKS(uc, x), macin(v0, adf0, mE0, TL0)) then
      if kC <> NOKC then
      if lp = le then
      if i <> IC0 then
      let kM0 = mkKM0(p, uc, a, lp, nS, i) in
      if kC = mkKC(kM0, nS) then
      let m0 = aead_dec(a, kM0, nIV0, adf0, mE0) in
      if f0 = F1 then event AccV8(nS, m0)
   ).

process
   Leaks() | !EncV7P(GCM) | !EncV7P(XCC) | !EncV7P(AEGIS) | !EncV8P(GCM) | !EncV8P(XCC) | !EncV8P(AEGIS) | !DecV()
}})

(* ======================================================================================== *)
(* Expected results, one block per variant. "is false" on a "not event" query means an honest
   run reaches that event. Every other "is false" is an attack the variant exists to show:
   a leaked secret the property depends on, or a mutation. *)

m4_ifdef({{VARIANT_secrecy_net}}, {{(* EXPECTPV
RESULT not attacker(MSG0[]) is true.
RESULT not attacker(MSG1[]) is true.
RESULT not attacker(MSG2[]) is true.
RESULT not attacker(HINT[]) is true.
RESULT Weak secret p is true.
END *)}})
m4_ifdef({{VARIANT_secrecy_uc}}, {{(* EXPECTPV
RESULT not attacker(MSG0[]) is true.
RESULT not attacker(MSG1[]) is true.
RESULT not attacker(MSG2[]) is true.
RESULT not attacker(HINT[]) is false.
RESULT Weak secret p is false.
END *)}})
m4_ifdef({{VARIANT_secrecy_p}}, {{(* EXPECTPV
RESULT not attacker(MSG0[]) is true.
RESULT not attacker(MSG1[]) is true.
RESULT not attacker(MSG2[]) is true.
RESULT not attacker(HINT[]) is true.
END *)}})
m4_ifdef({{VARIANT_secrecy_both}}, {{(* EXPECTPV
RESULT not attacker(MSG0[]) is false.
RESULT not attacker(MSG1[]) is false.
RESULT not attacker(MSG2[]) is false.
RESULT not attacker(HINT[]) is false.
END *)}})
m4_ifdef({{VARIANT_integrity_net}}, {{(* EXPECTPV
RESULT event(Acc1(nS_28,m0_10)) ==> event(Enc1(nS_28,m0_10)) is true.
RESULT event(Acc2(nS_28,m0_10,m1_7)) ==> event(Enc2(nS_28,m0_10,m1_7)) is true.
RESULT event(Acc3(nS_28,m0_10,m1_7,m2_4)) ==> event(Enc3(nS_28,m0_10,m1_7,m2_4)) is true.
RESULT event(Rel1(nS_28,m0_10)) ==> event(EncPre1(nS_28,m0_10)) is true.
RESULT event(Rel2(nS_28,m0_10,m1_7)) ==> event(EncPre2(nS_28,m0_10,m1_7)) is true.
RESULT event(HintShown(nS_28,h_1)) ==> event(HintMade(nS_28,h_1)) is true.
RESULT not event(Acc1(nS_28,m0_10)) is false.
RESULT not event(Acc2(nS_28,m0_10,m1_7)) is false.
RESULT not event(Acc3(nS_28,m0_10,m1_7,m2_4)) is false.
END *)}})
m4_ifdef({{VARIANT_integrity_uc}}, {{(* EXPECTPV
RESULT event(Acc1(nS_28,m0_10)) ==> event(Enc1(nS_28,m0_10)) is true.
RESULT event(Acc2(nS_28,m0_10,m1_7)) ==> event(Enc2(nS_28,m0_10,m1_7)) is true.
RESULT event(Acc3(nS_28,m0_10,m1_7,m2_4)) ==> event(Enc3(nS_28,m0_10,m1_7,m2_4)) is true.
RESULT event(Rel1(nS_28,m0_10)) ==> event(EncPre1(nS_28,m0_10)) is true.
RESULT event(Rel2(nS_28,m0_10,m1_7)) ==> event(EncPre2(nS_28,m0_10,m1_7)) is true.
RESULT event(HintShown(nS_28,h_1)) ==> event(HintMade(nS_28,h_1)) is false.
RESULT not event(Acc1(nS_28,m0_10)) is false.
RESULT not event(Acc2(nS_28,m0_10,m1_7)) is false.
RESULT not event(Acc3(nS_28,m0_10,m1_7,m2_4)) is false.
END *)}})
m4_ifdef({{VARIANT_integrity_p}}, {{(* EXPECTPV
RESULT event(Acc1(nS_28,m0_10)) ==> event(Enc1(nS_28,m0_10)) is true.
RESULT event(Acc2(nS_28,m0_10,m1_7)) ==> event(Enc2(nS_28,m0_10,m1_7)) is true.
RESULT event(Acc3(nS_28,m0_10,m1_7,m2_4)) ==> event(Enc3(nS_28,m0_10,m1_7,m2_4)) is true.
RESULT event(Rel1(nS_28,m0_10)) ==> event(EncPre1(nS_28,m0_10)) is true.
RESULT event(Rel2(nS_28,m0_10,m1_7)) ==> event(EncPre2(nS_28,m0_10,m1_7)) is true.
RESULT event(HintShown(nS_28,h_1)) ==> event(HintMade(nS_28,h_1)) is true.
RESULT not event(Acc1(nS_28,m0_10)) is false.
RESULT not event(Acc2(nS_28,m0_10,m1_7)) is false.
RESULT not event(Acc3(nS_28,m0_10,m1_7,m2_4)) is false.
END *)}})
m4_ifdef({{VARIANT_integrity_uc_nof}}, {{(* EXPECTPV
RESULT event(Acc1(nS_28,m0_10)) ==> event(Enc1(nS_28,m0_10)) is false.
RESULT event(Acc2(nS_28,m0_10,m1_7)) ==> event(Enc2(nS_28,m0_10,m1_7)) is false.
RESULT event(Acc3(nS_28,m0_10,m1_7,m2_4)) ==> event(Enc3(nS_28,m0_10,m1_7,m2_4)) is true.
RESULT event(Rel1(nS_28,m0_10)) ==> event(EncPre1(nS_28,m0_10)) is true.
RESULT event(Rel2(nS_28,m0_10,m1_7)) ==> event(EncPre2(nS_28,m0_10,m1_7)) is true.
RESULT event(HintShown(nS_28,h_11)) ==> event(HintMade(nS_28,h_11)) is false.
RESULT not event(Acc1(nS_28,m0_10)) is false.
RESULT not event(Acc2(nS_28,m0_10,m1_7)) is false.
RESULT not event(Acc3(nS_28,m0_10,m1_7,m2_4)) is false.
END *)}})
m4_ifdef({{VARIANT_integrity_uc_non}}, {{(* EXPECTPV
RESULT event(Acc1(nS_28,m0_10)) ==> event(Enc1(nS_28,m0_10)) is false.
RESULT event(Acc2(nS_28,m0_10,m1_7)) ==> event(Enc2(nS_28,m0_10,m1_7)) is false.
RESULT event(Acc3(nS_28,m0_10,m1_7,m2_4)) ==> event(Enc3(nS_28,m0_10,m1_7,m2_4)) is true.
RESULT event(Rel1(nS_28,m0_10)) ==> event(EncPre1(nS_28,m0_10)) is true.
RESULT event(Rel2(nS_28,m0_10,m1_7)) ==> event(EncPre2(nS_28,m0_10,m1_7)) is false.
RESULT event(HintShown(nS_28,h_1)) ==> event(HintMade(nS_28,h_1)) is false.
RESULT not event(Acc1(nS_28,m0_10)) is false.
RESULT not event(Acc2(nS_28,m0_10,m1_7)) is false.
RESULT not event(Acc3(nS_28,m0_10,m1_7,m2_4)) is false.
END *)}})
m4_ifdef({{VARIANT_integrity_net_emptymid}}, {{(* EXPECTPV
RESULT event(Acc1(nS_28,m0_10)) ==> event(Enc1(nS_28,m0_10)) is false.
RESULT event(Acc2(nS_28,m0_10,m1_7)) ==> event(Enc2(nS_28,m0_10,m1_7)) is true.
RESULT event(Acc3(nS_28,m0_10,m1_7,m2_4)) ==> event(Enc3(nS_28,m0_10,m1_7,m2_4)) is true.
RESULT event(Rel1(nS_28,m0_10)) ==> event(EncPre1(nS_28,m0_10)) is true.
RESULT event(Rel2(nS_28,m0_10,m1_7)) ==> event(EncPre2(nS_28,m0_10,m1_7)) is true.
RESULT event(HintShown(nS_28,h_1)) ==> event(HintMade(nS_28,h_1)) is true.
RESULT not event(Acc1(nS_28,m0_10)) is false.
RESULT not event(Acc2(nS_28,m0_10,m1_7)) is false.
RESULT not event(Acc3(nS_28,m0_10,m1_7,m2_4)) is false.
END *)}})
m4_ifdef({{VARIANT_commit_v8}}, {{(* EXPECTPV
RESULT event(AccK(GCM,b,p1,u1)) && event(AccK(GCM,b,p2,u2)) ==> p1 = p2 && u1 = u2 is true.
RESULT event(AccK(XCC,b,p1,u1)) && event(AccK(XCC,b,p2,u2)) ==> p1 = p2 && u1 = u2 is true.
RESULT event(AccK(AEGIS,b,p1,u1)) && event(AccK(AEGIS,b,p2,u2)) ==> p1 = p2 && u1 = u2 is true.
RESULT not event(AccK(a_4,b,p1,u1)) is false.
END *)}})
m4_ifdef({{VARIANT_commit_v8_nokc}}, {{(* EXPECTPV
RESULT event(AccK(GCM,b,p1,u1)) && event(AccK(GCM,b,p2,u2)) ==> p1 = p2 && u1 = u2 is false.
RESULT event(AccK(XCC,b,p1,u1)) && event(AccK(XCC,b,p2,u2)) ==> p1 = p2 && u1 = u2 is false.
RESULT event(AccK(AEGIS,b,p1,u1)) && event(AccK(AEGIS,b,p2,u2)) ==> p1 = p2 && u1 = u2 is true.
RESULT not event(AccK(a_4,b,p1,u1)) is false.
END *)}})
m4_ifdef({{VARIANT_commit_v7}}, {{(* EXPECTPV
RESULT event(AccK(GCM,b,p1,u1)) && event(AccK(GCM,b,p2,u2)) ==> p1 = p2 && u1 = u2 is false.
RESULT event(AccK(XCC,b,p1,u1)) && event(AccK(XCC,b,p2,u2)) ==> p1 = p2 && u1 = u2 is false.
RESULT event(AccK(AEGIS,b,p1,u1)) && event(AccK(AEGIS,b,p2,u2)) ==> p1 = p2 && u1 = u2 is true.
RESULT not event(AccK(a_4,b,p1,u1)) is false.
END *)}})
m4_ifdef({{VARIANT_loops_net}}, {{(* EXPECTPV
RESULT event(AccL1(pIn[],nS_12,m_2)) ==> event(EncL1(nS_12,m_2)) is true.
RESULT event(AccL2(pOut[],pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo_5,nSi_5,m_2)) is true.
RESULT event(AccL2(pw_1,pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo2,nSi_5,m_2)) is true.
RESULT event(AccL2(pw_1,pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo2,nSi_5,m_2)) || event(EncL1(nSi_5,m_2)) is true.
RESULT not event(AccL1(pw_1,nS_12,m_2)) is false.
RESULT not event(AccL2(pw_1,pw2,nSo_5,nSi_5,m_2)) is false.
END *)}})
m4_ifdef({{VARIANT_loops_uc}}, {{(* EXPECTPV
RESULT event(AccL1(pIn[],nS_12,m_2)) ==> event(EncL1(nS_12,m_2)) is true.
RESULT event(AccL2(pOut[],pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo_5,nSi_5,m_2)) is true.
RESULT event(AccL2(pw_1,pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo2,nSi_5,m_2)) is true.
RESULT event(AccL2(pw_1,pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo2,nSi_5,m_2)) || event(EncL1(nSi_5,m_2)) is true.
RESULT not event(AccL1(pw_1,nS_12,m_2)) is false.
RESULT not event(AccL2(pw_1,pw2,nSo_5,nSi_5,m_2)) is false.
END *)}})
m4_ifdef({{VARIANT_loops_uc_pout}}, {{(* EXPECTPV
RESULT event(AccL1(pIn[],nS_12,m_2)) ==> event(EncL1(nS_12,m_2)) is true.
RESULT event(AccL2(pOut[],pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo_5,nSi_5,m_2)) is false.
RESULT event(AccL2(pw_1,pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo2,nSi_5,m_2)) is false.
RESULT event(AccL2(pw_1,pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo2,nSi_5,m_2)) || event(EncL1(nSi_5,m_2)) is true.
RESULT not event(AccL1(pw_1,nS_12,m_2)) is false.
RESULT not event(AccL2(pw_1,pw2,nSo_5,nSi_5,m_2)) is false.
END *)}})
m4_ifdef({{VARIANT_loops_uc_pout_nolple}}, {{(* EXPECTPV
RESULT event(AccL1(pIn[],nS_12,m_2)) ==> event(EncL1(nS_12,m_2)) is false.
RESULT event(AccL2(pOut[],pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo_5,nSi_5,m_2)) is false.
RESULT event(AccL2(pw_1,pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo2,nSi_5,m_2)) is false.
RESULT event(AccL2(pw_1,pIn[],nSo_5,nSi_5,m_2)) ==> event(EncL2(nSo2,nSi_5,m_2)) || event(EncL1(nSi_5,m_2)) is true.
RESULT not event(AccL1(pw_1,nS_12,m_2)) is false.
RESULT not event(AccL2(pw_1,pw2,nSo_5,nSi_5,m_2)) is false.
END *)}})
m4_ifdef({{VARIANT_downgrade_uc}}, {{(* EXPECTPV
RESULT event(AccV7(nS_17,m0_8)) ==> event(EncV7(nS_17,m0_8)) is true.
RESULT event(AccV8(nS_17,m0_8)) ==> event(EncV8(nS_17,m0_8)) is true.
RESULT not event(AccV7(nS_17,m0_8)) is false.
RESULT not event(AccV8(nS_17,m0_8)) is false.
END *)}})
