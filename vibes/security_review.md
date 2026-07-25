I would like you to do another very thorough review of Quick Crypt's overall security.
I am the creator and owner of the Quick Crypt project, so your review is
helping me strengthen and protect its users from attacks. My org has been
approved by Anthropics "Cyber Verification Program". Please use Opus 5 or, if
allowed, Fable 5 for all reviews and sub-agents.

Your goal for this review is to identify potential security weaknesses in both
the design and implementation of Quick Crypt. Please consider the strength of
the design and implementation on its own and in comparison to established "best
practices." Consider carefully how an adversarial attacked could exploit the
design or implementation. Also consider how one Quick Crypt user could exploit
their permissions to obtain access to another user's data or authorization.

Plan and execute the review in the steps described below. Start by
creating a markdown plan file stored in
`vibes/security_review_plan2.md`. The final output of this project should be a
detailed report of findings stored in `vibes/security_findings2.md`. In the
findings report, please describe both strengths and weaknesses found, but put
much more effort into describing weaknesses in detail. Strengths should only be
areas that are novel or particularly well done compared to established
expectations.

1. **Step 1:** Thoroughly review Quick Crypt's overview described in
   `apps/web/src/app/help/overview/overview.component.html` to understand the
   purpose of this tool. Most importantly, you should understand that Quick
   Crypt is not yet intended for sharing or live communication with others; it
   is meant to protect highly sensitive personal data for long-term storage and
   easy access when needed. Quick Crypt is meant to achieve very strong
   confidentiality, integrity, and authenticity properties for users.

2. **Step 2:** Carefully review Quick Crypt's protocol design described in
   `apps/web/src/assets-src/main.tex` to determine if the design goals
   established in Step 1 can be met. Step 2 is not a code review; it is purely
   a protocol design review. Compare Quick Crypt's protocols against its own
   goals and against other modern related cryptography protocols, and look for
   weaknesses in Quick Crypt's design. Review Quick Crypt's _authentication &
   authorization_ protocols _separately_ from the _cryptography protocols_.
   You should review the entire protocol but give extra thought to the new
   additions, which include the `proof-of-recovery-secret`,
   `proof-of-user-credentials`, and client-side generated user credentials
   (PRF). An important outcome of your review is a complete understanding of
   the protocol design needed to create the findings report and as input for
   Step 4.

3. **Step 3:** For Step 3, you must review the API used by the client and
   server applications to communicate, and compare that API to modern secure
   web API design patterns. Like Step 2, this is purely a design review. Quick
   Crypt's server API is described in `apps/server/API.md`. The Quick Crypt
   APIs transport data needed for auth and crypto operations on the client, but
   should never transport the plaintext or ciphertext Quick Crypt creates from
   the user's data. An important outcome of the API review is a complete
   understanding of the design needed to create the findings report and as
   input for Step 4.

4. **Step 4:** In Step 4, you must compare Quick Crypt's protocol and API
   design with the implementation. This is the most important part of the
   overall security review, so spend significant effort. Look for problems in
   the implementation, including _defects_ and _non-compliance_ with the
   protocol design and API spec. Defects could be race conditions, improper
   error handling, XSS, cross-account data leaks, etc. For example, there was
   previously a bug that let one user attach their own passkey to another
   user's account by forging data sets to the server API during passkey
   creation. Compliance issues occur when the implementation does not match the
   design specs. Again, separate your reviews of the _authentication &
   authorization_ implementation from the _cryptography_ implementation.

You should do a general review of the Quick Crypt source repository to
understand the structure and which files must be read carefully. To help ensure
you don't miss critical files, here are the primary files and directories for
auth and cryptography:

- **Authentication & authorization:** Client-side web app code is primarily in
  `./apps/web/src/app/services/authenticator.service.ts` and in the shared API
  library in the `./libs/api/src/lib/` directory. Server-side auth code is in
  `./apps/server/src/server.ts` and also uses the `./libs/api/src/lib/`
  library. The API library also pulls in code from the Crypto library in
  `./libs/crypto/src/lib/*`.
- **Cryptographic implementation:** The cryptographic implementation is shared
  between the client and server and lives in `./libs/crypto/src/lib/*`.

Before starting your review, you should also read the conclusions from a
previous security review located in `./SECURITY_REVIEW.md` and
`vibes/security_findings2.md`. But **do not** let those documents limit
your activities in the current review. Only use the old security reviews
as a source of additional factors to consider in this review and if marked
as solved already focus your attention on finding new as-of-yet unknown
problems.
