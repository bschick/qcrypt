### Question ###
Looking for design review and feedback to improve the open source project below.

### Project justification ###
I recently switch from Evernote to Notion and found that Notion lacks a built-in text encrypt/decrypt capability. I've used Evernote's ability to do symmetric password based client-side encryption to store low to medium sensitive data for years and found it more convenient than installing another application and remembering how to use it (great encryption that you never use isn't all that great in the end). I'll also note that I never fully trusted Evernote's encryption since they provide little detail.

I looked for another tool that was convenient, trustworthy, and strong (in that order) to do password derived symmetric encryption for small amounts of text and did not like what I found. Since I also wanted a modest project to focus on, I created this and would appreciate some design feedback.

### Crypto basics ###
 - **Key Derivation:** PBKDF2 using SHA-512 and selectable iterations (default 0.5s of hashing with 800K minimum iterations)
 - **Salt, IV, Key:** Derived for each encryption action
 - **Block Encryption:** AES-256 (max for subtle crypto)
 - **Modes of Operation:** GCM, CBC, or CTR with optional HMAC-SHA256
 - **Encrypt-then-MAC:** I convinced myself it doesn't matter in this context, but stayed with the [best practice][1]
 - **Random data:** Perhaps a gimmick, but optionally from random.org or local pseudorandom

Is that sound?

### Other Goals ###
 - Very easy to use and hard to screw up
 - 100% client-side crypto, once the app loads networking could be disabled 
 - Open source for peer review and liberal license
 - Follow crypto best practices (this site has been very helpful)
 - Password derived keys with a decent password strength indicator
 - Customizable encryption options (constrained to values not known to be insecure)
 - Single page browser "app" that works across all devices with a modern browser
 - Use built-in W3C browser SubtleCrypto (for perf, trust, and x-platform)
 - No adverts, cookies, tracking, etc.
 - Achieve best web-app security rating (csp, strong cert, sri, hsts, xfo, etc..)

Since the crypto was relatively straightforward, and uses standardized functions, my focus was more on making the browser app as trustworthy as possible. I read various posts describing why web-apps are not as trustworthy as signed installable binaries, and that's probably still true, but the web has come a long way with CSP, SRI, and friends. I used observatory.mozilla.org and other free scanners to secure the app (still a few items to improve). Any suggestions about making web-apps trustworthy for this purpose?

You can try the app: https://qcrypt.schicks.net/<br>
Review the source code: https://github.com/bschick/qcrypt<br>
In particular review: [key derivation][2], [encryption][3], and [decryption][4]<br>

Suggestions and pull requests welcome!

  [1]: https://crypto.stackexchange.com/questions/202/should-we-mac-then-encrypt-or-encrypt-then-mac
  [2]: https://github.com/bschick/qcrypt/blob/v1.0.0/src/app/qcrypt.component.ts#L724
  [3]: https://github.com/bschick/qcrypt/blob/v1.0.0/src/app/qcrypt.component.ts#L782
  [4]: https://github.com/bschick/qcrypt/blob/v1.0.0/src/app/qcrypt.component.ts#L836



  Comment:
  Yes, I think codereview would be more suitable. Note that even if it was on topic, your question is also very open ended (how to make this tool better) and unlikely to be answered satisfactorily here.
  
  Codereview has pretty strickt rules (I do crypto code reviews there, finally hit 5k rep, hard place to get rep). I would never use any protocol that is not fully described, even if this is just password based encryption with an optional authentication tag added to it. Besides that, the site doesn't make clear what it can be used for. Just performing encryption is not a use case.



I am working on a tool that uses password derived keys for AES and a selectable modes of operation **to encrypt (and later decrypt) text for storage on an insecure media**. The tool is constrained to using only the functions provided by the browser [SubtleCrypto][1] API, which are described as "low-level cryptographic primitives that are very easy to misuse". The protocol below seems simple/typical, but I'd like to describe it more formally and ask if I've designed this well or not. Questions:

 1. How can I make the description below closer to what people in this field expect?
 2. What is the mathematical notation for array slicing. For example, in python `a[:128]`. Perhaps submatrix notation `a[1;1...128]`?
 3. Do you see problems with the protocol?


**~~Updated based on comments~~**

**Agents**<br>
$A$ - Alice<br>
$S$ - Browser with SubtleCrypto API<br>
$R$ - https://www.random.org/cgi-bin/randbyte?nbytes=32<br>
$D$ - Insecure persistent storage system<br>

**Browser Functions**<br>
$E_O$ - AES-256 cipher in mode of operation o<br>
$K$ - PBKDF2 512 bit key derivation function using SHA-512<br>
$H$ - 256 bit FIPS 198-1 HMAC tag generator<br>
$V$ - 256 bit FIPS 198-1 HMAC tag validator<br>
$P$ - Cryptographically strong pseudo random generator<br>

**Values**<br>
$m$ - Clear text message<br>
$p$ - Clear text password<br>
$c$ - Encrypted text<br>
$t$ - 256 bit HMAC tag<br>
$b$ - Valid or invalid HMAC tag<br>
$i$ - PBKDF2 iteration count (minimum 800,000)<br>
$o$ - Block cipher mode of operation (GCM, CBC, CTR)<br>
$r$ - 256 bits of true or pseudo random data<br>
$n_{IV}$ - 128 bit true or pseudo random initialization vector<br>
$n_S$ - 128 bit true or pseudo random salt<br>
$d$ - 512 bits of derived key material<br>
$k_C$ - 256 bit cipher key<br>
$k_S$ - 256 bit signing key<br>

 
**Message Encryption by A**<br>
$A \rightarrow S : m, p, i, o\\
S\textrm{ computes}:\\
\hspace{10pt}r = P(256) \lor S \overset{\textrm{https}}{\leftarrow} R\\
\hspace{10pt}n_S = r[0:128)\\
\hspace{10pt}n_{IV} = r[128:256)\\
\hspace{10pt}d = K(p, n_S, i)\\
\hspace{10pt}k_C = d[0:256)\\
\hspace{10pt}k_S = d[256:512)\\
\hspace{10pt}c = E_O(m, n_{IV}, k_C)\\
\hspace{10pt}t = H( c \mathbin\Vert n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i, k_S)\\
S \rightarrow A: t \mathbin\Vert c \mathbin\Vert  n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i$

**Message Storage by A**<br>
$A \rightarrow D: t \mathbin\Vert c \mathbin\Vert n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i$

**Message Decryption by A**<br>
$A \leftarrow D:  t \mathbin\Vert c \mathbin\Vert  n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i\\
A \rightarrow S:  p , t \mathbin\Vert c \mathbin\Vert  n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i\\
S\textrm{ computes}:\\
\hspace{10pt}d = K(p, n_S, i)\\
\hspace{10pt}k_C = d[0:256)\\
\hspace{10pt}k_S = d[256:512)\\
\hspace{10pt}b = V( c \mathbin\Vert n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i, k_S, t)\\
\hspace{10pt}\textrm{if }b:\\
\hspace{10pt}\hspace{10pt}m = E_O^{-1}(c, n_{IV}, k_C)\\
S \rightarrow A : b, m\textrm{ if }b$


  [1]: https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto


<html>

<b>Agents</b><br/>
<img src="https://math.vercel.app/?inline=A\textrm{ - Alice}" /><br/>
<img src="https://math.vercel.app/?inline=S\textrm{ - Browser with SubtleCrypto API}" /><br/>
<img src="https://math.vercel.app/?inline=R\textrm{ - https://www.random.org/cgi-bin/randbyte?nbytes=32}" /><br/>
<img src="https://math.vercel.app/?inline=D\textrm{ - Insecure persistent storage system}" /><br/>

<b>Browser Functions</b><br/>
<img src="https://math.vercel.app/?inline=E_O\textrm{ - AES-256 cipher in mode of operation }o" /><br/>
<img src="https://math.vercel.app/?inline=K\textrm{ - PBKDF2 512 bit key derivation function using SHA-512}" /><br/>
<img src="https://math.vercel.app/?inline=H\textrm{ - 256 bit FIPS 198-1 HMAC tag generator}" /><br/>
<img src="https://math.vercel.app/?inline=V\textrm{ - 256 bit FIPS 198-1 HMAC tag validator}" /><br/>
<img src="https://math.vercel.app/?inline=P\textrm{ - Cryptographically strong pseudo random generator}" /><br/>

<b>Variables</b><br/>
<img src="https://math.vercel.app/?inline=m\textrm{ - Clear text message}" /><br/>
<img src="https://math.vercel.app/?inline=p\textrm{ - Clear text password}" /><br/>
<img src="https://math.vercel.app/?inline=i\textrm{ - PBKDF2 iteration count (minimum 800,000)}" /><br/>
<img src="https://math.vercel.app/?inline=d\textrm{ - 512 bits of PBKDF2 derived key material}" /><br/>
<img src="https://math.vercel.app/?inline=k_C\textrm{ - 256 bit cipher key}" /><br/>
<img src="https://math.vercel.app/?inline=K_S\textrm{ - 256 bit signing key}" /><br/>
<img src="https://math.vercel.app/?inline=o\textrm{ - Block cipher mode of operation [GCM, CBC, CTR]}" /><br/>
<img src="https://math.vercel.app/?inline=r\textrm{ - 256 bits of true or pseudo random data}" /><br/>
<img src="https://math.vercel.app/?inline=n_{IV}\textrm{ - 128 bit true or pseudo random initialization vector}" /><br/>
<img src="https://math.vercel.app/?inline=n_S\textrm{ - 128 bit true or pseudo random salt}" /><br/>
<img src="https://math.vercel.app/?inline=c\textrm{ - Encrypted text}" /><br/>
<img src="https://math.vercel.app/?inline=t\textrm{ - 256 bit HMAC tag}" /><br/>
<img src="https://math.vercel.app/?inline=b\textrm{ - Valid or invalid HMAC tag}" /><br/>

 
**Message Encryption by A**<br>
$A \rightarrow S : m, p, i, o\\
S\textrm{ computes}:\\
\hspace{10pt}r = P(256) \lor S \overset{\textrm{https}}{\leftarrow} R\\
\hspace{10pt}n_S = r[0:128)\\
\hspace{10pt}n_{IV} = r[128:256)\\
\hspace{10pt}d = K(p, n_S, i)\\
\hspace{10pt}k_C = d[0:256)\\
\hspace{10pt}k_S = d[256:512)\\
\hspace{10pt}c = E_O(m, n_{IV}, k_C)\\
\hspace{10pt}t = H( c \mathbin\Vert n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i, k_S)\\
S \rightarrow A: t \mathbin\Vert c \mathbin\Vert  n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i$

**Message Storage by A**<br>
$A \rightarrow D: t \mathbin\Vert c \mathbin\Vert n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i$

**Message Decryption by A**<br>
$A \leftarrow D:  t \mathbin\Vert c \mathbin\Vert  n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i$\\
$A \rightarrow S:  p , t \mathbin\Vert c \mathbin\Vert  n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i$\\
S\textrm{ computes}:\\
\hspace{10pt}d = K(p, n_S, i)\\
\hspace{10pt}k_C = d[0:256)\\
\hspace{10pt}k_S = d[256:512)\\
\hspace{10pt}b = V( c \mathbin\Vert n_{IV} \mathbin\Vert n_S \mathbin\Vert o \mathbin\Vert i, k_S, t)\\
\hspace{10pt}\textrm{if }b:\\
\hspace{10pt}\hspace{10pt}m = E_O^{-1}(c, n_{IV}, k_C)\\
S \rightarrow A : b, m\textrm{ if }b$