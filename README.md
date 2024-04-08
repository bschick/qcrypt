# QuickCrypt

A client-side browser "app" that encrypts and decrypts text using a password you provide. Quick Crypt uses cryptographic features built into modern browsers, ensuring that your password, clear text, and even encrypted cipher text do not unexpectedly traverse the internet.

[![Open in StackBlitz](https://developer.stackblitz.com/img/open_in_stackblitz.svg)](https://stackblitz.com/github/bschick/qcrypt)


<ins>Crypto Details</ins>
* Cryto Library: Browser native Web Crypto API
* Key Derivation: PBKDF2 using SHA-512 and selectable iterations (max of 0.5s of hashing or 800K)
* Key Length: 256 bits (max for web crypto)
* Encryption: AES with selectable mode of operation and optional HMAC-SHA256
* Random Data: random.org or window.crypto.getRandomValues
