# Quick Crypt: Easy, Trustworthy Personal Encryption

We created Quick Crypt to make it safe and convenient to encrypt sensitive data you want to store in insecure locations. Storing confidential information in note taking applications, planning services, online documents, or similar tools is convenient but risky. Quick Crypt's primary author wanted to store sensitive information in a note taking application and not be limited to the few services that provide end-to-end encryption. Even services that support encryption typically do not define their protocols, making them hard to trust. Installable open-source encryption tools are powerful and trustworthy, but tedious to use and remember. Strong encryption that you don't use isn't all that good in the end.

Thus, Quick Crypt. A small-batch text-focused cipher tool designed to be easy to use, trustworthy, and convenient. It encrypts and decrypts data using cryptographic features available in modern browsers to ensure **your confidential data never leaves your system**. After sign-in, Quick Crypt works even with network access disabled. AEAD ciphers, passwords you supply, and passkey-protected credentials deliver privacy, integrity, authenticity, and website forgery protection.

We designed Quick Crypt to make it easy to encrypt data and to decrypt that data days or years later without needing to remember or install complicated tools. Quick Crypt's cipher armor format provides an optional reminder or link to the decryption page, so you only need to remember the password you used for encryption and have your passkey. Understanding how Quick Crypt works is optional, but if you are interested, the [protocols are documented](https://quickcrypt.org/help/protocol) and the code is open-source under the MIT license. Bug reports and pull requests are welcome.

<ins>Design Goals</ins>
- Easy to use and hard to screw up
- Nothing to install and works on most devices
- Unencrypted data and passwords never leave your system
- Encryption options constrained to secure values
- Follows current cryptographic best practices
- Well defined and [documented protocols](https://quickcrypt.org/help/protocol)
- After sign-in, works fully offline
- Uses trusted AEAD cipher modes (AES 256 GCM, XChaCha20 Poly1305, AEGIS 256)
- Uses the latest web security protocols (csp, cors, sri, hsts, xfo, corp, etc.)
- Keep an (A+ rating from MDN Observatory)[https://developer.mozilla.org/en-US/observatory/analyze?host=quickcrypt.org]
- Open-source for peer review
- No adverts or trackers
= No personally identifiable information (PII) collected

<br />

[Live Site](https://quickcrypt.org)
<br />
[Server Repository](https://github.com/bschick/qcrypt-server)



