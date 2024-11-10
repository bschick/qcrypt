# CHANGELOG.md

## 4.0.0 (2024-11-10)

Features:

  - added support for encryption and decrytion of files (even big files)
  - implemented [v4 encryption protocol](https://quickcrypt.org/help/protocol4)

Changes:

  - improved display and content of error messages
  - added documentation on cipher date binary structure
  - internally changed to [Streams API](https://developer.mozilla.org/en-US/docs/Web/API/Streams_API) to improve perf and simplify logic
  - updated various javascript packages
  - added test cases

Security:

  - moved loop encryption parameters into cipherdata so they cannot be manipulated post encryption
  - replaced SubtleCrypto HMAC algorithm with BLAKE2b keyed hash from libsodium

## 1.1.0 (2024-10-05)

Changes:

  -  hide option to encrypt in loops in preperation for version 4

## 1.0.0 (2024-01-28)

Features:

  - initial release