# CHANGELOG.md

## 5.0.0 (2025-06-22)

Security:

  - prevent block reordering or deletion in large clear text encryption
  - replaced WebCrypto getRandomValues function with libsodium randombytes_buf
  - increased min PBKDF2-HMAC-SHA512 iterations to 420,000 (max remains 4,294,000,000)
  - removed option to retrieve random data from https://random.org

Changes:

  - protocol and its description updated to v5
  - various other doc updates
  - improved enchiper and decipher state tracking
  - added a template for inspecting cipherdata files using [Hex Fiend](https://hexfiend.com/) on macOS
  - package updates

## 4.2.2 (2025-06-10)

Changes:

  - decrypt links now work through login redirects
  - improved layout of encryption options
  - small corrections to protocol description
  - other small doc updates
  - package updates

## 4.2.1 (2025-01-12)

Security:

  - automatically close password dialog when inactive

Changes:

  - fixed top nav button highlight problem
  - fixed some bubble help positioning issues (still not great)
  - improved password dialog resizing on small screens
  - various small material 3 layout fixes
  - minor doc updates
  - package updates

## 4.2.0 (2024-12-31)

Changes:

  - updated to angular 19 and material 3
  - changed styling to align with material 3
  - updated other packages

## 4.1.0 (2024-11-24)

Features:

  - added the ability to set a different cipher mode for each encryption loop
  - added a stand-alone command-line tool that can decrypt, encrypt, and show info

Changes:

  - updated simplewebauthn to v11 in web app (and server)
  - various documentation improvements

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
