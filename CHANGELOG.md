# CHANGELOG.md

## 6.0.0 (2025-11-13)

Security:
  - protocol version 6 released
    - replaced WebCrypto HKDF-SHA512 with libsodium BLAKE2b-512 KDF
    - use KDF to generate block number specific encryption keys for all blocks after the first
    - moved block flags from header to additional data to be incluced in AEAD ciphers
  - store optional client-side password and hint cache as TypedArray to allow overwrite
  - purge more sensitive variables from JavaScript memory sooner
  - [Quick Crypt bug bounty program](https://www.openbugbounty.org/bugbounty/schickb/) is live and offering rewards
  - added MTA-STS and WKD OpenPGP support for domain email (thanks to: [Vaibhav jain](https://www.linkedin.com/in/vaibhav-jain-aa5680254/))

Changes:

  - fixed read buffer size bug causing read stalls and missing term blocks (functional only issue)
  - improve site docs to stress the importance of keeping recovery words private
  - added more testing of block order manipulation detection
  - package updates

## 5.2.3 (2025-10-31)

Security:
  - updated packages, fixing Angular SSR and node-tar CVEs
  - added csrf tokens at the suggestion of vibe buddy Jules (atop existing SameSite=Strict cookies)

Changes:

  - fixed text coloring of password strengths
  - switch to refactored server API
  - added more testing, in particular of the server API, including fuzzing
  - made unit tests headless using playwright over karma
  - significant trial-and-error updates to AGENTS.md to enable AI coding agents

## 5.2.2 (2025-09-27)

Security:
  - replaced outdated angular-password-strength-meter with custom component

Features:
  - minimum password strength can now be adjusted on the password entry dialog

Changes:

  - password entry dialog layout improvements
  - removed password strength meter on decryption password dialog
  - updated to angular@20

## 5.2.1 (2025-09-14)

Changes:

  - updated API calls to match server changes
  - more playwright e2e tests
  - package updates

## 5.2.0 (2025-09-02)

Security:
  - earlier and more explicit overwriting of variables containing sensitive data

Changes:

  - added playwright e2e testing (and addressed minor issues discovered during testing)
  - added versioning to server API path
  - improved handling of identity changes across browser tabs

## 5.1.1 (2025-08-02)

Changes:

  - fixed reminder toggle state management

## 5.1.0 (2025-08-01)

Security:

  - switched to bip39 word patterns for account recovery (removing the need to store user credentials)
  - switched to httponly JWT cookies for sessions (reducing transport of user credentials)
  - require reauthentication to retrieve sensitive information like recovery words
  - sign out affects all open Quick Crypt browser tabs and windows

Changes:

  - sessions now work across browser tabs and windows
  - reduced inactivity logout to 1.5 hours and max elapsed time logout to 3 hours
  - improved default input focus on a few pages

## 5.0.1 (2025-07-29)

Changes:

  - compatibility changes to prepare for 5.1.0 release

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
