# Security Audit: Quick Crypt Encryption Protocol & Implementation

**Date:** 2026-02-01
**Scope:** Full codebase review with focus on encryption/decryption protocol, key derivation, cryptographic primitives, key management, input validation, and web security.
**Codebase version:** v6.1.1 (commit ebec571)

---

## Executive Summary

Quick Crypt is a well-designed, security-conscious browser-based encryption application. The V6 encryption protocol follows cryptographic best practices including MAC-before-decrypt (Doom Principle avoidance), AEAD ciphers with authenticated additional data, fresh random salt/IV per encryption, block-key derivation, MAC chaining, constant-time comparisons, and memory wiping of sensitive material. No high or critical severity issues were identified. Several low and informational findings are documented below.

---

## Protocol Overview (V6)

The V6 protocol encrypts data in blocks:

1. **Key derivation:** `PBKDF2-HMAC-SHA512(password || userCred, salt, iterations)` produces a 256-bit encryption key
2. **Signing key:** `BLAKE2b-KDF(userCred, context="cipherda...", instance=1)` produces a 256-bit signing key
3. **Hint key:** `BLAKE2b-KDF(userCred, context="hint enc", instance=1)` produces a 256-bit hint encryption key
4. **Block0:** Header (MAC + version + payload size) + Additional Data (flags, alg, IV, salt, IC, loop params, encrypted hint) + Encrypted Data (AEAD with additional data binding)
5. **BlockN:** Header + Additional Data (flags, alg, IV) + Encrypted Data using derived block key: `BLAKE2b-KDF(root_key, context="block en", instance=blockNum)`
6. **MAC chain:** Each block's MAC includes the previous block's MAC, preventing reordering/truncation

---

## Findings

### LOW-1: Hardcoded CSP Nonce in index.html

**File:** `src/index.html:42`
```html
<qcrypt-root ngCspNonce="ew26COJKMG8qrA/bjTcl0w=="></qcrypt-root>
```

**Description:** The `ngCspNonce` attribute contains a static, hardcoded nonce value. CSP nonces are designed to be unique per request to prevent inline script/style injection even if an attacker knows the CSP policy. A static nonce that is visible in the source code provides no protection against an attacker who can inject inline content, since they can simply include the same nonce.

**Impact:** Reduced effectiveness of nonce-based CSP for inline style protection. This is an Angular-specific attribute primarily used for Angular's inline styles. The actual CSP headers are likely configured at the deployment level (CloudFront/API Gateway), which may provide adequate protection through other CSP directives.

**Recommendation:** Generate the nonce server-side per request and inject it into the HTML response. Angular supports this via server-side rendering or template injection.

---

### LOW-2: PBKDF2 Rather Than Memory-Hard KDF

**File:** `src/app/services/ciphers-current.ts:1716-1727`

**Description:** Password-based key derivation uses PBKDF2-HMAC-SHA512. While the iteration counts are substantial (minimum 420,000, default 1,000,000, max ~4.29 billion), PBKDF2 is not memory-hard. It is vulnerable to acceleration by GPUs and ASICs because each PBKDF2 iteration requires minimal memory.

**Impact:** An attacker with GPU or ASIC hardware can test password candidates faster per dollar than on CPUs. Memory-hard KDFs like Argon2id or scrypt resist this by requiring significant RAM per computation, making parallel attacks expensive.

**Mitigating factors:**
- The Web Crypto API (SubtleCrypto) does not natively support Argon2 or scrypt, making PBKDF2 the practical choice for browser-based key derivation
- The high iteration counts and use of SHA-512 (which is less GPU-friendly than SHA-256) provide reasonable protection
- The userCred (32 bytes of server-managed entropy) is mixed into the password material, adding a second factor that an offline attacker would need

**Recommendation:** Document this trade-off. If browser support for Argon2id emerges in the Web Crypto API in the future, consider migrating. Alternatively, a JavaScript or WASM Argon2id implementation could be used, though with a performance penalty compared to native SubtleCrypto PBKDF2.

---

### LOW-3: Hint and Primary Ciphertext Share the Same IV

**File:** `src/app/services/ciphers-current.ts:524-529` (encryption), `src/app/services/ciphers-current.ts:1220-1225` (decryption)

**Description:** During Block0 encryption, the hint is encrypted using the same IV as the primary ciphertext, but with a different key (hint key `hk` vs. encryption key `ek`). The hint encryption call:
```typescript
encryptedHint = await EncipherV6._doEncrypt(eparams.alg, hk, iv, hintBytes);
```
uses the same `iv` that is later used for:
```typescript
const encryptedData = await EncipherV6._doEncrypt(eparams.alg, this._ek, iv, clearBuffer, additionalData);
```

**Impact:** For the three supported AEAD algorithms (AES-GCM, XChaCha20-Poly1305, AEGIS-256), using the same nonce with different keys is cryptographically safe. The critical constraint for these ciphers is that the same (key, nonce) pair is never reused, and that constraint is satisfied here since `hk != ek`. However, this pattern is unusual and could become problematic if future algorithm additions have multi-key nonce-reuse vulnerabilities.

**Recommendation:** Consider generating a separate IV for hint encryption, derived deterministically (e.g., by XORing the primary IV with a constant or using the KDF). This would eliminate the shared-nonce pattern at no performance cost.

---

### LOW-4: Standard Double-Quote Not Stripped in Cipher Armor Fallback Parser

**File:** `src/app/core/armor.ts:73`
```typescript
if (!trimmed.startsWith('{')) {
    trimmed = `{"ct":"${trimmed.replace(/[''"'"‚„\n\r\t\\ ]/g, '')}"}`;
}
```

**Description:** When `parseCipherArmor` receives bare (non-JSON) cipher text, it wraps it in a JSON object by string interpolation. The regex strips various Unicode quotation marks, whitespace, and backslashes, but does **not** strip the standard ASCII double-quote character (U+0022 `"`). An input containing `"` could break out of the JSON string value.

For example, input `AAAA","x":"y` would produce `{"ct":"AAAA","x":"y"}`, which parses as valid JSON with `ct = "AAAA"` and an extra property `x`.

**Impact:** Minimal in practice. The code only accesses `jsonParts.ct` and ignores other properties. Any injected or truncated `ct` value would fail during base64 decoding or AEAD decryption (authentication tag verification). There is no code path where injected JSON properties could cause harm.

**Recommendation:** Add `"` (U+0022) to the character stripping regex for defense in depth, or use a more robust approach such as encoding the raw input as base64 before JSON wrapping.

---

### LOW-5: Legacy V4 Protocol Weaknesses (Read-Only, Backward Compatibility)

**File:** `src/app/services/deciphers-old.ts`

**Description:** The V4 decryption protocol has two design limitations compared to V6:

1. **No MAC chaining (V4):** `DecipherV4._verifyMAC()` (line 520) does not include the previous block's MAC in the hash input. Individual blocks are authenticated, but an attacker who can modify the ciphertext stream could theoretically reorder blocks without detection by the MAC alone. (The AEAD authentication tags on each block provide some protection against this.)

2. **No block key derivation (V4):** `DecipherV4.decryptBlockN()` (line 447) uses the root encryption key directly for all blocks, unlike V6 which derives a unique key per block. With AES-GCM's 96-bit random nonce, the birthday bound applies after approximately 2^32 blocks encrypted with the same key.

**Impact:** These are legacy protocol limitations. V4 is used only for decrypting old data; all new encryption uses V6 which addresses both issues. No action needed unless a policy decision is made to drop V4 support.

**Recommendation:** Consider adding a deprecation notice or migration path for V4 encrypted data. Both V5 and V6 fix the MAC chaining issue; V6 also adds per-block key derivation.

---

### INFO-1: KDF Context Strings Exceed libsodium 8-Byte Limit

**File:** `src/app/services/ciphers-current.ts:74-76`
```typescript
export const KDF_INFO_SIGNING = "cipherdata signing key";  // 22 chars
export const KDF_INFO_HINT = "hint encryption key";        // 19 chars
export const KDF_INFO_BLOCK = "block encryption key";      // 20 chars
```

**Description:** `sodium.crypto_kdf_derive_from_key` expects an 8-byte context parameter (`crypto_kdf_CONTEXTBYTES = 8`). The context strings here are 19-22 bytes long. The libsodium-wrappers library truncates these to the first 8 bytes: "cipherd\0", "hint enc", "block en" respectively. The comment on line 73 says "To generate matching keys, these must not change" confirming these values are effectively frozen.

**Impact:** None. The truncated 8-byte prefixes are unique for each purpose, so key separation is maintained. However, the full string values are misleading since only the first 8 characters affect key derivation.

**Recommendation:** For clarity, either truncate the constants to 8 characters or add a comment documenting the truncation behavior.

---

### INFO-2: Console Logging of Errors and Benchmark Data

**Files:**
- `src/app/services/ciphers-current.ts:151-154` (benchmark logging)
- `src/app/services/ciphers-current.ts:574, 660, 923, 1233, 1358` (error logging)

**Description:** `console.error(err)` in catch blocks logs full error objects including stack traces. The benchmark function logs the device's hash rate, iteration count, and maximum iteration count. In production, this information is visible in the browser's developer console.

**Impact:** Minimal since this is client-side code. An attacker who has access to the developer console already has access to the page's JavaScript context. However, the benchmark data could help an attacker estimate the time required to brute-force passwords for a known iteration count, and detailed error messages could aid in understanding protocol internals.

**Recommendation:** Consider reducing log verbosity in production builds. The benchmark log could be gated behind a debug flag.

---

### INFO-3: 16-Byte Salt for PBKDF2

**File:** `src/app/services/cipher.consts.ts:35`
```typescript
export const SLT_BYTES = 16;
```

**Description:** The PBKDF2 salt is 16 bytes (128 bits). NIST SP 800-132 recommends at least 128 bits, so this meets the minimum. A 32-byte salt would provide additional margin against pre-computation attacks, particularly given the long intended lifetime of encrypted data.

**Impact:** Meets current standards. The 128-bit salt space (2^128 possible values) is large enough that salt collisions are astronomically unlikely even across all users and all encryptions.

**Recommendation:** No action required. A future protocol version could increase to 32 bytes for additional margin.

---

### INFO-4: No Explicit Minimum Password Length

**File:** `src/app/core/core.dialogs.ts:138`

**Description:** Password acceptance during encryption is governed by the zxcvbn strength score meeting a `minStrength` threshold. There is no hard minimum character length requirement. While zxcvbn would reject extremely short passwords as weak, the absence of an explicit length check means the policy is entirely strength-based.

**Impact:** Negligible. The zxcvbn library effectively prevents trivially short or weak passwords. A 1-character password would score 0 (weakest) and be rejected. The strength-based approach is generally considered superior to length-based policies.

**Recommendation:** No action needed. The strength-based approach is appropriate.

---

### INFO-5: Error Messages Include Internal State

**Files:** Multiple locations in `ciphers-current.ts`, `deciphers-old.ts`

**Description:** Error messages include specific values from internal state:
- `'Invalid ic of: ' + ic`
- `'Invalid version of: ' + ver`
- `'Cipher data length mismatch1: ' + payload.byteLength`
- `'Encipher invalid state ' + this._state`

**Impact:** Since all decryption happens client-side, there is no server-side oracle for an attacker to exploit. The error messages are visible only to the user in their own browser. In a server-side context these would be more concerning.

---

### INFO-6: localStorage Stores User Identifiers

**File:** `src/app/services/authenticator.service.ts:404-407`

**Description:** `localStorage` stores `userid`, `username`, `pkid`, `sessionexpiry`, and `activityexpiry`. These persist across browser sessions and are accessible to any JavaScript running on the same origin.

**Impact:** The stored values are identifiers and timestamps, not secrets. The `userCred` (the actual cryptographic credential) is only held in memory and is wiped on logout. If the origin were compromised via XSS, the identifiers could be used for user enumeration, but not for decryption.

---

## Positive Security Findings

The following security practices were verified and are commendable:

| Practice | Implementation | Location |
|----------|---------------|----------|
| **MAC-before-decrypt** | MAC verified before any decryption operation | `ciphers-current.ts:1208-1215` |
| **Constant-time MAC comparison** | Uses `sodium.memcmp()` | `ciphers-current.ts:1385` |
| **Fresh random salt + IV per encryption** | Generated via `sodium.randombytes_buf(48)` | `ciphers-current.ts:487-491` |
| **AEAD with Additional Data binding** | Algorithm, IV, salt, IC, flags bound to ciphertext | `ciphers-current.ts:545-551` |
| **MAC chaining (V6)** | Previous block MAC included in current MAC | `ciphers-current.ts:781` |
| **Terminal block validation (V6)** | Prevents block truncation and injection | `ciphers-current.ts:1305-1315` |
| **Per-block key derivation (V6)** | Unique derived key per block via BLAKE2b-KDF | `ciphers-current.ts:629` |
| **Memory wiping of keys** | Keys overwritten with random data before release | `ciphers-current.ts:116-124, 577-579, 663-665` |
| **Password material wiping** | `rawMaterial` and `pwdBytes` overwritten after PBKDF2 | `ciphers-current.ts:1707-1709` |
| **userCred wiped on logout** | `crypto.getRandomValues(this._userCred)` | `authenticator.service.ts:529` |
| **CSRF token protection** | `x-csrf-token` header on all API requests | `authenticator.service.ts:239` |
| **Session management** | 6-hour absolute + 1.5-hour activity timeout | `authenticator.service.ts:41-42` |
| **Password strength checking** | zxcvbn with custom matchers for reuse and hint similarity | `strengthmeter.component.ts` |
| **Sanitized innerHTML** | `DomSanitizer.sanitize(SecurityContext.HTML, ...)` | `core.component.ts` |
| **No dangerous APIs** | No `eval()`, `Function()`, or string-based `setTimeout` | Codebase-wide |
| **No cookie manipulation** | Session cookies managed server-side (HttpOnly) | `authenticator.service.ts` |
| **Parameter validation** | All cryptographic parameters validated before use | Throughout `ciphers-current.ts` |
| **Version-gated features** | Protocol version checked and enforced | `ciphers.ts:89-99` |
| **bypassSecurityTrust limited** | Only used for static asset SVG URLs | `core.component.ts:152-169` |

---

## Algorithm Assessment

| Algorithm | Implementation | Nonce Size | Tag Size | Assessment |
|-----------|---------------|------------|----------|------------|
| AES-256-GCM | Web Crypto API | 12 bytes | 16 bytes | Standard, correct usage. New key per encryption prevents nonce-reuse risk. |
| XChaCha20-Poly1305 | libsodium | 24 bytes | 16 bytes | Extended nonce eliminates birthday concerns. Good choice. |
| AEGIS-256 | libsodium | 32 bytes | 32 bytes | Modern, high-performance AEAD. Larger tag provides stronger authentication. |

All three algorithms are well-regarded AEAD constructions appropriate for this use case.

---

## Conclusion

The Quick Crypt encryption protocol and implementation demonstrate strong security engineering. The V6 protocol addresses known weaknesses from earlier versions (V1/V4) and implements defense-in-depth measures including MAC chaining, per-block key derivation, and terminal block verification. The client-side architecture eliminates most server-side attack vectors, and sensitive material is properly managed in memory.

The findings documented above are low severity or informational. The most actionable items are:
1. **LOW-1:** Generate CSP nonces server-side per request
2. **LOW-3:** Use a separate IV for hint encryption
3. **LOW-4:** Strip standard double-quotes in the armor fallback parser
4. **INFO-1:** Clarify KDF context string truncation behavior
