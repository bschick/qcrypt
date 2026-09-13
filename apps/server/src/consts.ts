/* MIT License

Copyright (c) 2025 Brad Schick

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE. */

import {
   PAYLOAD_SIZE_MIN,
   HEADER_BYTES_6P,
   ADDIONTAL_DATA_MAX_BYTES,
   AUTH_TAG_MAX_BYTES,
   ENCRYPTED_HINT_MAX_BYTES,
} from '@qcrypt/crypto/consts';

export const RETRIES = 3;
export const RPNAME = 'Quick Crypt';
export const ALGIDS = [24, 7, 3, 1, -7, -257];

export { RECOVERYID_BYTES, CHALLENGE_BYTES } from '@qcrypt/api';

export const USERID_BYTES = 16;
export const INVITABLEID_BYTES = 16;
export const USERCRED_BYTES = 32;
export const USERCRED_ENC_MIN_BYTES = USERCRED_BYTES + PAYLOAD_SIZE_MIN + HEADER_BYTES_6P;
export const USERCRED_ENC_MAX_BYTES =
   USERCRED_BYTES + AUTH_TAG_MAX_BYTES + ADDIONTAL_DATA_MAX_BYTES + HEADER_BYTES_6P - ENCRYPTED_HINT_MAX_BYTES;
export const JWTMATERIAL_BYTES = 32;
export const LINKID_BYTES = 16;
export const UNAME_LEN_BYTES = 1;
export const UNAME_MIN_LEN = 6;
export const UNAME_MAX_LEN = 31;

// export const CERT_VERSION = 1;
// export const CERT_VERSION_BYTES = 2;
// export const CERT_KEY_BYTES = 32; // crypto_sign_PUBLICKEYBYTES, but sodium global consts are not ready yet
// export const CERT_MAX_BYTES = CERT_VERSION_BYTES + CERT_KEY_BYTES + USERID_BYTES + UNAME_LEN_BYTES + Math.pow(2, UNAME_LEN_BYTES * 8);

export const NOUSER_ID = 'AAAAAAAAAAAAAAAAAAAAAA';

export const KMS_KEYID_NEW = process.env.KMSKeyId_New!;
export const KMS_KEYID_BACKUP = process.env.KMSKeyId_Old!;

// PROOF_SKEW_MS must stay below CHALLENGE_TTL_SECS or proof nonces expire within the window and replay becomes possible
export const PROOF_SKEW_MS = 120 * 1000;
export const CHALLENGE_TTL_SECS = 300;
