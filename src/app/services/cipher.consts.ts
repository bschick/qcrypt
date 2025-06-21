/* MIT License

Copyright (c) 2024 Brad Schick

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

export const AES_GCM_TAG_BYTES = 16;
export const X20_PLY_TAG_BYTES = 16; // sodium.crypto_aead_xchacha20poly1305_IETF_ABYTES, is not ready yet
export const AEGIS_256_TAG_BYTES = 32; // sodium.crypto_aead_aegis256_ABYTES, is not ready yet
export const AUTH_TAG_MAX_BYTES = Math.max(X20_PLY_TAG_BYTES, AES_GCM_TAG_BYTES, AEGIS_256_TAG_BYTES);
export const AUTH_TAG_MIN_BYTES = Math.min(X20_PLY_TAG_BYTES, AES_GCM_TAG_BYTES, AEGIS_256_TAG_BYTES);

export const ENCRYPTED_HINT_MAX_BYTES = 255;
export const ENCRYPTED_HINT_MIN_BYTES = 0;
export const HINT_LEN_BYTES = 1;
export const IV_MIN_BYTES = 12;
export const IV_MAX_BYTES = 32;
export const ALG_BYTES = 2;
export const SLT_BYTES = 16;
export const IC_BYTES = 4;
export const LPP_BYTES = 1;
export const VER_BYTES = 2;
export const MAC_BYTES = 32;
export const USERCRED_BYTES = 32;
export const PAYLOAD_SIZE_BYTES = 3;
export const FLAGS_BYTES = 1;

// Changing this is the future will be messy. Better change version and put
// length changes into the payload
export const HEADER_BYTES = MAC_BYTES + VER_BYTES + PAYLOAD_SIZE_BYTES + FLAGS_BYTES;

export const PAYLOAD_SIZE_MIN = IV_MIN_BYTES + ALG_BYTES + AUTH_TAG_MIN_BYTES + 1;
export const PAYLOAD_SIZE_MAX = 16777215;  // limit to 3 bytes size (extra byte is reserved)

export const ADDIONTAL_DATA_MAX_BYTES = ALG_BYTES + IV_MAX_BYTES + IC_BYTES + SLT_BYTES + LPP_BYTES + HINT_LEN_BYTES + ENCRYPTED_HINT_MAX_BYTES;
export const CLEAR_DATA_MAX_BYTES = PAYLOAD_SIZE_MAX - ADDIONTAL_DATA_MAX_BYTES;

export const LP_MAX = 16;
export const ICOUNT_MIN = 420000;
export const ICOUNT_DEFAULT = 1000000;
export const ICOUNT_MAX = 4294000000; // limited to 4 bytes unsigned rounded to millions

// Change version number when the encoding format changes or we add a new
// cipher algorithm
export const VERSION1 = 1;
export const VERSION4 = 4;
export const VERSION5 = 5;
export const CURRENT_VERSION = VERSION5;
export const V1_BELOW = VERSION4 // leave fixed at 4

// needs to fit into 255 bytes encypted... this allows for all double byte + max auth tag
export const HINT_MAX_LEN = Math.trunc(ENCRYPTED_HINT_MAX_BYTES / 2 - AUTH_TAG_MAX_BYTES);

export const AlgInfo: { [key: string]: { [key: string]: string | number } } = {
   'AES-GCM': { 'id': 1, 'description': 'AES 256 GCM', 'iv_bytes': 12 },
   'X20-PLY': { 'id': 2, 'description': 'XChaCha20 Poly1305', 'iv_bytes': 24 },
   'AEGIS-256': { 'id': 3, 'description': 'AEGIS 256', 'iv_bytes': 32 },
};
