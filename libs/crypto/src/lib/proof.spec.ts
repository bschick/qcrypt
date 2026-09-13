import { describe, it, expect, beforeEach } from 'vitest';
import { cryptoReady } from './crypto';
import { getRandom, bufferToHexString } from './utils';
import { getProofKeyPair, createProof, verifyProof } from './proof';

const KEY_CONTEXT = 'ProofKey';
const SIG_CONTEXT = 'qcrypt/usercred/proof/v1';

// ML-DSA-65 sizes from FIPS 204
const PUBKEY_BYTES = 1952;
const SECKEY_BYTES = 4032;

async function sha256Hex(bytes: Uint8Array): Promise<string> {
   return bufferToHexString(await crypto.subtle.digest('SHA-256', bytes.slice(0) as Uint8Array<ArrayBuffer>));
}

function countingSecret(): Uint8Array<ArrayBuffer> {
   const secret = new Uint8Array(32);
   for (let pos = 0; pos < secret.length; pos++) {
      secret[pos] = pos;
   }
   return secret;
}

describe('proof primitive', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('derives a deterministic keypair from a secret and context', () => {
      const secret = getRandom(32);
      const first = getProofKeyPair(secret, KEY_CONTEXT);
      const second = getProofKeyPair(secret, KEY_CONTEXT);
      expect(first.pubKey).toEqual(second.pubKey);
      expect(first.secKey).toEqual(second.secKey);
      expect(first.pubKey.length).toBe(PUBKEY_BYTES);
   });

   /* Pinned because the server stores each account's derived public key. If a libcrux upgrade
    * changed keygen output, every stored key would stop matching what clients derive and every
    * account would fail proof verification, which these hashes catch before a release.
    */
   it('derives the keypair stored public keys were built from', async () => {
      const { pubKey, secKey } = getProofKeyPair(countingSecret(), KEY_CONTEXT);

      expect(pubKey.length).toBe(PUBKEY_BYTES);
      expect(secKey.length).toBe(SECKEY_BYTES);
      await expect(sha256Hex(pubKey)).resolves.toBe('c005b0bab26b7892397f67dea233776f09ab7236516451e999e378f1a1efe19b');
      await expect(sha256Hex(secKey)).resolves.toBe('c98811abde4d691c0badd284b95c6b5b99312e5c09f56a8991f058becf4d838f');
   });

   it('changes the keypair when the secret or the context changes', () => {
      const secret = getRandom(32);
      const base = getProofKeyPair(secret, KEY_CONTEXT).pubKey;
      expect(getProofKeyPair(getRandom(32), KEY_CONTEXT).pubKey).not.toEqual(base);
      expect(getProofKeyPair(secret, 'OtherKey').pubKey).not.toEqual(base);
   });

   it('rejects a secret shorter than the minimum', () => {
      expect(() => getProofKeyPair(getRandom(16), KEY_CONTEXT)).toThrow();
   });

   it('signs and verifies, throwing on a tampered message, tampered signature, or wrong context', () => {
      const { pubKey, secKey } = getProofKeyPair(getRandom(32), KEY_CONTEXT);
      const message = new TextEncoder().encode('qcrypt-usercred-v1\nGET\n/v1/user\n1730000000000\nabc');
      const signature = createProof(secKey, message, SIG_CONTEXT);
      expect(() => verifyProof(pubKey, message, signature, SIG_CONTEXT)).not.toThrow();

      const tamperedMessage = message.slice();
      tamperedMessage[0] ^= 0x01;
      expect(() => verifyProof(pubKey, tamperedMessage, signature, SIG_CONTEXT)).toThrow();

      const tamperedSignature = signature.slice();
      tamperedSignature[0] ^= 0x01;
      expect(() => verifyProof(pubKey, message, tamperedSignature, SIG_CONTEXT)).toThrow();

      expect(() => verifyProof(pubKey, message, signature, 'qcrypt/other/v1')).toThrow();
   });
});
