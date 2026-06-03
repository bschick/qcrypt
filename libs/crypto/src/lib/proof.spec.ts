import { describe, it, expect, beforeEach } from 'vitest';
import { cryptoReady } from './crypto';
import { getRandom } from './utils';
import { getProofKeyPair, signProof, verifyProof } from './proof';

const KEY_CONTEXT = 'ProofKey';
const SIG_CONTEXT = 'qcrypt/usercred/proof/v1';

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
      expect(first.pubKey.length).toBe(1952);
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
      const signature = signProof(secKey, message, SIG_CONTEXT);
      expect(verifyProof(pubKey, message, signature, SIG_CONTEXT)).toBe(true);

      const tamperedMessage = message.slice();
      tamperedMessage[0] ^= 0x01;
      expect(() => verifyProof(pubKey, tamperedMessage, signature, SIG_CONTEXT)).toThrow();

      const tamperedSignature = signature.slice();
      tamperedSignature[0] ^= 0x01;
      expect(() => verifyProof(pubKey, message, tamperedSignature, SIG_CONTEXT)).toThrow();

      expect(() => verifyProof(pubKey, message, signature, 'qcrypt/other/v1')).toThrow();
   });
});
