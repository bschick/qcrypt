import { describe, it, expect, beforeEach } from 'vitest';
import { cryptoReady, getRandom } from '@qcrypt/crypto';
import { getUserCredProofPubKey, signUserCredProof, verifyUserCredProof } from './index';

describe('userCred proof', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('signs a request and verifies it with the derived public key', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredProofPubKey(userCred);
      const signature = signUserCredProof(userCred, 'GET', '/v1/user', '1730000000000', 'abc');
      expect(verifyUserCredProof(pubKey, 'GET', '/v1/user', '1730000000000', 'abc', signature)).toBe(true);
   });

   it('throws when any signed field differs', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredProofPubKey(userCred);
      const signature = signUserCredProof(userCred, 'POST', '/v1/passkeys', '100', 'aa');
      expect(() => verifyUserCredProof(pubKey, 'DELETE', '/v1/passkeys', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, 'POST', '/v1/other', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, 'POST', '/v1/passkeys', '101', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, 'POST', '/v1/passkeys', '100', 'bb', signature)).toThrow();
   });

   it('throws for a public key derived from a different userCred', () => {
      const signature = signUserCredProof(getRandom(32), 'GET', '/v1/user', '100', 'aa');
      const otherPubKey = getUserCredProofPubKey(getRandom(32));
      expect(() => verifyUserCredProof(otherPubKey, 'GET', '/v1/user', '100', 'aa', signature)).toThrow();
   });

   it('throws when the signature is manipulated', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredProofPubKey(userCred);
      const signature = signUserCredProof(userCred, 'GET', '/v1/user', '100', 'aa');
      signature[0] ^= 0x01;
      expect(() => verifyUserCredProof(pubKey, 'GET', '/v1/user', '100', 'aa', signature)).toThrow();
   });
});
