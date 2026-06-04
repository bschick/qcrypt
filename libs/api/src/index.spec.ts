import { describe, it, expect, beforeEach } from 'vitest';
import { cryptoReady, getRandom } from '@qcrypt/crypto';
import { getUserCredPubKey, signUserCredProof, verifyUserCredProof } from './index';

describe('userCred proof', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('sign request and verfiy with derived public key', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, 'GET', '/v1/user', '1730000000000', 'abc');
      expect(verifyUserCredProof(pubKey, 'GET', '/v1/user', '1730000000000', 'abc', signature)).toBe(true);
   });

   it('throw when signed fields differs', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, 'POST', '/v1/passkeys', '100', 'aa');
      expect(() => verifyUserCredProof(pubKey, 'DELETE', '/v1/passkeys', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, 'POST', '/v1/other', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, 'POST', '/v1/passkeys', '101', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, 'POST', '/v1/passkeys', '100', 'bb', signature)).toThrow();
   });

   it('throw when a the wrong public key is used', () => {
      const signature = signUserCredProof(getRandom(32), 'GET', '/v1/user', '100', 'aa');
      const otherPubKey = getUserCredPubKey(getRandom(32));
      expect(() => verifyUserCredProof(otherPubKey, 'GET', '/v1/user', '100', 'aa', signature)).toThrow();
   });

   it('thow when the signature is manipulated', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, 'GET', '/v1/user', '100', 'aa');
      signature[0] ^= 0x01;
      expect(() => verifyUserCredProof(pubKey, 'GET', '/v1/user', '100', 'aa', signature)).toThrow();
   });
});
