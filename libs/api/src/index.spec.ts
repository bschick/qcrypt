import { describe, it, expect, beforeEach } from 'vitest';
import { cryptoReady, getRandom, bytesToBase64 } from '@qcrypt/crypto';
import { getUserCredPubKey, signUserCredProof, verifyUserCredProof } from './index';

describe('userCred proof', () => {
   let userId: string;

   beforeEach(async () => {
      await cryptoReady();
      userId = bytesToBase64(getRandom(16));
   });

   it('sign request and verfiy with derived public key', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, userId, 'GET', '/v1/user', '1730000000000', 'abc');
      expect(verifyUserCredProof(pubKey, userId, 'GET', '/v1/user', '1730000000000', 'abc', signature)).toBe(true);
   });

   it('throw when signed fields differs', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, userId, 'POST', '/v1/passkeys', '100', 'aa');
      const otherUserId = bytesToBase64(getRandom(16));
      expect(() => verifyUserCredProof(pubKey, otherUserId, 'POST', '/v1/passkeys', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, userId, 'DELETE', '/v1/passkeys', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, userId, 'POST', '/v1/other', '100', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, userId, 'POST', '/v1/passkeys', '101', 'aa', signature)).toThrow();
      expect(() => verifyUserCredProof(pubKey, userId, 'POST', '/v1/passkeys', '100', 'bb', signature)).toThrow();
   });

   it('throw when a the wrong public key is used', () => {
      const signature = signUserCredProof(getRandom(32), userId, 'GET', '/v1/user', '100', 'aa');
      const otherPubKey = getUserCredPubKey(getRandom(32));
      expect(() => verifyUserCredProof(otherPubKey, userId, 'GET', '/v1/user', '100', 'aa', signature)).toThrow();
   });

   it('thow when the signature is manipulated', () => {
      const userCred = getRandom(32);
      const pubKey = getUserCredPubKey(userCred);
      const signature = signUserCredProof(userCred, userId, 'GET', '/v1/user', '100', 'aa');
      signature[0] ^= 0x01;
      expect(() => verifyUserCredProof(pubKey, userId, 'GET', '/v1/user', '100', 'aa', signature)).toThrow();
   });
});
