import { describe, it, expect, beforeEach } from 'vitest';
import { cryptoReady, getCrux } from './crypto';

const CONTEXT = new TextEncoder().encode('qcrypt/proof/v1');

describe('crux ML-DSA-65', () => {
   beforeEach(async () => {
      await cryptoReady();
   });

   it('keygen from a 32-byte seed is deterministic', () => {
      const crux = getCrux();
      const seed = new Uint8Array(32).fill(0x11);
      const first = crux.ml_dsa_65_keygen(seed);
      const second = crux.ml_dsa_65_keygen(seed);
      expect(first.pubKey).toEqual(second.pubKey);
      expect(first.secKey).toEqual(second.secKey);
      expect(first.pubKey.length).toBe(1952);
   });

   it('signs and verifies, and rejects tampering', () => {
      const crux = getCrux();
      const pair = crux.ml_dsa_65_keygen(new Uint8Array(32).fill(7));
      const message = new TextEncoder().encode('the exact request');
      const randomness = new Uint8Array(32).fill(3);
      const signature = crux.ml_dsa_65_sign(pair.secKey, message, CONTEXT, randomness);
      expect(signature.length).toBe(3309);
      expect(crux.ml_dsa_65_verify(pair.pubKey, message, CONTEXT, signature)).toBe(true);

      const tampered = signature.slice();
      tampered[0] ^= 0x01;
      expect(crux.ml_dsa_65_verify(pair.pubKey, message, CONTEXT, tampered)).toBe(false);
      expect(crux.ml_dsa_65_verify(pair.pubKey, new TextEncoder().encode('different'), CONTEXT, signature)).toBe(false);
   });
});
