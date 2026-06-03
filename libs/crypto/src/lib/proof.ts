import { getCrux, getSodium } from './crypto';
import { getRandom } from './utils';

export function getProofKeyPair(secret: Uint8Array, context: string): { pubKey: Uint8Array<ArrayBuffer>; secKey: Uint8Array<ArrayBuffer> } {
   const sodium = getSodium();
   if (secret.byteLength < sodium.crypto_kdf_KEYBYTES) {
      throw new Error('proof secret too short');
   }
   if (context.length !== sodium.crypto_kdf_CONTEXTBYTES) {
      throw new Error('proof context must be 8 bytes');
   }

   const seed = sodium.crypto_kdf_derive_from_key(32, 1, context, secret);
   const keyPair = getCrux().ml_dsa_65_keygen(seed);
   seed.fill(0);
   return keyPair;
}

export function signProof(secKey: Uint8Array, message: Uint8Array, context: string): Uint8Array<ArrayBuffer> {
   return getCrux().ml_dsa_65_sign(secKey, message, new TextEncoder().encode(context), getRandom(32));
}

export function verifyProof(pubKey: Uint8Array, message: Uint8Array, signature: Uint8Array, context: string): boolean {
   if (getCrux().ml_dsa_65_verify(pubKey, message, new TextEncoder().encode(context), signature)) {
      return true;
   }
   throw new Error('proof verification failed');
}
