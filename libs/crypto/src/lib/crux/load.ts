import init, * as crux from './qc_crux.js';
import { CRUX_WASM_BASE64 } from './wasm';
import { base64URLStringToBuffer } from '../base64';
import { ensureArrayBuffer } from '../utils';

export interface Crux {
   ml_dsa_65_keygen(seed: Uint8Array): { pubKey: Uint8Array<ArrayBuffer>; secKey: Uint8Array<ArrayBuffer> };
   ml_dsa_65_sign(sk: Uint8Array, message: Uint8Array, context: Uint8Array, randomness: Uint8Array): Uint8Array<ArrayBuffer>;
   ml_dsa_65_verify(pk: Uint8Array, message: Uint8Array, context: Uint8Array, signature: Uint8Array): boolean;
}

export async function loadCrux(): Promise<Crux> {
   await init({ module_or_path: new Uint8Array(base64URLStringToBuffer(CRUX_WASM_BASE64)) });
   return {
      ml_dsa_65_keygen(seed: Uint8Array) {
         const pair = crux.ml_dsa_65_keygen(seed);
         // getters copy pk/sk out of wasm, so free() releases the wasm keypair (and the secret) without invalidating them
         try {
            return { pubKey: ensureArrayBuffer(pair.pk), secKey: ensureArrayBuffer(pair.sk) };
         } finally {
            pair.free();
         }
      },
      ml_dsa_65_sign: (sk, message, context, randomness) => ensureArrayBuffer(crux.ml_dsa_65_sign(sk, message, context, randomness)),
      ml_dsa_65_verify: crux.ml_dsa_65_verify,
   };
}
