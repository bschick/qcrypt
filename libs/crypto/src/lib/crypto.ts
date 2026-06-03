import type { Sodium, Crux } from './crypto-load';

// Lazy-loads libsodium + libcrux into one chunk instead of inflating main.

let _cryptoReady: Promise<void> | undefined;
let _sodium: Sodium | undefined;
let _crux: Crux | undefined;

export function cryptoReady(): Promise<void> {
   if (!_cryptoReady) {
      _cryptoReady = import('./crypto-load').then(async (mod) => {
         const loaded = await mod.load();
         _sodium = loaded.sodium;
         _crux = loaded.crux;
      });
   }
   return _cryptoReady;
}

export function getSodium(): Sodium {
   if (!_sodium) {
      throw new Error('crypto: cryptoReady() not awaited');
   }
   return _sodium;
}

export function getCrux(): Crux {
   if (!_crux) {
      throw new Error('crypto: cryptoReady() not awaited');
   }
   return _crux;
}
