import { describe, it, expect, beforeEach } from 'vitest';
import { createHash } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
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
      const signatureHash = createHash('sha256').update(signature).digest('hex');
      expect(signatureHash).toBe('5fddef3cedd4640ec968e36eb22223e5cef6f460cd97b56ac2e6108b3de4f24c');
      expect(crux.ml_dsa_65_verify(pair.pubKey, message, CONTEXT, signature)).toBe(true);

      const tampered = signature.slice();
      tampered[0] ^= 0x01;
      expect(crux.ml_dsa_65_verify(pair.pubKey, message, CONTEXT, tampered)).toBe(false);
      expect(crux.ml_dsa_65_verify(pair.pubKey, new TextEncoder().encode('different'), CONTEXT, signature)).toBe(false);
   });
});

describe('crux manifest', () => {
   const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));
   const readRepo = (file: string) => readFileSync(`${repoRoot}${file}`, 'utf8');
   const manifest = JSON.parse(readRepo('libs/crypto/crux/manifest.json'));
   const recorded: [string, string][] = Object.entries({ ...manifest.inputs, ...manifest.outputs });

   it('lists every crux input and artifact', () => {
      const sources = readdirSync(`${repoRoot}libs/crypto/crux/src`, { recursive: true, encoding: 'utf8' })
         .filter((file) => file.endsWith('.rs'))
         .map((file) => `libs/crypto/crux/src/${file}`);
      const configs = ['Cargo.lock', 'Cargo.toml', 'regen.mjs', 'rust-toolchain.toml'].map(
         (file) => `libs/crypto/crux/${file}`,
      );
      expect(Object.keys(manifest.inputs).sort()).toEqual([...configs, ...sources].sort());
      expect(Object.keys(manifest.outputs).sort()).toEqual(
         ['qc_crux.d.ts', 'qc_crux.js', 'wasm.ts'].map((file) => `libs/crypto/src/lib/crux/${file}`),
      );
   });

   it('records the pinned tool versions', () => {
      const regen = readRepo('libs/crypto/crux/regen.mjs');
      expect(manifest.toolchain).toEqual({
         rustc: readRepo('libs/crypto/crux/rust-toolchain.toml').match(/channel = "([^"]+)"/)?.[1],
         'wasm-pack': regen.match(/WASM_PACK_VERSION = '([^']+)'/)?.[1],
         'wasm-opt': regen.match(/WASM_OPT_VERSION = '([^']+)'/)?.[1],
         'wasm-bindgen': readRepo('libs/crypto/crux/Cargo.lock').match(
            /name = "wasm-bindgen"\nversion = "([^"]+)"/,
         )?.[1],
      });
   });

   // A mismatch means crux source or artifacts changed without running pnpm build:libs:crux
   it.each(recorded)('%s matches manifest.json', (file, hash) => {
      const actual = createHash('sha256')
         .update(readFileSync(`${repoRoot}${file}`))
         .digest('hex');
      expect(actual).toBe(hash);
   });
});
