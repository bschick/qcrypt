import { describe, it, expect, beforeEach } from 'vitest';
import { createHash, randomBytes } from 'node:crypto';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative, sep } from 'node:path';
import { fileURLToPath } from 'node:url';
import { cryptoReady, getCrux } from './crypto';
import init, { stack_bounds } from './crux/qc_crux.js';

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

// wasm memory outlives each call, so anything a call leaves there is readable until a later call overwrites it
describe('crux memory after each call', () => {
   let memory: WebAssembly.Memory;

   beforeEach(async () => {
      await cryptoReady();
      // Returns the instance that cryptoReady created
      memory = (await init()).memory;
   });

   function indexOf(haystack: Uint8Array, needle: Uint8Array): number {
      for (let pos = haystack.indexOf(needle[0]); pos !== -1; pos = haystack.indexOf(needle[0], pos + 1)) {
         if (needle.every((byte, offset) => haystack[pos + offset] === byte)) {
            return pos;
         }
      }
      return -1;
   }

   it('holds no seed or signing key bytes, and an all-zero stack, after keygen and sign', () => {
      // The stack can hold transformed key material that a search for the key bytes misses.
      // stack_bounds runs before keygen, so the stack zeroing after keygen also clears its frame.
      const [stackLow, stackHigh] = stack_bounds();
      expect(stackHigh).toBeGreaterThan(stackLow);
      const crux = getCrux();
      const seed = new Uint8Array(randomBytes(32));
      const { secKey } = crux.ml_dsa_65_keygen(seed);
      // ML-DSA-65 signing keys start with rho (32 bytes), K (32 bytes) and tr (64 bytes), then s1
      const secrets = {
         seed,
         K: secKey.slice(32, 64),
         s1: secKey.slice(128, 160),
         secKeyEnd: secKey.slice(-32),
      };
      const nowhere = { seed: -1, K: -1, s1: -1, secKeyEnd: -1 };
      const expectNoResidue = (step: string) => {
         const bytes = new Uint8Array(memory.buffer);
         const found = Object.fromEntries(
            Object.entries(secrets).map(([name, secret]) => [name, indexOf(bytes, secret)]),
         );
         expect(found, `${step}: offsets of secrets in wasm memory`).toEqual(nowhere);
         expect(
            bytes.subarray(stackLow, stackHigh).findIndex((byte) => byte !== 0),
            `${step}: stack`,
         ).toBe(-1);
      };

      expectNoResidue('keygen');
      const message = new TextEncoder().encode('the exact request');
      crux.ml_dsa_65_sign(secKey, message, CONTEXT, new Uint8Array(randomBytes(32)));
      expectNoResidue('sign');
      // Copies the signing key onto the stack before rejecting the randomness
      expect(() => crux.ml_dsa_65_sign(secKey, message, CONTEXT, new Uint8Array(31))).toThrow();
      expectNoResidue('failed sign');
   });
});

describe('crux manifest', () => {
   const repoRoot = fileURLToPath(new URL('../../../../', import.meta.url));
   const readRepo = (file: string) => readFileSync(`${repoRoot}${file}`, 'utf8');
   const manifest = JSON.parse(readRepo('libs/crypto/crux/manifest.json'));
   const recorded: [string, string][] = Object.entries({ ...manifest.inputs, ...manifest.outputs });

   it('lists every crux input and artifact', () => {
      // Every crate file the build can read, except build outputs and macOS .DS_Store files
      const crateDir = `${repoRoot}libs/crypto/crux`;
      const inputs = readdirSync(crateDir, { recursive: true, withFileTypes: true })
         .filter((entry) => entry.isFile() && entry.name !== '.DS_Store')
         .map((entry) => relative(crateDir, join(entry.parentPath, entry.name)))
         .filter((file) => !['manifest.json', 'pkg', 'target'].includes(file.split(sep)[0]))
         .map((file) => `libs/crypto/crux/${file}`);
      expect(Object.keys(manifest.inputs).sort()).toEqual(inputs.sort());
      expect(Object.keys(manifest.outputs).sort()).toEqual(
         ['qc_crux.d.ts', 'qc_crux.js', 'wasm.ts'].map((file) => `libs/crypto/src/lib/crux/${file}`),
      );
   });

   it('records the pinned tool versions', () => {
      const containerfile = readRepo('libs/crypto/crux/Containerfile');
      const containerPin = (name: string) => containerfile.match(new RegExp(`^ARG ${name}=(\\S+)$`, 'm'))?.[1];
      expect(manifest.toolchain).toEqual({
         rustc: readRepo('libs/crypto/crux/rust-toolchain.toml').match(/channel = "([^"]+)"/)?.[1],
         'wasm-pack': containerPin('WASM_PACK_VERSION'),
         'wasm-opt': containerPin('WASM_OPT_VERSION'),
         'wasm-bindgen': readRepo('libs/crypto/crux/Cargo.lock').match(
            /name = "wasm-bindgen"\nversion = "([^"]+)"/,
         )?.[1],
      });
      expect(containerPin('WASM_BINDGEN_VERSION')).toBe(manifest.toolchain['wasm-bindgen']);
   });

   // A mismatch means crux source or artifacts changed without running pnpm build:libs:crux
   it.each(recorded)('%s matches manifest.json', (file, hash) => {
      const actual = createHash('sha256')
         .update(readFileSync(`${repoRoot}${file}`))
         .digest('hex');
      expect(actual).toBe(hash);
   });
});
