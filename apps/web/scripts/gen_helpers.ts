// AI-Assist: 100% Claude Code Generated
//
// Shared helpers for the cipher-vector generation scripts
// (gen_ciphers_vectors.ts, gen_ciphersvc_vectors.ts).

import {
   PWDKeyProvider,
   Ciphers,
   getLatestEncipher,
   bytesToBase64,
   readStreamAll,
} from '@qcrypt/crypto';
import type { ReadOpts } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';

export function streamFromStr(s: string): ReadableStream<Uint8Array> {
   const data = new TextEncoder().encode(s);
   return new Blob([data], { type: 'application/octet-stream' }).stream();
}

export function streamFromBytes(data: Uint8Array): ReadableStream<Uint8Array> {
   return new Blob([data], { type: 'application/octet-stream' }).stream();
}

export function bytesFromStr(s: string): Uint8Array {
   return new TextEncoder().encode(s);
}

// Monkey-patches Ciphers._encodeAdditionalData to override the `term` flag on
// the first invocation (block0) and on the invocation that has term=true (the
// natural last block). null = pass through. Restores the original on return.
export async function withTermOverride<T>(
   forceBlock0Term: boolean | null,
   forceBlockNTerm: boolean | null,
   fn: () => Promise<T>
): Promise<T> {
   const original = (Ciphers as any)._encodeAdditionalData.bind(Ciphers);
   let firstCall = true;
   (Ciphers as any)._encodeAdditionalData = (args: any) => {
      let force: boolean | null = null;
      if (firstCall) {
         force = forceBlock0Term;
         firstCall = false;
      } else if (args.term === true) {
         force = forceBlockNTerm;
      }
      if (force !== null) {
         args = { ...args, term: force };
      }
      return original(args);
   };
   try {
      return await fn();
   } finally {
      (Ciphers as any)._encodeAdditionalData = original;
   }
}

// Like withTermOverride, but forces the same term value on every block.
// Use to produce "All Term" (force=true) or "No Term" (force=false) corpora.
export async function withTermOverrideEvery<T>(
   force: boolean,
   fn: () => Promise<T>
): Promise<T> {
   const original = (Ciphers as any)._encodeAdditionalData.bind(Ciphers);
   (Ciphers as any)._encodeAdditionalData = (args: any) => {
      if ('term' in args) {
         args = { ...args, term: force };
      }
      return original(args);
   };
   try {
      return await fn();
   } finally {
      (Ciphers as any)._encodeAdditionalData = original;
   }
}

// Encrypts everything in `clearStream` through a single getLatestEncipher
// invocation (single loop), repeatedly calling encryptBlockN until done.
// Returns the concatenated cipher bytes.
export async function encryptOneLoop(
   clearStream: ReadableStream<Uint8Array>,
   userCred: Uint8Array,
   pwd: string,
   hint: string | undefined,
   alg: cc.CipherAlgs,
   ic: number,
   readOpts?: ReadOpts,
   customAd?: Uint8Array
): Promise<Uint8Array> {
   const kp = new PWDKeyProvider(userCred.slice(0), [pwd, hint], customAd);
   const encipher = getLatestEncipher(clearStream, kp, alg, 1, 1, ic, readOpts);
   const parts: Uint8Array[] = [];
   while (true) {
      const block = await encipher.encryptBlock();
      for (const p of block.parts) {
         parts.push(p);
      }
      // CipherState.Finished is the terminal state. Use the numeric form to
      // avoid importing the enum (see ciphers-current.ts).
      if (block.state === 4 /* CipherState.Finished */) break;
   }
   return concat(parts);
}

// Reads a stream fully, returning the concatenated bytes.
export async function readAllBytes(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
   const buf = await readStreamAll(stream);
   return buf instanceof Uint8Array ? buf : new TextEncoder().encode(buf as unknown as string);
}

export function concat(parts: Uint8Array[]): Uint8Array {
   let total = 0;
   for (const p of parts) total += p.byteLength;
   const out = new Uint8Array(total);
   let off = 0;
   for (const p of parts) {
      out.set(p, off);
      off += p.byteLength;
   }
   return out;
}

// Formats a Uint8Array as a TS literal: `new Uint8Array([1, 2, 3, ...])`
export function uint8ArrayLiteral(bytes: Uint8Array): string {
   return `new Uint8Array([${Array.from(bytes).join(', ')}])`;
}

export function toBase64(bytes: Uint8Array): string {
   return bytesToBase64(bytes);
}

let cachedRule: string | null = null;
function getRule(): string {
   if (cachedRule === null) {
      const width = Math.min(process.stdout.columns ?? 80, 100);
      cachedRule = '═'.repeat(width - 1);
   }
   return cachedRule;
}

export function printBanner(name: string): void {
   const rule = getRule();
   console.log(rule);
   console.log(`   ${name}`);
   console.log(rule);
}
