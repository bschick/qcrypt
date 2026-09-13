// AI-Assist: 100% Claude Code Generated
//
// Shared helpers for the cipher-vector generation scripts
// (gen_ciphers_vectors.ts, gen_ciphersvc_vectors.ts).

import {
   PWDKeyProvider,
   MasterKeyKeyProvider,
   Ciphers,
   getLatestEncipher,
   bytesToBase64,
   readStreamAll,
   concatArrays,
} from '@qcrypt/crypto';
import type { ReadOpts } from '@qcrypt/crypto';
import * as cc from '@qcrypt/crypto/consts';
import type { GeneratedBlock } from './splice_vectors.ts';

export function streamFromStr(s: string): ReadableStream<Uint8Array> {
   const data = new TextEncoder().encode(s);
   return new Blob([data], { type: 'application/octet-stream' }).stream();
}

export function streamFromBytes(data: Uint8Array<ArrayBuffer>): ReadableStream<Uint8Array> {
   return new Blob([data], { type: 'application/octet-stream' }).stream();
}

export function bytesFromStr(s: string): Uint8Array {
   return new TextEncoder().encode(s);
}

// Monkey-patches Ciphers._encodeAD to override the `term` flag on
// the first invocation (block0) and on the invocation that has term=true (the
// natural last block). null = pass through. Restores the original on return.
export async function withTermOverride<T>(
   forceBlock0Term: boolean | null,
   forceBlockNTerm: boolean | null,
   fn: () => Promise<T>,
): Promise<T> {
   const original = (Ciphers as any)._encodeAD.bind(Ciphers);
   let firstCall = true;
   (Ciphers as any)._encodeAD = (args: any) => {
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
      (Ciphers as any)._encodeAD = original;
   }
}

// Like withTermOverride, but forces the same term value on every block.
// Use to produce "All Term" (force=true) or "No Term" (force=false) corpora.
export async function withTermOverrideEvery<T>(force: boolean, fn: () => Promise<T>): Promise<T> {
   const original = (Ciphers as any)._encodeAD.bind(Ciphers);
   (Ciphers as any)._encodeAD = (args: any) => {
      if ('term' in args) {
         args = { ...args, term: force };
      }
      return original(args);
   };
   try {
      return await fn();
   } finally {
      (Ciphers as any)._encodeAD = original;
   }
}

// Encrypts everything in `clearStream` through a single getLatestEncipher
// invocation (single loop), repeatedly calling encryptBlockN until done.
// Returns the concatenated cipher bytes.
export async function encryptOneLoop(
   clearStream: ReadableStream<Uint8Array>,
   userCred: Uint8Array<ArrayBuffer>,
   pwd: string,
   hint: string | undefined,
   alg: cc.CipherAlgs,
   ic: number,
   readOpts?: ReadOpts,
   extraKeyMaterial?: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
   const kp = new PWDKeyProvider(userCred.slice(0), [pwd, hint], extraKeyMaterial);
   return encryptAllBlocks(getLatestEncipher(clearStream, kp, alg, 1, 1, ic, readOpts));
}

// Master keys carry no password, so the iteration count is unused and passed as zero
export async function encryptOneLoopMaster(
   clearStream: ReadableStream<Uint8Array>,
   masterKey: Uint8Array<ArrayBuffer>,
   alg: cc.CipherAlgs,
   readOpts?: ReadOpts,
   extraKeyMaterial?: Uint8Array<ArrayBuffer>,
): Promise<Uint8Array> {
   const kp = new MasterKeyKeyProvider(masterKey.slice(0), extraKeyMaterial);
   return encryptAllBlocks(getLatestEncipher(clearStream, kp, alg, 1, 1, 0, readOpts));
}

async function encryptAllBlocks(encipher: ReturnType<typeof getLatestEncipher>): Promise<Uint8Array> {
   const parts: Uint8Array[] = [];
   while (true) {
      const block = await encipher.encryptBlock();
      for (const p of block.parts) {
         parts.push(p);
      }
      // CipherState.Finished is the terminal state. Use the numeric form to
      // avoid importing the enum (see ciphers-current.ts).
      if (block.state === 4 /* CipherState.Finished */) {
         break;
      }
   }
   return concatArrays(parts);
}

// Reads a stream fully, returning the concatenated bytes.
export async function readAllBytes(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
   const buf = await readStreamAll(stream);
   return buf instanceof Uint8Array ? buf : new TextEncoder().encode(buf as unknown as string);
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

const collected: GeneratedBlock[] = [];

export function collectedBlocks(): GeneratedBlock[] {
   return collected;
}

/* Emits a whole versioned entry wrapped in the markers spliceInto() matches on, so
 * regenerating replaces one named region rather than each vector individually. Field
 * lines arrive already indented. The printed form includes the markers so a first time
 * paste carries them; the collected form omits them since splicing keeps them in place.
 */
export function printVersionedBlock(
   name: string,
   indent: string,
   ver: number,
   generator: string,
   fieldLines: string[],
): void {
   printGeneratedBlock(name, ver, indent, [
      `${indent}//v${ver} — generated by: pnpm ${generator}`,
      `${indent}{`,
      `${indent}   ver: ${ver},`,
      ...fieldLines,
      `${indent}},`,
   ]);
}

/* Takes the entry verbatim, for shapes other than the { ver, ... } object. Region names carry
 * the version so that raising CURRENT_VERSION cannot overwrite an older version's pinned
 * vectors: the new version's blocks find no region and the splice refuses.
 */
export function printGeneratedBlock(name: string, ver: number, indent: string, lines: string[]): void {
   const qualified = `v${ver}:${name}`;
   collected.push({ name: qualified, lines });

   console.log(`${indent}// BEGIN GENERATED: ${qualified}`);
   for (const line of lines) {
      console.log(line);
   }
   console.log(`${indent}// END GENERATED: ${qualified}`);
}
