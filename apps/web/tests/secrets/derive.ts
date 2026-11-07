import { mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import sodium from 'libsodium-wrappers';
import * as api from '@qcrypt/api';
import {
   base64ToBytes,
   bytesToBase64,
   cryptoReady,
   decryptStream,
   getProofKeyPair,
   MasterKeyKeyProvider,
   parseCipherArmor,
   PROOF_SEED_BYTES,
   PWDKeyProvider,
   readStreamAll,
   setLogErrors,
   streamFromBytes,
   type KeyProvider,
} from '@qcrypt/crypto';
import { byteSecret, textSecret, type Secret } from './heapscan';

async function ready(): Promise<void> {
   await cryptoReady();
   await sodium.ready;
}

const MLDSA_RHO_BYTES = 32;
const MLDSA_K_BYTES = 32;
const MLDSA_TR_BYTES = 64;
const MLDSA_S1_OFFSET = MLDSA_RHO_BYTES + MLDSA_K_BYTES + MLDSA_TR_BYTES;
const S1_SAMPLE_BYTES = 32;

// The seed mirrors the derivation inside getProofKeyPair. ML-DSA-65 signing keys start with rho, K and tr,
// then s1, so K and the start of s1 stand in for the whole key. Each key pair is checked against the public
// key that libs/api computes, so a mismatch throws instead of silently searching for the wrong bytes.
function proofSecrets(prefix: string, secret: Uint8Array, context: string, expectedPubKey: string): Secret[] {
   const { pubKey, secKey } = getProofKeyPair(secret, context);
   if (bytesToBase64(pubKey) !== expectedPubKey) {
      throw new Error(`${prefix}: proof key derivation does not match libs/api`);
   }
   return [
      byteSecret(`${prefix}.proofSeed`, sodium.crypto_kdf_derive_from_key(PROOF_SEED_BYTES, 1, context, secret)),
      byteSecret(`${prefix}.proofKeyK`, secKey.slice(MLDSA_RHO_BYTES, MLDSA_RHO_BYTES + MLDSA_K_BYTES), false),
      byteSecret(`${prefix}.proofKeyS1`, secKey.slice(MLDSA_S1_OFFSET, MLDSA_S1_OFFSET + S1_SAMPLE_BYTES), false),
   ];
}

export async function userCredSecrets(userCred: string): Promise<Secret[]> {
   await ready();
   const bytes = new Uint8Array(Buffer.from(userCred, 'base64url'));
   return [
      byteSecret('userCred', bytes),
      ...proofSecrets('userCred', bytes, api.USERCRED_KEY_CONTEXT, api.getUserCredPubKey(bytes)),
   ];
}

function spacedWords(words: string): string {
   return words.trim().split(/\s+/).join(' ');
}

export function decodeRecoveryWords(words: string): Uint8Array {
   return mnemonicToEntropy(spacedWords(words), wordlist);
}

// The words encode recoveryId followed by the userId. Only recoveryId is secret.
export async function recoverySecrets(prefix: string, words: string): Promise<Secret[]> {
   await ready();
   const spaced = spacedWords(words);
   const wordsSecret = textSecret(`${prefix}.words`, words);
   if (spaced !== words) {
      wordsSecret.texts.push(['spaced', spaced]);
   }
   const secret = decodeRecoveryWords(words);
   return [
      wordsSecret,
      byteSecret(`${prefix}.id`, secret.slice(0, api.RECOVERYID_BYTES)),
      byteSecret(`${prefix}.secret`, secret),
      ...proofSecrets(prefix, secret, api.RECOVERY_KEY_CONTEXT, api.getRecoveryPubKey(secret)),
   ];
}

type RecordedKeys = { alg?: string; keys: Map<string, Uint8Array> };

// Copies every key the wrapped provider hands out, including those of cloned providers, before purge wipes them
class RecordingKeyProvider implements KeyProvider {
   constructor(
      private readonly _inner: KeyProvider,
      private readonly _recorded: RecordedKeys,
   ) {}

   purge(): void {
      this._inner.purge();
   }

   clone(): KeyProvider {
      return new RecordingKeyProvider(this._inner.clone(), this._recorded);
   }

   setCipherDataInfo(cdInfo: Parameters<KeyProvider['setCipherDataInfo']>[0]): void {
      this._recorded.alg = cdInfo.alg;
      this._inner.setCipherDataInfo(cdInfo);
   }

   setHint(hint: string | undefined): void {
      this._inner.setHint(hint);
   }

   getCipherDataInfo(): ReturnType<KeyProvider['getCipherDataInfo']> {
      return this._inner.getCipherDataInfo();
   }

   async getCipherKey(encrypting: boolean): Promise<Uint8Array<ArrayBuffer>> {
      return this._record('cipherKey', await this._inner.getCipherKey(encrypting));
   }

   async getBlockCipherKey(blockNum: number): Promise<Uint8Array<ArrayBuffer>> {
      return this._record(`blockKey${blockNum}`, await this._inner.getBlockCipherKey(blockNum));
   }

   async getSigningKey(): Promise<Uint8Array<ArrayBuffer>> {
      return this._record('signingKey', await this._inner.getSigningKey());
   }

   async getHintCipherKeyAndIV(
      baseIV: Uint8Array<ArrayBuffer>,
   ): Promise<[Uint8Array<ArrayBuffer>, Uint8Array<ArrayBuffer>]> {
      const [hintKey, hintIV] = await this._inner.getHintCipherKeyAndIV(baseIV);
      return [this._record('hintKey', hintKey), hintIV];
   }

   async getKeyCommitment(): Promise<Uint8Array<ArrayBuffer>> {
      return this._record('commitKey', await this._inner.getKeyCommitment());
   }

   get supportsCommitment(): boolean {
      return this._inner.supportsCommitment;
   }

   getExtraKeyMaterial(): Uint8Array<ArrayBuffer> | undefined {
      return this._inner.getExtraKeyMaterial();
   }

   private _record(name: string, key: Uint8Array<ArrayBuffer>): Uint8Array<ArrayBuffer> {
      this._recorded.keys.set(name, key.slice());
      return key;
   }
}

// Decrypts cipherData in Node and records every key the decryption used. Each key derived by
// crypto_kdf_derive_from_key also gets an entry named `<key>.mixedKey`, holding the key that call received: the
// hash of the master key, the salt and the context.
async function decryptRecording(
   cipherData: Uint8Array<ArrayBuffer>,
   keyProvider: KeyProvider,
): Promise<RecordedKeys & { clear: Uint8Array }> {
   const recorded: RecordedKeys = { keys: new Map() };
   const kdfCalls: { key: Uint8Array; output: Uint8Array }[] = [];
   const kdf = sodium.crypto_kdf_derive_from_key;
   // libs/crypto looks the function up on this same object at each call
   const mutableSodium = sodium as { crypto_kdf_derive_from_key: typeof kdf };
   mutableSodium.crypto_kdf_derive_from_key = ((length: number, id: number, context: string, key: Uint8Array) => {
      const output = kdf(length, id, context, key);
      kdfCalls.push({ key: key.slice(), output: output.slice() });
      return output;
   }) as typeof kdf;
   try {
      const clear = await readStreamAll(
         await decryptStream(streamFromBytes(cipherData), new RecordingKeyProvider(keyProvider, recorded)),
      );
      for (const [name, key] of [...recorded.keys]) {
         const call = kdfCalls.find((kdfCall) => Buffer.from(kdfCall.output.subarray(0, key.length)).equals(key));
         if (call) {
            recorded.keys.set(`${name}.mixedKey`, call.key);
         }
      }
      return { ...recorded, clear };
   } finally {
      mutableSodium.crypto_kdf_derive_from_key = kdf;
   }
}

export type CipherSecrets = {
   alg: string;
   // Keys derived from the password, which a breakpoint during a later operation cannot recover
   passwordKeys: Secret[];
   // Keys derived from userCred and public cipher data alone
   userCredKeys: Secret[];
};

// Decrypts the cipher armor, or the bytes of an encrypted file, in Node and records every key the decryption used.
// Encryption used the same keys, since they derive from the salt in the cipher data. Throws unless the decryption
// reproduces clear.
export async function cipherSecrets(
   prefix: string,
   cipher: string | Uint8Array<ArrayBuffer>,
   userCred: string,
   password: string,
   clear: string | Uint8Array,
): Promise<CipherSecrets> {
   await ready();
   const recorded = await decryptRecording(
      typeof cipher === 'string' ? parseCipherArmor(cipher) : cipher,
      new PWDKeyProvider(new Uint8Array(Buffer.from(userCred, 'base64url')), [password]),
   );
   const clearBytes = typeof clear === 'string' ? new TextEncoder().encode(clear) : clear;
   if (!Buffer.from(recorded.clear).equals(clearBytes)) {
      throw new Error(`${prefix}: decrypting the cipher data in Node did not reproduce the clear data`);
   }
   // Mixed keys are missing when libs/crypto loads a different libsodium module than this file
   if (!recorded.keys.has('signingKey.mixedKey')) {
      throw new Error(`${prefix}: recorded no mixed keys`);
   }

   const userCredKeyNames = ['signingKey', 'hintKey'];
   const passwordKeys: Secret[] = [];
   const userCredKeys: Secret[] = [];
   // The key commitment is stored in the cipher armor, so it is public. Its mixed key derives nothing else.
   recorded.keys.delete('commitKey');
   recorded.keys.delete('commitKey.mixedKey');
   for (const [name, key] of recorded.keys) {
      const secret = byteSecret(`${prefix}.${name}`, key);
      if (userCredKeyNames.includes(name.replace(/\.mixedKey$/, ''))) {
         userCredKeys.push(secret);
      } else {
         passwordKeys.push(secret);
      }
   }
   return { alg: recorded.alg ?? 'unknown', passwordKeys, userCredKeys };
}

// Returns the keys masterKey derives to decrypt userCredEnc. Decryption with any other master key fails
// authentication, which returns undefined.
export async function masterKeySecrets(
   prefix: string,
   userCredEnc: string,
   masterKey: Uint8Array,
   userId: string,
   userCred: string,
): Promise<Secret[] | undefined> {
   await ready();
   // Failures are expected for every other master key, so the library does not log them
   setLogErrors(false);
   // The key provider takes ownership of its master key and wipes it
   const recorded = await decryptRecording(
      base64ToBytes(userCredEnc),
      new MasterKeyKeyProvider(new Uint8Array(masterKey), userId),
   )
      .catch(() => undefined)
      .finally(() => setLogErrors(true));
   if (recorded && !Buffer.from(recorded.clear).equals(Buffer.from(userCred, 'base64url'))) {
      throw new Error(`${prefix}: decrypting userCredEnc in Node did not reproduce userCred`);
   }
   return recorded && [...recorded.keys].map(([name, key]) => byteSecret(`${prefix}.${name}`, key));
}
