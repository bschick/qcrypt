import { mnemonicToEntropy } from '@scure/bip39';
import { wordlist } from '@scure/bip39/wordlists/english.js';
import sodium from 'libsodium-wrappers';
import * as api from '@qcrypt/api';
import {
   bytesToBase64,
   cryptoReady,
   decryptStream,
   getProofKeyPair,
   parseCipherArmor,
   PWDKeyProvider,
   readStreamAll,
   streamFromBytes,
   type KeyProvider,
} from '@qcrypt/crypto';
import { byteSecret, textSecret, type Secret } from './heapscan';

// Must match the proof key contexts in libs/api. Each derivation below is checked against the public key
// that libs/api computes, so a mismatch throws instead of silently searching for the wrong bytes.
const USERCRED_KEY_CONTEXT = 'UCredKey';
const RECOVERY_KEY_CONTEXT = 'RecovKey';

async function ready(): Promise<void> {
   await cryptoReady();
   await sodium.ready;
}

// The seed mirrors the derivation inside getProofKeyPair. ML-DSA-65 signing keys start with rho (32 bytes),
// K (32 bytes) and tr (64 bytes), then s1, so K and the first 32 bytes of s1 stand in for the whole key.
function proofSecrets(prefix: string, secret: Uint8Array, context: string, expectedPubKey: string): Secret[] {
   const { pubKey, secKey } = getProofKeyPair(secret, context);
   if (bytesToBase64(pubKey) !== expectedPubKey) {
      throw new Error(`${prefix}: proof key derivation does not match libs/api`);
   }
   return [
      byteSecret(`${prefix}.proofSeed`, sodium.crypto_kdf_derive_from_key(32, 1, context, secret)),
      byteSecret(`${prefix}.proofKeyK`, secKey.slice(32, 64), false),
      byteSecret(`${prefix}.proofKeyS1`, secKey.slice(128, 160), false),
   ];
}

export async function userCredSecrets(userCred: string): Promise<Secret[]> {
   await ready();
   const bytes = new Uint8Array(Buffer.from(userCred, 'base64url'));
   return [
      byteSecret('userCred', bytes),
      ...proofSecrets('userCred', bytes, USERCRED_KEY_CONTEXT, api.getUserCredPubKey(bytes)),
   ];
}

// The words encode recoveryId followed by the userId. Only recoveryId is secret.
export async function recoverySecrets(prefix: string, words: string): Promise<Secret[]> {
   await ready();
   const spaced = words.trim().split(/\s+/).join(' ');
   const wordsSecret = textSecret(`${prefix}.words`, words);
   if (spaced !== words) {
      wordsSecret.texts.push(['spaced', spaced]);
   }
   const secret = mnemonicToEntropy(spaced, wordlist);
   return [
      wordsSecret,
      byteSecret(`${prefix}.id`, secret.slice(0, api.RECOVERYID_BYTES)),
      byteSecret(`${prefix}.secret`, secret),
      ...proofSecrets(prefix, secret, RECOVERY_KEY_CONTEXT, api.getRecoveryPubKey(secret)),
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

export type CipherSecrets = {
   alg: string;
   // Keys derived from the password, which a breakpoint during a later operation cannot recover
   passwordKeys: Secret[];
   // Keys derived from userCred and public cipher data alone
   userCredKeys: Secret[];
};

// Decrypts the cipher armor in Node and records every key the decryption used. Encryption used the same keys,
// since they derive from the salt in the armor. Throws unless the decryption reproduces clearText.
export async function cipherSecrets(
   prefix: string,
   armor: string,
   userCred: string,
   password: string,
   clearText: string,
): Promise<CipherSecrets> {
   await ready();
   const recorded: RecordedKeys = { keys: new Map() };
   const keyProvider = new RecordingKeyProvider(
      new PWDKeyProvider(new Uint8Array(Buffer.from(userCred, 'base64url')), [password]),
      recorded,
   );
   const decrypted = await readStreamAll(await decryptStream(streamFromBytes(parseCipherArmor(armor)), keyProvider));
   if (new TextDecoder().decode(decrypted) !== clearText) {
      throw new Error(`${prefix}: decrypting the cipher armor in Node did not reproduce the clear text`);
   }

   const userCredKeyNames = ['signingKey', 'hintKey'];
   const passwordKeys: Secret[] = [];
   const userCredKeys: Secret[] = [];
   // The key commitment is stored in the cipher armor, so it is public
   recorded.keys.delete('commitKey');
   for (const [name, key] of recorded.keys) {
      const secret = byteSecret(`${prefix}.${name}`, key);
      if (userCredKeyNames.includes(name)) {
         userCredKeys.push(secret);
      } else {
         passwordKeys.push(secret);
      }
   }
   return { alg: recorded.alg ?? 'unknown', passwordKeys, userCredKeys };
}
