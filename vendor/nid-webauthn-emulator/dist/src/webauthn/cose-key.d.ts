import { type KeyObject } from "node:crypto";
/** @see https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples */
export declare abstract class CoseKey {
    kty: number;
    alg: number;
    constructor(kty: number, alg: number);
    abstract toBytes(): Uint8Array<ArrayBuffer>;
    abstract toJwk(): JsonWebKey;
    toKeyObject(): KeyObject;
    static fromKeyObject(keyObject: KeyObject): CoseKey;
    toDer(): Uint8Array<ArrayBuffer>;
    static fromDer(der: Uint8Array<ArrayBuffer>): CoseKey;
    equals(other: CoseKey): boolean;
    static fromBytes(bytes: Uint8Array<ArrayBuffer>): CoseKey;
    static fromDecoded(coseKey: Record<number, unknown>): CoseKey;
    static fromJwk(jwk: JsonWebKey): CoseKey;
}
