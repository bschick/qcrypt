"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
exports.CoseKey = void 0;
const node_crypto_1 = __importDefault(require("node:crypto"));
const encode_utils_1 = __importDefault(require("../libs/encode-utils"));
/** @see https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples */
class CoseKey {
    kty;
    alg;
    constructor(kty, alg) {
        this.kty = kty;
        this.alg = alg;
    }
    toKeyObject() {
        return node_crypto_1.default.createPublicKey({ format: "jwk", key: this.toJwk() });
    }
    static fromKeyObject(keyObject) {
        return CoseKey.fromJwk(keyObject.export({ format: "jwk" }));
    }
    toDer() {
        return new Uint8Array(this.toKeyObject().export({ format: "der", type: "spki" }));
    }
    static fromDer(der) {
        return CoseKey.fromKeyObject(node_crypto_1.default.createPublicKey({ format: "der", type: "spki", key: Buffer.from(der) }));
    }
    equals(other) {
        return this.toKeyObject().equals(other.toKeyObject());
    }
    static fromBytes(bytes) {
        return CoseKey.fromDecoded(encode_utils_1.default.decodeCbor(bytes));
    }
    static fromDecoded(coseKey) {
        switch (coseKey[3]) {
            case -7:
                return new CoseKeyP256(coseKey[-2], coseKey[-3]);
            case -8:
                return new CoseKeyEd25519(coseKey[-2]);
            case -257:
                return new CoseKeyRSA(coseKey[-1], coseKey[-2]);
            default:
                throw new Error("Not supported key type");
        }
    }
    static fromJwk(jwk) {
        if (jwk.crv === "P-256")
            return CoseKeyP256.fromJwk(jwk);
        if (jwk.crv === "Ed25519")
            return CoseKeyEd25519.fromJwk(jwk);
        if (jwk.kty === "RSA")
            return CoseKeyRSA.fromJwk(jwk);
        throw new Error("Not supported key type");
    }
}
exports.CoseKey = CoseKey;
class CoseKeyP256 extends CoseKey {
    x;
    y;
    constructor(x, y) {
        super(2, -7);
        this.x = x;
        this.y = y;
    }
    toBytes() {
        const coseKey = {
            1: this.kty,
            3: this.alg,
            [-1]: 1,
            [-2]: this.x,
            [-3]: this.y,
        };
        return encode_utils_1.default.encodeCbor(coseKey);
    }
    toJwk() {
        return {
            kty: "EC",
            crv: "P-256",
            x: encode_utils_1.default.encodeBase64Url(this.x),
            y: encode_utils_1.default.encodeBase64Url(this.y),
        };
    }
    static fromJwk(jwk) {
        return new CoseKeyP256(encode_utils_1.default.decodeBase64Url(jwk.x), encode_utils_1.default.decodeBase64Url(jwk.y));
    }
}
class CoseKeyEd25519 extends CoseKey {
    x;
    constructor(x) {
        super(1, -8);
        this.x = x;
    }
    toBytes() {
        const coseKey = {
            1: this.kty,
            3: this.alg,
            [-1]: 6,
            [-2]: this.x,
        };
        return encode_utils_1.default.encodeCbor(coseKey);
    }
    toJwk() {
        return {
            kty: "OKP",
            crv: "Ed25519",
            x: encode_utils_1.default.encodeBase64Url(this.x),
        };
    }
    static fromJwk(jwk) {
        return new CoseKeyEd25519(encode_utils_1.default.decodeBase64Url(jwk.x));
    }
}
class CoseKeyRSA extends CoseKey {
    n;
    e;
    constructor(n, e) {
        super(3, -257);
        this.n = n;
        this.e = e;
    }
    toBytes() {
        const coseKey = {
            1: this.kty,
            3: this.alg,
            [-1]: this.n,
            [-2]: this.e,
        };
        return encode_utils_1.default.encodeCbor(coseKey);
    }
    toJwk() {
        return {
            kty: "RSA",
            n: encode_utils_1.default.encodeBase64Url(this.n),
            e: encode_utils_1.default.encodeBase64Url(this.e),
        };
    }
    static fromJwk(jwk) {
        return new CoseKeyRSA(encode_utils_1.default.decodeBase64Url(jwk.n), encode_utils_1.default.decodeBase64Url(jwk.e));
    }
}
