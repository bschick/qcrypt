"use strict";
Object.defineProperty(exports, "__esModule", { value: true });
const cbor_1 = require("./cbor");
function encodeBase64Url(data) {
    const buffer = bufferSourceToUint8Array(data);
    let binaryString = "";
    for (let i = 0; i < buffer.length; i++) {
        binaryString += String.fromCharCode(buffer[i]);
    }
    return btoa(binaryString).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
function decodeBase64Url(base64Url) {
    const binaryString = atob(base64Url.replace(/-/g, "+").replace(/_/g, "/"));
    const bytes = new Uint8Array(binaryString.length);
    for (let i = 0; i < binaryString.length; i++) {
        bytes[i] = binaryString.charCodeAt(i);
    }
    return bytes;
}
function bufferSourceToUint8Array(data) {
    if (data instanceof ArrayBuffer) {
        return new Uint8Array(data);
    }
    return new Uint8Array(data.buffer.slice(data.byteOffset, data.byteOffset + data.byteLength));
}
function strToUint8Array(data) {
    return new Uint8Array(data.split("").map((c) => c.charCodeAt(0)));
}
const EncodeUtils = {
    strToUint8Array,
    bufferSourceToUint8Array,
    encodeBase64Url,
    decodeBase64Url,
    encodeCbor: cbor_1.encodeCbor,
    decodeCbor: cbor_1.decodeCbor,
    decodeCborWithRemainder: cbor_1.decodeCborWithRemainder,
};
exports.default = EncodeUtils;
