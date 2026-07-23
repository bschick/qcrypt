import { decodeCbor, decodeCborWithRemainder, encodeCbor } from "./cbor";
declare function encodeBase64Url(data: BufferSource): string;
declare function decodeBase64Url(base64Url: string): Uint8Array<ArrayBuffer>;
declare function bufferSourceToUint8Array(data: BufferSource): Uint8Array<ArrayBuffer>;
declare function strToUint8Array(data: string): Uint8Array<ArrayBuffer>;
declare const EncodeUtils: {
    strToUint8Array: typeof strToUint8Array;
    bufferSourceToUint8Array: typeof bufferSourceToUint8Array;
    encodeBase64Url: typeof encodeBase64Url;
    decodeBase64Url: typeof decodeBase64Url;
    encodeCbor: typeof encodeCbor;
    decodeCbor: typeof decodeCbor;
    decodeCborWithRemainder: typeof decodeCborWithRemainder;
};
export default EncodeUtils;
