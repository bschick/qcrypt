export declare function encodeCbor(data: object): Uint8Array<ArrayBuffer>;
export declare function decodeCbor<T>(data: Uint8Array<ArrayBuffer>): T;
export declare function decodeCborWithRemainder<T>(data: Uint8Array<ArrayBuffer>): {
    value: T;
    remainder: Uint8Array<ArrayBuffer>;
};
