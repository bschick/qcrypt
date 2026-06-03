/* tslint:disable */
/* eslint-disable */

export class MlDsa65KeyPair {
    private constructor();
    free(): void;
    [Symbol.dispose](): void;
    readonly pk: Uint8Array;
    readonly sk: Uint8Array;
}

export function ml_dsa_65_keygen(seed: Uint8Array): MlDsa65KeyPair;

export function ml_dsa_65_sign(sk: Uint8Array, message: Uint8Array, context: Uint8Array, randomness: Uint8Array): Uint8Array;

export function ml_dsa_65_verify(pk: Uint8Array, message: Uint8Array, context: Uint8Array, signature: Uint8Array): boolean;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_mldsa65keypair_free: (a: number, b: number) => void;
    readonly ml_dsa_65_keygen: (a: number, b: number) => [number, number, number];
    readonly ml_dsa_65_sign: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number, number];
    readonly ml_dsa_65_verify: (a: number, b: number, c: number, d: number, e: number, f: number, g: number, h: number) => [number, number, number];
    readonly mldsa65keypair_pk: (a: number) => [number, number];
    readonly mldsa65keypair_sk: (a: number) => [number, number];
    readonly __wbindgen_externrefs: WebAssembly.Table;
    readonly __wbindgen_malloc: (a: number, b: number) => number;
    readonly __externref_table_dealloc: (a: number) => void;
    readonly __wbindgen_free: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
