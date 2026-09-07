export function mlkemKeypairFromSeed(mlkemSeed: any): {
    secretKey: import("@noble/post-quantum/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
    publicKey: import("@noble/post-quantum/utils.js", { with: { "resolution-mode": "import" } }).TRet<Uint8Array>;
};
export function buildRecipient(pkX: any, mlkemSeed: any): Uint8Array<any>;
export function xwingCombiner(ssM: any, ssX: any, ctX: any, pkX: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function splitDecapsulate(ssX: any, ciphertext: any, pkX: any, mlkemSeed: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function ctXOf(ciphertext: any): any;
export function xwingEncapsHost(pk: any): {
    sharedSecret: Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
    ciphertext: Uint8Array<any>;
};
export function deriveLabelTag(label: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function encodeRecipient(pubkey: any): string;
export function decodeRecipient(recipient: any): Uint8Array<ArrayBuffer>;
export function encodeIdentity(label: any): string;
export function decodeIdentity(s: any): {
    derived: boolean;
    label: string;
} | null;
export const XWING_LABEL: Uint8Array<ArrayBuffer>;
export const MLKEM_PK: 1184;
export const MLKEM_CT: 1088;
export const XWING_PK: 1216;
export const XWING_CT: 1120;
export const SEED: 32;
