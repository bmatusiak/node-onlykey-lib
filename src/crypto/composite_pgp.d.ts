export const BLOB_LEN: 160;
export const OFF_ED25519: 0;
export const OFF_MLDSA_SEED: 32;
export const OFF_X25519: 64;
export const OFF_MLKEM_SEED: 96;
export const ED25519_SK_LEN: 32;
export const MLDSA_SEED_LEN: 32;
export const X25519_SK_LEN: 32;
export const MLKEM_SEED_LEN: 64;
export const HALF_ECC: 0;
export const HALF_PQC: 1;
export const MLKEM_CT_LEN: 1088;
export const X25519_PT_LEN: 32;
export const SS_LEN: 32;
export const ED25519_SIG_LEN: 64;
export const MLDSA_SIG_LEN: 3309;
export const PQC_KEY_TYPE_BYTE: 103;
export function packBlob(ed25519Sk: any, mldsaSeed: any, x25519Sk: any, mlkemSeed: any): Uint8Array<ArrayBuffer>;
export function unpackBlob(blob: any): {
    ed25519Sk: any;
    mldsaSeed: any;
    x25519Sk: any;
    mlkemSeed: any;
};
export function generateCompositeKey(openpgp: any, { userId }?: {}): Promise<{
    armoredPublicKey: any;
    blob: Uint8Array<ArrayBuffer>;
}>;
export function registerCompositeHooks(openpgp: any, ok: any, slot: any): void;
