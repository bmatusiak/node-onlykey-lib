export const ROUNDS: 600000;
/** the derive label of an entry's own key (deviceVault adds `vault:`) */
export function entryLabel(id: any): string;
/** A passphrase entry's key: PBKDF2 (600k) of the passphrase, combined with the manager key by HKDF. */
export function passphraseKey({ passphrase, salt, managerKey, onProgress }: {
    passphrase: any;
    salt: any;
    managerKey: any;
    onProgress?: null | undefined;
}): Promise<Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>>;
/** The entry with its secret fields moved into `inner`, sealed under `innerKey`. */
export function sealInner(entry: any, innerKey: any, randomBytes: any, { seal, salt }: {
    seal: any;
    salt?: null | undefined;
}): any;
/** The entry with its secret fields back, opened with `innerKey`; throws when the key is wrong. */
export function openInner(entry: any, innerKey: any): any;
/** the salt a passphrase entry was sealed with */
export function saltOf(entry: any): Uint8Array<ArrayBuffer> | null;
