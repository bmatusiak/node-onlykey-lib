/** The trailing byte of a backup made with an Ed25519 key - every passphrase key. */
export const PASSPHRASE_BACKUP_TRAILER: number;
/** The device's acceptance threshold for the first decrypted byte (:6629). */
export const FIRST_BYTE_MIN: 253;
/**
 * Would the device accept this backup with this slot-131 key?
 *
 * @param {Uint8Array} blob  the decoded backup (parsers.parseBackup, as bytes)
 * @param {Uint8Array} key   the 32-byte backup key (sha256 of the passphrase bytes)
 * @returns {{accepted: boolean|null, firstByte?: number, reason?: string}}
 *   `accepted: null` when the file is not a passphrase-protected backup and
 *   the question cannot be answered.
 */
export function predictRestore(blob: Uint8Array, key: Uint8Array): {
    accepted: boolean | null;
    firstByte?: number;
    reason?: string;
};
/**
 * Pick the key a passphrase backup will restore with.
 *
 * Tries keys.backupPassphraseCandidates() in order - UTF-8, then Latin-1
 * legacy only when the two differ - against predictRestore().
 *
 * @param {Uint8Array} blob
 * @param {string} passphrase
 * @param {object} [opts]
 * @param {'utf-8'|'latin-1-legacy'|null} [opts.encoding] skip the choice and
 *   use this form (still checked: a key the device would refuse is refused here)
 * @returns {{slot: number, type: number, key: Uint8Array, encoding: string, tried: string[]}}
 * @throws when no candidate opens the backup, or two do and none was named
 */
export function chooseBackupKey(blob: Uint8Array, passphrase: string, { encoding }?: {
    encoding?: "utf-8" | "latin-1-legacy" | null | undefined;
}): {
    slot: number;
    type: number;
    key: Uint8Array;
    encoding: string;
    tried: string[];
};
