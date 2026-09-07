export const BACKUP_BEGIN: "-----BEGIN ONLYKEY BACKUP-----";
export const BACKUP_END: "-----END ONLYKEY BACKUP-----";
export const FIRMWARE_BEGIN: "-----BEGIN SIGNED FIRMWARE-----";
/**
 * The literal string that bounces a config-mode device into the bootloader.
 *
 * Sent through the firmware upload path before any real firmware. Four
 * characters, so its packet header is (4/2).toString(16) = '2'. It appears
 * three times in the original, inline and unexplained.
 */
export const BOOTLOADER_KICK: "1234";
/**
 * Lines beginning with '--' are structural, not data.
 *
 * That covers the BEGIN and END markers AND the trailing '--<base64 digest>'
 * line, which is why the test is a prefix rather than an exact match.
 */
export function isMarker(line: any): boolean;
/**
 * A backup file to the hex stream the device restores from.
 *
 * Every non-marker line is base64; decoded and concatenated they form one
 * continuous stream, which the restore chunker then splits at 57 bytes.
 */
export function parseBackup(text: any): string;
/**
 * Verify a backup file's trailing digest.
 *
 * A rolling hash: start from 32 zero bytes and, for each data line, hash the
 * previous digest concatenated with that line's decoded bytes. The expected
 * value is the base64 on the '--' line that is not the BEGIN/END marker.
 *
 * Chained rather than a hash over the whole file, so a reordering is caught as
 * well as a modification.
 */
export function verifyBackup(text: any): {
    ok: boolean;
    reason: string;
    digest: string;
    expected?: undefined;
} | {
    ok: boolean;
    expected: string;
    digest: string;
    reason?: undefined;
};
/**
 * A firmware file to its blocks.
 *
 * NOT the same shape as a backup: these lines are already hex, there is no
 * base64 step, and each line stays a SEPARATE block that is chunked and
 * acknowledged on its own. Concatenating them - which the backup path does -
 * would destroy the block structure the loader depends on.
 *
 * The first line is the BEGIN marker and the last is the END footer; the
 * original drops both by shifting and by iterating to length - 1.
 */
export function parseFirmware(text: any): string[];
/**
 * A firmware block's structure, per the loader's own comments.
 *
 *   [0..63]    this block's signature   (32 bytes)
 *   [64]       block info               (one nibble)
 *   [65..128]  the next block's signature
 */
export function describeFirmwareBlock(block: any): {
    signature: any;
    info: any;
    nextSignature: any;
} | null;
