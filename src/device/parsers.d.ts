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
 * A firmware block's structure, in HEX CHARACTERS.
 *
 *   [0..63]    this block's signature      (32 bytes)
 *   [64..65]   block info                  (1 byte)
 *   [66..129]  the next block's signature  (32 bytes)
 *   [130..]    the block itself
 *
 * THE INFO FIELD IS A BYTE, AND THIS READ IT AS A NIBBLE. The loader's own
 * comment calls it a nibble, which is true of what it CONTAINS and not of the
 * space it occupies, and every field after the signature was shifted one hex
 * character left as a result. firmware.js:describeBlock had it right all along,
 * so the app's screen was never affected; the only caller here was a test built
 * to the same wrong shape.
 *
 * The release images settle it. Their block lines are 33026 and 32898 hex
 * characters: a 130-character header leaves 16448 and 16384 bytes, the second
 * being exactly a 16 KB flash page, while a 129-character one leaves an odd
 * number of hex characters, which is not a whole number of bytes at all.
 * See ok-rn/FINDING-two-block-describers-disagree-by-a-nibble.md.
 */
export function describeFirmwareBlock(block: any): {
    signature: any;
    info: any;
    nextSignature: any;
} | null;
