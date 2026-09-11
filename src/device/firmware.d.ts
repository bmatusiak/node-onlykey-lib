export const BEGIN: "-----BEGIN SIGNED FIRMWARE-----";
export const END: "-----END SIGNED FIRMWARE-----";
/** The kick: OKFWUPDATE with "1234" as its two bytes (OnlyKeyComm.js:2100). */
export const KICK_HEX: "1234";
export namespace SAYS {
    let REQUESTED: RegExp;
    let RECEIVED: RegExp;
    let NEXT_BLOCK: RegExp;
    let LOADED: RegExp;
    let ERROR: RegExp;
}
/**
 * The blocks of a signed firmware file, in order.
 *
 * The desktop trims the file, drops the first line and the last
 * (parseFirmwareData) and sends everything between - which is BEGIN and
 * END going, since every signed file ends with END. This asks that the
 * first line be the BEGIN marker rather than assuming, stops at END when
 * it is there and keeps every block when it is not (dropping "the last
 * line" of a file without END would drop a block), and refuses a line that
 * is not hex - a block the bootloader would reject halfway through an
 * update is better refused before the kick.
 *
 * @param {string} text
 * @returns {string[]} hex lines, one per block
 */
export function parseSignedFirmware(text: string): string[];
/**
 * What the desktop logs per block, for a progress line.
 *
 * Read in whole bytes. loadFirmware logs slice(64,65) as "block info" and
 * slice(65,129) as the next signature - a nibble boundary, which no byte
 * layout has - so this takes the info byte as two hex characters and the
 * next signature from 66. Which of the two is right is a question for a
 * real signed file, and nothing is sent differently either way: the line
 * goes to the bootloader whole.
 */
export function describeBlock(line: any): {
    signature: any;
    info: any;
    nextSignature: any;
    bytes: number;
};
/** The one frame that asks a config-mode key to reboot into its bootloader. */
export function kickFrame(): Uint8Array<ArrayBufferLike>;
/**
 * A block as frames: [{frame, final}], 57 bytes each, 0xFF header on all but
 * the last, whose header is its length - exactly submitFirmwareData's
 * `maxPacketSize = 114` hex characters and `packetHeader`.
 */
export function blockFrames(line: any): {
    frame: Uint8Array<ArrayBufferLike>;
    final: boolean;
    bytes: number;
}[];
