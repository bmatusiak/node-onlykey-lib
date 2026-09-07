/**
 * 57 payload bytes per report.
 *
 * The frame is 4 header + 1 msg + 1 packet-header byte = 6, leaving 57 of the
 * 64. For OKSETPRIV it is 4 + msg + slot + type = 7, leaving 57 as well - the
 * numbers coincide, which is part of why these look interchangeable.
 */
export const CHUNK_BYTES: 57;
/** 57 bytes as hex characters. */
export const CHUNK_HEX: number;
/**
 * The header byte that means "a full chunk, more follow".
 *
 * Any value <= 57 means "this is the last chunk and it holds this many bytes".
 * So an input that divides exactly by 57 ends with a header of 0x39 (57), NOT
 * 0xFF - the `<= 0` test in the original is inclusive, and the final full
 * chunk is still final.
 */
export const MORE_FOLLOW: 255;
/**
 * Split a hex string into restore/firmware packets.
 *
 * Each packet is [header][up to 57 data bytes], where the header is 0xFF for
 * every chunk but the last and the byte count for the last.
 *
 * @param {string} hex  an even-length hex string
 * @returns {Array<{header: number, data: Uint8Array, final: boolean}>}
 */
export function hexPackets(hex: string): Array<{
    header: number;
    data: Uint8Array;
    final: boolean;
}>;
/** One 64-byte frame for a restore/firmware packet. */
export function buildHexPacket(msg: any, packet: any): Uint8Array<ArrayBufferLike>;
/**
 * Send a hex payload as restore or firmware packets.
 *
 * @param {object}   spec
 * @param {number}   spec.msg      MSG.OKRESTORE or MSG.OKFWUPDATE
 * @param {string}   spec.hex
 * @param {function} spec.send     async (frame) => void
 * @param {function} [spec.awaitAck]  async (packet) => void, awaited between
 *                   packets. Firmware update gates on "RECEIVED OKFWUPDATE";
 *                   restore fires back-to-back with no acknowledgement.
 * @param {function} [spec.onProgress]
 */
export function sendHexStream({ msg, hex, send, awaitAck, onProgress }: {
    msg: number;
    hex: string;
    send: Function;
    awaitAck?: Function | undefined;
    onProgress?: Function | undefined;
}): Promise<number>;
/**
 * Split an RSA private key for OKSETPRIV.
 *
 * Deliberately separate from the above, because the framing is different in
 * every respect: the input is bytes rather than hex, there is NO length header
 * on any packet, and slot and type are repeated identically on every one.
 *
 * TERMINATION IS DEVICE-SIDE. Nothing on the wire says "last packet". The
 * device knows the total because `type` encodes the key size and it counts to
 * 128 * type - so a key whose length is an exact multiple of 57 ends with a
 * full packet that is indistinguishable from a middle one, and that is fine
 * only because of the counting. Do not "improve" this into a length-headed
 * format; the device would stop understanding it.
 */
export function rsaPackets(key: any): Uint8Array<ArrayBuffer>[];
/**
 * @param {object}   spec
 * @param {number}   spec.slot
 * @param {number}   spec.type   1-4 for RSA 1024/2048/3072/4096, plus modifiers
 * @param {Uint8Array} spec.key  p || q
 * @param {function} spec.send
 */
export function sendRsaKey({ slot, type, key, send, onProgress }: {
    slot: number;
    type: number;
    key: Uint8Array;
    send: Function;
}): Promise<number>;
/**
 * The RSA key length the device will expect for a given type.
 *
 * Exposed so a caller can check its key before sending: a mismatch is not
 * reported by the device, it simply waits for bytes that never arrive.
 */
export function rsaKeyLength(type: any): number;
