/**
 * 57 payload bytes per report.
 *
 * The frame is 4 header + 1 msg + 1 packet-header byte = 6, leaving 57 of the
 * 64. For OKSETPRIV it is 4 + msg + slot + type = 7, leaving 57 as well - the
 * numbers coincide, which is part of why these look interchangeable.
 */
export const CHUNK_BYTES: 57;
/**
 * Split raw bytes into crypto packets.
 *
 * Same 57-byte chunking as hexPackets, over bytes rather than hex, because
 * what gets signed is a digest and what gets decrypted is ciphertext - neither
 * arrives as a hex string.
 */
export function bytePackets(bytes: any): {
    header: number;
    data: Uint8Array<ArrayBuffer>;
    final: boolean;
}[];
/**
 * One 64-byte frame for a crypto packet.
 *
 * THE SLOT BYTE IS THE WHOLE DIFFERENCE, and it is one byte in a place that
 * makes the two framings look interchangeable:
 *
 *     restore/firmware   [header|msg     |0xFF-or-len|57 bytes]
 *     sign/decrypt       [header|msg|slot|0xFF-or-len|57 bytes]
 *
 * process_packets() reads buffer[4] as the command, buffer[5] as the SLOT,
 * buffer[6] as 0xFF-or-length and buffer[7..] as the data
 * (okcore.cpp:7472-7519). Reusing buildHexPacket here would put the length
 * byte where the firmware reads the slot and start the data one byte early -
 * so the device would look up a key in whatever slot the length happened to
 * name, and sign the wrong bytes with it. Both halves fail silently.
 *
 * The 57 is not a coincidence between the two: 4 header + msg + chunk-header
 * is 6, and 4 + msg + slot + chunk-header is 7 - but OKSETPRIV also spends
 * its seventh byte on a type, so all three leave 57. That is exactly why the
 * wrong frame is the same length as the right one and passes every check
 * except the device.
 */
export function buildSlotPacket(msg: any, slot: any, packet: any): Uint8Array<ArrayBufferLike>;
/**
 * Stream bytes to a slot-addressed command: OKSIGN, OKDECRYPT.
 *
 * Returns the packets sent, because the CHALLENGE the device then asks for is
 * derived from exactly these bytes - sha256 over the accumulated payload
 * (okcore.cpp:7577-7587) - and the caller has to be able to compute the same
 * digits to know which buttons to press.
 *
 * @param {object}   spec
 * @param {number}   spec.msg    MSG.OKSIGN or MSG.OKDECRYPT
 * @param {number}   spec.slot
 * @param {Uint8Array} spec.data
 * @param {function} spec.send   async (frame) => void
 * @param {function} [spec.onProgress]
 */
export function sendSlotStream({ msg, slot, data, send, onProgress }: {
    msg: number;
    slot: number;
    data: Uint8Array;
    send: Function;
    onProgress?: Function | undefined;
}): Promise<{
    packets: number;
    bytes: Uint8Array<ArrayBuffer>;
}>;
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
