/**
 * @param {*} value  number | string | Uint8Array | Array | Map | object | boolean | null
 * @returns {Uint8Array}
 */
export function encode(value: any): Uint8Array;
/**
 * @param {Uint8Array} buf
 * @returns {*} Maps stay Maps, byte strings stay Uint8Arrays
 */
export function decode(buf: Uint8Array): any;
/**
 * Decode ONE item and say where it ended.
 *
 * decode() insists the buffer holds exactly one item, which is the right
 * default - a trailing byte usually means the wrong slice was passed. But CTAP2
 * puts two CBOR items back to back with no length between them and expects the
 * reader to know: authData's attested-credential-data ends with a COSE key, and
 * an extension map may follow it immediately. The only way past the key is to
 * decode it and be told the offset.
 *
 * @param {Uint8Array} buf
 * @param {number} [pos]
 * @returns {{value: *, next: number}} next is the offset just past the item
 */
export function decodeFirst(buf: Uint8Array, pos?: number): {
    value: any;
    next: number;
};
/** Maps to plain objects, for readable assertion messages. Lossy on purpose. */
export function plain(value: any): any;
