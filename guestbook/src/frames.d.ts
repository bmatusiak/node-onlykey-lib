/** @returns {Uint8Array[]} the writes for one message, each at most `size` bytes */
export function fragment(msg: any, size: any): Uint8Array[];
/**
 * Feed fragments as they arrive; `push` returns the whole message when its last fragment
 * lands, otherwise null. Throws on a fragment out of place.
 */
export function createAssembler(): {
    push(frag: any): Uint8Array<ArrayBuffer> | null;
};
export const MAX_MESSAGE: 65535;
