/** @returns {Uint8Array[]} the writes for one message, each at most `size` bytes */
export function fragment(msg: any, size: any): Uint8Array[];
/**
 * Feed fragments as they arrive; `push` returns the whole message when its last fragment
 * lands, otherwise null. Throws on a fragment out of place. `progress` says how far the message
 * now arriving has come - {have, want} in bytes, or null between messages - so a screen can show
 * a large one coming in (a +PQC certificate is ~15 KB, seconds over Bluetooth).
 */
export function createAssembler(): {
    progress(): {
        have: number;
        want: number;
    } | null;
    push(frag: any): Uint8Array<ArrayBuffer> | null;
};
export const MAX_MESSAGE: 65535;
