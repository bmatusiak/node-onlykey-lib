/**
 * Put both on the global, if they are not already there.
 *
 * Never replaces a platform implementation: a real one handles every encoding
 * and streams, and this one does neither.
 *
 * @returns {{installed: string[], reason: string}}
 */
export function installTextCodecs(): {
    installed: string[];
    reason: string;
};
export class ShimTextEncoder {
    get encoding(): string;
    /** @param {string} [input] @returns {Uint8Array} */
    encode(input?: string): Uint8Array;
    /**
     * The Web API's encodeInto, which writes in place and reports how far it got.
     *
     * Implemented by encoding then copying rather than incrementally, so a
     * destination too small to hold the whole string truncates at a byte
     * boundary rather than splitting a character - which is what the spec
     * requires and what a naive byte-wise copy gets wrong.
     */
    encodeInto(source: any, destination: any): {
        read: number;
        written: number;
    };
}
export class ShimTextDecoder {
    constructor(label?: string, options?: {});
    _fatal: boolean;
    _ignoreBOM: boolean;
    get encoding(): string;
    get fatal(): boolean;
    get ignoreBOM(): boolean;
    /** @param {BufferSource} [input] @returns {string} */
    decode(input?: BufferSource): string;
}
