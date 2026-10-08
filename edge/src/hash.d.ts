/** SHA-256 over the parts in order (Uint8Array, or a string = an ASCII tag). */
export function H(...parts: any[]): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
export function hmacSha256(key: any, msg: any): Uint8Array<ArrayBufferLike> & Uint8Array<ArrayBuffer>;
/** ASCII only (the domain tags); anything else is a programming error. */
export function ascii(text: any): Uint8Array<any>;
export function u32le(n: any): Uint8Array<ArrayBuffer>;
export function u8(n: any): Uint8Array<ArrayBuffer>;
export function bytes32(b: any, what: any): Uint8Array<ArrayBufferLike>;
export function same(a: any, b: any): boolean;
