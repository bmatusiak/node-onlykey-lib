export function derLength(n: any): Uint8Array<ArrayBuffer>;
export function tlv(tag: any, content: any): Uint8Array<ArrayBuffer>;
export function sequence(...items: any[]): Uint8Array<ArrayBuffer>;
export function octets(bytes: any): Uint8Array<ArrayBuffer>;
export const NULL: Uint8Array<ArrayBuffer>;
/** A non-negative INTEGER from big-endian bytes, a number or a BigInt. */
export function integer(value: any): Uint8Array<ArrayBuffer>;
export function oid(dotted: any): Uint8Array<ArrayBuffer>;
