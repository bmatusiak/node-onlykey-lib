/**
 * The whole private key from p, q and e. d is taken mod lambda(n) (the
 * smallest working exponent, as OpenSSL does); dp, dq and qi are the CRT values.
 * @param {{p: Uint8Array|bigint, q: Uint8Array|bigint, e?: number|bigint}} primes
 * @returns {{n: bigint, e: bigint, d: bigint, p: bigint, q: bigint, dp: bigint, dq: bigint, qi: bigint}}
 */
export function fromPrimes({ p, q, e }: {
    p: Uint8Array | bigint;
    q: Uint8Array | bigint;
    e?: number | bigint;
}): {
    n: bigint;
    e: bigint;
    d: bigint;
    p: bigint;
    q: bigint;
    dp: bigint;
    dq: bigint;
    qi: bigint;
};
/**
 * RSA from its two primes - all an OnlyKey keeps (p || q in the slot) and all
 * a key generator has to hand over. Everything else is arithmetic, done once
 * here for the PKCS#8 writer and the WebCrypto shim's host-generated keys.
 *
 * BigInt, so it runs under Hermes. BigInts cannot be zeroed; a caller keeps
 * them for as short a time as it can and drops the references.
 */
export function bigFrom(bytes: any): bigint;
/** Big-endian bytes, left-padded to `length` when given. */
export function bigTo(value: any, length?: number): Uint8Array<ArrayBuffer>;
/** Bits in n. */
export function bitLength(n: any): any;
export function modInverse(a: any, m: any): number;
