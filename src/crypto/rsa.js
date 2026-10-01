'use strict';

/**
 * RSA from its two primes - all an OnlyKey keeps (p || q in the slot) and all
 * a key generator has to hand over. Everything else is arithmetic, done once
 * here for the PKCS#8 writer and the WebCrypto shim's host-generated keys.
 *
 * BigInt, so it runs under Hermes. BigInts cannot be zeroed; a caller keeps
 * them for as short a time as it can and drops the references.
 */

const bigFrom = (bytes) => {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
};

/** Big-endian bytes, left-padded to `length` when given. */
function bigTo(value, length = 0) {
  const out = [];
  let v = value;
  do { out.unshift(Number(v & 0xffn)); v >>= 8n; } while (v > 0n);
  while (out.length < length) out.unshift(0);
  return Uint8Array.from(out);
}

function gcd(a, b) {
  while (b) [a, b] = [b, a % b];
  return a;
}

function modInverse(a, m) {
  let [r0, r1] = [((a % m) + m) % m, m];
  let [s0, s1] = [1n, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  if (r0 !== 1n) throw new Error('RSA: no inverse - p and q do not make a usable key');
  return ((s0 % m) + m) % m;
}

/**
 * The whole private key from p, q and e. d is taken mod lambda(n) (the
 * smallest working exponent, as OpenSSL does); dp, dq and qi are the CRT values.
 * @param {{p: Uint8Array|bigint, q: Uint8Array|bigint, e?: number|bigint}} primes
 * @returns {{n: bigint, e: bigint, d: bigint, p: bigint, q: bigint, dp: bigint, dq: bigint, qi: bigint}}
 */
function fromPrimes({ p, q, e = 65537 }) {
  const P = typeof p === 'bigint' ? p : bigFrom(p);
  const Q = typeof q === 'bigint' ? q : bigFrom(q);
  const E = BigInt(e);
  if (P === Q) throw new Error('RSA: p and q are the same prime');
  const lambda = ((P - 1n) * (Q - 1n)) / gcd(P - 1n, Q - 1n);
  const d = modInverse(E, lambda);
  return {
    n: P * Q, e: E, d, p: P, q: Q,
    dp: d % (P - 1n), dq: d % (Q - 1n), qi: modInverse(Q, P),
  };
}

/** Bits in n. */
const bitLength = (n) => n.toString(2).length;

module.exports = { fromPrimes, bigFrom, bigTo, bitLength, modInverse };
