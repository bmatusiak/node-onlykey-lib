'use strict';

/**
 * The crypto Edge verifies with: pure JS by default (the lib's one vendored
 * @noble copy, spec L6), or a faster one a host plugs in.
 *
 * WHY (A13, 2026-10-07): on a Galaxy A13 under Hermes, the phone's checks spent
 * ~1 s a sync in JS crypto - SHA-256 over the copy and the hash chains, P-256 on
 * checkpoints, the ticket message hashes - while the app already links OpenSSL
 * (okssl), which does the same in native code in a few ms. Brad: "try not to use
 * JS crypto if okssl can provide it as a faster version".
 *
 * One library, any GUI: the PC and the web app keep the JS here; ok-rn calls
 * setCryptoProvider() at start with OpenSSL. A provider may give any subset; the
 * rest stays JS. Every function is SYNCHRONOUS (the checks are), so a native
 * provider must be too.
 *
 * Both implementations must give the same answer for every input, the edge
 * cases included, so the rules that decide a verdict are kept HERE, around the
 * provider, not inside it:
 * - P-256: the signature is 64 bytes r||s over a 32-byte digest; with lowS a
 *   high-s signature is refused before any provider sees it (as noble's lowS).
 * - Ed25519: strict RFC 8032 (no ZIP-215 leniency), which is what OpenSSL does.
 */
const { sha256: nobleSha256 } = require('../vendor/exports/@noble/hashes/sha2.js');
const { hmac } = require('../vendor/exports/@noble/hashes/hmac.js');
const { p256 } = require('../vendor/exports/@noble/curves/nist.js');
const { ed25519 } = require('../vendor/exports/@noble/curves/ed25519.js');

const js = {
  sha256: (bytes) => nobleSha256(bytes),
  sha256Repeat(bytes, times) {
    let x = bytes;
    for (let k = 0; k < times; k++) x = nobleSha256(x);
    return x;
  },
  hmacSha256: (key, msg) => hmac(nobleSha256, key, msg),
  p256VerifyDigest: (sig, digest, publicKey) => p256.verify(sig, digest, publicKey, { prehash: false, lowS: false }),
  ed25519Verify: (sig, msg, publicKey) => ed25519.verify(sig, msg, publicKey, { zip215: false }),
};

let impl = js;
let implName = 'js';

/**
 * Plug in a faster implementation (any subset of the functions above); null puts
 * the JS back. name is for the log and the tests.
 */
function setCryptoProvider(provider, name = 'custom') {
  impl = provider ? { ...js, ...provider } : js;
  implName = provider ? name : 'js';
}

function cryptoProviderName() {
  return implName;
}

/* P-256's order n, halved: a signature with s above it is the malleable twin */
const P256_HALF_N = 0x7fffffff800000007fffffffffffffffde737d56d38bcf4279dce5617e3192a8n;
function highS(sig) {
  let s = 0n;
  for (let i = 32; i < 64; i++) s = (s << 8n) | BigInt(sig[i]);
  return s > P256_HALF_N;
}

function sha256(bytes) {
  return impl.sha256(bytes);
}

/** SHA-256 applied `times` times (a budget's hash chain: up to 1,024 a reveal) */
function sha256Repeat(bytes, times) {
  if (!Number.isInteger(times) || times < 0) throw new RangeError(`crypto: not a repeat count: ${times}`);
  return times === 0 ? bytes : impl.sha256Repeat(bytes, times);
}

function hmacSha256(key, msg) {
  return impl.hmacSha256(key, msg);
}

/**
 * P-256 over a 32-byte digest: sig = r||s (64 bytes), publicKey = SEC1 (65 bytes,
 * 0x04||x||y). Never throws: anything malformed is false.
 */
function p256VerifyDigest(sig, digest, publicKey, { lowS = true } = {}) {
  try {
    if (!(sig instanceof Uint8Array) || sig.length !== 64 || digest.length !== 32) return false;
    if (lowS && highS(sig)) return false;
    return impl.p256VerifyDigest(sig, digest, publicKey) === true;
  } catch {
    return false;
  }
}

/** P-256 over a message (hashed with SHA-256 first, as noble's prehash) */
function p256Verify(sig, msg, publicKey, opts) {
  return p256VerifyDigest(sig, sha256(msg), publicKey, opts);
}

/** Ed25519, strict. Never throws: anything malformed is false. */
function ed25519Verify(sig, msg, publicKey) {
  try {
    if (!(sig instanceof Uint8Array) || sig.length !== 64 || publicKey.length !== 32) return false;
    return impl.ed25519Verify(sig, msg, publicKey) === true;
  } catch {
    return false;
  }
}

module.exports = {
  sha256, sha256Repeat, hmacSha256, p256Verify, p256VerifyDigest, ed25519Verify,
  setCryptoProvider, cryptoProviderName, js,
};
