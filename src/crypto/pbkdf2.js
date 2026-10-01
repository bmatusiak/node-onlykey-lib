'use strict';

/**
 * PBKDF2-HMAC-SHA256 - the passphrase stretching behind Key Chain's
 * encrypted PEM copies - done natively wherever the platform can, and with
 * PROGRESS where it cannot (owner, 2026-10-01).
 *
 * 600000 rounds is nothing to Node or a browser (native code, under a
 * second) and a long, silent wait to Hermes, which interprets JavaScript with
 * no JIT. So, in order:
 *
 *   1. WebCrypto's own PBKDF2 - Node's and a browser's; under Hermes the
 *      lib's shim, but only when the host lent it a native implementation
 *      (install({ pbkdf2 }) - ok-rn lends Android's). Fast; progress jumps
 *      from 0 to 1.
 *   2. Otherwise this file's loop, the RFC 8018 definition written out so it
 *      can say how far it has got (onProgress) and let the UI draw between
 *      steps. @noble's pbkdf2 is the same arithmetic but has no progress.
 *
 * The output is the same either way - test/pbkdf2.test.js holds all three
 * paths to Node's crypto.pbkdf2Sync.
 */

const { hmac } = require('../vendor/exports/@noble/hashes/hmac.js');
const { sha256 } = require('../vendor/exports/@noble/hashes/sha2.js');

const BLOCK = 32; /* SHA-256 output */
const PROGRESS_EVERY = 4096;

/**
 * The plain loop, with progress. Kept separate so the shim can use it and the
 * tests can drive it directly.
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @param {number} dkLen bytes
 * @param {{onProgress?: ((fraction: number) => void) | null}} [opts]
 * @returns {Promise<Uint8Array>}
 */
async function pbkdf2Loop(password, salt, iterations, dkLen, { onProgress = null } = {}) {
  if (!(iterations >= 1)) throw new Error('PBKDF2 needs at least one round');
  const blocks = Math.ceil(dkLen / BLOCK);
  const out = new Uint8Array(blocks * BLOCK);
  const prf = hmac.create(sha256, password);
  /* one reusable instance, as @noble's own pbkdf2 does - no allocation per round */
  let work = prf._cloneInto();
  const total = blocks * iterations;
  let done = 0;
  for (let b = 1; b <= blocks; b++) {
    const index = Uint8Array.of(b >>> 24, (b >>> 16) & 0xff, (b >>> 8) & 0xff, b & 0xff);
    const u = new Uint8Array(BLOCK);
    work = prf._cloneInto(work);
    work.update(salt).update(index).digestInto(u);
    const t = out.subarray((b - 1) * BLOCK, b * BLOCK);
    t.set(u);
    for (let i = 1; i < iterations; i++) {
      work = prf._cloneInto(work);
      work.update(u).digestInto(u);
      for (let j = 0; j < BLOCK; j++) t[j] ^= u[j];
      if (++done % PROGRESS_EVERY === 0) {
        if (onProgress) onProgress(done / total);
        /* Yield, so a UI can draw the bar it was just told about. */
        await new Promise((r) => setTimeout(r, 0));
      }
    }
    done += 1;
  }
  prf.destroy();
  work.destroy();
  if (onProgress) onProgress(1);
  return out.slice(0, dkLen);
}

/**
 * PBKDF2-HMAC-SHA256, native where the platform has it.
 * @param {Uint8Array} password
 * @param {Uint8Array} salt
 * @param {number} iterations
 * @param {number} dkLen bytes
 * @param {{onProgress?: ((fraction: number) => void) | null}} [opts]
 * @returns {Promise<Uint8Array>}
 */
async function pbkdf2Sha256(password, salt, iterations, dkLen, { onProgress = null } = {}) {
  const subtle = globalThis.crypto && globalThis.crypto.subtle;
  const shim = subtle && subtle.okShim;
  /* A platform WebCrypto, or the shim WITH a native hook; the shim on its own is this loop without progress. */
  if (subtle && (!shim || shim.nativePbkdf2)) {
    try {
      if (onProgress) onProgress(0);
      const key = await subtle.importKey('raw', password, 'PBKDF2', false, ['deriveBits']);
      const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations }, key, dkLen * 8);
      if (onProgress) onProgress(1);
      return new Uint8Array(bits);
    } catch (err) {
      if (!err || err.name !== 'NotSupportedError') throw err;
    }
  }
  return pbkdf2Loop(password, salt, iterations, dkLen, { onProgress });
}

module.exports = { pbkdf2Sha256, pbkdf2Loop };
