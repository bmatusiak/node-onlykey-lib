/*
 * src/crypto/pbkdf2.js and the shim's PBKDF2 - one answer on every path,
 * held to Node's own crypto.pbkdf2Sync: the platform's WebCrypto, the shim
 * with a lent native PBKDF2 (ok-rn: Android's), the shim alone, and the
 * JavaScript loop that reports progress.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { pbkdf2Sha256, pbkdf2Loop } = require('../src/crypto/pbkdf2');
const { createSubtle } = require('../src/webcrypto/subtle');

const ref = (pw, salt, it, len) => crypto.pbkdf2Sync(Buffer.from(pw), Buffer.from(salt), it, len, 'sha256').toString('hex');
const hex = (b) => Buffer.from(b).toString('hex');

test('the loop is PBKDF2-HMAC-SHA256: matches Node across rounds and lengths, and reports progress to 1', async () => {
  for (const [pw, salt, it, len] of [['password', 'salt', 1, 32], ['pass', 'NaCl', 4097, 32], ['a longer pass', 'sixteen-byte-slt', 10000, 64]]) {
    const seen = [];
    const out = await pbkdf2Loop(Buffer.from(pw), Buffer.from(salt), it, len, { onProgress: (f) => seen.push(f) });
    assert.equal(hex(out), ref(pw, salt, it, len), `${it} rounds, ${len} bytes`);
    assert.equal(seen[seen.length - 1], 1);
    assert.ok(seen.every((f, i) => i === 0 || f >= seen[i - 1]), 'progress never goes backwards');
  }
});

test('the shim: a lent native PBKDF2 is used; without one the answer is the same', async () => {
  const calls = [];
  const native = async (pw, salt, it, len) => { calls.push(it); return Uint8Array.from(crypto.pbkdf2Sync(pw, salt, it, len, 'sha256')); };
  for (const subtle of [createSubtle({ pbkdf2: native }), createSubtle()]) {
    const key = await subtle.importKey('raw', Buffer.from('passphrase'), 'PBKDF2', false, ['deriveBits']);
    const bits = await subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt: Buffer.from('salty'), iterations: 2000 }, key, 256);
    assert.equal(hex(bits), ref('passphrase', 'salty', 2000, 32));
  }
  assert.deepEqual(calls, [2000], 'the native one ran once, for the shim that was lent it');
  assert.equal(createSubtle({ pbkdf2: native }).okShim.nativePbkdf2, true);
  assert.equal(createSubtle().okShim.nativePbkdf2, false);
});

test('pbkdf2Sha256 takes the native path when there is one, the loop with progress when there is not', async () => {
  const saved = Object.getOwnPropertyDescriptor(globalThis, 'crypto');
  const use = (subtle) => Object.defineProperty(globalThis, 'crypto', { value: { subtle }, configurable: true, writable: true });
  try {
    let lent = 0;
    use(createSubtle({ pbkdf2: async (pw, salt, it, len) => { lent += 1; return Uint8Array.from(crypto.pbkdf2Sync(pw, salt, it, len, 'sha256')); } }));
    let seen = [];
    let out = await pbkdf2Sha256(Buffer.from('pw'), Buffer.from('s'), 9000, 32, { onProgress: (f) => seen.push(f) });
    assert.equal(hex(out), ref('pw', 's', 9000, 32));
    assert.equal(lent, 1);
    assert.deepEqual(seen, [0, 1], 'native: no steps to report, just start and end');

    use(createSubtle());
    seen = [];
    out = await pbkdf2Sha256(Buffer.from('pw'), Buffer.from('s'), 9000, 32, { onProgress: (f) => seen.push(f) });
    assert.equal(hex(out), ref('pw', 's', 9000, 32));
    assert.ok(seen.length > 2, 'the shim alone: the loop, with progress');
  } finally {
    if (saved) Object.defineProperty(globalThis, 'crypto', saved);
  }
  /* Node's own WebCrypto, as it is. */
  const out = await pbkdf2Sha256(Buffer.from('pw'), Buffer.from('s'), 9000, 32);
  assert.equal(hex(out), ref('pw', 's', 9000, 32));
});
