/*
 * Three vectors, asserted separately.
 *
 * A wrong transit key and a chunking bug both surface as "the device answered
 * noise", so each step has to be able to fail on its own. In particular,
 * skipping HSalsa20 yields the raw X25519 point rather than the beforenm
 * value, and that is the likeliest porting mistake - so it gets its own
 * negative assertion rather than being implied.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const path = require('path');

const transit = require('../src/session/transit');
const { toHex, fromHex } = require('../src/bytes');

let reference = null;
try {
  reference = require(
    path.resolve(__dirname, '..', '..', 'onlykey-testing', 'lib', 'device', 'transit.js'),
  );
} catch { /* cross-checks skip themselves */ }

/*
 * The reference treats @noble/ciphers as an OPTIONAL dependency and resolves
 * it from its own node_modules, which need not have it. probe() is how it says
 * so, and beforenm() is the only part that needs it - box() and
 * connectPayload() work regardless, so they are cross-checked either way.
 */
const referenceHasNoble = Boolean(reference) && reference.probe().ok;

const V = transit.VECTORS;

test('beforenm matches NaCl crypto_box_beforenm', () => {
  const got = transit.beforenm(fromHex(V.bobPublic), fromHex(V.aliceSecret));
  assert.equal(toHex(got), V.beforenm);
});

test('beforenm is NOT the raw X25519 point', () => {
  // The likeliest way to get this wrong is to stop after the shared secret.
  const raw = '4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742';
  const got = transit.beforenm(fromHex(V.bobPublic), fromHex(V.aliceSecret));
  assert.notEqual(toHex(got), raw, 'HSalsa20 step was skipped');
});

test('the box matches the NIST zero-key zero-IV vector', () => {
  // Pins the keystream independently of the key derivation, so a KDF mistake
  // and a cipher mistake cannot be confused for each other.
  const got = transit.box(new Uint8Array(32), new Uint8Array(16));
  assert.equal(toHex(got), V.boxZero);
});

test('the box is its own inverse', () => {
  const key = transit.transitKey(fromHex(V.bobPublic), fromHex(V.aliceSecret));
  const plain = fromHex('00112233445566778899aabbccddeeff');
  assert.deepEqual(Array.from(transit.box(key, transit.box(key, plain))), Array.from(plain));
});

test('the box is length-preserving', () => {
  // The 228-byte request chunking depends on this; a tag would break it.
  const key = new Uint8Array(32);
  for (const n of [1, 16, 17, 228, 512]) {
    assert.equal(transit.box(key, new Uint8Array(n)).length, n);
  }
});

test('transitKey is SHA256 over raw beforenm bytes', () => {
  const { sha256 } = require('@noble/hashes/sha2.js');
  const expected = toHex(sha256(fromHex(V.beforenm)));
  const got = transit.transitKey(fromHex(V.bobPublic), fromHex(V.aliceSecret));
  assert.equal(toHex(got), expected);
});

test('a key that is not 32 bytes is rejected rather than truncated', () => {
  assert.throws(() => transit.box(new Uint8Array(16), new Uint8Array(4)), /32 bytes/);
});

test('connectPayload is 43 bytes with the documented layout', () => {
  const pk = new Uint8Array(32).fill(0xab);
  const out = transit.connectPayload(pk, { when: 0x68bd1f40 * 1000 });
  assert.equal(out.length, 43);
  assert.deepEqual(Array.from(out.subarray(0, 5)), [0xff, 0xff, 0xff, 0xff, 0xe4]);
  assert.deepEqual(Array.from(out.subarray(5, 9)), [0x68, 0xbd, 0x1f, 0x40], 'epoch is BE');
  assert.deepEqual(Array.from(out.subarray(9, 41)), Array.from(pk));
  assert.equal(out[41], 0x63);
  assert.equal(out[42], 0x6c);
});

test('a short public key is rejected', () => {
  assert.throws(() => transit.connectPayload(new Uint8Array(31)), /32 bytes/);
});

test('parseConnectReply opens a sealed status tail', () => {
  const key = new Uint8Array(32).fill(7);
  const reply = new Uint8Array(32 + 16);
  reply.set(new Uint8Array(32).fill(0xcd), 0);
  reply.set(transit.box(key, Uint8Array.from(Buffer.from('UNLOCKEDv3.0.4\0\0', 'latin1'))), 32);

  const out = transit.parseConnectReply(reply, key);
  assert.equal(out.sealed, true);
  assert.match(out.status, /^UNLOCKEDv3\.0\.4/);
  assert.equal(toHex(out.devicePublic), 'cd'.repeat(32));
});

test('parseConnectReply falls back to a plaintext tail', () => {
  const reply = new Uint8Array(32 + 12);
  reply.set(Uint8Array.from(Buffer.from('INITIALIZED\0', 'latin1')), 32);
  const out = transit.parseConnectReply(reply, new Uint8Array(32));
  assert.equal(out.status, 'INITIALIZED');
});

/* ---- cross-check against the hardware-proven reference ------------------ */

test('beforenm matches onlykey-testing', { skip: !referenceHasNoble }, () => {
  const got = transit.beforenm(fromHex(V.bobPublic), fromHex(V.aliceSecret));
  const theirs = reference.beforenm(
    Buffer.from(V.bobPublic, 'hex'), Buffer.from(V.aliceSecret, 'hex'),
  );
  assert.equal(toHex(got), theirs.toString('hex'));
});

test('box matches onlykey-testing over many lengths', { skip: !reference }, () => {
  const key = Buffer.alloc(32, 0x5a);
  for (const n of [0, 1, 15, 16, 17, 64, 228, 512, 3309]) {
    const data = Buffer.alloc(n, 0xa5);
    assert.equal(
      toHex(transit.box(new Uint8Array(key), new Uint8Array(data))),
      reference.box(key, data).toString('hex'),
      `length ${n} differs from the reference`,
    );
  }
});

test('connectPayload matches the reference from offset 5', { skip: !reference }, () => {
  // The reference zero-fills [0..4]; we emit the frame header every shipped
  // client emits. Everything the firmware reads is at 5 and beyond.
  const pk = Buffer.alloc(32, 0x11);
  const when = 0x68bd1f40 * 1000;
  const mine = transit.connectPayload(new Uint8Array(pk), { when });
  const theirs = reference.connectPayload(pk, { when });
  assert.equal(theirs.length, 43);
  assert.equal(toHex(mine.subarray(5)), theirs.subarray(5).toString('hex'));
});

test('the reference self-test still passes', { skip: !referenceHasNoble }, () => {
  assert.doesNotThrow(() => reference.selfTest());
});
