'use strict';
/*
 * labelHashOf (Brad, 2026-10-10: the firmware presents what it signs): the 32 bytes a derived
 * sign carries for a Key Chain entry, computed here with node's own SHA-256 - not with the
 * library's identityHash - so a wrong shape cannot pass by agreeing with itself.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { labelHashOf, identityName } = require('../src/derive');

const sha = (s) => crypto.createHash('sha256').update(Buffer.from(s, 'ascii')).digest('hex');

test('labelHashOf: gpg hashes "gpg://<uid>", ssh hashes "user@host" (or a host alone)', () => {
  const uid = 'Claude (nitro16) 2026 <bmatusiak+agent@gmail.com>';
  assert.equal(labelHashOf({ kind: 'derived', scheme: 'gpg', label: uid }), sha(`gpg://${uid}`));
  assert.equal(labelHashOf({ kind: 'derived', scheme: 'ssh', label: 'claude@nitro16' }), sha('claude@nitro16'));
  assert.equal(labelHashOf({ kind: 'derived', scheme: 'ssh', label: 'github.com' }), sha('github.com'));
});

test('labelHashOf: an entry the firmware recorded keeps its hash; anything else names nothing', () => {
  const h = 'AB'.repeat(32);
  assert.equal(labelHashOf({ kind: 'derived', labelHash: h }), h.toLowerCase());
  assert.equal(labelHashOf({ kind: 'derived', label: `hash:${h}` }), h.toLowerCase());
  assert.equal(labelHashOf({ kind: 'derived', scheme: 'label', label: 'web' }), null);
  assert.equal(labelHashOf({ kind: 'slot', label: 'x' }), null);
  assert.equal(labelHashOf(null), null);
});

test('identityName: the identity as the person knows it', () => {
  assert.equal(identityName({ kind: 'derived', scheme: 'gpg', label: 'A <a@b>' }), 'gpg://A <a@b>');
  assert.equal(identityName({ kind: 'derived', scheme: 'ssh', label: 'claude@nitro16' }), 'ssh://claude@nitro16');
  assert.equal(identityName({ kind: 'derived', label: `hash:${'ab'.repeat(32)}` }), null, 'a recorded hash has no name');
});

/* the press record (okplugin_key_chain.cpp), built here byte by byte */
const { decodePress, nameOfLabel } = require('../src/press');

test('decodePress: version, transport, opcode, slot, subject, label - from bytes or hex', () => {
  const subject = Array.from({ length: 32 }, (_, i) => i);
  const label = Array.from({ length: 32 }, (_, i) => 0xa0 + (i % 16));
  const rec = Uint8Array.from([1, 0, 0xed, 221, 1, ...subject, ...label]);
  const hexOf = (a) => Buffer.from(a).toString('hex');
  const want = { transport: 'vendor', opcode: 0xed, slot: 221, subject: hexOf(subject), label: hexOf(label) };
  assert.deepEqual(decodePress(rec), want);
  assert.deepEqual(decodePress(hexOf(rec)), want);
  assert.equal(decodePress(Uint8Array.from([1, 1, 0xf0, 2, 0, ...subject, ...new Array(32).fill(0)])).label, null);
  assert.equal(decodePress(Uint8Array.from([2, ...rec.subarray(1)])), null);
  assert.equal(decodePress(rec.subarray(0, 40)), null);
});

test('nameOfLabel: not listed; listed by a recorded hash, unnamed; named by an entry with the text', () => {
  const uid = 'A (x) <a@x>';
  const label = sha(`gpg://${uid}`);
  const list = [];
  assert.deepEqual(nameOfLabel(list, label), { listed: false, name: null });
  list.push({ kind: 'derived', label: `hash:${label}` });
  assert.deepEqual(nameOfLabel(list, label), { listed: true, name: null });
  list.push({ kind: 'derived', scheme: 'gpg', label: uid });
  assert.deepEqual(nameOfLabel(list, label.toUpperCase()), { listed: true, name: `gpg://${uid}` });
});
