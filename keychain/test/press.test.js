'use strict';

/*
 * The firmware's press records (keychain/src/press.js): a sign's, and a derive's - which also
 * says press or code, the code computed from its subject exactly as the derive gate does.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const press = require('../src/press');

const hex = (b) => Buffer.from(b).toString('hex');

test('a sign record decodes as before; it says no mode', () => {
  const rec = new Uint8Array(69);
  rec.set([1, 0, 0xed, 201, 1]);
  rec.fill(7, 37, 69);
  const p = press.decodePress(hex(rec));
  assert.equal(p.opcode, 0xed);
  assert.equal(p.slot, 201);
  assert.equal(p.label, '07'.repeat(32));
  assert.equal(p.mode, null);
});

test('a derive record: OKCONNECT, slot 128, the label, and press or code', () => {
  const data = new Uint8Array(32 + 65).fill(3);
  const subject = nodeCrypto.createHash('sha256').update(data).digest();
  for (const [byte, mode] of [[1, 'press'], [0, 'code']]) {
    const rec = new Uint8Array(70);
    rec.set([1, 0, press.DERIVE_OPCODE, press.DERIVE_SLOT, 1]);
    rec.set(subject, 5);
    rec.set(data.subarray(0, 32), 37);
    rec[69] = byte;
    const p = press.decodePress(rec);
    assert.equal(p.opcode, 0xe4);
    assert.equal(p.slot, 128);
    assert.equal(p.mode, mode);
    assert.equal(p.label, '03'.repeat(32));
  }
});

test('the code: bytes 0, 15, 31 of the subject, mod 6, plus one', () => {
  const h = new Uint8Array(32);
  h[0] = 11; h[15] = 6; h[31] = 255;
  assert.deepEqual(press.codeOf(hex(h)), [11 % 6 + 1, 1, 255 % 6 + 1]);
  assert.deepEqual(press.codeOf(hex(h), 3), [11 % 3 + 1, 1, 255 % 3 + 1]);
  assert.throws(() => press.codeOf('00'), /32-byte/);
});

test('the end record: the test result, signed', () => {
  assert.deepEqual(press.decodePressEnd('0101'), { result: 1 });
  assert.deepEqual(press.decodePressEnd('01fe'), { result: -2 });
  assert.equal(press.decodePressEnd('0200'), null);
});
