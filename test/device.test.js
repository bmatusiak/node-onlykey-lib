/*
 * The device layer.
 *
 * Several of these assert the CORRECTED behaviour rather than the original's,
 * and say so where that is the case. The originals are in OnlyKey-App and each
 * defect is cited at its fix site.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const slots = require('../src/device/slots');
const chunker = require('../src/device/chunker');
const enc = require('../src/device/encoders');
const { toHex, fromLatin1 } = require('../src/bytes');

/* ------------------------------------------------------------------- slots */

test('classic slot numbering is a +0/+6 split', () => {
  assert.equal(slots.slotNumber('1a'), 1);
  assert.equal(slots.slotNumber('6a'), 6);
  assert.equal(slots.slotNumber('1b'), 7);
  assert.equal(slots.slotNumber('6b'), 12);
});

test('DUO interleaves a and b within each three-slot band', () => {
  // Not one offset: consecutive profiles occupy contiguous runs of six.
  const duo = slots.DEVICE_TYPE.DUO;
  assert.deepEqual(
    ['1a', '2a', '3a', '1b', '2b', '3b'].map((s) => slots.slotNumber(s, duo)),
    [1, 2, 3, 4, 5, 6],
  );
  assert.deepEqual(
    ['4a', '6a', '4b', '6b'].map((s) => slots.slotNumber(s, duo)),
    [7, 9, 10, 12],
  );
  assert.equal(slots.slotNumber('12b', duo), 24);
});

test('XX is the device-global slot 0, by name rather than by coercion', () => {
  // The original reaches 0 via strPad('XX') -> NaN -> 0.
  assert.equal(slots.slotNumber('XX'), slots.GLOBAL_SLOT);
  assert.equal(slots.GLOBAL_SLOT, 0);
});

test('an out-of-range slot is an error, not undefined', () => {
  // The original DUO branch has no else and silently returns undefined.
  assert.throws(() => slots.slotNumber('13a', slots.DEVICE_TYPE.DUO), /out of range/);
  assert.throws(() => slots.slotNumber('7a'), /out of range/);
  assert.throws(() => slots.slotNumber('nonsense'), /unrecognised/);
});

test('label tokens 1a-1e are a lookup table, NOT hex', () => {
  // Read as hex, 1a would be 26 - out of every valid range, so it presents as
  // "labels stop at 19" rather than as a parse error.
  assert.equal(slots.labelSlotNumber('1a'), 20);
  assert.equal(slots.labelSlotNumber('1e'), 24);
  assert.notEqual(slots.labelSlotNumber('1a'), 0x1a);
  assert.equal(slots.labelSlotNumber('07'), 7);
  assert.equal(slots.labelSlotNumber('19'), 19);
});

test('the first label response is discarded as priming', () => {
  // Consuming it as a label drops label #1 and shifts everything after it.
  const r = new slots.LabelReader();
  assert.equal(r.push(fromLatin1('01|first')), 'primed');
  assert.equal(r.push(fromLatin1('01|first')), 'stored');
  assert.equal(r.result().labels[0], 'first');
});

test('a label line needs its pipe at index 2', () => {
  const r = new slots.LabelReader();
  r.push(fromLatin1('priming'));
  assert.equal(r.push(fromLatin1('1|short')), 'ignored');
  assert.equal(r.push(fromLatin1('001|long')), 'ignored');
  assert.equal(r.push(fromLatin1('02|ok')), 'stored');
});

test('the read completes at the last slot for the device type', () => {
  const r = new slots.LabelReader(slots.DEVICE_TYPE.CLASSIC);
  r.push(fromLatin1('priming'));
  for (let i = 1; i <= 11; i++) {
    assert.equal(r.push(fromLatin1(`${String(i).padStart(2, '0')}|s${i}`)), 'stored');
  }
  assert.equal(r.push(fromLatin1('12|last')), 'done');
  const out = r.result();
  assert.equal(out.complete, true);
  assert.equal(out.labels[11], 'last');
});

test('a device error ends the read', () => {
  const r = new slots.LabelReader();
  r.push(fromLatin1('priming'));
  assert.equal(r.push(fromLatin1('Error not in config mode')), 'error');
  assert.match(r.result().error, /not in config mode/);
});

/* ----------------------------------------------------------------- chunker */

test('a non-final restore chunk is headed FF', () => {
  const packets = chunker.hexPackets('ab'.repeat(100)); // 100 bytes
  assert.equal(packets.length, 2);
  assert.equal(packets[0].header, chunker.MORE_FOLLOW);
  assert.equal(packets[0].data.length, 57);
  assert.equal(packets[1].header, 43, 'the tail carries its byte count');
  assert.equal(packets[1].final, true);
});

test('an exact multiple of 57 ends with a COUNT header, not FF', () => {
  // The original's `<= 0` test is inclusive: a final full chunk is still
  // final, and gets 0x39 (57) rather than 0xFF.
  const packets = chunker.hexPackets('cd'.repeat(114)); // exactly 2 x 57
  assert.equal(packets.length, 2);
  assert.equal(packets[0].header, chunker.MORE_FOLLOW);
  assert.equal(packets[1].header, 57);
  assert.equal(packets[1].final, true);
});

test('a single short payload is one final chunk', () => {
  const packets = chunker.hexPackets('0102030405');
  assert.equal(packets.length, 1);
  assert.equal(packets[0].header, 5);
  assert.equal(packets[0].final, true);
});

test('an odd-length hex payload is refused rather than silently zeroed', () => {
  // The original computes (len/2).toString(16) -> "1c.8" -> NaN -> a zero
  // header byte, i.e. a final packet claiming zero bytes.
  assert.throws(() => chunker.hexPackets('abc'), /odd length/);
});

test('a restore frame is header-then-data inside one report', () => {
  const [packet] = chunker.hexPackets('aabbcc');
  const frame = chunker.buildHexPacket(0xf1, packet);
  assert.equal(frame.length, 64);
  assert.deepEqual(Array.from(frame.subarray(0, 5)), [0xff, 0xff, 0xff, 0xff, 0xf1]);
  assert.equal(frame[5], 3, 'the packet header byte');
  assert.deepEqual(Array.from(frame.subarray(6, 9)), [0xaa, 0xbb, 0xcc]);
});

test('the firmware path can gate on an ack between packets', async () => {
  const sent = [];
  const acks = [];
  await chunker.sendHexStream({
    msg: 0xf4,
    hex: 'ee'.repeat(120),
    send: async (f) => { sent.push(f); },
    awaitAck: async (p) => { acks.push(p.header); },
  });
  assert.equal(sent.length, 3);
  assert.deepEqual(acks, [0xff, 0xff], 'acked between packets, not after the last');
});

test('an RSA key is chunked with NO length header', () => {
  // Termination is device-side: type encodes the size and the device counts to
  // 128 * type. A length header here would be a protocol change.
  const packets = chunker.rsaPackets(new Uint8Array(256));
  assert.deepEqual(packets.map((p) => p.length), [57, 57, 57, 57, 28]);
});

test('an RSA frame repeats slot and type on every packet', async () => {
  const sent = [];
  await chunker.sendRsaKey({
    slot: 2, type: 2, key: new Uint8Array(120).fill(9),
    send: async (f) => { sent.push(f); },
  });
  assert.equal(sent.length, 3);
  for (const frame of sent) {
    assert.equal(frame[4], 0xef, 'OKSETPRIV');
    assert.equal(frame[5], 2, 'slot repeated');
    assert.equal(frame[6], 2, 'type repeated');
  }
});

test('rsaKeyLength states what the device will wait for', () => {
  assert.equal(chunker.rsaKeyLength(1), 128);
  assert.equal(chunker.rsaKeyLength(2), 256);
  assert.equal(chunker.rsaKeyLength(4), 512);
  // Modifiers live in the high nibble and must not change the size.
  assert.equal(chunker.rsaKeyLength(0x80 | 2), 256);
  assert.throws(() => chunker.rsaKeyLength(5), /1-4/);
});

/* ---------------------------------------------------------------- encoders */

test('base32 handles = padding', () => {
  // The original does not strip it: indexOf('=') is -1, (-1).toString(2) is
  // "-1", and the zero-pad makes "000-1", corrupting the whole bit string.
  assert.equal(toHex(enc.base32ToBytes('MZXW6===')), '666f6f');
  assert.equal(toHex(enc.base32ToBytes('MZXW6')), '666f6f');
});

test('base32 matches RFC 4648 vectors', () => {
  const cases = [
    ['MY======', '66'],
    ['MZXQ====', '666f'],
    ['MZXW6===', '666f6f'],
    ['MZXW6YQ=', '666f6f62'],
    ['MZXW6YTB', '666f6f6261'],
  ];
  for (const [b32, hex] of cases) {
    assert.equal(toHex(enc.base32ToBytes(b32)), hex, b32);
  }
});

test('base32 does not truncate a trailing nibble', () => {
  // A 26-char secret is 130 bits; the original emits an odd nibble count and
  // the caller's .match(/.{2}/g) drops the last one.
  const secret = 'A'.repeat(26);
  const bytes = enc.base32ToBytes(secret);
  assert.equal(bytes.length, 16, '130 bits is 16 whole bytes');
  assert.equal(enc.base32ToHex(secret).length, 32, 'even hex length');
});

test('base32 tolerates the spacing people paste', () => {
  assert.equal(toHex(enc.base32ToBytes('mzxw 6yt-b')), '666f6f6261');
});

test('an invalid base32 character is refused', () => {
  assert.throws(() => enc.base32ToBytes('MZXW6!'), /invalid base32/);
});

test('modhex round-trips', () => {
  assert.equal(enc.modhexToHex('cbdefghijklnrtuv'), '0123456789abcdef');
  assert.equal(enc.hexToModhex('0123456789abcdef'), 'cbdefghijklnrtuv');
  assert.throws(() => enc.modhexToHex('xyz'), /invalid modhex/);
});

test('a Yubikey credential is public||private||secret', () => {
  const out = enc.yubiCredential({
    publicId: 'cccccccccccb',           // 6 bytes of modhex
    privateId: '010203040506',
    secretKey: '00112233445566778899aabbccddeeff',
  });
  assert.equal(toHex(out), '000000000001' + '010203040506' + '00112233445566778899aabbccddeeff');
  assert.equal(out.length, 6 + 6 + 16);
});

test('a public id longer than 6 bytes is kept, not truncated', () => {
  // OnlyKeyComm.js:1687 caps this at 12 hex chars and silently drops the rest.
  // Yubico allows up to 16 bytes.
  const out = enc.yubiCredential({
    publicId: 'cccccccccccccccc',       // 8 bytes
    privateId: '010203040506',
    secretKey: '00'.repeat(16),
  });
  assert.equal(out.length, 8 + 6 + 16, 'the full public id survived');
});

test('a short private id or secret is refused rather than shifting the fields', () => {
  // Slicing and moving on produces a credential the device accepts and that
  // simply never authenticates.
  assert.throws(
    () => enc.yubiCredential({ publicId: 'cccc', privateId: '0102', secretKey: '00'.repeat(16) }),
    /private id must be/,
  );
  assert.throws(
    () => enc.yubiCredential({ publicId: 'cccc', privateId: '010203040506', secretKey: '0011' }),
    /secret must be/,
  );
});

test('TFATYPE values are the literal strings the device compares', () => {
  assert.equal(enc.TFA_TYPE.GOOGLE_AUTH, 'googleAuthOtp');
  assert.equal(enc.TFA_TYPE.YUBIKEY, 'YubikeyOtp');
});
