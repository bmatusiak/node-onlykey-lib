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
const crypto = require('crypto');

const transit = require('../src/session/transit');
const { toHex, fromHex, fromLatin1 } = require('../src/bytes');

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

/*
 * THE TWO beforenm() FUNCTIONS TAKE DIFFERENT THINGS, and the reference's is
 * not interchangeable with ours.
 *
 * Ours takes raw bytes. The reference computes the shared point with
 * `crypto.diffieHellman()`, whose `privateKey` must be a KeyObject - a raw
 * Buffer is rejected with ERR_OSSL_UNSUPPORTED, which reads like the platform
 * lacking X25519 and is nothing of the kind. Its own selfTest() wraps the key
 * in PKCS#8 before calling it, and that is the calling convention.
 *
 * This test used to hand it a Buffer. It went unnoticed because the reference
 * treats @noble/ciphers as an optional dependency and probe() reported it
 * missing, so the whole cross-check SKIPPED - installing that dependency in the
 * sibling checkout is what first ran these lines.
 */
function referencePrivateKey(hex) {
  return crypto.createPrivateKey({
    key: Buffer.concat([
      Buffer.from('302e020100300506032b656e04220420', 'hex'),
      Buffer.from(hex, 'hex'),
    ]),
    format: 'der',
    type: 'pkcs8',
  });
}

test('beforenm matches onlykey-testing', { skip: !referenceHasNoble }, () => {
  const got = transit.beforenm(fromHex(V.bobPublic), fromHex(V.aliceSecret));
  const theirs = reference.beforenm(
    Buffer.from(V.bobPublic, 'hex'), referencePrivateKey(V.aliceSecret),
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

/* -------------------------------------------- the two OKCONNECT replies */

test('a plaintext status reply is recognised as NOT a key exchange', () => {
  /*
   * Measured on a real device: over the vendor interface okcore.cpp dispatches
   * OKCONNECT to set_time(), which answers hidprint(HW_MODEL(UNLOCKED)) - a
   * plaintext status from byte 0, with no public key anywhere in it.
   *
   * Read as an exchange, its first 32 characters become a "device public key"
   * and the session derives a transit key from ASCII text. Nothing errors; the
   * session simply reports itself established and every later box() is
   * nonsense.
   */
  const reply = new Uint8Array(64);
  reply.set(fromLatin1('UNLOCKEDv3.0.4-testc'), 0);

  const out = transit.parseConnectReply(reply, null);
  assert.equal(out.kind, 'status');
  assert.equal(out.status, 'UNLOCKEDv3.0.4-testc');
  assert.equal(out.devicePublic, null, 'there is no key to derive from');
  assert.equal(out.sealed, false);
});

test('a real key exchange is still read as one', () => {
  // 32 bytes of key material then a boxed tail. The discriminator must not
  // mistake this for text just because some bytes happen to be printable.
  const keys = transit.keypair();
  const key = transit.transitKey(keys.publicKey, keys.secretKey);
  const tail = transit.box(key, fromLatin1('UNLOCKEDv3.0.4-testc'));

  const reply = new Uint8Array(32 + tail.length);
  reply.set(keys.publicKey, 0);
  reply.set(tail, 32);

  const out = transit.parseConnectReply(reply, key);
  assert.equal(out.kind, 'exchange');
  assert.equal(out.sealed, true);
  assert.equal(out.status, 'UNLOCKEDv3.0.4-testc');
});

test('an all-printable public key would be astronomically unlikely', () => {
  /*
   * The discriminator's one assumption, stated so it is not mistaken for a
   * guess: a 32-byte X25519 public key that is entirely printable ASCII has
   * probability (95/256)^32, around 1e-14. This asserts the rule rather than
   * the odds - a reply whose key half contains ANY non-printable byte is an
   * exchange.
   */
  const reply = new Uint8Array(64);
  reply.set(fromLatin1('UNLOCKED'), 0);
  reply[8] = 0xff; // one non-printable byte inside the first 32
  assert.equal(transit.parseConnectReply(reply, null).kind, 'exchange');
});

test('a status reply shorter than a key exchange is still valid', () => {
  /*
   * From the device: hidprint() sends strlen bytes, so the vendor reply to
   * OKCONNECT is 11 bytes of "INITIALIZED" - not 64. The emulator pads its
   * reports, which is the only reason a universal 33-byte minimum ever passed
   * here; a transport reporting the true length would have rejected a
   * perfectly good reply with a message about a size the vendor path never
   * promised.
   */
  const out = transit.parseConnectReply(fromLatin1('INITIALIZED'), null);
  assert.equal(out.kind, 'status');
  assert.equal(out.status, 'INITIALIZED');
});

test('a short reply that is NOT text is still refused', () => {
  // The minimum still applies to the exchange form, where it is real.
  assert.throws(
    () => transit.parseConnectReply(Uint8Array.from([0xff, 0x01, 0x02]), null),
    /a key exchange needs at least 33/,
  );
});

test('the exact bytes the device sent are parsed as status', () => {
  // Captured from a Samsung SM-S136DL running the emulated firmware:
  // "Sending transport response data 49 4E 49 54 49 41 4C 49 5A 45 44 0 ..."
  const observed = fromHex('494e495449414c495a4544' + '00'.repeat(13));
  const out = transit.parseConnectReply(observed, null);
  assert.equal(out.kind, 'status');
  assert.equal(out.status, 'INITIALIZED');
  assert.equal(out.sealed, false, 'and no session key was invented from it');
});

/* ------------------------------------------------ the beta-8c exchange */

test('a v0.2-beta.8c reply puts its key at 21, and is told apart by the reply itself', () => {
  /*
   * The web app has branched on this since the beginning
   * (onlykey-api.js:168-198): in this one firmware the public key is at
   * bytes 21..53 and the version string is in the CLEAR at 8..20, where a
   * modern reply has the first 32 bytes of the key. Detecting it from the
   * reply is what makes it work at all - the version this branch depends on
   * is inside the very message being parsed.
   *
   * Reading a legacy reply with the modern offsets does not fail: it derives
   * a transit key from the wrong 32 bytes and the session reports itself
   * established, which is the silent failure parseConnectReply exists to
   * prevent. Pinned here with a synthetic reply because no release in the
   * matrix is beta-8c; the offsets are the web app's, the crypto after them
   * is shared with the modern path.
   */
  const key = new Uint8Array(32).map((_, i) => (i * 7 + 1) & 0xff);
  const reply = new Uint8Array(64);
  reply.set(Uint8Array.from('v0.2-beta.8c', (c) => c.charCodeAt(0)), 8);
  reply.set(key, 21);

  const out = transit.parseConnectReply(reply, null);
  assert.equal(out.kind, 'exchange');
  assert.equal(out.layout, 'legacy');
  assert.equal(out.status, 'v0.2-beta.8c');
  assert.deepEqual([...out.devicePublic], [...key]);
});

test('a modern exchange reply is unaffected, and says which layout it was', () => {
  const key = new Uint8Array(32).map((_, i) => (i * 3 + 9) & 0xff);
  const reply = new Uint8Array(64);
  reply.set(key, 0);
  reply.set(Uint8Array.from('UNLOCKEDv3.0.4', (c) => c.charCodeAt(0)), 32);

  const out = transit.parseConnectReply(reply, null);
  assert.equal(out.layout, 'modern');
  assert.deepEqual([...out.devicePublic], [...key]);
});

test('the legacy marker has to be the whole version field, not a fragment of a key', () => {
  /*
   * The check reads bytes 8..20 as printable text and compares the WHOLE
   * string. A modern key whose bytes 8..20 happen to be printable must not
   * be mistaken for beta-8c, so a near-miss is checked rather than assumed.
   */
  const reply = new Uint8Array(64);
  reply.set(Uint8Array.from('v0.2-beta.8d', (c) => c.charCodeAt(0)), 8);
  assert.equal(transit.parseConnectReply(reply, null).layout, 'modern');
});
