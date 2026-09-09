/**
 * The WebCrypto shim, checked against the real thing.
 *
 * Node HAS `crypto.subtle`, so this suite has the best oracle available: run
 * the same operation through both and compare. That is the difference between
 * a test that proves the shim correct and one that proves it self-consistent -
 * and self-consistent is exactly what a wrong implementation also is.
 *
 * Where the two disagree, the shim is wrong. There is no case in this file
 * where a difference is explained away.
 *
 * The shim exists because React Native has `crypto.getRandomValues` and no
 * `subtle`, and OpenPGP.js v6 reads WebCrypto at module scope - so the fork's
 * factory throws before it exports anything. See
 * ok-rn/FINDING-the-openpgp-fork-does-not-load-under-hermes.md.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const { createSubtle, install } = require('../src/webcrypto/subtle');
const { toHex } = require('../src/bytes');

/** The shim under test, and Node's own, side by side. */
const shim = createSubtle();
const real = globalThis.crypto.subtle;

const u8 = (n, seed = 1) => Uint8Array.from({ length: n }, (_, i) => (i * seed + 7) & 0xff);
const hex = (buf) => toHex(new Uint8Array(buf));

/* ------------------------------------------------------------------ digest */

test('digest matches for every hash openpgp asks for', async () => {
  const data = u8(200);
  for (const name of ['SHA-1', 'SHA-256', 'SHA-384', 'SHA-512']) {
    assert.equal(
      hex(await shim.digest(name, data)),
      hex(await real.digest(name, data)),
      `${name} disagrees`,
    );
  }
});

test('an unknown hash is a NotSupportedError, not a wrong answer', async () => {
  await assert.rejects(() => shim.digest('SHA-3', u8(8)), (e) => e.name === 'NotSupportedError');
});

/* --------------------------------------------------------------------- AES */

test('AES-CBC encrypts identically, padding included', async () => {
  /*
   * The padding is load-bearing. openpgp builds CFB out of one CBC block and
   * takes the ciphertext MINUS its final block, which is the PKCS#7 pad block -
   * so a shim that omitted padding would shift every byte it reads back.
   */
  const key = u8(32, 3);
  const iv = u8(16, 5);
  const pt = u8(64, 7);

  const mine = await shim.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);
  const theirs = await real.importKey('raw', key, { name: 'AES-CBC' }, false, ['encrypt']);

  assert.equal(
    hex(await shim.encrypt({ name: 'AES-CBC', iv }, mine, pt)),
    hex(await real.encrypt({ name: 'AES-CBC', iv }, theirs, pt)),
  );
});

test('AES-CTR encrypts identically', async () => {
  const key = u8(32, 11);
  const counter = u8(16, 13);
  const pt = u8(70, 17);

  const mine = await shim.importKey('raw', key, { name: 'AES-CTR' }, false, ['encrypt']);
  const theirs = await real.importKey('raw', key, { name: 'AES-CTR' }, false, ['encrypt']);

  assert.equal(
    hex(await shim.encrypt({ name: 'AES-CTR', counter, length: 128 }, mine, pt)),
    hex(await real.encrypt({ name: 'AES-CTR', counter, length: 128 }, theirs, pt)),
  );
});

test('AES-GCM round trips against the real implementation, both ways', async () => {
  const key = u8(32, 19);
  const iv = u8(12, 23);
  const aad = u8(16, 29);
  const pt = u8(48, 31);

  const mine = await shim.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const theirs = await real.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);

  const ct = await shim.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, mine, pt);
  assert.equal(hex(ct), hex(await real.encrypt({ name: 'AES-GCM', iv, additionalData: aad, tagLength: 128 }, theirs, pt)));

  // And what the real one sealed, the shim opens.
  const sealed = await real.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, theirs, pt);
  const opened = await shim.decrypt({ name: 'AES-GCM', iv, additionalData: aad }, mine, sealed);
  assert.equal(hex(opened), hex(pt));
});

test('a tampered GCM tag is an OperationError, not a silent plaintext', async () => {
  const key = u8(32, 37);
  const iv = u8(12, 41);
  const mine = await shim.importKey('raw', key, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
  const ct = new Uint8Array(await shim.encrypt({ name: 'AES-GCM', iv }, mine, u8(32)));
  ct[ct.length - 1] ^= 0x01;

  await assert.rejects(
    () => shim.decrypt({ name: 'AES-GCM', iv }, mine, ct),
    (e) => e.name === 'OperationError',
  );
});

/* ------------------------------------------------------------------ AES-KW */

test('AES-KW wraps what the real one unwraps', async () => {
  const kek = u8(32, 43);
  const secret = u8(32, 47);

  const mineKek = await shim.importKey('raw', kek, { name: 'AES-KW' }, false, ['wrapKey', 'unwrapKey']);
  const realKek = await real.importKey('raw', kek, { name: 'AES-KW' }, false, ['wrapKey', 'unwrapKey']);

  const toWrap = await shim.importKey('raw', secret, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']);
  const wrapped = await shim.wrapKey('raw', toWrap, mineKek, { name: 'AES-KW' });

  const back = await real.unwrapKey(
    'raw', wrapped, realKek, { name: 'AES-KW' }, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign'],
  );
  assert.equal(hex(await real.exportKey('raw', back)), hex(secret),
    'the real implementation could not unwrap what the shim wrapped');
});

test('a corrupted wrap fails as an OperationError', async () => {
  const kek = await shim.importKey('raw', u8(32, 53), { name: 'AES-KW' }, false, ['unwrapKey']);
  const rubbish = u8(40, 59);
  await assert.rejects(
    () => shim.unwrapKey('raw', rubbish, kek, { name: 'AES-KW' }, { name: 'HMAC', hash: 'SHA-256' }, true, ['sign']),
    (e) => e.name === 'OperationError',
  );
});

/* -------------------------------------------------------------------- HMAC */

test('HMAC signs identically and verifies both ways', async () => {
  const secret = u8(32, 61);
  const data = u8(128, 67);
  const algo = { name: 'HMAC', hash: 'SHA-256' };

  const mine = await shim.importKey('raw', secret, algo, false, ['sign', 'verify']);
  const theirs = await real.importKey('raw', secret, algo, false, ['sign', 'verify']);

  const sig = await shim.sign('HMAC', mine, data);
  assert.equal(hex(sig), hex(await real.sign('HMAC', theirs, data)));
  assert.equal(await shim.verify('HMAC', mine, sig, data), true);
  assert.equal(await real.verify('HMAC', theirs, sig, data), true);
});

test('HMAC verify rejects a wrong signature rather than throwing', async () => {
  const algo = { name: 'HMAC', hash: 'SHA-256' };
  const key = await shim.importKey('raw', u8(32, 71), algo, false, ['sign', 'verify']);
  assert.equal(await shim.verify('HMAC', key, u8(32), u8(16)), false);
});

/* -------------------------------------------------------------------- HKDF */

test('HKDF derives the same bits', async () => {
  const ikm = u8(32, 73);
  const salt = u8(16, 79);
  const info = u8(8, 83);

  const mine = await shim.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const theirs = await real.importKey('raw', ikm, 'HKDF', false, ['deriveBits']);
  const params = { name: 'HKDF', hash: 'SHA-256', salt, info };

  assert.equal(
    hex(await shim.deriveBits(params, mine, 256)),
    hex(await real.deriveBits(params, theirs, 256)),
  );
});

/* ---------------------------------------------------------------- Ed25519 */

test('Ed25519 signatures verify in the real implementation', async () => {
  const pair = await shim.generateKey('Ed25519', true, ['sign', 'verify']);
  const data = u8(64, 89);

  const sig = await shim.sign('Ed25519', pair.privateKey, data);
  assert.equal(sig.byteLength, 64);

  const jwk = await shim.exportKey('jwk', pair.publicKey);
  const theirPub = await real.importKey('jwk', jwk, 'Ed25519', false, ['verify']);
  assert.equal(await real.verify('Ed25519', theirPub, sig, data), true,
    'the real implementation rejected a signature the shim produced');
});

test('Ed25519 verifies what the real implementation signed', async () => {
  const pair = await real.generateKey('Ed25519', true, ['sign', 'verify']);
  const data = u8(48, 97);
  const sig = await real.sign('Ed25519', pair.privateKey, data);

  const jwk = await real.exportKey('jwk', pair.publicKey);
  const mine = await shim.importKey('jwk', jwk, 'Ed25519', false, ['verify']);
  assert.equal(await shim.verify('Ed25519', mine, sig, data), true);
});

test('an Ed25519 private jwk round trips through the shim', async () => {
  const pair = await shim.generateKey('Ed25519', true, ['sign', 'verify']);
  const jwk = await shim.exportKey('jwk', pair.privateKey);
  assert.equal(jwk.kty, 'OKP');
  assert.equal(jwk.crv, 'Ed25519');
  assert.ok(jwk.d && jwk.x, 'a private jwk carries both halves');

  const back = await shim.importKey('jwk', jwk, 'Ed25519', false, ['sign']);
  const data = u8(32, 101);
  assert.equal(
    hex(await shim.sign('Ed25519', back, data)),
    hex(await shim.sign('Ed25519', pair.privateKey, data)),
  );
});

/* ------------------------------------------------------------------- ECDSA */

test('ECDSA signatures verify in the real implementation, on every curve', async () => {
  /*
   * The signature FORMAT is the trap. WebCrypto's ECDSA signature is the raw
   * r||s pair; @noble hands back DER unless told otherwise, and a DER
   * signature verifies nowhere.
   */
  for (const [curve, hash] of [['P-256', 'SHA-256'], ['P-384', 'SHA-384'], ['P-521', 'SHA-512']]) {
    const algo = { name: 'ECDSA', namedCurve: curve };
    const pair = await shim.generateKey(algo, true, ['sign', 'verify']);
    const data = u8(80, 103);

    const sig = await shim.sign({ name: 'ECDSA', hash }, pair.privateKey, data);
    const jwk = await shim.exportKey('jwk', pair.publicKey);
    const theirs = await real.importKey('jwk', jwk, algo, false, ['verify']);

    assert.equal(
      await real.verify({ name: 'ECDSA', hash }, theirs, sig, data), true,
      `${curve} signature rejected by the real implementation`,
    );
  }
});

test('ECDSA verifies what the real implementation signed, every time', async () => {
  /*
   * TWENTY signatures, not one. ECDSA's S value lands in the upper half about
   * half the time, and @noble rejects a high-S signature by default while
   * WebCrypto happily produces them - so a single-signature test passes about
   * half the time and looks like flakiness rather than a bug. Measured before
   * the fix: 9 of 20 genuine signatures rejected.
   */
  const algo = { name: 'ECDSA', namedCurve: 'P-256' };
  for (let i = 0; i < 20; i++) {
    const pair = await real.generateKey(algo, true, ['sign', 'verify']);
    const data = u8(64, 107 + i);
    const sig = await real.sign({ name: 'ECDSA', hash: 'SHA-256' }, pair.privateKey, data);

    const jwk = await real.exportKey('jwk', pair.publicKey);
    const mine = await shim.importKey('jwk', jwk, algo, false, ['verify']);
    assert.equal(
      await shim.verify({ name: 'ECDSA', hash: 'SHA-256' }, mine, sig, data), true,
      `signature ${i} rejected - high-S signatures are valid and WebCrypto emits them`,
    );
  }
});

/* -------------------------------------------------------------------- ECDH */

test('ECDH derives the same secret as the real implementation', async () => {
  /*
   * WebCrypto's ECDH yields the X COORDINATE alone. @noble returns a
   * compressed point whose leading byte is a parity tag, so passing that
   * through gives a secret one byte too long that agrees with nobody.
   */
  const algo = { name: 'ECDH', namedCurve: 'P-256' };
  const a = await real.generateKey(algo, true, ['deriveBits']);
  const b = await real.generateKey(algo, true, ['deriveBits']);

  const expected = await real.deriveBits({ name: 'ECDH', public: b.publicKey }, a.privateKey, 256);

  const mineA = await shim.importKey('jwk', await real.exportKey('jwk', a.privateKey), algo, false, ['deriveBits']);
  const mineB = await shim.importKey('jwk', await real.exportKey('jwk', b.publicKey), algo, false, []);

  assert.equal(hex(await shim.deriveBits({ name: 'ECDH', public: mineB }, mineA, 256)), hex(expected));
});

test('X25519 ECDH agrees with the real implementation', async () => {
  const a = await real.generateKey('X25519', true, ['deriveBits']);
  const b = await real.generateKey('X25519', true, ['deriveBits']);
  const expected = await real.deriveBits({ name: 'X25519', public: b.publicKey }, a.privateKey, 256);

  const mineA = await shim.importKey('jwk', await real.exportKey('jwk', a.privateKey), 'X25519', false, ['deriveBits']);
  const mineB = await shim.importKey('jwk', await real.exportKey('jwk', b.publicKey), 'X25519', false, []);

  assert.equal(hex(await shim.deriveBits({ name: 'ECDH', public: mineB }, mineA, 256)), hex(expected));
});

/* -------------------------------------------------------------- the refusals */

test('RSA refuses by name instead of returning something wrong', async () => {
  /*
   * @noble has no RSA and this project's PGP is composite post-quantum, so an
   * RSA path here would be code nobody runs. A caller can act on a
   * NotSupportedError; it cannot act on wrong bytes.
   */
  await assert.rejects(
    () => shim.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048 }, true, ['sign']),
    (e) => e.name === 'NotSupportedError' && /RSA/.test(e.message),
  );
  await assert.rejects(
    () => shim.importKey('jwk', { kty: 'RSA' }, { name: 'RSASSA-PKCS1-v1_5' }, false, ['verify']),
    (e) => e.name === 'NotSupportedError',
  );
});

test('a key used outside its declared usages is refused', async () => {
  const key = await shim.importKey('raw', u8(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  await assert.rejects(() => shim.verify('HMAC', key, u8(32), u8(8)),
    (e) => e.name === 'InvalidAccessError');
});

test('a non-extractable key cannot be exported', async () => {
  const key = await shim.importKey('raw', u8(32), { name: 'AES-GCM' }, false, ['encrypt']);
  await assert.rejects(() => shim.exportKey('raw', key), (e) => e.name === 'InvalidAccessError');
});

/* ------------------------------------------------------------------ install */

test('install refuses to replace a real implementation', () => {
  /*
   * Node HAS crypto.subtle, so this is the case that matters: a host with a
   * complete, better-tested implementation must keep it. The library is
   * platform-free and never installs itself.
   */
  const result = install();
  assert.equal(result.installed, false);
  assert.match(result.reason, /already has/);
  assert.equal(globalThis.crypto.subtle, real, 'the platform implementation is untouched');
});

test('install replaces one only when told to, and can be undone', () => {
  const result = install({ force: true });
  assert.equal(result.installed, true);
  assert.notEqual(globalThis.crypto.subtle, real);

  Object.defineProperty(globalThis.crypto, 'subtle', {
    value: real, configurable: true, writable: true,
  });
  assert.equal(globalThis.crypto.subtle, real);
});

/* -------------------------------------------------------- the text codecs */

/*
 * Hermes has no TextDecoder, and openpgp reaches for one the moment it reads
 * armour - so a key that generates perfectly still cannot be parsed back.
 * Checked against Node's own, for the same reason as everything above.
 */

const { ShimTextEncoder, ShimTextDecoder, installTextCodecs } = require('../src/webcrypto/text');

const SAMPLES = [
  '',
  'plain ascii',
  'héllo wörld',
  'em — dash, ellipsis …',
  'emoji 😀 and 👨‍👩‍👧 a family',
  '日本語のテキスト',
  '\u0000 embedded nul \u0000',
];

test('the encoder agrees with the platform on every sample', () => {
  const mine = new ShimTextEncoder();
  const real = new TextEncoder();
  for (const s of SAMPLES) {
    assert.deepEqual(Array.from(mine.encode(s)), Array.from(real.encode(s)), `encode ${JSON.stringify(s)}`);
  }
});

test('the decoder agrees with the platform on every sample', () => {
  const mine = new ShimTextDecoder();
  const real = new TextDecoder();
  const encoder = new TextEncoder();
  for (const s of SAMPLES) {
    const bytes = encoder.encode(s);
    assert.equal(mine.decode(bytes), real.decode(bytes), `decode ${JSON.stringify(s)}`);
  }
});

test('a leading BOM is dropped, and kept when asked', () => {
  const withBom = Uint8Array.from([0xef, 0xbb, 0xbf, 0x68, 0x69]);
  assert.equal(new ShimTextDecoder().decode(withBom), new TextDecoder().decode(withBom));
  assert.equal(
    new ShimTextDecoder('utf-8', { ignoreBOM: true }).decode(withBom),
    new TextDecoder('utf-8', { ignoreBOM: true }).decode(withBom),
  );
});

test('encodeInto truncates at a character boundary, not mid-sequence', () => {
  /*
   * 'é' is two bytes. A destination with room for one of them must write
   * NEITHER - a lone lead byte is not a character, and the spec says so.
   */
  const mine = new ShimTextEncoder();
  const real = new TextEncoder();
  for (const size of [0, 1, 2, 3, 4, 8]) {
    const a = new Uint8Array(size);
    const b = new Uint8Array(size);
    const mineResult = mine.encodeInto('éé', a);
    const realResult = real.encodeInto('éé', b);
    assert.deepEqual(Array.from(a), Array.from(b), `bytes at size ${size}`);
    assert.equal(mineResult.written, realResult.written, `written at size ${size}`);
    assert.equal(mineResult.read, realResult.read, `read at size ${size}`);
  }
});

test('an encoding we do not implement throws instead of guessing', () => {
  // Decoding shift-jis as utf-8 produces plausible mojibake, which is worse
  // than a refusal a caller can see.
  assert.throws(() => new ShimTextDecoder('shift-jis'), /only implements utf-8/);
});

test('installTextCodecs leaves a platform implementation alone', () => {
  const before = globalThis.TextDecoder;
  const result = installTextCodecs();
  assert.deepEqual(result.installed, []);
  assert.equal(globalThis.TextDecoder, before);
});

test('installTextCodecs fills in what is missing', () => {
  /*
   * The Hermes case, reproduced by deleting the globals - the same technique
   * vault.test.js uses, and the only way a Node suite can see this class of
   * bug at all.
   */
  const savedEncoder = globalThis.TextEncoder;
  const savedDecoder = globalThis.TextDecoder;
  try {
    delete globalThis.TextEncoder;
    delete globalThis.TextDecoder;

    const result = installTextCodecs();
    assert.deepEqual(result.installed.sort(), ['TextDecoder', 'TextEncoder']);
    assert.equal(new globalThis.TextDecoder().decode(new globalThis.TextEncoder().encode('ok')), 'ok');
  } finally {
    globalThis.TextEncoder = savedEncoder;
    globalThis.TextDecoder = savedDecoder;
  }
});
