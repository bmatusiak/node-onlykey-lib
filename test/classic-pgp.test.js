/*
 * Classic PGP keys on the device (src/crypto/classic_pgp.js).
 *
 * A real openpgp round trip through the hardware hooks: the message is
 * encrypted and verified by openpgp itself, and only the private operations go
 * to `ok`. Here `ok` is a fake DEVICE that does what 3.1.0 does with the key's
 * own secrets (raw RSA with PKCS#1 v1.5, Ed25519 over the digest, X25519 with
 * the byte-reversed scalar) - so a wrong payload shape, a missing pad or a
 * wrong split of the answer fails the round trip, not a byte comparison.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const openpgp = require('../src/crypto/pgp');
const { registerClassicHooks, leftPad } = require('../src/crypto/classic_pgp');
const { ed25519, x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');

const big = (b) => BigInt('0x' + (Buffer.from(b).toString('hex') || '0'));
const bytes = (n, len) => Uint8Array.from(Buffer.from(n.toString(16).padStart(len * 2, '0'), 'hex'));
function modpow(b, e, m) {
  let r = 1n; b %= m;
  for (; e > 0n; e >>= 1n) { if (e & 1n) r = (r * b) % m; b = (b * b) % m; }
  return r;
}
/* DigestInfo prefixes the device adds (RFC 8017 9.2 note 1). */
const DIGEST_INFO = {
  32: '3031300d060960864801650304020105000420',
  64: '3051300d060960864801650304020305000440',
};

/** A fake device holding one RSA key: what okcrypto.cpp's rsa_sign/rsa_decrypt do. */
function rsaDevice(keyPacket, calls) {
  const { n, e } = keyPacket.publicParams;
  const { d } = keyPacket.privateParams;
  const k = n.length;
  return {
    async decrypt(slot, c, opts) {
      calls.push({ op: 'decrypt', slot, len: c.length, opts });
      assert.equal(c.length, k, 'the device takes the ciphertext at exactly modulus size');
      const em = bytes(modpow(big(c), big(d), big(n)), k);
      assert.equal(em[0], 0); assert.equal(em[1], 2);
      return em.subarray(em.indexOf(0, 2) + 1);
    },
    async sign(slot, digest, opts) {
      calls.push({ op: 'sign', slot, len: digest.length, opts });
      const t = Buffer.concat([Buffer.from(DIGEST_INFO[digest.length], 'hex'), Buffer.from(digest)]);
      const em = Buffer.concat([Buffer.from([0, 1]), Buffer.alloc(k - t.length - 3, 0xff), Buffer.from([0]), t]);
      return bytes(modpow(big(em), big(d), big(n)), k);
    },
  };
}

test('RSA: decrypt a message and sign one, with the private key only on the "device"', async () => {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'rsa', rsaBits: 2048, userIDs: [{ name: 'hw' }], format: 'object',
  });
  const pub = publicKey;
  const calls = [];
  /* Primary key signs, the subkey decrypts - two slots, as on a device. */
  const signer = rsaDevice(privateKey.keyPacket, calls);
  const decrypter = rsaDevice(privateKey.subkeys[0].keyPacket, calls);
  const ok = { sign: signer.sign, decrypt: decrypter.decrypt };
  registerClassicHooks(openpgp, ok, { signSlot: 2, decryptSlot: 1 });
  const hwKey = openpgp.createHardwarePrivateKey(pub);

  const message = await openpgp.createMessage({ text: 'classic on the device' });
  const armored = await openpgp.encrypt({ message, encryptionKeys: pub });
  const { data } = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: armored }), decryptionKeys: hwKey,
  });
  assert.equal(data, 'classic on the device');

  const signed = await openpgp.sign({
    message: await openpgp.createCleartextMessage({ text: 'signed by the device' }), signingKeys: hwKey,
  });
  const verified = await openpgp.verify({
    message: await openpgp.readCleartextMessage({ cleartextMessage: signed }), verificationKeys: pub,
  });
  await verified.signatures[0].verified;

  const sign = calls.find((c) => c.op === 'sign');
  assert.equal(sign.slot, 2);
  assert.equal(sign.opts.expectBytes, 256, 'the modulus size is known, so it is passed');
  const dec = calls.find((c) => c.op === 'decrypt');
  assert.equal(dec.slot, 1);
  assert.equal(dec.opts.expectBytes, undefined, 'a decrypt\'s plaintext length is the device\'s to know');
});

test('Ed25519 + cv25519: sign and decrypt through the device', async () => {
  const { privateKey, publicKey } = await openpgp.generateKey({
    type: 'ecc', curve: 'curve25519Legacy', userIDs: [{ name: 'hw' }], format: 'object',
  });
  const seed = privateKey.keyPacket.privateParams.seed;
  const d = privateKey.subkeys[0].keyPacket.privateParams.d;
  const ok = {
    async sign(slot, digest) { return ed25519.sign(digest, seed); },
    async decrypt(slot, point, opts) {
      assert.equal(opts.expectBytes, 32);
      const V = point.length === 33 ? point.subarray(1) : point;
      /* openpgp keeps the cv25519 scalar big-endian; the device reverses it (swap_buffer). */
      return x25519.getSharedSecret(Uint8Array.from(d).reverse(), V);
    },
  };
  registerClassicHooks(openpgp, ok, { signSlot: 101, decryptSlot: 102 });
  const hwKey = openpgp.createHardwarePrivateKey(publicKey);

  const armored = await openpgp.encrypt({
    message: await openpgp.createMessage({ text: 'ecc on the device' }), encryptionKeys: publicKey,
  });
  const { data } = await openpgp.decrypt({
    message: await openpgp.readMessage({ armoredMessage: armored }), decryptionKeys: hwKey,
  });
  assert.equal(data, 'ecc on the device');

  const signed = await openpgp.sign({
    message: await openpgp.createCleartextMessage({ text: 'ecc signed' }), signingKeys: hwKey,
  });
  const verified = await openpgp.verify({
    message: await openpgp.readCleartextMessage({ cleartextMessage: signed }), verificationKeys: publicKey,
  });
  await verified.signatures[0].verified;
});

test('the limits are refusals, not wrong answers', async () => {
  assert.deepEqual(Array.from(leftPad(Uint8Array.of(5), 3)), [0, 0, 5]);
  assert.throws(() => leftPad(new Uint8Array(4), 3), /longer than the 3-byte modulus/);
});
