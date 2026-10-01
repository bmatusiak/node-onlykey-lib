/*
 * Key Chain L3: keys made on the host - and the WebCrypto shim's RSA hook,
 * which is how ok-rn (Hermes, no WebCrypto) makes them with Android's
 * generator. Node's own WebCrypto and crypto are the reference.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { hostKey, wipe, RSA_BITS } = require('../src/keychain/generate');
const keys = require('../src/device/keys');
const { createSubtle } = require('../src/webcrypto/subtle');
const rsa = require('../src/crypto/rsa');

/* Node's generator handing over primes - what the Android native module does in ok-rn. */
async function nodePrimes(bits, e) {
  const { privateKey } = crypto.generateKeyPairSync('rsa', { modulusLength: bits, publicExponent: e });
  const jwk = privateKey.export({ format: 'jwk' });
  return { p: Uint8Array.from(Buffer.from(jwk.p, 'base64url')), q: Uint8Array.from(Buffer.from(jwk.q, 'base64url')) };
}

test('ECC keys: each type\'s public key, and material the device loader takes', async () => {
  for (const [type, keyType] of [['ed25519', 1], ['p256', 2], ['secp256k1', 3], ['x25519', 4]]) {
    const k = await hostKey(type);
    assert.equal(k.keyType, keyType, type);
    assert.equal(k.secret.length, 32);
    assert.equal(k.publicKey.length, type === 'p256' || type === 'secp256k1' ? 64 : 32, type);
    const prepared = keys.prepareKey(k.material, { slot: 101, signature: true });
    assert.equal(prepared.type & 0x0f, keyType, type);
    assert.deepEqual([...prepared.key], [...k.secret]);
  }
});

test('RSA through Node\'s own WebCrypto: primes the slot layout takes, n = p*q', async () => {
  const k = await hostKey('rsa', { bits: 2048, subtle: crypto.webcrypto.subtle });
  assert.equal(k.p.length, 128);
  assert.equal(k.q.length, 128);
  assert.equal(rsa.bigFrom(k.publicKey), rsa.bigFrom(k.p) * rsa.bigFrom(k.q));
  const prepared = keys.prepareKey(k.material, { slot: 1, decryption: true });
  assert.equal(prepared.type & 0x0f, 2, 'RSA type = bits / 1024');
});

test('the shim makes RSA only with a host generator, and checks what it is given', async () => {
  await assert.rejects(hostKey('rsa', { subtle: createSubtle() }), (err) => err.name === 'NotSupportedError');

  const subtle = createSubtle({ rsaGenerate: nodePrimes });
  const k = await hostKey('rsa', { bits: 3072, subtle });
  assert.equal(k.p.length, 192);
  assert.equal(rsa.bitLength(rsa.bigFrom(k.publicKey)), 3072);
  /* Node accepts the JWK the shim serves - the same object openpgp's generate$b reads. */
  const pair = await subtle.generateKey({ name: 'RSASSA-PKCS1-v1_5', modulusLength: 2048, publicExponent: Uint8Array.of(1, 0, 1) }, true, ['sign']);
  const jwk = await subtle.exportKey('jwk', pair.privateKey);
  const nodeKey = crypto.createPrivateKey({ key: jwk, format: 'jwk' });
  const sig = crypto.sign('sha256', Buffer.from('kc'), nodeKey);
  assert.ok(crypto.verify('sha256', Buffer.from('kc'), crypto.createPublicKey({ key: { kty: 'RSA', n: jwk.n, e: jwk.e }, format: 'jwk' }), sig));

  const short = createSubtle({ rsaGenerate: (bits, e) => nodePrimes(bits - 256, e) });
  await assert.rejects(hostKey('rsa', { bits: 2048, subtle: short }), /1792-bit modulus for 2048/);
});

test('only 2048, 3072 and 4096; device-only and unknown types say where to go', async () => {
  assert.deepEqual(RSA_BITS, [2048, 3072, 4096]);
  await assert.rejects(hostKey('rsa', { bits: 1024, subtle: crypto.webcrypto.subtle }), /2048, 3072, 4096/);
  await assert.rejects(hostKey('xwing'), /use the device/);
});

test('wipe zeroes every private byte the result holds', async () => {
  const e = await hostKey('ed25519');
  wipe(e);
  assert.ok(e.secret.every((b) => b === 0));
  const r = await hostKey('rsa', { subtle: crypto.webcrypto.subtle });
  wipe(r);
  assert.ok(r.p.every((b) => b === 0) && r.q.every((b) => b === 0));
});
