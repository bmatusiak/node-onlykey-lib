/*
 * The crypto provider (src/crypto/provider.js): Edge's hashing and signature
 * checks go through it, a host may plug in a faster one (ok-rn: OpenSSL), and
 * the verdict rules (P-256 lowS, strict Ed25519) stay outside the provider so
 * every implementation answers the same.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('../src/crypto/provider');
const chain = require('../src/edge/chain');
const grants = require('../src/edge/grants');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const { ed25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');

/* a provider that counts its calls and otherwise is the JS one */
function counting() {
  const calls = { sha256: 0, sha256Repeat: 0, hmacSha256: 0, p256VerifyDigest: 0, ed25519Verify: 0 };
  const p = {};
  for (const k of Object.keys(calls)) p[k] = (...a) => { calls[k]++; return crypto.js[k](...a); };
  return { p, calls };
}

test.afterEach(() => crypto.setCryptoProvider(null));

test('the default is the JS one', () => {
  assert.equal(crypto.cryptoProviderName(), 'js');
});

test('a plugged-in provider is the one Edge uses: hash chains, HMAC, checkpoints', () => {
  const { p, calls } = counting();
  crypto.setCryptoProvider(p, 'counting');
  assert.equal(crypto.cryptoProviderName(), 'counting');
  const seed = new Uint8Array(32).fill(7);
  const genesis = grants.grantGenesis(seed, 10);
  assert.equal(calls.sha256Repeat, 1);
  const sk = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(sk, false).subarray(1);
  const fields = { deviceId: chain.deviceIdOf(pub), seq: 5, head: genesis };
  assert.equal(chain.verifyCheckpoint(fields, chain.signCheckpoint(fields, sk), pub), true);
  assert.ok(calls.p256VerifyDigest >= 1 && calls.sha256 >= 1);
  crypto.setCryptoProvider(null);
  assert.equal(crypto.cryptoProviderName(), 'js');
  assert.deepEqual(grants.grantGenesis(seed, 10), genesis); /* the same answer from JS */
});

test('a provider that lies changes the verdict - so the checks really go through it', () => {
  const sk = p256.utils.randomSecretKey();
  const pub = p256.getPublicKey(sk, false).subarray(1);
  const fields = { deviceId: chain.deviceIdOf(pub), seq: 1, head: new Uint8Array(32).fill(1) };
  const sig = chain.signCheckpoint(fields, sk);
  crypto.setCryptoProvider({ p256VerifyDigest: () => false }, 'liar');
  assert.equal(chain.verifyCheckpoint(fields, sig, pub), false);
});

test('P-256 lowS is decided outside the provider: a high-s twin is refused even if the provider accepts it', () => {
  const sk = p256.utils.randomSecretKey();
  const pubSec1 = p256.getPublicKey(sk, false);
  const msg = Uint8Array.from([1, 2, 3]);
  const sig = p256.sign(msg, sk, { prehash: true });
  const n = p256.Point.CURVE().n;
  let s = 0n;
  for (let i = 32; i < 64; i++) s = (s << 8n) | BigInt(sig[i]);
  const twin = sig.slice();
  let hs = n - s;
  for (let i = 63; i >= 32; i--) { twin[i] = Number(hs & 0xffn); hs >>= 8n; }
  assert.equal(crypto.p256Verify(sig, msg, pubSec1), true);
  crypto.setCryptoProvider({ p256VerifyDigest: () => true }, 'accepts-all');
  assert.equal(crypto.p256Verify(twin, msg, pubSec1), false);
  crypto.setCryptoProvider(null);
  /* a checkpoint is lowS: false - its twin verifies, as before the provider */
  assert.equal(crypto.p256VerifyDigest(twin, crypto.sha256(msg), pubSec1, { lowS: false }), true);
});

test('Ed25519 is strict and never throws; malformed input is false', () => {
  const sk = ed25519.utils.randomSecretKey();
  const pub = ed25519.getPublicKey(sk);
  const msg = Uint8Array.from([9, 9]);
  const sig = ed25519.sign(msg, sk);
  assert.equal(crypto.ed25519Verify(sig, msg, pub), true);
  assert.equal(crypto.ed25519Verify(sig, Uint8Array.from([9, 8]), pub), false);
  assert.equal(crypto.ed25519Verify(sig.slice(0, 63), msg, pub), false);
  assert.equal(crypto.p256Verify(new Uint8Array(64), msg, new Uint8Array(65)), false);
});

test('sha256Repeat: 0 times is the input; a bad count throws', () => {
  const x = new Uint8Array(32).fill(3);
  assert.equal(crypto.sha256Repeat(x, 0), x);
  assert.deepEqual(crypto.sha256Repeat(x, 2), crypto.sha256(crypto.sha256(x)));
  assert.throws(() => crypto.sha256Repeat(x, -1), RangeError);
});
