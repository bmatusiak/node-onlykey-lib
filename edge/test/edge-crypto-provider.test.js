/*
 * Edge through the crypto provider (src/crypto/provider.js): its hash chains, HMAC
 * and checkpoint checks go through whatever provider the host plugged in (ok-rn:
 * OpenSSL). Split out of test/crypto-provider.test.js in step 3b, so core's provider
 * tests run without edge/.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const crypto = require('../../src/crypto/provider');
const chain = require('../src/chain');
const grants = require('../src/grants');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');

/* a provider that counts its calls and otherwise is the JS one */
function counting() {
  const calls = { sha256: 0, sha256Repeat: 0, hmacSha256: 0, p256VerifyDigest: 0, ed25519Verify: 0 };
  const p = {};
  for (const k of Object.keys(calls)) p[k] = (...a) => { calls[k]++; return crypto.js[k](...a); };
  return { p, calls };
}

test.afterEach(() => crypto.setCryptoProvider(null));

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
