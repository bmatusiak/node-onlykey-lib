/*
 * This computer trades its bucket with another device (bucket/cli/trade.js): the kept bucket made the first time, the
 * bucket key made once through the key and kept beside it (owner-only, never in the bucket), the trade's result in
 * the kept file; a device that does not trade is said plainly. Every test runs in a scratch root.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const crypto = require('crypto');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const home = require('../cli/home');
const { tradeWith, keyFile, storeRules } = require('../cli/trade');
const bucketLib = require('../src/bucket');
const bid = require('../src/bucket-identity');
const trade = require('../src/trade');

function fakeKey(seed) {
  const calls = { ecdh: 0, sign: 0 };
  const secretOf = (identity, keyType) => sha256(new Uint8Array([...new TextEncoder().encode(seed), ...identity, keyType]));
  return { calls, deriveSecret: async (label, { rpId } = {}) => { calls.derive = (calls.derive || 0) + 1; return sha256(new TextEncoder().encode(`${seed}|${label}|${rpId}`)); }, keySite: async () => ({ on: true, site: 'okt.example' }), agent: {
    publicKey: async (identity, { keyType }) => (keyType === 1 ? ed25519.getPublicKey(secretOf(identity, 1)) : x25519.getPublicKey(secretOf(identity, 4))),
    ecdh: async (identity, peer) => { calls.ecdh++; return x25519.getSharedSecret(secretOf(identity, 4), peer); },
    sign: async (identity, message) => { calls.sign++; return ed25519.sign(message, secretOf(identity, 1)); },
  } };
}

async function phoneOf(seed) {
  const key = fakeKey(seed);
  const { publicKey, id } = await bid.readIdentity(key);
  const bucketKey = await bid.deriveBucketKeyAt(key, publicKey, 'okt.example');
  const certificate = await bid.certify(key, publicKey, bucketKey.publicKey);
  const me = { id, identityPublicKey: publicKey, bucketKey, certificate };
  const bucket = bucketLib.create({ owner: id });
  const answer = trade.peerSide({ bucket: () => bucket, me: () => me, randomBytes: (n) => new Uint8Array(crypto.randomBytes(n)), rules: storeRules() });
  return { id, bucket, send: async (m) => answer(m, 'this computer') };
}

test.afterEach(() => home.setRoot(null));

test('a new computer trades with the phone: it keeps the bucket, makes its bucket key once (owner-only), takes the phone\'s data', async () => {
  home.setRoot(fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-trade-')));
  const phone = await phoneOf('backup-1');
  bucketLib.kv(phone.bucket, 'guestbook-test').setItem('myname', 'Pixel Tester');
  const key = fakeKey('backup-1');
  const r = await tradeWith({ send: phone.send, okcrypto: key, net: 'test' });
  assert.equal(r.traded, true, r.why);
  assert.deepEqual(r.taken, { 'guestbook-test': 1 });
  const kept = home.read(home.identityFile(phone.id, 'test'));
  assert.equal(bucketLib.kv(kept, 'guestbook-test').getItem('myname'), 'Pixel Tester');
  assert.deepEqual(key.calls, { ecdh: 0, sign: 1, derive: 1 }, 'the bucket key: one derive (under the site the key names) and one signature, once');
  if (process.platform !== 'win32') assert.equal(fs.statSync(keyFile(phone.id, 'test')).mode & 0o777, 0o600);
  assert.ok(!fs.readFileSync(home.identityFile(phone.id, 'test'), 'utf8').includes(JSON.parse(fs.readFileSync(keyFile(phone.id, 'test'), 'utf8')).bucketSecretKey), 'the bucket key is not in the bucket');
  /* the next trade: no presses, and the computer's own change goes to the phone */
  home.kv(home.identityAt(phone.id, 'test', 'keychain-test')).setItem('list', '{"format":"onlykey-keychain","version":1,"entries":[]}');
  const again = await tradeWith({ send: phone.send, okcrypto: key, net: 'test' });
  assert.equal(again.traded, true);
  assert.deepEqual(key.calls, { ecdh: 0, sign: 1, derive: 1 });
  assert.ok(bucketLib.kv(phone.bucket, 'keychain-test').getItem('list'));
});

test('a device that does not trade (or does not answer): said plainly, nothing changed', async () => {
  home.setRoot(fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-trade-')));
  const r = await tradeWith({ send: async () => null, okcrypto: fakeKey('backup-1'), net: 'test' });
  assert.equal(r.traded, false);
  assert.match(r.why, /does not trade yet/);
});

test('a kept bucket key whose certificate does not verify is not used: it is made again, and the trade goes on', async () => {
  home.setRoot(fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-trade-')));
  const phone = await phoneOf('backup-1');
  const key = fakeKey('backup-1');
  const first = await tradeWith({ send: phone.send, okcrypto: key, net: 'test' });
  assert.equal(first.traded, true, first.why);
  assert.deepEqual(key.calls, { ecdh: 0, sign: 1, derive: 1 });
  /* the certificate turned into other bytes (as when a key's answers were crossed with someone else's) */
  const f = keyFile(phone.id, 'test');
  const j = JSON.parse(fs.readFileSync(f, 'utf8'));
  j.certificate = j.certificate.replace(/^../, j.certificate.startsWith('00') ? '01' : '00');
  fs.writeFileSync(f, JSON.stringify(j));
  const again = await tradeWith({ send: phone.send, okcrypto: key, net: 'test' });
  assert.equal(again.traded, true, again.why);
  assert.deepEqual(key.calls, { ecdh: 0, sign: 2, derive: 2 }, 'made again');
});

test('a bucket key kept from before (v1, the ECDH) is made again under the site the key names - the bucket records are untouched', async () => {
  home.setRoot(fs.mkdtempSync(path.join(os.tmpdir(), 'okbucket-trade-')));
  const phone = await phoneOf('backup-1');
  const key = fakeKey('backup-1');
  assert.equal((await tradeWith({ send: phone.send, okcrypto: key, net: 'test' })).traded, true);
  /* the kept file as a v1 computer wrote it: no version */
  const f = keyFile(phone.id, 'test');
  const j = JSON.parse(fs.readFileSync(f, 'utf8'));
  delete j.v;
  fs.writeFileSync(f, JSON.stringify(j));
  const bucketFile = home.identityFile(phone.id, 'test');
  home.kv(home.identityAt(phone.id, 'test', 'guestbook-test')).setItem('myname', 'kept before');
  const again = await tradeWith({ send: phone.send, okcrypto: key, net: 'test' });
  assert.equal(again.traded, true, again.why);
  assert.equal(key.calls.derive, 2, 'the old key was not made again');
  assert.equal(JSON.parse(fs.readFileSync(f, 'utf8')).v, bid.BUCKET_KEY_VERSION, 'kept as v2');
  assert.equal(home.kv(home.identityAt(phone.id, 'test', 'guestbook-test')).getItem('myname'), 'kept before', 'the bucket lost its records');
});
