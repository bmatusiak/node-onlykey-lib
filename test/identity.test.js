'use strict';
/*
 * plugins/identity: who the key is, read once and held, and PROVEN (Brad, 2026-10-28: "anything that uses the
 * identity plugin needs to verify the key is true, this includes the CLI").
 *
 * Against a stand-in okcrypto with a real Ed25519 identity key (the agent's, as the firmware derives it per label):
 * what the plugin asks is counted, so "read once" is a count; the proofs are real signatures, so an impostor that
 * only repeats the identity's public key is refused by the arithmetic, not by a flag.
 */
const test = require('node:test');
const assert = require('node:assert');
const { EventEmitter } = require('events');
const { ed25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');
const { randomBytes } = require('../src/vendor/exports/@noble/hashes/utils.js');
const bucketIdentity = require('../bucket/src/bucket-identity');
const identityPlugin = require('../plugins/identity');

/* a key: the identity's secret, and what it is asked (or an impostor: it reports the key's public key, signs with its own) */
function fakeKey({ secret = randomBytes(32), signWith = secret, site = 'ok-edge.example', slow = 0 } = {}) {
  const asked = { publicKey: 0, site: 0, sign: 0 };
  const okcrypto = {
    async keySite() { asked.site += 1; return { on: !!site, site }; },
    agent: {
      async publicKey() { asked.publicKey += 1; if (slow) await new Promise((r) => setTimeout(r, slow)); return ed25519.getPublicKey(secret); },
      async sign(label, message) { asked.sign += 1; return ed25519.sign(message, signWith); },
    },
  };
  return { okcrypto, asked, secret };
}
function compose(key, services = {}) {
  let out;
  const app = { EventEmitter, services: { ...services } };
  identityPlugin({ app, host: { randomBytes }, okcrypto: key.okcrypto }, (err, provided) => { if (err) throw err; out = provided.identity; });
  app.services.identity = out;
  return out;
}

test('load: read once - a second load and callers at the same time get the same read, no new request', async () => {
  const key = fakeKey({ slow: 20 });
  const identity = compose(key);
  const [a, b] = await Promise.all([identity.load(), identity.load()]);
  assert.equal(a, b);
  assert.equal(await identity.load(), a);
  assert.deepEqual(key.asked, { publicKey: 1, site: 1, sign: 0 });
  assert.equal(a.id, bucketIdentity.identityIdOf(ed25519.getPublicKey(key.secret)));
  assert.equal(a.site, 'ok-edge.example');
  assert.equal(a.verified, null, 'read is not proven');
  await identity.load({ force: true });
  assert.equal(key.asked.publicKey, 2, 'force reads the key again');
});

test('load: a feature adds its own part (identityPart), kept under its service name', async () => {
  const key = fakeKey();
  const identity = compose(key, { edge: { identityPart: async () => ({ deviceId: 'abc' }) }, plain: {} });
  const held = await identity.load();
  assert.deepEqual(held.parts, { edge: { deviceId: 'abc' } });
});

test('verify: the key signs a fresh challenge with the identity key - proven; requireVerified refuses until then', async () => {
  const key = fakeKey();
  const identity = compose(key);
  await identity.load();
  assert.throws(() => identity.requireVerified(), (e) => e.code === 'IDENTITY_NOT_PROVEN');
  const held = await identity.verify();
  assert.equal(held.verified.how, 'signature');
  assert.equal(identity.requireVerified(), held);
});

test('verify: an impostor that repeats the identity public key but signs with another key is refused', async () => {
  const key = fakeKey({ signWith: randomBytes(32) });
  const identity = compose(key);
  await identity.load();
  await assert.rejects(identity.verify(), (e) => e.code === 'IDENTITY_NOT_PROVEN');
  assert.equal(identity.current().verified, null);
  assert.throws(() => identity.requireVerified(), (e) => e.code === 'IDENTITY_NOT_PROVEN');
});

test('proveByBucket: the bucket key derived is the one the identity certified - proven; another is refused', async () => {
  const key = fakeKey();
  const identity = compose(key);
  const held = await identity.load();
  const bucketPublicKey = ed25519.getPublicKey(randomBytes(32));
  const certificate = await bucketIdentity.certify(key.okcrypto, held.publicKey, bucketPublicKey);
  assert.throws(() => identity.proveByBucket({ bucketPublicKey, certificate, derivedPublicKey: ed25519.getPublicKey(randomBytes(32)) }),
    (e) => e.code === 'IDENTITY_NOT_PROVEN', 'a derived key that is not the certified one');
  const other = await bucketIdentity.certify(fakeKey().okcrypto, held.publicKey, bucketPublicKey);
  assert.throws(() => identity.proveByBucket({ bucketPublicKey, certificate: other, derivedPublicKey: bucketPublicKey }),
    (e) => e.code === 'IDENTITY_NOT_PROVEN', 'a certificate another identity signed');
  assert.equal(identity.proveByBucket({ bucketPublicKey, certificate, derivedPublicKey: bucketPublicKey }).verified.how, 'bucket');
});

test('forget: nothing held, and a read in flight is not kept for the next key', async () => {
  const key = fakeKey({ slow: 30 });
  const identity = compose(key);
  const changes = [];
  identity.on('change', (h) => changes.push(h ? 'held' : 'none'));
  await identity.load();
  await identity.verify();
  identity.forget();
  assert.equal(identity.current(), null);
  const reading = identity.load();
  identity.forget();
  await assert.rejects(reading, /changed while it was read/);
  assert.equal(identity.current(), null);
  assert.deepEqual(changes, ['held', 'held', 'none']);
});
