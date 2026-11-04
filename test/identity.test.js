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
const bucket = require('../bucket/src/bucket.js');

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

/* THE KEY'S STATE IN ONE PLACE (Brad, 2026-11-03: "a simple local storage like api ... cleanup is as simple as state = {}") */
test('store: the key\'s state as localStorage reads it - any value, kept as given; forget empties it before anyone hears', () => {
  const identity = compose(fakeKey());
  const heads = new Map([[1, 'a']]);
  identity.store.setItem('edge.heads', heads);
  identity.store.setItem('card.offer', { device: 'x' });
  assert.equal(identity.store.getItem('edge.heads'), heads, 'the same object back, not a copy');
  assert.equal(identity.store.getItem('nothing'), null);
  assert.deepEqual(identity.store.keys().sort(), ['card.offer', 'edge.heads']);
  identity.store.removeItem('card.offer');
  assert.deepEqual(identity.store.keys(), ['edge.heads']);
  let seenAtForget = null;
  identity.on('forgotten', () => { seenAtForget = identity.store.keys(); });
  identity.forget('locked');
  assert.deepEqual(seenAtForget, [], 'empty before the listeners hear the key went');
  assert.equal(identity.store.getItem('edge.heads'), null);
  identity.store.setItem('a', 1);
  identity.store.clear();
  assert.deepEqual(identity.store.keys(), []);
});

/* "then we can see what is using the state and it makes it debuggable" (Brad, 2026-11-03) */
test('store: what holds the key\'s state is told - a first value, a removal, a clear with its why; names only, never values', () => {
  const identity = compose(fakeKey());
  const seen = [];
  identity.on('store', (e) => seen.push(e));
  identity.store.setItem('edge.heads', new Map());
  identity.store.setItem('edge.heads', new Map([[1, 2]]));
  identity.store.setItem('secret.thing', 'do not tell');
  identity.store.removeItem('nothing');
  identity.store.removeItem('edge.heads');
  identity.forget('locked');
  identity.forget('again');
  assert.deepEqual(seen, [
    { op: 'add', key: 'edge.heads' },
    { op: 'add', key: 'secret.thing' },
    { op: 'remove', key: 'edge.heads' },
    { op: 'clear', keys: ['secret.thing'], why: 'locked' },
  ], 'a second value of a key, a removal of nothing and an empty clear say nothing');
  assert.ok(!JSON.stringify(seen).includes('do not tell'), 'never a value');
});

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

test('load: a site read that FAILED is not "no site" - the next load asks again; a key that says none is none', async () => {
  const key = fakeKey();
  let fail = true;
  const plain = key.okcrypto.keySite;
  key.okcrypto.keySite = async () => { if (fail) { key.asked.site += 1; throw new Error('the key did not answer'); } return plain(); };
  const identity = compose(key);
  assert.equal((await identity.load()).site, undefined, 'not read');
  fail = false;
  assert.equal((await identity.load()).site, 'ok-edge.example', 'asked again, and kept');
  assert.equal((await identity.load()).site, 'ok-edge.example');
  assert.equal(key.asked.site, 2, 'once more, not every load');
  const none = fakeKey({ site: null });
  const id2 = compose(none);
  assert.equal((await id2.load()).site, null);
  await id2.load();
  assert.equal(none.asked.site, 1, 'a key with no site is asked once');
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

test('proveByBucket: the bucket this device sealed for the identity opens with the key secret - proven; another key or another identity bucket is refused', async () => {
  const key = fakeKey();
  const identity = compose(key);
  const held = await identity.load();
  const secret = randomBytes(32);
  const sealed = bucket.seal(bucket.create({ owner: held.id }), secret, randomBytes);
  assert.throws(() => identity.proveByBucket({ sealed, key: randomBytes(32) }), (e) => e.code === 'IDENTITY_NOT_PROVEN', 'the secret of another key');
  const others = bucket.seal(bucket.create({ owner: 'f'.repeat(32) }), secret, randomBytes);
  assert.throws(() => identity.proveByBucket({ sealed: others, key: secret }), (e) => e.code === 'IDENTITY_NOT_PROVEN', 'the bucket of another identity');
  assert.equal(identity.current().verified, null);
  const out = identity.proveByBucket({ sealed, key: secret });
  assert.equal(out.held.verified.how, 'bucket');
  assert.equal(out.bucket.owner, held.id, 'the bucket comes back opened');
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

test('forget tells its why to forgotten listeners, held or not (a key unplugged ends the login)', async () => {
  const identity = compose(fakeKey());
  const told = [];
  identity.on('forgotten', (why) => told.push(why));
  identity.forget('unplugged');
  await identity.load();
  identity.forget();
  assert.deepEqual(told, ['unplugged', null]);
  assert.equal(identity.current(), null);
});

test('proveByRows: the rows this device keeps for the identity open with the key secret - proven; another secret or another owner is refused', async () => {
  const sealedCopy = require('../bucket/src/sealedcopy');
  const key = fakeKey();
  const identity = compose(key);
  const held = await identity.load();
  const secret = randomBytes(32);
  const keys = sealedCopy.keysOf({ secretKey: secret });
  const rowsFor = (owner) => {
    const b = bucket.create({ owner });
    bucket.kv(b, 'guestbook').setItem('myname', 'Pixel');
    const t = sealedCopy.table(b, keys);
    const rows = Object.fromEntries(Object.entries(sealedCopy.sealRows(b, keys, Object.keys(t.rows), { randomBytes })).map(([id, r]) => [id, r.blob]));
    const o = sealedCopy.sealOwner(owner, keys, randomBytes);
    return { ...rows, [o.id]: o.blob };
  };
  assert.throws(() => identity.proveByRows({ rows: rowsFor(held.id), key: randomBytes(32) }), (e) => e.code === 'IDENTITY_NOT_PROVEN', 'the secret of another key');
  assert.throws(() => identity.proveByRows({ rows: rowsFor('f'.repeat(32)), key: secret }), (e) => e.code === 'IDENTITY_NOT_PROVEN', 'the rows of another identity');
  assert.equal(identity.current().verified, null);
  const out = identity.proveByRows({ rows: rowsFor(held.id), key: secret });
  assert.equal(out.held.verified.how, 'bucket');
  assert.equal(bucket.kv(out.bucket, 'guestbook').getItem('myname'), 'Pixel');
});

test('proveLogin: the key signs the bucket key with the MCP challenge; checked, the identity is proven', async () => {
  const bid = require('../bucket/src/bucket-identity');
  const key = fakeKey();
  const identity = compose(key);
  await identity.load();
  const bucketPublicKey = new Uint8Array(32).fill(4);
  const asked = { host: '127.0.0.1:8790', nonce: new Uint8Array(32).fill(6) };
  const proof = await identity.proveLogin(asked, bucketPublicKey);
  assert.equal(proof.length, 64);
  assert.equal(identity.current().verified.how, 'login');
  assert.equal(bid.verifyCertificate({ identityPublicKey: identity.current().publicKey, bucketPublicKey, certificate: proof, login: asked }), true);
  assert.equal(bid.verifyCertificate({ identityPublicKey: identity.current().publicKey, bucketPublicKey, certificate: proof, login: { ...asked, host: 'other:1' } }), false);
});
