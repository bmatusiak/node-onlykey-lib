/*
 * The bucket trade (bucket/src/trade.js, ok-edge plan S3): two devices of one bucket identity prove themselves to
 * each other over fresh nonces, compare their states, then trade HAVE and GIVE until the states match; a device of another backup, a
 * replayed hello, an out-of-order message - each gets the same plain refusal, and the peer shows nothing first.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { ed25519, x25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const bucketLib = require('../src/bucket');
const bid = require('../src/bucket-identity');
const trade = require('../src/trade');

const rnd = (n) => new Uint8Array(crypto.randomBytes(n));

/* a device of one backup: the bucket identity, bucket key and certificate its key makes (as bucket-identity.test) */
async function device(seed) {
  const secretOf = (identity, keyType) => sha256(new Uint8Array([...new TextEncoder().encode(seed), ...identity, keyType]));
  const key = { agent: {
    publicKey: async (identity, { keyType }) => (keyType === 1 ? ed25519.getPublicKey(secretOf(identity, 1)) : x25519.getPublicKey(secretOf(identity, 4))),
    ecdh: async (identity, peer) => x25519.getSharedSecret(secretOf(identity, 4), peer),
    sign: async (identity, message) => ed25519.sign(message, secretOf(identity, 1)),
  } };
  const { publicKey, id } = await bid.readIdentity(key);
  const bucketKey = await bid.deriveBucketKey(key, publicKey);
  const certificate = await bid.certify(key, publicKey, bucketKey.publicKey);
  return { id, identityPublicKey: publicKey, bucketKey, certificate };
}

let tick = 0;
const kv = (b, store) => bucketLib.kv(b, store, { now: () => new Date(Date.UTC(2026, 9, 25, 1, 0, tick++)).toISOString() });

/* one whole trade, as bucket/cli/trade.js runs it: proof, states, then HAVE/GIVE rounds until the states match */
async function run(computer, peer) {
  const c = trade.computerSide({ bucket: computer.bucket, me: computer.me, randomBytes: rnd });
  const answer = trade.peerSide({ bucket: () => peer.bucket, me: () => peer.me, randomBytes: rnd, seen: peer.seen });
  const sent = [];
  const ask = (m) => { sent.push(m.type); return answer(m, 'desktop'); };
  const a1 = ask(c.hello());
  const m2 = c.prove(a1);
  if (!m2) return { refusedAt: 'proof', a1, sent };
  let step = c.compare(ask(m2));
  if (!step) return { refusedAt: 'state', sent };
  if (step.same) return { done: true, same: true, settled: true, sent, taken: {}, gave: {} };
  const taken = {}; const gave = {};
  for (;;) {
    const g = c.give(ask(step.message));
    if (!g) return { refusedAt: 'have', sent };
    Object.assign(taken, g.taken);
    const s = c.settle(ask(g.message));
    if (!s) return { refusedAt: 'give', sent };
    Object.assign(gave, s.taken);
    if (s.same) return { done: true, settled: true, sent, taken, gave };
    if (!s.message) return { done: true, settled: false, differs: s.differs, sent, taken, gave };
    step = s;
  }
}

test('two devices of one backup prove themselves and trade: each ends with the other\'s changes', async () => {
  const me = await device('backup-1');
  const desktop = { me: { ...me }, bucket: bucketLib.create({ owner: me.id }) };
  const phone = { me: { ...me }, bucket: bucketLib.create({ owner: me.id }), seen: new Set() };
  kv(phone.bucket, 'guestbook').setItem('myname', 'Pixel Tester');
  kv(desktop.bucket, 'keychain').setItem('list', '{"format":"onlykey-keychain","version":1,"entries":[]}');
  const r = await run(desktop, phone);
  assert.ok(r.done, `refused at ${r.refusedAt}`);
  assert.equal(kv(desktop.bucket, 'guestbook').getItem('myname'), 'Pixel Tester');
  assert.ok(kv(phone.bucket, 'keychain').getItem('list'));
  assert.deepEqual(r.gave, { keychain: 1 });
  assert.ok(r.settled, 'the states match after the trade');
});

test('two devices already holding the same bucket: in sync after the states - no HAVE, no GIVE sent', async () => {
  const me = await device('backup-1');
  const desktop = { me: { ...me }, bucket: bucketLib.create({ owner: me.id }) };
  kv(desktop.bucket, 'guestbook').setItem('myname', 'Pixel Tester');
  const phone = { me: { ...me }, bucket: JSON.parse(JSON.stringify(desktop.bucket)), seen: new Set() };
  const r = await run(desktop, phone);
  assert.ok(r.same, 'the same state');
  assert.deepEqual(r.sent, [trade.TYPES.HELLO, trade.TYPES.PROVE]);
});

test('a trade is complete only when the states match - both sides end with one state', async () => {
  const me = await device('backup-1');
  const desktop = { me: { ...me }, bucket: bucketLib.create({ owner: me.id }) };
  const phone = { me: { ...me }, bucket: bucketLib.create({ owner: me.id }), seen: new Set() };
  kv(phone.bucket, 'guestbook').setItem('myname', 'Pixel Tester');
  kv(desktop.bucket, 'passwords').setItem('s1/onlyagent-vault/credentials/aa', 'sealed-a');
  kv(phone.bucket, 'passwords').setItem('s1/onlyagent-vault/credentials/bb', 'sealed-b');
  const r = await run(desktop, phone);
  assert.ok(r.settled);
  const rep = require('../src/replicate');
  assert.equal(rep.stateOf(desktop.bucket).hash, rep.stateOf(phone.bucket).hash);
  /* and the next check is two small messages */
  const again = await run(desktop, phone);
  assert.ok(again.same);
});

test('a device of another backup is refused at the proof - the peer showed no HAVE, no GIVE', async () => {
  const mine = await device('backup-1');
  const theirs = await device('backup-2');
  const phone = { me: mine, bucket: bucketLib.create({ owner: mine.id }), seen: new Set() };
  kv(phone.bucket, 'guestbook').setItem('myname', 'Pixel Tester');
  /* claims the phone's identity, holds another backup's bucket key */
  const impostor = { me: { ...theirs, id: mine.id }, bucket: bucketLib.create({ owner: mine.id }) };
  const c = trade.computerSide({ bucket: impostor.bucket, me: impostor.me, randomBytes: rnd });
  const answer = trade.peerSide({ bucket: () => phone.bucket, me: () => phone.me, randomBytes: rnd, seen: phone.seen });
  const a1 = answer(c.hello(), 'evil');
  assert.ok(a1.ok && !a1.have && !a1.give, 'hello answers with a proof and a nonce only');
  /* the impostor's own check of the phone passes - the phone is real - but its proof of itself cannot */
  const forged = { type: trade.TYPES.PROVE, v: 1, identity: mine.id, proof: trade.prove(impostor.me, Buffer.from(a1.nonce, 'hex'), 'computer'), state: { hash: 'x', stores: {} } };
  assert.deepEqual(answer(forged, 'evil'), { ok: false, refusal: 'no' });
  assert.deepEqual(answer({ type: trade.TYPES.GIVE, identity: mine.id, give: { guestbook: { myname: { v: 'x', at: '2099-01-01T00:00:00.000Z' } } } }, 'evil'), { ok: false, refusal: 'no' });
  assert.equal(kv(phone.bucket, 'guestbook').getItem('myname'), 'Pixel Tester', 'nothing was taken');
});

test('another identity, a replayed hello, a GIVE out of turn, a closed bucket: the same plain refusal', async () => {
  const me = await device('backup-1');
  const other = await device('backup-2');
  const phone = { me, bucket: bucketLib.create({ owner: me.id }), seen: new Set() };
  const answer = trade.peerSide({ bucket: () => phone.bucket, me: () => phone.me, randomBytes: rnd, seen: phone.seen });
  const c = trade.computerSide({ bucket: bucketLib.create({ owner: other.id }), me: other, randomBytes: rnd });
  assert.deepEqual(answer(c.hello(), 'x'), { ok: false, refusal: 'no' }, 'another identity');
  const same = trade.computerSide({ bucket: bucketLib.create({ owner: me.id }), me, randomBytes: rnd });
  const hello = same.hello();
  assert.ok(answer(hello, 'x').ok);
  assert.deepEqual(answer(hello, 'x'), { ok: false, refusal: 'no' }, 'the same nonce again');
  assert.deepEqual(answer({ type: trade.TYPES.GIVE, identity: me.id, give: {} }, 'y'), { ok: false, refusal: 'no' }, 'no trade started');
  assert.deepEqual(answer({ type: trade.TYPES.HAVE, identity: me.id, have: {} }, 'x'), { ok: false, refusal: 'no' }, 'a HAVE before the proof');
  const closed = trade.peerSide({ bucket: () => null, me: () => null, randomBytes: rnd });
  assert.deepEqual(closed(same.hello(), 'x'), { ok: false, refusal: 'no' }, 'bucket not open');
  assert.equal(answer({ type: 'okedge.request' }, 'x'), null, 'not a trade: not answered here');
});

/*
 * A store kept as one value goes over in pieces (rules.js listParts): one contact added on the phone - of 200 - is the
 * only thing given, and both sides end with one state.
 */
test('one changed item of a big list is all that is given - and the states match after', async () => {
  const me = await device('backup-1');
  const rules = { guestbook: require('../src/rules').guestbook() };
  const contacts = Array.from({ length: 200 }, (_, i) => ({ id: `c${i}`, name: `contact ${i}`, keys: [{ id: `k${i}`, kind: 'ssh', value: 'x'.repeat(100), updatedAt: '2026-10-25T01:00:00.000Z' }] }));
  const desktop = { me: { ...me }, bucket: bucketLib.create({ owner: me.id }) };
  kv(desktop.bucket, 'guestbook').setItem('guestbook:v1', JSON.stringify({ v: 1, contacts }));
  const phone = { me: { ...me }, bucket: JSON.parse(JSON.stringify(desktop.bucket)), seen: new Set() };
  kv(phone.bucket, 'guestbook').setItem('guestbook:v1', JSON.stringify({ v: 1, contacts: [...contacts, { id: 'new', name: 'met on the go', keys: [{ id: 'kn', kind: 'ssh', value: 'y', updatedAt: '2026-10-25T02:00:00.000Z' }] }] }));
  const c = trade.computerSide({ bucket: desktop.bucket, me: desktop.me, randomBytes: rnd, rules });
  const answer = trade.peerSide({ bucket: () => phone.bucket, me: () => phone.me, randomBytes: rnd, seen: phone.seen, rules });
  const step = c.compare(answer(c.prove(answer(c.hello(), 'd')), 'd'));
  assert.ok(!step.same);
  const haveAnswer = answer(step.message, 'd');
  const given = haveAnswer.give.guestbook || {};
  assert.deepEqual(Object.keys(given), ['guestbook:v1\u0001#new'], 'the phone gives the one new contact, not the list');
  assert.ok(JSON.stringify(haveAnswer.give).length < 1000, 'a few hundred bytes, not the whole list');
  const g = c.give(haveAnswer);
  const s = c.settle(answer(g.message, 'd'));
  assert.ok(s.same, 'the states match');
  const names = JSON.parse(kv(desktop.bucket, 'guestbook').getItem('guestbook:v1')).contacts.map((x) => x.id);
  assert.equal(names.length, 201);
  assert.ok(names.includes('new'));
});
