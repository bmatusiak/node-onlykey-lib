'use strict';
/*
 * R20 known peers (okedge sync phase 2, P2a): the places a sync may send
 * copies to, added and removed only with a press, each a link in the chain.
 * Against the fake key (edge/test/helpers/fake-edge-key.js), which models the
 * soft key's okplugin_edge PEER_ADD / PEER_REMOVE / PEER_LIST.
 */
const test = require('node:test');
const assert = require('node:assert');
const { codes, chain, grants } = require('../src');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

/* a peer's key as the key gives keys: X || Y */
const peerKey = () => p256.getPublicKey(p256.utils.randomSecretKey(), false).slice(1);

const lastLink = async (edge) => {
  const h = await edge.head();
  const [l] = await edge.pickup(h.seq, 1);
  return chain.decodeLink(l.link);
};

test('a peer is added with a press: a peer-add link whose subject is SHA256(X || Y), then listed', async () => {
  const edge = edgeOver(fakeKey());
  const key = peerKey();
  const r = await edge.peerAdd(key, { timeoutMs: 2000 });
  const f = await lastLink(edge);
  assert.equal(f.seq, r.seq);
  assert.equal(f.op, codes.OP.PEER_ADD);
  assert.ok(f.flags & codes.FLAG.PRESS_OBSERVED);
  assert.equal(f.slot, 0);
  assert.deepEqual([...f.subject], [...sha256(key)]);
  assert.deepEqual([...grants.peerSubject(key)], [...sha256(key)]);
  const list = await edge.peers();
  assert.equal(list.max, 4);
  assert.equal(list.k, 0, 'k is not set until E5');
  assert.equal(list.peers.length, 1);
  assert.deepEqual([...list.peers[0].publicKey], [...key]);
});

test('peerAdd takes the key as 64, 65 or 33 bytes - the same peer each way', async () => {
  const edge = edgeOver(fakeKey());
  const key = peerKey();
  await edge.peerAdd(Uint8Array.from([4, ...key]), { timeoutMs: 2000 });
  const compressed = p256.Point.fromBytes(Uint8Array.from([4, ...key])).toBytes(true);
  await assert.rejects(edge.peerAdd(compressed, { timeoutMs: 2000 }), (e) => e.status === 'peer-known');
});

test('a fifth peer is refused (peers-full); a removed peer frees its place and the later ones move down', async () => {
  const edge = edgeOver(fakeKey());
  const keys = [peerKey(), peerKey(), peerKey(), peerKey()];
  for (const k of keys) await edge.peerAdd(k, { timeoutMs: 2000 });
  await assert.rejects(edge.peerAdd(peerKey(), { timeoutMs: 2000 }), (e) => e.status === 'peers-full');
  await edge.peerRemove(1, { timeoutMs: 2000 });
  const f = await lastLink(edge);
  assert.equal(f.op, codes.OP.PEER_REMOVE);
  assert.equal(f.slot, 1);
  assert.deepEqual([...f.subject], [...sha256(keys[1])], 'the removal names the key it removed');
  const list = await edge.peers();
  assert.deepEqual(list.peers.map((p) => p.index), [0, 1, 2]);
  assert.deepEqual(list.peers.map((p) => Buffer.from(p.publicKey).toString('hex')),
    [keys[0], keys[2], keys[3]].map((k) => Buffer.from(k).toString('hex')));
  await assert.rejects(edge.peerRemove(3, { timeoutMs: 2000 }), (e) => e.status === 'no-such-peer');
});

test('a point not on P-256 never reaches the key', async () => {
  const edge = edgeOver(fakeKey());
  await assert.rejects(edge.peerAdd(new Uint8Array(64).fill(1), { timeoutMs: 2000 }));
});

test('no peer is added while the key is restoring (R26)', async () => {
  const edge = edgeOver(fakeKey({ restoring: true }));
  await assert.rejects(edge.peerAdd(peerKey(), { timeoutMs: 2000 }), (e) => e.status === 'restoring');
});

test('the status words match the soft key (okplugin_edge.h 0x13-0x16)', () => {
  assert.equal(codes.STATUS[0x13].name, 'peers-full');
  assert.equal(codes.STATUS[0x14].name, 'peer-known');
  assert.equal(codes.STATUS[0x15].name, 'bad-key');
  assert.equal(codes.STATUS[0x16].name, 'no-such-peer');
});

/* ------------------------------------------------ the request and the phone's approval */

const { request, approve } = require('../src');
const signer = () => request.peerSignerFromSecret(p256.utils.randomSecretKey());

test('a peer request is signed by the key it names; a changed name, another key or a replay is dropped', async () => {
  const s = signer();
  const msg = await request.buildPeerAdd({ signer: s, name: 'NITRO16 copies' });
  const seen = new Set();
  assert.deepEqual(request.verifyPeerAdd(msg, { seen }), { ok: true });
  assert.equal(request.verifyPeerAdd({ ...msg, name: 'Someone else' }, { seen }).reason, 'bad-signature');
  assert.equal(request.verifyPeerAdd({ ...msg, peer: Buffer.from(signer().publicKey).toString('hex') }, { seen }).reason, 'bad-signature');
  seen.add(msg.nonce);
  assert.equal(request.verifyPeerAdd(msg, { seen }).reason, 'replayed');
  assert.equal(request.verifyPeerAdd({ ...msg, peer: 'zz' }).reason, 'malformed');
});

test('approvePeerAdd: Yes then the press adds it to the KEY\'s list and checks the link', async () => {
  const edge = edgeOver(fakeKey());
  const s = signer();
  const asked = [];
  const r = await approve.approvePeerAdd(await request.buildPeerAdd({ signer: s, name: 'NITRO16 copies' }), {
    edge, seen: new Set(), ask: async (v) => { asked.push(v); return 'approve'; }, timeoutMs: 2000,
  });
  assert.equal(r.ok, true);
  assert.equal(r.index, 0);
  assert.equal(asked.length, 1);
  assert.equal(asked[0].name, 'NITRO16 copies');
  assert.equal(asked[0].fingerprint, request.fingerprint(Buffer.from(s.publicKey).toString('hex')));
  const f = await lastLink(edge);
  assert.equal(f.seq, r.seq);
  assert.equal(f.op, codes.OP.PEER_ADD);
  /* asked again: the key already lists it - no sheet, no press */
  const again = await approve.approvePeerAdd(await request.buildPeerAdd({ signer: s, name: 'NITRO16 copies' }), {
    edge, seen: new Set(), ask: async () => assert.fail('asked for a place the key already knows'),
  });
  assert.deepEqual([again.ok, again.already, again.index], [true, true, 0]);
});

test('approvePeerAdd: Decline or nobody answering adds nothing; a bad signature gets no answer', async () => {
  const edge = edgeOver(fakeKey());
  const before = (await edge.head()).seq;
  const s = signer();
  for (const answer of ['decline', 'timeout']) {
    const r = await approve.approvePeerAdd(await request.buildPeerAdd({ signer: s, name: 'x' }), { edge, seen: new Set(), ask: async () => answer });
    assert.equal(r.ok, false);
    assert.equal(r.refusal, answer === 'decline' ? 'declined' : 'timeout');
  }
  const forged = { ...(await request.buildPeerAdd({ signer: s, name: 'x' })), name: 'y' };
  const d = await approve.approvePeerAdd(forged, { edge, seen: new Set(), ask: async () => assert.fail('a forged request reached the sheet') });
  assert.equal(d.dropped, 'bad-signature');
  assert.equal((await edge.head()).seq, before, 'a refused peer request wrote a link');
  assert.equal((await edge.peers()).peers.length, 0);
});
