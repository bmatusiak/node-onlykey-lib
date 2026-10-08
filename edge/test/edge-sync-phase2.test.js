'use strict';
/*
 * okedge sync phase 2 (Brad, 2026-10-05): a place that keeps copies fills the
 * phone's copy; only a place on the key's list; a sheet, Yes, a press, and a
 * `sync` link whose subject is SHA256 of what moved; a fork stops it.
 */
const test = require('node:test');
const assert = require('node:assert');
const { codes, chain, request, approve, sync } = require('../src');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { fakeKey, edgeOver, DEVICE } = require('./helpers/fake-edge-key');

const signer = () => request.peerSignerFromSecret(p256.utils.randomSecretKey());
const hex = (b) => Buffer.from(b).toString('hex');

/* a little chain of n links, the way the key writes them */
function links(n, deviceId = DEVICE) {
  let head = chain.genesis(deviceId);
  const out = [];
  for (let seq = 0; seq < n; seq += 1) {
    const link = chain.encodeLink({ seq, op: codes.OP.SIGN, decision: 1, slot: 2, flags: 1, grantId: 0, subject: new Uint8Array(32).fill(seq + 1) });
    head = chain.weld(head, link);
    out.push({ link, head, reveal: null });
  }
  return out;
}

test('messages: signed by the place\'s key; a changed payload, another key or a replay is dropped', async () => {
  const s = signer();
  const have = await sync.buildHave({ signer: s, deviceId: DEVICE, name: 'NITRO16 copies' });
  assert.deepEqual(sync.verify(have), { ok: true });
  assert.equal(sync.verify({ ...have, payload: { ...have.payload, name: 'someone else' } }).reason, 'bad-signature');
  assert.equal(sync.verify({ ...have, peer: hex(signer().publicKey) }).reason, 'bad-signature');
  assert.equal(sync.verify(have, { seen: new Set([have.nonce]) }).reason, 'replayed');
  const msgs = await sync.buildLinks({ signer: s, deviceId: DEVICE, records: links(90) });
  assert.equal(msgs.length, 3, '90 links go in batches of 40');
  assert.ok(msgs.every((m) => sync.verify(m).ok && m.payload.sid === msgs[0].payload.sid && m.payload.parts === 3));
  assert.deepEqual(msgs.map((m) => m.payload.links.length), [40, 40, 10]);
  const tampered = JSON.parse(JSON.stringify(msgs[1]));
  tampered.payload.links[0][0] = '00'.repeat(64);
  assert.equal(sync.verify(tampered).reason, 'bad-signature', 'a link swapped in transit passed');
  assert.deepEqual(sync.recordsOf(msgs[2]).map((r) => chain.decodeLink(r.link).seq), [80, 81, 82, 83, 84, 85, 86, 87, 88, 89]);
});

test('ranges and what the phone lacks: only the gaps are sent', () => {
  const all = links(12);
  assert.deepEqual(sync.rangesOf([0, 1, 2, 5, 6, 9]), [[0, 2], [5, 6], [9, 9]]);
  const lacks = sync.missing(all, [[0, 2], [5, 6], [9, 9]]);
  assert.deepEqual(lacks.map((r) => chain.decodeLink(r.link).seq), [3, 4, 7, 8, 10, 11]);
});

test('merge: gaps filled in seq order; a link that disagrees with the phone\'s is a fork, never chosen between', () => {
  const all = links(10);
  const phone = [all[0], all[1], all[5], all[6]];
  const m = sync.merge(phone, all);
  assert.deepEqual(m.links.map((r) => chain.decodeLink(r.link).seq), [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]);
  assert.deepEqual(m.added.map((r) => chain.decodeLink(r.link).seq), [2, 3, 4, 7, 8, 9]);
  assert.deepEqual(m.conflicts, []);
  const other = links(10, new Uint8Array(16).fill(7)); /* the same seqs, other bytes */
  const forked = sync.merge(phone, [other[1], all[2]]);
  assert.deepEqual(forked.conflicts, [1]);
});

/*
 * THE TEST VECTOR (spec, 2026-10-05): SHA256("OKEDGE-SYNC-v1" || SHA256(peer
 * pubkey) || first u32le || last u32le || head after the merge || SHA256(Key
 * Chain list) or 32 zero bytes). Fixed inputs, the expected bytes built with
 * node:crypto here - not the lib - and the same vector is checked against the
 * soft key's firmware in the plugin kit (tests/kit.test.js).
 */
const VECTOR = {
  peer: Buffer.from('6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5', 'hex'),
  first: 268, last: 269,
  head: Buffer.alloc(32, 0xab),
  keychain: null,
};
/* ------------------------------------------------ the Key Chain list (merged, never "yours") */

const list = require('../../keychain/src/list');
const derived = (label, pub, extra = {}) => list.createEntry({ kind: 'derived', type: 'ed25519', scheme: 'ssh', label, publicKey: pub, created: '2026-10-05T00:00:00.000Z', ...extra });
const pubOf = (n) => require('../../src/vendor/exports/@noble/curves/ed25519.js').ed25519.getPublicKey(new Uint8Array(32).fill(n));

test('the Key Chain digest is one text for one list, whatever the order it was held in', () => {
  const a = derived('ssh://a@pc', pubOf(1));
  const b = derived('ssh://b@pc', pubOf(2));
  assert.equal(hex(sync.keychainDigest([a, b])), hex(sync.keychainDigest([b, a])));
  assert.notEqual(hex(sync.keychainDigest([a, b])), hex(sync.keychainDigest([a])));
});

test('the plan: the place\'s entries come in, the phone\'s go out; a phone hash-derive and the place\'s named one become ONE entry', () => {
  const k = pubOf(3);
  const phoneHash = derived('hash:' + 'ab'.repeat(32), k);
  const phoneOnly = derived('ssh://phone@x', pubOf(4));
  const pcNamed = derived('ssh://agent@nitro16', k);
  const pcOnly = derived('ssh://pc@x', pubOf(5));
  const plan = sync.keychainPlan([phoneHash, phoneOnly], [pcNamed, pcOnly]);
  assert.equal(plan.merged.length, 3, 'the twin was not joined');
  assert.equal(plan.in, 2, 'the place\'s two entries (one new, one joined) count as in');
  assert.ok(plan.out >= 1, 'the phone-only entry must go back to the place');
  /* the place takes the merged list back: nothing of its own is missing, and it now holds what the phone holds */
  const check = sync.checkTaken([pcNamed, pcOnly], plan.merged);
  assert.equal(check.ok, true);
  assert.equal(hex(sync.keychainDigest(check.entries)), hex(sync.keychainDigest(plan.merged)));
  /* a phone that dropped one of the place's entries is refused */
  assert.deepEqual(sync.checkTaken([pcNamed, pcOnly], plan.merged.filter((e) => e.id !== pcOnly.id)).missing, [pcOnly.id]);
});

test('Key Chain parts are signed, re-checked on arrival, and never carry "yours"', async () => {
  const s = signer();
  const entries = Array.from({ length: 30 }, (_, i) => derived(`ssh://u${i}@pc`, pubOf(10 + i), { pgp: undefined }));
  const msgs = await sync.buildKeychain({ signer: s, deviceId: DEVICE, sid: '01'.repeat(8), entries });
  assert.ok(msgs.length >= 2, 'a long list did not split into parts');
  assert.ok(msgs.every((m) => sync.verify(m).ok));
  const back = sync.keychainEntriesOf(msgs.flatMap((m) => m.payload.entries));
  assert.equal(back.length, 30);
  /* a "yours" mark slipped into a part is dropped on arrival - list.parse refuses or strips it */
  const marked = sync.keychainEntriesOf([{ ...msgs[0].payload.entries[0], yours: true }]);
  assert.equal(marked[0].yours, undefined);
  const commit = await sync.buildCommit({ signer: s, deviceId: DEVICE, sid: '01'.repeat(8), linkParts: 0, keychainParts: msgs.length });
  assert.deepEqual(sync.verify(commit), { ok: true });
  assert.deepEqual(sync.verify(await sync.buildTake({ signer: s, deviceId: DEVICE, sid: '01'.repeat(8), part: 0 })), { ok: true });
});

test('the same entries built in a different key order are the same list: same text, same digest, nothing to move', () => {
  const a = derived('ssh://a@pc', pubOf(1));
  const reordered = list.createEntry(Object.fromEntries(Object.entries(JSON.parse(list.serialize([a])).entries[0]).reverse()));
  assert.equal(sync.keychainText([a]), sync.keychainText([reordered]));
  assert.equal(hex(sync.keychainDigest([a])), hex(sync.keychainDigest([reordered])));
  const plan = sync.keychainPlan([a], [reordered]);
  assert.deepEqual([plan.in, plan.out], [0, 0], 'a re-ordered copy of the same entry was counted as moving');
});

test('lastSeen alone is not a change: two lists that differ only in when a key was last used need no sync - and it still travels when something real moves', async () => {
  const a = derived('ssh://agent@nitro16', pubOf(1), { lastSeen: '2026-10-05T10:00:00.000Z' });
  const later = derived('ssh://agent@nitro16', pubOf(1), { lastSeen: '2026-10-05T17:08:12.036Z' });
  assert.equal(hex(sync.keychainDigest([a])), hex(sync.keychainDigest([later])));
  assert.deepEqual([sync.keychainPlan([later], [a]).in, sync.keychainPlan([later], [a]).out], [0, 0], 'a lastSeen bump asked for a sync');
  const s = signer();
  const msgs = await sync.buildKeychain({ signer: s, deviceId: DEVICE, sid: '02'.repeat(8), entries: [later, derived('ssh://x@y', pubOf(2))] });
  const back = sync.keychainEntriesOf(msgs.flatMap((m) => m.payload.entries));
  assert.equal(back.find((e) => e.label === 'ssh://agent@nitro16').lastSeen, '2026-10-05T17:08:12.036Z', 'lastSeen did not travel');
});
