'use strict';

/*
 * The CLI keeps its Edge logs in the key's identity bucket (edge/cli/copy.js useIdentityBucket; PROPOSAL-sync-and-
 * identity.md Phase 1): a log only in the Edge home's old store comes over the first time it is read (this computer's
 * history goes with it; the old record is left as it was), a save writes only the keys that changed, every log is
 * listed, and without an identity bucket the copies stay where they were.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const chain = require('../src/chain');
const copyfile = require('../src/copyfile');
const { OP, DECISION } = require('../src/codes');
const bucketHome = require('../../bucket/cli/home');
const copy = require('../cli/copy');

const sk = new Uint8Array(32).fill(3);
const pub = p256.getPublicKey(sk, false).subarray(1);
const id = chain.deviceIdOf(pub);
const links = Array.from({ length: 70 }, (_, seq) => chain.encodeLink({ seq, op: seq % 2 ? OP.SIGN : OP.GRANT_CREATE, decision: seq % 2 ? DECISION.SELF_PRESS : DECISION.APPROVE, subject: new Uint8Array(32).fill(seq + 1), grantId: 1 + (seq >> 1), version: 1 }));
const heads = chain.heads(links, chain.genesis(id));
const copyOf = (upTo) => ({ ...copyfile.empty(id), publicKey: pub, links: links.slice(0, upTo + 1).map((l, i) => ({ link: l, head: heads[i] })), lastSeen: { seq: upTo, head: heads[upTo] } });
const BUCKET_ID = 'ab'.repeat(16);
const EDGE_ID = 'cd'.repeat(16);

function scratch() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-logs-'));
  bucketHome.setRoot(root);
  copy.useIdentityBucket(null);
  return path.join(root, 'edge', EDGE_ID);
}
test.afterEach(() => { copy.useIdentityBucket(null); bucketHome.setRoot(null); });

const logStore = () => bucketHome.kv(bucketHome.identityAt(BUCKET_ID, 'live', 'edge-logs'));

test('a log only in the Edge home comes into the identity bucket when it is first read; the old record stays', () => {
  const home = scratch();
  bucketHome.kv(bucketHome.edgeAt(home, 'copies')).setItem(copyfile.toJSON(copyOf(0)).deviceId.slice(0, 16), JSON.stringify(copyfile.toJSON(copyOf(66))));
  copy.useIdentityBucket({ id: BUCKET_ID, net: 'live' });
  const c = copy.load(home, id);
  assert.equal(c.links.length, 67);
  const keys = logStore().keys();
  assert.ok(keys.some((k) => k.endsWith('.links.000001')), `blocks written: ${keys.join(', ')}`);
  assert.equal(bucketHome.read(bucketHome.identityFile(BUCKET_ID, 'live')).owner, BUCKET_ID, 'the bucket is the identity\'s');
  assert.ok(bucketHome.kv(bucketHome.edgeAt(home, 'copies')).keys().length, 'the old record is left');
  /* read again: from the blocks */
  assert.equal(copy.load(home, id).links.length, 67);
});

test('a save writes only what changed; every log is listed; without an identity bucket the old store is used', () => {
  const home = scratch();
  copy.useIdentityBucket({ id: BUCKET_ID, net: 'live' });
  /* nothing kept yet: an empty copy, nothing written */
  assert.equal(copy.load(home, id).links.length, 0);
  assert.deepEqual(logStore().keys(), []);
  /* keepNotes loads and saves: the first note writes the meta and its block */
  copy.keepNotes(home, id, { reasons: { 3: 'sign 3' }, messages: {} });
  const first = logStore().entries();
  assert.deepEqual(Object.keys(first).map((k) => k.split('.').slice(1).join('.')).sort(), ['meta', 'notes.000000']);
  /* a note in the next block: only that block is new, the rest untouched */
  copy.keepNotes(home, id, { reasons: { 65: 'sign 65' }, messages: {} });
  const second = logStore().entries();
  const changed = Object.keys(second).filter((k) => second[k] !== first[k]);
  assert.deepEqual(changed.map((k) => k.split('.').slice(1).join('.')), ['notes.000001']);
  assert.equal(copy.blocks(home, { net: 'live' }).length, 1, 'the log is listed');
  copy.useIdentityBucket(null);
  assert.deepEqual(bucketHome.kv(bucketHome.edgeAt(home, 'copies')).keys(), [], 'no identity bucket: the old store, still empty');
});

test('every log of the identity comes into its bucket once (a wiped key\'s too); one the bucket holds is left as it is', () => {
  const home = scratch();
  /* this key's log, and another device's - a key since wiped - both only in the Edge home */
  const sk2 = new Uint8Array(32).fill(4);
  const pub2 = p256.getPublicKey(sk2, false).subarray(1);
  const id2 = chain.deviceIdOf(pub2);
  const l2 = [chain.encodeLink({ seq: 0, op: OP.SIGN, decision: DECISION.SELF_PRESS, subject: new Uint8Array(32).fill(9), grantId: 1, version: 1 })];
  const other = { ...copyfile.empty(id2), publicKey: pub2, links: [{ link: l2[0], head: chain.heads(l2, chain.genesis(id2))[0] }] };
  const old = bucketHome.kv(bucketHome.edgeAt(home, 'copies'));
  old.setItem(copyfile.toJSON(copyOf(0)).deviceId.slice(0, 16), JSON.stringify(copyfile.toJSON(copyOf(5))));
  old.setItem(copyfile.toJSON(other).deviceId.slice(0, 16), JSON.stringify(copyfile.toJSON(other)));
  copy.useIdentityBucket({ id: BUCKET_ID, net: 'live' });
  /* this key's log is in the bucket already, newer than the Edge home's: it stays */
  copy.load(home, id);
  copy.keepNotes(home, id, { reasons: { 3: 'kept' }, messages: {} });
  assert.equal(copy.adoptAll(home), 1, 'only the other device\'s log was missing');
  assert.equal(copy.adoptAll(home), 0, 'once');
  assert.equal(copy.load(home, id2).links.length, 1);
  assert.ok(JSON.stringify(logStore().entries()).includes('kept'), 'the bucket\'s own (newer) log was not written over');
});

test('the testnet keeps its logs in its own store and bucket file', () => {
  const home = scratch();
  copy.useIdentityBucket({ id: BUCKET_ID, net: 'test' });
  copy.keepNotes(home, id, { reasons: { 3: 'x' }, messages: {} });
  assert.ok(bucketHome.kv(bucketHome.identityAt(BUCKET_ID, 'test', 'edge-logs-test')).keys().length);
  assert.equal(fs.existsSync(bucketHome.identityFile(BUCKET_ID, 'live')), false);
});
