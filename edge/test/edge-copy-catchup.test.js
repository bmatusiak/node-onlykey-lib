'use strict';

/*
 * A service keeps this computer's copy up with the key between checks (edge/cli/copy.js catchUp; key 3, 2026-10-29: a
 * ship through one service made ~21 links before its close, and the key's ring of 8 had let #565-#577 go). Only the
 * links right after the copy's last are kept, each welded to the one before; a link that does not weld stops it; a
 * ring that no longer reaches the copy keeps nothing (sync, at the close, reports the gap).
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

const sk = new Uint8Array(32).fill(5);
const pub = p256.getPublicKey(sk, false).subarray(1);
const id = chain.deviceIdOf(pub);
const links = Array.from({ length: 20 }, (_, seq) => chain.encodeLink({ seq, op: OP.SIGN, decision: DECISION.SELF_PRESS, subject: new Uint8Array(32).fill(seq + 1), grantId: 1, version: 1 }));
const heads = chain.heads(links, chain.genesis(id));
const rec = (seq) => ({ link: links[seq], head: heads[seq] });

function scratch(upTo) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-catchup-'));
  bucketHome.setRoot(root);
  copy.useIdentityBucket(null);
  const home = path.join(root, 'edge', 'cd'.repeat(16));
  const c = { ...copyfile.empty(id), publicKey: pub, links: Array.from({ length: upTo + 1 }, (_, s) => rec(s)) };
  bucketHome.kv(bucketHome.edgeAt(home, 'copies')).setItem(copyfile.toJSON(c).deviceId.slice(0, 16), JSON.stringify(copyfile.toJSON(c)));
  return home;
}
test.afterEach(() => { copy.useIdentityBucket(null); bucketHome.setRoot(null); });

/* the key: its head at `top`, its ring from `oldest`, PICKUP of up to 8 */
const keyAt = (top, oldest, swap = {}) => ({
  head: async () => ({ seq: top, head: heads[top], oldest }),
  pickup: async (from, n) => {
    const out = [];
    for (let s = Math.max(from, oldest); s < from + n && s <= top; s++) out.push(swap[s] || rec(s));
    return from < oldest ? [] : out;
  },
});

test('the links after the copy are read in, every one welded, past one PICKUP', async () => {
  const home = scratch(4);
  assert.equal(await copy.catchUp(keyAt(15, 8), home, id), 0, 'the ring no longer reaches #5: nothing kept');
  assert.equal(await copy.catchUp(keyAt(15, 5), home, id), 11);
  assert.equal(copy.load(home, id).links.length, 16);
  assert.equal(await copy.catchUp(keyAt(15, 8), home, id), 0, 'up to date: nothing more');
});

test('a link that does not weld stops it: only the ones before it are kept', async () => {
  const home = scratch(4);
  const forged = { link: links[7], head: new Uint8Array(32).fill(9) };
  assert.equal(await copy.catchUp(keyAt(12, 5, { 7: forged }), home, id), 2);
  assert.equal(copy.load(home, id).links.length, 7);
});
