/*
 * The bucket replicates by itself (bucket/src/replicate.js, ok-edge plan S3): two devices of one identity swap HAVE
 * and GIVE and end up holding the same bucket and the same base; an edit on one side is taken by the other with no
 * question; an edit on both sides goes to the store's rule, or to the person - never decided silently.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const bucket = require('../src/bucket');
const rep = require('../src/replicate');
const rules = require('../src/rules');
const list = require('../../keychain/src/list');

const OWNER = 'ab'.repeat(16);
let tick = 0;
const now = () => new Date(Date.UTC(2026, 9, 25, 0, 0, tick++)).toISOString();
const make = () => bucket.create({ owner: OWNER });
const kv = (b, store) => bucket.kv(b, store, { now });

/* one swap, both sides exactly as two devices run it: HAVE both ways, GIVE both ways, take both ways */
function swap(a, b, baseA = {}, baseB = {}, opts = {}) {
  const haveA = rep.summarize(a);
  const haveB = rep.summarize(b);
  const giveA = rep.give(a, haveA, haveB, baseA);
  const giveB = rep.give(b, haveB, haveA, baseB);
  const ra = rep.take(a, giveB, haveA, haveB, baseA, opts);
  const rb = rep.take(b, giveA, haveB, haveA, baseB, opts);
  return { ra, rb, giveA, giveB, haveA };
}
const stores = (b) => JSON.stringify(bucket.parse(bucket.serialize(b)).stores);

test('first swap, nothing in common: both end with everything, the same base on both sides; HAVE carries no values', () => {
  const a = make(); const b = make();
  kv(a, 'guestbook').setItem('myname', 'Brad');
  kv(b, 'cryptobox').setItem('cryptobox:v1', '{"messages":[]}');
  const { ra, rb, haveA } = swap(a, b);
  assert.equal(stores(a), stores(b));
  assert.deepEqual(ra.base, rb.base);
  assert.equal(kv(b, 'guestbook').getItem('myname'), 'Brad');
  assert.ok(!JSON.stringify(haveA).includes('Brad'), 'a HAVE holds hashes and dates only');
  assert.deepEqual(ra.conflicts, []);
});

test('after a swap, an edit on one side is taken by the other - no question - and a removal travels too', () => {
  const a = make(); const b = make();
  kv(a, 'guestbook').setItem('myname', 'Brad');
  kv(a, 'guestbook').setItem('offered', '["k1"]');
  let { ra, rb } = swap(a, b);
  kv(b, 'guestbook').setItem('myname', 'Brad M');
  kv(a, 'guestbook').removeItem('offered');
  ({ ra, rb } = swap(a, b, ra.base, rb.base));
  assert.equal(kv(a, 'guestbook').getItem('myname'), 'Brad M');
  assert.equal(kv(b, 'guestbook').getItem('offered'), null, 'removed there is removed here');
  assert.deepEqual(ra.conflicts, []);
  assert.deepEqual(rb.conflicts, []);
  assert.equal(stores(a), stores(b));
  assert.deepEqual(ra.base, rb.base);
  /* nothing changed: the next swap gives nothing */
  const again = swap(a, b, ra.base, rb.base);
  assert.deepEqual(again.giveA, {});
  assert.deepEqual(again.giveB, {});
});

test('the same key changed on both sides, no rule to join them: a conflict for the person on both sides, each keeps its own', () => {
  const a = make(); const b = make();
  kv(a, 'guestbook').setItem('myname', 'Brad');
  let { ra, rb } = swap(a, b);
  kv(a, 'guestbook').setItem('myname', 'Brad (laptop)');
  kv(b, 'guestbook').setItem('myname', 'Brad (phone)');
  ({ ra, rb } = swap(a, b, ra.base, rb.base));
  assert.equal(kv(a, 'guestbook').getItem('myname'), 'Brad (laptop)');
  assert.equal(kv(b, 'guestbook').getItem('myname'), 'Brad (phone)');
  assert.equal(ra.conflicts.length, 1);
  assert.equal(ra.conflicts[0].into.v, 'Brad (laptop)', 'named from this side: into is what is here');
  assert.equal(ra.conflicts[0].from.v, 'Brad (phone)');
  assert.equal(rb.conflicts[0].into.v, 'Brad (phone)');
  assert.deepEqual(ra.base, rb.base, 'the base keeps what both last agreed on');
  /* the person picks on one side: the next swap carries the pick to the other */
  kv(b, 'guestbook').setItem('myname', 'Brad (laptop)');
  ({ ra, rb } = swap(a, b, ra.base, rb.base));
  /* the same value on both sides (each dated when it changed there): agreed, nothing to give */
  assert.equal(kv(a, 'guestbook').getItem('myname'), kv(b, 'guestbook').getItem('myname'));
  assert.deepEqual(ra.conflicts, []);
  assert.deepEqual(ra.base, rb.base);
  assert.deepEqual(swap(a, b, ra.base, rb.base).giveA, {});
});

test('the Key Chain list changed on both sides: the list rule joins them, the same on both sides, nothing dropped', () => {
  const a = make(); const b = make();
  const entry = (label, fill) => list.createEntry({ kind: 'derived', scheme: 'ssh', label, type: 'ed25519', publicKey: new Uint8Array(32).fill(fill), firstSeen: 'x', lastSeen: 'x', tools: [] });
  kv(a, 'keychain').setItem('list', list.serialize([entry('laptop@host', 1)]));
  kv(b, 'keychain').setItem('list', list.serialize([entry('phone@host', 2)]));
  const opts = { rules: { keychain: rules.keychain(list) } };
  let { ra, rb } = swap(a, b, {}, {}, opts);
  assert.equal(stores(a), stores(b), 'both computed the same join');
  assert.deepEqual(list.parse(kv(a, 'keychain').getItem('list')).map((e) => e.label).sort(), ['laptop@host', 'phone@host']);
  assert.deepEqual(ra.base, rb.base);
  assert.deepEqual(ra.conflicts, []);
  const again = swap(a, b, ra.base, rb.base, opts);
  assert.deepEqual(again.giveA, {});
});

test('a GIVE that does not match the HAVE it came with is not taken, and nothing is agreed for it', () => {
  const a = make(); const b = make();
  kv(b, 'guestbook').setItem('myname', 'Brad');
  const haveA = rep.summarize(a);
  const haveB = rep.summarize(b);
  const giveB = rep.give(b, haveB, haveA, {});
  giveB.guestbook.myname.v = 'Mallory';
  const ra = rep.take(a, giveB, haveA, haveB, {});
  assert.equal(kv(a, 'guestbook').getItem('myname'), null);
  assert.equal(ra.base.guestbook, undefined);
});
