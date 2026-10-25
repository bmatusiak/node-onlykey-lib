/*
 * The bucket replicates by itself (bucket/src/replicate.js, ok-edge plan S3; Brad, 2026-10-25: "the stale mobile
 * device will most likely talk to the desktop at one point, so they trade when they can"): two devices of one
 * identity trade HAVE and GIVE whenever they talk and each imports the other's changes - the newer value wins,
 * removals travel as archived values, nothing is asked, and whoever traded last holds everything.
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

/* one trade, both sides exactly as two devices run it */
function trade(a, b, opts = {}) {
  const haveA = rep.summarize(a);
  const haveB = rep.summarize(b);
  const giveA = rep.give(a, haveA, haveB);
  const giveB = rep.give(b, haveB, haveA);
  const ra = rep.take(a, giveB, opts);
  const rb = rep.take(b, giveA, opts);
  return { ra, rb, giveA, giveB, haveA };
}
const live = (b) => JSON.stringify(Object.fromEntries(Object.entries(b.stores).map(([n, s]) => [n, Object.fromEntries(Object.entries(s).map(([k, r]) => [k, [r.v, !!r.archived]]))])));

test('a new device has nothing: one trade and it holds everything; a HAVE carries hashes and dates, no values', () => {
  const desktop = make(); const fresh = make();
  kv(desktop, 'guestbook').setItem('myname', 'Brad');
  kv(desktop, 'cryptobox').setItem('cryptobox:v1', '{"messages":[]}');
  const { haveA, giveB } = trade(desktop, fresh);
  assert.equal(live(fresh), live(desktop));
  assert.deepEqual(giveB, {}, 'the new device had nothing to give');
  assert.ok(!JSON.stringify(haveA).includes('Brad'));
});

test('the stale phone catches up at its next trade - with what the desktop took from another device meanwhile', () => {
  const phone = make(); const desktop = make(); const pixel = make();
  kv(phone, 'guestbook').setItem('myname', 'Brad');
  trade(phone, desktop);
  /* the phone is away; the desktop changes, and trades with another device of the identity */
  kv(desktop, 'guestbook').setItem('myname', 'Brad M');
  kv(pixel, 'cryptobox').setItem('cryptobox:v1', '{"messages":[1]}');
  trade(desktop, pixel);
  /* the phone comes back */
  const { ra } = trade(phone, desktop);
  assert.equal(kv(phone, 'guestbook').getItem('myname'), 'Brad M', 'the newer value');
  assert.equal(kv(phone, 'cryptobox').getItem('cryptobox:v1'), '{"messages":[1]}', 'passed on by the desktop');
  assert.deepEqual(ra.conflicts, []);
  assert.equal(live(phone), live(desktop));
  const again = trade(phone, desktop);
  assert.deepEqual([again.giveA, again.giveB], [{}, {}], 'nothing new: nothing given');
});

test('the same key changed on both: the later one wins on both sides; a later removal wins as an archived value', () => {
  const a = make(); const b = make();
  kv(a, 'guestbook').setItem('myname', 'Brad');
  kv(a, 'guestbook').setItem('offered', '["k1"]');
  trade(a, b);
  kv(a, 'guestbook').setItem('myname', 'Brad (laptop)');
  kv(b, 'guestbook').setItem('myname', 'Brad (phone)'); /* later */
  kv(b, 'guestbook').removeItem('offered');
  const { ra, rb } = trade(a, b);
  assert.equal(kv(a, 'guestbook').getItem('myname'), 'Brad (phone)');
  assert.equal(kv(b, 'guestbook').getItem('myname'), 'Brad (phone)');
  assert.equal(kv(a, 'guestbook').getItem('offered'), null);
  assert.deepEqual(kv(a, 'guestbook').archivedKeys(), ['offered'], 'never deleted - archived on both sides');
  assert.deepEqual([ra.conflicts, rb.conflicts], [[], []]);
});

test('the Key Chain list changed on both sides: joined per entry, the same on both sides, nothing dropped', () => {
  const a = make(); const b = make();
  const entry = (label, fill) => list.createEntry({ kind: 'derived', scheme: 'ssh', label, type: 'ed25519', publicKey: new Uint8Array(32).fill(fill), firstSeen: 'x', lastSeen: 'x', tools: [] });
  kv(a, 'keychain').setItem('list', list.serialize([entry('laptop@host', 1)]));
  kv(b, 'keychain').setItem('list', list.serialize([entry('phone@host', 2)]));
  const opts = { rules: { keychain: rules.keychain(list) } };
  trade(a, b, opts);
  assert.deepEqual(list.parse(kv(a, 'keychain').getItem('list')).map((e) => e.label).sort(), ['laptop@host', 'phone@host']);
  assert.equal(kv(a, 'keychain').getItem('list'), kv(b, 'keychain').getItem('list'), 'both computed the same join');
});

test('a bucket written during the trade is refused before anything is given', () => {
  const a = make(); const b = make();
  kv(a, 'guestbook').setItem('myname', 'Brad');
  const haveA = rep.summarize(a);
  kv(a, 'guestbook').setItem('myname', 'Brad again');
  assert.throws(() => rep.give(a, haveA, rep.summarize(b)), /changed during the trade/);
});
