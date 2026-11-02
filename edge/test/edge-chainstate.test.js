'use strict';

/*
 * One chain state per key (edge/src/chainstate.js; S4 step 9): a head only from a check that vouched for it now, the
 * events ('checked' every time, 'changed' on a new verdict kind, 'sealed' when told), one check at a time per key -
 * askers during it share it - and the skipped answer when the host says nothing changed.
 */
const test = require('node:test');
const assert = require('node:assert');
const { createChainState } = require('../src/chainstate');

const ID = 'AB'.repeat(16);
const H = (n) => new Uint8Array(32).fill(n);
const view = (kind, headSeq) => ({ verdict: { kind, ...(kind === 'verified' ? { through: headSeq } : {}) }, headSeq, rows: [] });

test('a head only from a check that vouched for it now', () => {
  const s = createChainState();
  let a = s.record(ID, { view: view('verified', 9), lastSeen: { seq: 9, head: H(9) }, path: 'full' });
  assert.equal(a.ok, true);
  assert.deepEqual(a.head, { seq: 9, head: H(9) });
  assert.equal(a.deviceId, ID.toLowerCase());
  a = s.record(ID, { view: view('verified', 10), lastSeen: { seq: 9, head: H(9) } });
  assert.equal(a.head, null, 'lastSeen is an older head than the key\'s: no head');
  assert.equal(a.ok, false);
  a = s.record(ID, { view: view('tampered', 10), lastSeen: { seq: 10, head: H(10) } });
  assert.equal(a.head, null, 'a tampered copy offers none');
  a = s.record(ID, { view: view('gap', 10), lastSeen: { seq: 10, head: H(10) } });
  assert.deepEqual(a.head, { seq: 10, head: H(10) }, 'a gap vouches for its head');
  assert.equal(a.ok, false, 'but is not ok');
  assert.equal(s.current(ID), a);
});

test('events: checked every time, changed on a new kind, sealed when told; a listener that throws breaks nothing', () => {
  const s = createChainState();
  const seen = [];
  s.on('checked', () => seen.push('checked'));
  s.on('changed', (a) => seen.push(`changed:${a.view.verdict.kind}`));
  const off = s.on('sealed', () => seen.push('sealed'));
  s.on('checked', () => { throw new Error('a listener\'s own failure'); });
  s.record(ID, { view: view('verified', 1), lastSeen: { seq: 1, head: H(1) } });
  s.record(ID, { view: view('verified', 2), lastSeen: { seq: 2, head: H(2) }, sealed: true });
  off();
  s.record(ID, { view: view('unsigned', 3), lastSeen: null, sealed: true });
  assert.deepEqual(seen, ['checked', 'changed:verified', 'checked', 'sealed', 'checked', 'changed:unsigned']);
  assert.throws(() => s.on('nope', () => {}), /no event/);
});

test('validity: one check at a time per key; skipped when nothing changed; forget checks again', async () => {
  const s = createChainState();
  let checks = 0;
  let release;
  const check = () => new Promise((resolve) => {
    checks += 1;
    release = () => { s.record(ID, { view: view('verified', 4), lastSeen: { seq: 4, head: H(4) }, path: 'full' }); resolve(); };
  });
  const unchanged = async () => true;
  const p1 = s.validity(ID, { unchanged, check });
  const p2 = s.validity(ID, { unchanged, check });
  assert.equal(p1, p2, 'an asker during a check shares it');
  await new Promise((r) => setImmediate(r));
  release();
  assert.equal((await p1).path, 'full');
  assert.equal(checks, 1);
  const again = await s.validity(ID, { unchanged, check });
  assert.equal(again.path, 'skipped', 'nothing changed: from memory');
  assert.equal(checks, 1);
  const changed = s.validity(ID, { unchanged: async () => false, check });
  await new Promise((r) => setImmediate(r));
  release();
  assert.equal((await changed).path, 'full');
  assert.equal(checks, 2);
  s.forget(ID);
  assert.equal(s.current(ID), null);
  const fresh = s.validity(ID, { unchanged, check });
  await new Promise((r) => setImmediate(r));
  release();
  await fresh;
  assert.equal(checks, 3, 'forgotten: no answer to skip from - a check');
});
