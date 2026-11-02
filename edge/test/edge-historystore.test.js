'use strict';

/*
 * The key's own chain copy a host keeps (edge/src/historystore.js; S4 step 8): the app's key and stored form exactly
 * (a copy the app wrote reads as it is - nothing migrated), the session's copy handed out as a copy, an edit made to the
 * stored copy while the host runs never written over, an old-chain copy (no v) not read, and where the copy ends -
 * the last link's head, or the anchor of a copy holding nothing after it - for the key session's knownHead.
 */
const test = require('node:test');
const assert = require('node:assert');
const { createHistory } = require('../src/historystore');
const chain = require('../src/chain');
const { OP, DECISION } = require('../src/codes');

function memoryKv() {
  const m = new Map();
  return {
    m,
    getItem: async (k) => (m.has(k) ? m.get(k) : null),
    setItem: async (k, v) => { m.set(k, String(v)); },
    removeItem: async (k) => { m.delete(k); },
    getAllKeys: async () => [...m.keys()],
  };
}
const DEV = 'cd'.repeat(16);
const hex = (b) => Buffer.from(b).toString('hex');
const b32 = (n) => new Uint8Array(32).fill(n);
const link = (seq) => chain.encodeLink({ seq, op: OP.SIGN, decision: DECISION.SELF_PRESS, subject: b32(seq + 1), grantId: 2, version: 1 });

/* a copy as the ok-edge app stored it (edgeStore.ts saveMirror, v1) */
const appStored = JSON.stringify({
  v: 1, deviceId: DEV,
  links: [{ link: hex(link(4)), head: hex(b32(40)) }, { link: hex(link(5)), head: hex(b32(50)), reveal: hex(b32(9)) }],
  messages: { 5: 'signed a commit' }, lastSeen: { seq: 5, head: hex(b32(50)) }, lastSync: 1000,
  anchor: { seq: 3, head: hex(b32(30)) }, seen: { 4: 900, 5: 950 },
  reasons: { 5: { computer: 'nitro16', text: 'ship', at: 940 } },
  refusals: [{ computer: 'box', seq: 5, status: 'EDGE:05', at: 960 }],
  seals: [{ seq: 5, head: hex(b32(50)), signature: hex(b32(7)), ended: [2] }],
});

test('a copy the app stored reads as it is, under the same key, and saves back to the same text', async () => {
  const kv = memoryKv();
  kv.m.set(`okrn.edge.mirror.${DEV}`, appStored);
  const h = createHistory({ kv, prefix: () => 'okrn.edge.mirror.' });
  const m = await h.load(DEV);
  assert.equal(m.links.length, 2);
  assert.equal(chain.decodeLink(m.links[1].link).seq, 5);
  assert.deepEqual([...m.links[1].reveal], [...b32(9)]);
  assert.equal(m.messages[5], 'signed a commit', 'messages keyed by number');
  assert.equal(m.anchor.seq, 3);
  assert.equal(m.reasons[5].computer, 'nitro16');
  assert.deepEqual(m.seals[0].ended, [2]);
  const r = await h.save(m);
  assert.deepEqual(r, { written: false, outside: false }, 'nothing changed: nothing written');
  assert.equal(kv.m.get(`okrn.edge.mirror.${DEV}`), appStored, 'the stored text is the app\'s, byte for byte');
});

test('load hands out a copy: a change not saved changes nothing; a save is kept', async () => {
  const kv = memoryKv();
  const h = createHistory({ kv, prefix: () => 'p.' });
  const m = await h.load(DEV);
  m.links.push({ link: link(0), head: b32(1), reveal: null });
  assert.equal((await h.load(DEV)).links.length, 0, 'not saved');
  assert.deepEqual(await h.save(m), { written: true, outside: false });
  assert.equal((await h.load(DEV)).links.length, 1);
  assert.deepEqual(await h.ids(), [DEV]);
});

test('an edit made to the stored copy while the host runs is never written over', async () => {
  const kv = memoryKv();
  const h = createHistory({ kv, prefix: () => 'p.' });
  const m = await h.load(DEV);
  m.links.push({ link: link(0), head: b32(0xa1), reveal: null });
  await h.save(m);
  const edited = kv.m.get(`p.${DEV}`).replace(hex(b32(0xa1)), hex(b32(0xa2)));
  kv.m.set(`p.${DEV}`, edited);
  m.links.push({ link: link(1), head: b32(3), reveal: null });
  assert.deepEqual(await h.save(m), { written: false, outside: true });
  assert.equal(kv.m.get(`p.${DEV}`), edited, 'the outside edit stands');
  const back = await h.load(DEV);
  assert.deepEqual([...back.links[0].head], [...b32(0xa2)], 'the next load reads the store (the verdict then checks it)');
});

test('a copy of the old chain (no v) is not read; forget removes the copy', async () => {
  const kv = memoryKv();
  kv.m.set(`p.${DEV}`, JSON.stringify({ deviceId: DEV, links: [{ link: hex(link(0)), head: hex(b32(1)) }] }));
  const h = createHistory({ kv, prefix: () => 'p.' });
  assert.equal((await h.load(DEV)).links.length, 0);
  await h.forget(DEV);
  assert.equal(kv.m.has(`p.${DEV}`), false);
});

test('where the copy ends: the last link with its head, the anchor of an empty copy, nothing otherwise', async () => {
  const kv = memoryKv();
  const h = createHistory({ kv, prefix: () => 'p.' });
  assert.equal(await h.ends(DEV), null, 'an empty copy: no end');
  const m = await h.load(DEV);
  m.anchor = { seq: 3, head: b32(30) };
  await h.save(m);
  assert.deepEqual(await h.ends(DEV), { seq: 3, head: b32(30) }, 'nothing after the anchor: the anchor');
  m.links.push({ link: link(4), head: b32(40), reveal: null });
  await h.save(m);
  assert.deepEqual(await h.ends(DEV), { seq: 4, head: b32(40) });
  m.links.push({ link: link(5), head: new Uint8Array(0), reveal: null });
  await h.save(m);
  assert.equal(await h.ends(DEV), null, 'a last link without its head: no end (never an older one)');
});

/*
 * S4 step 6: links of the key's OWN chain taken into its copy - the rules (verdict.takeOwn) and the keep (take): a fork
 * refused, a copy that would not verify refused, every added link a checked one unless a LOSS accounts for it; kept
 * into the copy as it is now, each new link's first-seen time recorded, a fork at keep time keeps nothing.
 */
const { takeOwn } = require('../src/verdict');

test('takeOwn: a fork, an unverified copy and an unchecked link are refused; a link in an accepted loss is not', () => {
  const added = [{ link: link(6) }, { link: link(7) }];
  assert.equal(takeOwn({ added, conflicts: [5], verdict: { kind: 'verified' }, verifiedSeqs: [6, 7] }).refusal, 'invalid');
  assert.equal(takeOwn({ added, conflicts: [], verdict: { kind: 'tampered' }, verifiedSeqs: [] }).refusal, 'copy_unverified');
  const r = takeOwn({ added, conflicts: [], verdict: { kind: 'gap' }, verifiedSeqs: [6] });
  assert.equal(r.ok, false);
  assert.match(r.detail, /#7 cannot be checked/);
  assert.deepEqual(takeOwn({ added, conflicts: [], verdict: { kind: 'gap' }, verifiedSeqs: [6], losses: [{ from: 7, to: 9 }] }), { ok: true });
  assert.deepEqual(takeOwn({ added, conflicts: [], verdict: { kind: 'verified' }, verifiedSeqs: new Set([6, 7]) }), { ok: true });
  assert.deepEqual(takeOwn({ added: [], conflicts: [], verdict: { kind: 'unsigned' }, verifiedSeqs: [] }), { ok: true }, 'nothing to add: nothing refused');
});

test('take: merged into the copy as it is now, first-seen times kept; a fork keeps nothing', async () => {
  const kv = memoryKv();
  const h = createHistory({ kv, prefix: () => 'p.' });
  const m = await h.load(DEV);
  m.links.push({ link: link(4), head: b32(40), reveal: null });
  m.seen[4] = 100;
  await h.save(m);
  const r = await h.take(DEV, [{ link: link(4), head: b32(40), reveal: null }, { link: link(5), head: b32(50), reveal: null }], 500);
  assert.equal(r.added, 1);
  const after = await h.load(DEV);
  assert.equal(after.links.length, 2);
  assert.deepEqual(after.seen, { 4: 100, 5: 500 }, 'a link held before keeps its own seen time');
  const other = chain.encodeLink({ seq: 5, op: OP.SIGN, decision: DECISION.SELF_PRESS, subject: b32(99), grantId: 2, version: 1 });
  await assert.rejects(h.take(DEV, [{ link: other, head: b32(51), reveal: null }]), /a fork at #5/);
  assert.equal((await h.load(DEV)).links.length, 2, 'nothing kept');
});
