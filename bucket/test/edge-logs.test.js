'use strict';

/*
 * The Edge logs in the identity bucket (edge/src/logblocks.js, rules.edgeLogs; PROPOSAL-sync-and-identity.md Phase 1):
 * a device's copy cut into blocks comes back whole; two devices that each kept part of one log end with all of it
 * (links are signed and unique: the union); a fork is reported and never repaired; and after the first trade a new
 * link moves only the block it grew and the meta - not the whole log.
 */
const test = require('node:test');
const assert = require('node:assert');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const chain = require('../../edge/src/chain');
const copyfile = require('../../edge/src/copyfile');
const logblocks = require('../../edge/src/logblocks');
const history = require('../../edge/src/history');
const { OP, DECISION } = require('../../edge/src/codes');
const bucket = require('../src');
const replicate = require('../src/replicate');

const sk = new Uint8Array(32).fill(7);
const pub = p256.getPublicKey(sk, false).subarray(1);
const id = chain.deviceIdOf(pub);
const K = require('../../edge/test/helpers/hybrid-key').edgeKey(sk);
const b32 = (n) => new Uint8Array(32).fill(n % 256);
/* 150 links: budgets of a grant, a sign and a receipt, over and over - more than two blocks */
const N = 150;
const opOf = (seq) => [OP.GRANT_CREATE, OP.SIGN, OP.RECEIPT][seq % 3];
const links = Array.from({ length: N }, (_, seq) => chain.encodeLink({
  seq, op: opOf(seq), decision: opOf(seq) === OP.SIGN ? DECISION.SELF_PRESS : DECISION.APPROVE, subject: b32(seq + 1), grantId: 1 + Math.floor(seq / 3), version: 1,
}));
const heads = chain.heads(links, chain.genesis(id));

/* a copy holding links from..upTo, with notes and openings for them */
function copyJSON(from, upTo, extra = {}) {
  const reasons = {};
  const messages = {};
  for (let s = from; s <= upTo; s++) {
    if (opOf(s) === OP.SIGN) reasons[s] = `sign ${s}`;
    if (opOf(s) === OP.RECEIPT) messages[s] = `receipt ${s}`;
  }
  const openings = [];
  for (let s = from; s <= upTo; s++) if (opOf(s) === OP.GRANT_CREATE) openings.push({ grantId: 1 + Math.floor(s / 3), reason: `budget ${s}`, scopes: [], uses: 1, lifetime: 60, opened: s, from: 'test' });
  return copyfile.toJSON({
    ...copyfile.empty(id), publicKey: pub, publicKeyPq: K.publicKeyPq,
    links: links.slice(from, upTo + 1).map((l, i) => ({ link: l, head: heads[from + i] })),
    lastSeen: { seq: upTo, head: heads[upTo] },
    seals: [{ seq: upTo, head: heads[upTo], ...K.sign({ deviceId: id, seq: upTo, head: heads[upTo] }) }],
    notes: { reasons, messages },
    openings,
    ...extra,
  });
}
const STORE = 'edge-logs';
const rules = { [STORE]: bucket.rules.edgeLogs(logblocks) };
const withLog = (j) => {
  const b = bucket.create({ owner: 'k1' });
  const s = bucket.kv(b, STORE);
  for (const [k, v] of Object.entries(logblocks.split(j))) s.setItem(k, v);
  return b;
};
const entriesOf = (b) => { const s = bucket.kv(b, STORE); return Object.fromEntries(s.keys().map((k) => [k, s.getItem(k)])); };
const dev = logblocks.devOf(copyfile.toJSON(copyfile.empty(id)).deviceId);

/* a whole trade between two buckets, both ways, as the trade runs it */
function trade(a, b) {
  const ha = replicate.summarize(a, { rules });
  const hb = replicate.summarize(b, { rules });
  const ga = replicate.give(a, ha, hb, { rules });
  const gb = replicate.give(b, hb, ha, { rules });
  const ra = replicate.take(a, gb, { rules });
  const rb = replicate.take(b, ga, { rules });
  return { ga, gb, ra, rb };
}

test('edge-logs: a copy cut into blocks joins back to the same copy (and the same budget history)', () => {
  const j = copyJSON(0, N - 1);
  const parts = logblocks.split(j);
  assert.deepEqual(Object.keys(parts).filter((k) => k.includes('.links.')), [`${dev}.links.000000`, `${dev}.links.000001`, `${dev}.links.000002`]);
  const back = logblocks.join(parts, j.deviceId);
  assert.deepEqual(back, JSON.parse(JSON.stringify(j)));
  assert.deepEqual(history.budgetHistory(back), history.budgetHistory(j));
  assert.deepEqual(logblocks.devices(Object.keys(parts)), [dev]);
});

test('edge-logs: two devices each holding part of one log trade to the whole of it, the same on both sides', () => {
  /* the CLI read #0..#99 from the key, the web app #60..#149 */
  const a = withLog(copyJSON(0, 99));
  const b = withLog(copyJSON(60, N - 1));
  const r = trade(a, b);
  assert.deepEqual(r.ra.conflicts, []);
  assert.deepEqual(r.rb.conflicts, []);
  const ja = logblocks.join(entriesOf(a), copyfile.toJSON(copyfile.empty(id)).deviceId);
  const jb = logblocks.join(entriesOf(b), copyfile.toJSON(copyfile.empty(id)).deviceId);
  assert.equal(ja.links.length, N, 'every link, from both sides');
  assert.deepEqual(ja, jb, 'both sides hold the same log');
  assert.equal(ja.checkpoint, undefined);
  assert.equal(ja.lastSeen.seq, N - 1, 'the newer lastSeen');
  assert.equal(ja.openings.length, N / 3, 'every budget\'s opening words');
  assert.equal(Object.keys(ja.notes.reasons).length, N / 3);
  /* settled: a second trade moves nothing */
  const again = trade(a, b);
  assert.deepEqual([again.ga, again.gb], [{}, {}]);
});

test('edge-logs: after the first trade, a new link moves only its block and the meta', () => {
  const a = withLog(copyJSON(0, 140));
  const b = withLog(copyJSON(0, 140));
  trade(a, b);
  /* a reads one more link */
  const s = bucket.kv(a, STORE);
  for (const [k, v] of Object.entries(logblocks.split(copyJSON(0, 141)))) s.setItem(k, v);
  const r = trade(a, b);
  const moved = Object.keys(r.ga[STORE] || {}).sort();
  assert.deepEqual(moved.filter((k) => k.includes('.links.')), [`${dev}.links.000002`], 'only the tail block');
  assert.ok(moved.length <= 4, `a handful of small keys, not the log: ${moved.join(', ')}`);
  assert.equal(logblocks.join(entriesOf(b), copyfile.toJSON(copyfile.empty(id)).deviceId).links.length, 142);
});

test('edge-logs: a fork is reported and never repaired - this side keeps its log', () => {
  const j = copyJSON(0, 99);
  const forged = JSON.parse(JSON.stringify(j));
  /* the other side's #70 is another link */
  const other = chain.encodeLink({ seq: 70, op: OP.SIGN, decision: DECISION.SELF_PRESS, subject: b32(250), grantId: 24, version: 1 });
  const at = forged.links.findIndex((l) => chain.decodeLink(Buffer.from(l.link, 'hex')).seq === 70);
  forged.links[at] = { ...forged.links[at], link: Buffer.from(other).toString('hex') };
  const a = withLog(j);
  const b = withLog(forged);
  const before = entriesOf(a);
  const r = trade(a, b);
  assert.equal(r.ra.conflicts.length, 1);
  assert.match(r.ra.conflicts[0].reason, /fork, reported, never repaired/);
  assert.throws(() => r.ra.conflicts[0].apply(), /never repaired/);
  assert.equal(entriesOf(a)[`${dev}.links.000001`], before[`${dev}.links.000001`], 'the forked block is left as it was');
});

test('edge-logs: different keys for one device are a fork; an archived block is not taken', () => {
  const j = copyJSON(0, 10);
  const other = withLog({ ...j, publicKey: Buffer.from(p256.getPublicKey(new Uint8Array(32).fill(9), false).subarray(1)).toString('hex') });
  const a = withLog(j);
  const r = trade(a, other);
  assert.ok(r.ra.conflicts.some((c) => /different keys/.test(c.reason)));
  const c = withLog(copyJSON(0, 10));
  const d = bucket.create({ owner: 'k1' });
  bucket.kv(c, STORE).removeItem(`${dev}.links.000000`);
  replicate.take(d, replicate.give(c, replicate.summarize(c, { rules }), {}, { rules }), { rules });
  assert.equal(bucket.kv(d, STORE).getItem(`${dev}.links.000000`), null);
});

test('a host files a copy that holds less than the bucket (a fresh web app from the checkpoint): the bucket keeps every link, gains the new ones; a fork is not written', () => {
  const full = logblocks.split(copyJSON(0, 140));
  /* the web app: only from #120, and two links the bucket has not seen yet */
  const r = logblocks.fileInto(full, copyJSON(120, 149));
  assert.deepEqual(r.forks, []);
  const after = { ...full, ...r.changed };
  const j = logblocks.join(after, require('../../src/bytes').toHex(id));
  assert.equal(j.links.length, 150, 'links lost or not gained');
  assert.ok(!Object.keys(r.changed).some((k) => k.endsWith('.links.0000')), 'a block the host did not change was written');
  assert.deepEqual(logblocks.fileInto(after, copyJSON(120, 149)).changed, {}, 'filing it again changed something');
  /* the same seq with other bytes: reported, the block left as it was */
  const forked = copyJSON(120, 149);
  forked.links[0] = { ...forked.links[0], head: '00'.repeat(32) };
  const f = logblocks.fileInto(after, forked);
  assert.equal(f.forks.length, 1);
  assert.ok(!Object.keys(f.changed).some((k) => /\.links\./.test(k) && k.endsWith('0001')), 'a forked block was written');
});

test('each log\'s newest link, from its last links block - what the sealed copy\'s heads row says', () => {
  const dev = require('../../src/bytes').toHex(id).slice(0, 16);
  assert.deepEqual(logblocks.newestSeqs(logblocks.split(copyJSON(0, 140))), { [dev]: 140 });
  assert.deepEqual(logblocks.newestSeqs({}), {});
});

/*
 * THE FIELDS THE APP KEPT ONLY ON ITS DEVICE (S4 step 1, 2026-11-02): the anchor, a seal's `ended`, who wrote a reason
 * and when, the refused TX starts - each comes back from the blocks as it went in, and two copies merge them by their
 * rules (the earlier anchor; ended kept from either side; who and refusals by union, refusals capped).
 */
test('edge-logs: the anchor, seals\' ended, notes.who and refusals survive the blocks and merge by their rules', () => {
  const who = { 4: { computer: 'nitro16', at: 1000 } };
  const a = copyJSON(0, 40, {
    anchor: { seq: 30, head: heads[30] },
    refusals: [{ seq: 12, computer: 'nitro16', at: 10, status: 'no budget' }],
  });
  a.notes.who = who;
  a.seals = a.seals.map((s) => ({ ...s, ended: [7] }));
  /* through the blocks and back: the same JSON */
  const back = logblocks.join(logblocks.split(a), toHexId());
  assert.deepEqual(back.anchor, a.anchor);
  assert.deepEqual(back.refusals, a.refusals);
  assert.deepEqual(back.notes.who, who);
  assert.deepEqual(back.seals.at(-1).ended, [7]);
  /* and through copyfile, as every host reads a copy */
  const c = copyfile.fromJSON(back, id);
  assert.equal(c.anchor.seq, 30);
  assert.deepEqual(copyfile.toJSON(c).anchor, a.anchor);

  /* two copies: the earlier anchor; a seal's ended from the side that knows it; refusals and who by union */
  const b = copyJSON(20, 40, {
    anchor: { seq: 20, head: heads[20] },
    refusals: [{ seq: 33, computer: 'box', at: 20, status: 'expired' }],
  });
  b.notes.who = { 25: { computer: 'box', at: 2000 } };
  b.seals = b.seals.map((s) => ({ ...s, ended: [8] }));
  const m = copyfile.merge(copyfile.fromJSON(a, id), copyfile.fromJSON(b, id));
  assert.equal(m.fork, null);
  assert.equal(m.copy.anchor.seq, 20, 'the earlier anchor');
  assert.deepEqual(m.copy.seals.find((s) => s.seq === 40).ended, [7, 8], 'the budgets each copy knew the seal closed');
  assert.deepEqual(m.copy.refusals.map((r) => r.seq), [12, 33]);
  assert.deepEqual(Object.keys(m.copy.notes.who).sort(), ['25', '4']);

  /* refusals are capped at the newest REFUSALS_KEPT */
  const many = Array.from({ length: copyfile.REFUSALS_KEPT + 5 }, (_, i) => ({ seq: i, computer: 'x', at: i, status: 'w' }));
  const capped = copyfile.merge(copyfile.fromJSON(copyJSON(0, 2, { refusals: many.slice(0, 30) }), id), copyfile.fromJSON(copyJSON(0, 2, { refusals: many.slice(30) }), id));
  assert.equal(capped.copy.refusals.length, copyfile.REFUSALS_KEPT);
  assert.equal(capped.copy.refusals[0].at, 5, 'the oldest dropped first');

  /* in the bucket: filing b into a's blocks takes b's anchor and who without a fork */
  const filed = logblocks.fileInto(logblocks.split(a), b);
  assert.deepEqual(filed.forks, []);
  const after = logblocks.join({ ...logblocks.split(a), ...filed.changed }, toHexId());
  assert.equal(after.anchor.seq, 20);
  assert.deepEqual(Object.keys(after.notes.who).sort(), ['25', '4']);
});

/* an older copy (none of the new fields) reads and writes back unchanged - nothing in the bucket is rewritten */
test('edge-logs: a copy without the new fields round-trips unchanged', () => {
  const old = copyJSON(0, 70);
  assert.deepEqual(copyfile.toJSON(copyfile.fromJSON(old, id)), old);
  assert.deepEqual(logblocks.join(logblocks.split(old), toHexId()), old);
});

function toHexId() { return Buffer.from(id).toString('hex'); }
