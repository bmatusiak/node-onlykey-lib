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
