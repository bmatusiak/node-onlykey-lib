/*
 * Edge blocks as canonical JSON (edge/src/block.js; Brad, 2026-10-07: "we use
 * hash of a json"). A block is the links between two seals plus the key's
 * signed checkpoint, written as JSON whose SHA-256 is its id. Only the key's
 * signature is trusted: change any field and the block fails, and its id moves.
 * The seal is the hybrid checkpoint (2026-10-10): "sig" (P-256) and "sigPq"
 * (ML-DSA-65), both required.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const chain = require('../src/chain');
const { OP, DECISION } = require('../src/codes');
const block = require('../src/block');
const { edgeKey } = require('./helpers/hybrid-key');

/* a key: its Edge key pair and device id */
function key(fill) {
  const sk = new Uint8Array(32).fill(fill);
  const pub = p256.getPublicKey(sk, false).subarray(1);
  const k = edgeKey(sk);
  return { sk, pub, pubPq: k.publicKeyPq, sign: k.sign, id: chain.deviceIdOf(pub) };
}

const K = key(7);
const SIB = key(9);
const b32 = (n) => new Uint8Array(32).fill(n);

/* five links from genesis: a budget, a sign with its intent, its receipt, a LOSS (pressed), the budget's end */
function links(fromSeq = 0) {
  const L = [
    { op: OP.GRANT_CREATE, decision: DECISION.APPROVE, subject: b32(1), grantId: 12 },
    { op: OP.SIGN, decision: DECISION.SELF_PRESS, slot: 132, flags: 0x12, subject: b32(2), grantId: 12, grantStep: 1, scope: 1, intent: new Uint8Array(16).fill(0xab) },
    { op: OP.RECEIPT, decision: 0, subject: b32(3), grantId: fromSeq + 1 },
    { op: OP.LOSS, decision: DECISION.APPROVE, flags: 0x01, subject: b32(4), grantId: 0 },
    { op: OP.GRANT_END, decision: DECISION.APPROVE, subject: b32(5), grantId: 12 },
  ];
  return L.map((f, i) => chain.encodeLink({ ...f, seq: fromSeq + i, version: 1 }));
}

/* seal a run of links the way the key does: weld, then sign the head */
function seal(k, startHead, ls) {
  const heads = chain.heads(ls, startHead);
  const head = heads[heads.length - 1];
  const seq = chain.decodeLink(ls[ls.length - 1]).seq;
  return { seq, head, ...k.sign({ deviceId: k.id, seq, head }) };
}

function first() {
  const ls = links(0);
  const start = { seq: 0, head: chain.genesis(K.id) };
  return block.buildBlock({ net: 'live', deviceId: K.id, start, links: ls, checkpoint: seal(K, start.head, ls) });
}

test('canonical(): sorted keys, no spaces, the same bytes Python writes with sort_keys and (",", ":")', () => {
  assert.equal(block.canonical({ b: 1, a: [true, null, 'x"\\y'], c: { z: 0, y: -2 } }), '{"a":[true,null,"x\\"\\\\y"],"b":1,"c":{"y":-2,"z":0}}');
});

test('canonical() refuses what a block cannot hold: floats, unsafe integers, non-ASCII, other objects', () => {
  for (const bad of [1.5, NaN, 2 ** 53, 'é', '\n', new Map(), new Uint8Array(1), () => 1]) {
    assert.throws(() => block.canonical({ x: bad }), /edge block/, String(bad));
  }
});

test('a block reads plainly: op names, numbers, hex, and its seal', () => {
  const b = first();
  assert.equal(b.v, 1);
  assert.equal(b.net, 'live');
  assert.deepEqual(b.links.map((l) => l.op), ['grant_create', 'sign', 'receipt', 'loss', 'grant_end']);
  assert.equal(b.links[1].intent, 'ab'.repeat(16));
  assert.equal(b.links[0].intent, null);
  assert.equal(b.checkpoint.seq, 4);
  assert.equal('seen' in b, false, 'no anchors since 2026-10-08: a block holds only its own links and seal');
});

test('a block verifies with the key\'s public key only, and its id is the SHA-256 of its canonical JSON', () => {
  const b = first();
  const r = block.verifyBlock(b, K.pub, K.pubPq);
  assert.deepEqual(r, { ok: true, id: block.blockId(b) });
  assert.match(r.id, /^[0-9a-f]{64}$/);
  /* the same block built again has the same id */
  assert.equal(block.blockId(first()), r.id);
});

test('change any field and the block fails - and its id moves', () => {
  const b = first();
  const id = block.blockId(b);
  const edits = [
    ['a link\'s grant', (x) => { x.links[1].grant = 13; }],
    ['a link\'s op', (x) => { x.links[2].op = 'settle'; }],
    ['a link\'s intent', (x) => { x.links[1].intent = 'cd'.repeat(16); }],
    ['a link removed', (x) => { x.links.splice(2, 1); }],
    ['the seal\'s head', (x) => { x.checkpoint.head = '00'.repeat(32); }],
    ['the signature', (x) => { x.checkpoint.sig = `${x.checkpoint.sig.slice(0, -2)}00`; }],
    ['the pq signature', (x) => { x.checkpoint.sigPq = `${x.checkpoint.sigPq.slice(0, 200)}${x.checkpoint.sigPq[200] === '0' ? '1' : '0'}${x.checkpoint.sigPq.slice(201)}`; }],
    ['the pq signature removed', (x) => { delete x.checkpoint.sigPq; }],
    ['the device', (x) => { x.device = '11'.repeat(16); }],
    ['the start', (x) => { x.start.head = '22'.repeat(32); }],
    ['the net', (x) => { x.net = 'test'; }],
  ];
  for (const [what, edit] of edits) {
    const x = JSON.parse(JSON.stringify(b));
    edit(x);
    assert.notEqual(block.blockId(x), id, `${what}: id`);
    /* the net is not signed by the key - a test block claiming live still has its own id */
    if (what !== 'the net') assert.equal(block.verifyBlock(x, K.pub, K.pubPq).ok, false, `${what}: verify`);
  }
});

test('another key\'s public key does not verify the block', () => {
  assert.deepEqual(block.verifyBlock(first(), SIB.pub, SIB.pubPq), { ok: false, reason: 'device' });
});

test('block verify requires sigPq: the P-256 half alone, or another ML-DSA-65 key, is not a signed block', () => {
  const b = first();
  assert.equal(b.checkpoint.sigPq.length, chain.ML_DSA65.SIG * 2, 'the seal carries the ML-DSA-65 signature as hex');
  const p256Only = JSON.parse(JSON.stringify(b));
  delete p256Only.checkpoint.sigPq;
  assert.deepEqual(block.verifyBlock(p256Only, K.pub, K.pubPq), { ok: false, reason: 'signature' });
  /* the right P-256 key, the wrong (or no) ML-DSA-65 key */
  assert.deepEqual(block.verifyBlock(b, K.pub, SIB.pubPq), { ok: false, reason: 'signature' });
  assert.deepEqual(block.verifyBlock(b, K.pub, null), { ok: false, reason: 'signature' });
  assert.deepEqual(block.verifyBlock(b, K.pub), { ok: false, reason: 'signature' });
});

test('blocks chain: the second starts on the first\'s seal and names its id; a wrong prev fails', () => {
  const b1 = first();
  const ls = links(5);
  const start = { seq: 5, head: Uint8Array.from(Buffer.from(b1.checkpoint.head, 'hex')) };
  const b2 = block.buildBlock({ net: 'live', deviceId: K.id, start, prev: block.blockId(b1), links: ls, checkpoint: seal(K, start.head, ls) });
  assert.equal(block.verifyBlock(b2, K.pub, K.pubPq, b1).ok, true);
  const wrong = JSON.parse(JSON.stringify(b2));
  wrong.prev = '33'.repeat(32);
  assert.deepEqual(block.verifyBlock(wrong, K.pub, K.pubPq, b1), { ok: false, reason: 'prev' });
});

test('a link whose reserved bytes are not zero cannot be written as fields: refused at build', () => {
  const ls = links(0);
  ls[0][50] = 1; /* a grant_create link has nothing in 47-62 */
  const start = { seq: 0, head: chain.genesis(K.id) };
  assert.throws(() => block.buildBlock({ net: 'live', deviceId: K.id, start, links: ls, checkpoint: seal(K, start.head, ls) }), /reserved bytes/);
});

test('the same bytes and id as an independent writer (onlykey-edge make_block_vectors.py, Python stdlib)', () => {
  const V = require('./vectors/block-v1.json');
  assert.equal(block.canonical(V.block), V.canonical);
  assert.equal(block.blockId(V.block), V.id);
  /*
   * The Python writer is stdlib only and has no ML-DSA-65, so its block carries the P-256
   * half alone - not a signed block under the hybrid. Its canonical bytes and id still match;
   * the ML-DSA-65 half is added here in JS (any ML-DSA-65 key: only the checker's pinned key
   * matters) and the block then verifies against the vector's P-256 key.
   */
  const pub = Uint8Array.from(Buffer.from(V.publicKey, 'hex'));
  assert.deepEqual(block.verifyBlock(V.block, pub, K.pubPq), { ok: false, reason: 'signature' });
  const pq = chain.mlDsaKeys(new Uint8Array(32).fill(0x33));
  const fields = { deviceId: chain.deviceIdOf(pub), seq: V.block.checkpoint.seq, head: Uint8Array.from(Buffer.from(V.block.checkpoint.head, 'hex')) };
  const hybrid = JSON.parse(JSON.stringify(V.block));
  hybrid.checkpoint.sigPq = Buffer.from(chain.signCheckpointPq(fields, pq.secretKey)).toString('hex');
  assert.deepEqual(block.verifyBlock(hybrid, pub, pq.publicKey), { ok: true, id: block.blockId(hybrid) });
  assert.notEqual(block.blockId(hybrid), V.id, 'sigPq is part of the block, so of its id');
});

test('blocksFrom: a copy and its seals give its blocks, each continuing the last; links after the last seal stay open', () => {
  const ls = [...links(0), ...links(5), ...links(10).slice(0, 2)];
  const heads = chain.heads(ls, chain.genesis(K.id));
  const sealAt = (seq) => ({ seq, head: heads[seq], ...K.sign({ deviceId: K.id, seq, head: heads[seq] }) });
  const r = block.blocksFrom({ net: 'live', deviceId: K.id, records: ls.map((link) => ({ link })), seals: [sealAt(9), sealAt(4)] });
  assert.equal(r.blocks.length, 2);
  assert.equal(r.open, 2);
  assert.equal(block.verifyBlock(r.blocks[0], K.pub, K.pubPq).ok, true);
  assert.equal(block.verifyBlock(r.blocks[1], K.pub, K.pubPq, r.blocks[0]).ok, true);
  assert.equal(r.blocks[1].prev, block.blockId(r.blocks[0]));
});

test('blocksFrom: a copy that starts late, or has a hole, gives no wrong block - it says why', () => {
  const ls = links(0);
  const heads = chain.heads(ls, chain.genesis(K.id));
  const seal4 = { seq: 4, head: heads[4], ...K.sign({ deviceId: K.id, seq: 4, head: heads[4] }) };
  const late = block.blocksFrom({ net: 'live', deviceId: K.id, records: ls.slice(2).map((link) => ({ link })), seals: [seal4] });
  assert.equal(late.blocks.length, 0);
  assert.match(late.reason, /starts at #2/);
  const holed = block.blocksFrom({ net: 'live', deviceId: K.id, records: [ls[0], ls[1], ls[3], ls[4]].map((link) => ({ link })), seals: [seal4] });
  assert.equal(holed.blocks.length, 0);
  assert.match(holed.reason, /no link #2/);
});
