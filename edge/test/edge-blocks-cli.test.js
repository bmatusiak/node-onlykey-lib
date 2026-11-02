/*
 * `onlykey-js edge blocks` (BLOCKS.md, Brad 2026-10-07): this PC's copy cut
 * at the key's seals into JSON blocks. The seals are kept beside the copy (copy.keepSeals);
 * every block is checked against the key's public key kept at the last sync.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { toHex } = require('../../src/bytes');
const chain = require('../src/chain');
const block = require('../src/block');
const { OP, DECISION } = require('../src/codes');
const copy = require('../cli/copy');
const { main } = require('../../cli/index');

const sk = new Uint8Array(32).fill(5);
const pub = p256.getPublicKey(sk, false).subarray(1);
const id = chain.deviceIdOf(pub);
/* the hybrid checkpoint (2026-10-10): every seal carries the P-256 and the ML-DSA-65 signature */
const K = require('./helpers/hybrid-key').edgeKey(sk);
const pubPq = K.publicKeyPq;
const b32 = (n) => new Uint8Array(32).fill(n);

/* two budgets' worth of links, the second still open after its last link */
const links = [OP.GRANT_CREATE, OP.SIGN, OP.RECEIPT, OP.GRANT_END, OP.GRANT_CREATE, OP.SIGN].map((op, seq) =>
  chain.encodeLink({ seq, op, decision: op === OP.SIGN ? DECISION.SELF_PRESS : DECISION.APPROVE, subject: b32(seq + 1), grantId: 3, version: 1 }));
const heads = chain.heads(links, chain.genesis(id));
const sealAt = (seq) => ({ seq, head: heads[seq], ...K.sign({ deviceId: id, seq, head: heads[seq] }) });

function homeWithCopy() {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'okblocks-'));
  copy.store(home).setItem(toHex(id).slice(0, 16), JSON.stringify({ v: 1,
    deviceId: toHex(id), publicKey: toHex(pub), publicKeyPq: toHex(pubPq), lastSeen: null,
    links: links.map((l, i) => ({ link: toHex(l), head: toHex(heads[i]) })),
  }));
  return home;
}

async function run(argv) {
  const out = [];
  const err = [];
  const code = await main(argv, { out: (l) => out.push(l), err: (l) => err.push(l), start: () => { throw new Error('edge blocks opened a device'); } });
  return { code, out, err };
}

test('keepSeals merges by seq, and edge blocks lists the verified blocks without a phone', async () => {
  const home = homeWithCopy();
  try {
    copy.keepSeals(home, id, { seals: [sealAt(3)] });
    copy.keepSeals(home, id, { seals: [sealAt(3)] }); /* the same seal again: still one */
    assert.equal(copy.load(home, id).seals.length, 1);
    const r = await run(['edge', '--edge-home', home, 'blocks']);
    assert.equal(r.code, 0, r.err.join('\n'));
    const text = r.out.join('\n');
    assert.match(text, /1 block\(s\), 2 link\(s\) after the last seal/);
    assert.match(text, /#0-#3 .*verified/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('edge blocks --json prints blocks that verify on their own, against the key\'s public key', async () => {
  const home = homeWithCopy();
  try {
    copy.keepSeals(home, id, { seals: [sealAt(3), sealAt(5)] });
    const r = await run(['edge', '--edge-home', home, 'blocks', '--json']);
    assert.equal(r.code, 0, r.err.join('\n'));
    const blocks = JSON.parse(r.out.join('\n'));
    assert.equal(blocks.length, 2);
    /* one hybrid anchor ("B"): the newest block carries sigPq; the older seal dropped it when the newer came */
    assert.equal('sigPq' in blocks[0].checkpoint, false);
    assert.equal(typeof blocks[1].checkpoint.sigPq, 'string');
    assert.equal(copy.load(home, id).seals[0].signaturePq, undefined, 'the older seal is kept with its P-256 half only');
    assert.equal(block.verifyBlock(blocks[0], pub, pubPq, null, { anchor: false }).ok, true);
    assert.equal(block.verifyBlock(blocks[0], pub, pubPq).ok, false, 'an older block is no anchor');
    assert.equal(block.verifyBlock(blocks[1], pub, pubPq, blocks[0]).ok, true);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('a seal that is not the key\'s: edge blocks says the block does not verify, and exits 1', async () => {
  const home = homeWithCopy();
  try {
    const bad = sealAt(3);
    bad.signature = chain.signCheckpoint({ deviceId: id, seq: 3, head: heads[3] }, new Uint8Array(32).fill(6));
    copy.keepSeals(home, id, { seals: [bad] });
    const r = await run(['edge', '--edge-home', home, 'blocks']);
    assert.equal(r.code, 1);
    assert.match(r.out.join('\n'), /does not verify: signature/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});

test('a seal with only its P-256 half (no sigPq): kept, but its block does not verify', async () => {
  const home = homeWithCopy();
  try {
    const { signaturePq: _none, ...p256Only } = sealAt(3);
    copy.keepSeals(home, id, { seals: [p256Only] });
    const r = await run(['edge', '--edge-home', home, 'blocks']);
    assert.equal(r.code, 1);
    assert.match(r.out.join(' '), /does not verify: signature/);
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
