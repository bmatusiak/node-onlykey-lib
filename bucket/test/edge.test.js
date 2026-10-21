'use strict';

/*
 * The Edge copy in the bucket (ok-edge stage 0c): a computer's copy of one device's chain, carried
 * by every front end. Two copies that went apart merge into one that still verifies; a fork is
 * reported and never repaired; the audit dump is the chain's blocks - public, checked with the
 * device's keys alone (Brad, 2026-10-21: "externally verified using pubkeys").
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { toHex } = require('../../src/bytes');
const chain = require('../../edge/src/chain');
const block = require('../../edge/src/block');
const copyfile = require('../../edge/src/copyfile');
const { OP, DECISION } = require('../../edge/src/codes');
const bucket = require('../src');

const sk = new Uint8Array(32).fill(5);
const pub = p256.getPublicKey(sk, false).subarray(1);
const id = chain.deviceIdOf(pub);
const K = require('../../edge/test/helpers/hybrid-key').edgeKey(sk);
const b32 = (n) => new Uint8Array(32).fill(n);
const ops = [OP.GRANT_CREATE, OP.SIGN, OP.RECEIPT, OP.GRANT_END, OP.GRANT_CREATE, OP.SIGN];
const links = ops.map((op, seq) => chain.encodeLink({ seq, op, decision: op === OP.SIGN ? DECISION.SELF_PRESS : DECISION.APPROVE, subject: b32(seq + 1), grantId: 3, version: 1 }));
const heads = chain.heads(links, chain.genesis(id));
const sealAt = (seq) => ({ seq, head: heads[seq], ...K.sign({ deviceId: id, seq, head: heads[seq] }) });
const rnd = (n) => new Uint8Array(crypto.randomBytes(n));

/* a copy holding links 0..upTo, sealed where asked */
function copyJSON(upTo, sealSeqs) {
  return copyfile.toJSON({
    ...copyfile.empty(id), publicKey: pub, publicKeyPq: K.publicKeyPq,
    links: links.slice(0, upTo + 1).map((l, i) => ({ link: l, head: heads[i] })),
    seals: sealSeqs.map(sealAt),
  });
}
const KEY = `copy-${toHex(id).slice(0, 16)}`;
const withCopy = (j) => {
  const b = bucket.create({ owner: 'k1' });
  bucket.kv(b, 'edge.copies').setItem(KEY, JSON.stringify(j));
  return b;
};
const rules = { 'edge.copies': bucket.rules.edgeCopies(copyfile) };

test('a copy reads back as the same JSON it was written as (the CLI\'s file and the bucket share it)', () => {
  /* the first read adds the empty notes a copy without any gets (as the CLI's load always did); from then on it is stable */
  const j = copyfile.toJSON(copyfile.fromJSON(copyJSON(5, [3, 5]), id));
  assert.deepEqual(j.notes, { reasons: {}, messages: {} });
  assert.deepEqual(copyfile.toJSON(copyfile.fromJSON(j, id)), j);
  assert.equal(copyfile.fromJSON({ v: 0 }, id).links.length, 0, 'an older version reads as no copy');
});

test('two copies that went apart merge: every link, every seal (only the newest keeps its ML-DSA-65 half), and the blocks still verify', () => {
  const phone = withCopy(copyJSON(3, [3]));
  const web = withCopy(copyJSON(5, [5]));
  const { bucket: m, report } = bucket.merge(phone, web, { rules });
  assert.equal(report.conflicts.length, 0);
  assert.equal(report.taken['edge.copies'], 2, 'links #4 and #5 came from the other copy');
  const merged = JSON.parse(bucket.kv(m, 'edge.copies').getItem(KEY));
  assert.equal(merged.links.length, 6);
  assert.deepEqual(merged.seals.map((s) => [s.seq, Boolean(s.signaturePq)]), [[3, false], [5, true]]);
  const [dump] = bucket.rules.edgeBlocks(m, copyfile, { net: 'live' });
  assert.equal(dump.blocks.length, 2);
  assert.ok(dump.blocks.every((x) => x.ok), dump.blocks.map((x) => x.reason).join('; '));
});

test('a fork - the copies disagree at a seq both hold - is reported, this copy kept, and it cannot be picked away', () => {
  const phone = withCopy(copyJSON(5, [5]));
  const forked = copyJSON(5, [5]);
  const other = chain.encodeLink({ seq: 4, op: OP.GRANT_CREATE, decision: DECISION.APPROVE, subject: b32(99), grantId: 4, version: 1 });
  forked.links[4] = { link: toHex(other), head: toHex(chain.weld(heads[3], other)) };
  const { bucket: m, report } = bucket.merge(phone, withCopy(forked), { rules });
  assert.equal(report.conflicts.length, 1);
  assert.match(report.conflicts[0].reason, /disagree at #4 - a fork/);
  assert.equal(JSON.parse(bucket.kv(m, 'edge.copies').getItem(KEY)).links[4].link, toHex(links[4]), 'this copy stays as it was');
  assert.throws(() => bucket.resolve(m, report.conflicts[0], 'from'), /never repaired/);

  const otherKey = { ...copyJSON(5, [5]), publicKey: toHex(new Uint8Array(64).fill(1)) };
  const r2 = bucket.merge(phone, withCopy(otherKey), { rules });
  assert.match(r2.report.conflicts[0].reason, /different keys/);
});

test('the audit dump from a sealed bucket: only the Edge blocks, and anyone with the device\'s public keys checks them', () => {
  const b = withCopy(copyJSON(5, [3, 5]));
  bucket.kv(b, 'passwords').setItem('onlyagent-vault/credentials/mail', '{"encrypted":"secret"}');
  const file = bucket.seal(b, new Uint8Array(32).fill(7), rnd);
  const { bucket: opened } = bucket.open(file, { key: new Uint8Array(32).fill(7) });
  const dump = bucket.rules.edgeBlocks(opened, copyfile, { net: 'live' });
  const text = JSON.stringify(dump.map((d) => d.blocks.map((x) => x.block)));
  assert.doesNotMatch(text, /secret|onlyagent-vault/, 'nothing but the chain leaves');
  /* an outside party: the blocks and the device's public keys, nothing from the bucket */
  const blocks = JSON.parse(text)[0];
  let prev = null;
  blocks.forEach((bl, i) => {
    const v = block.verifyBlock(bl, pub, K.publicKeyPq, prev, { anchor: i === blocks.length - 1 });
    assert.ok(v.ok, v.reason);
    prev = bl;
  });
});
