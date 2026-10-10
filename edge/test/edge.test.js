'use strict';

/*
 * Edge chain library (edge/src/). The vectors in edge/test/vectors/edge-v1.json
 * come from onlykey-edge/edge/vectors/make_vectors.py - stdlib Python written from
 * the spec text, not from this code - so agreeing with them means two
 * independent readings of the spec produce the same bytes.
 */
const test = require('node:test');
const assert = require('node:assert');
const V = require('./vectors/edge-v1.json');
const { codes, chain, grants, receipts } = require('../src');
const { fromHex, toHex } = require('../../src/bytes');

const deviceId = fromHex(V.deviceId);
const entries = () => V.chain.map((e) => ({ link: fromHex(e.link), head: fromHex(e.head) }));
const lastSeq = V.chain.length - 1;
const keyHead = () => ({ seq: lastSeq, head: fromHex(V.chain[lastSeq].head) });

/* ---- vectors ---- */

test('vectors: genesis, every weld and the receipt subject match the Python reading', () => {
  assert.equal(toHex(chain.genesis(deviceId)), V.genesis);
  let h = chain.genesis(deviceId);
  for (const e of V.chain) {
    h = chain.weld(h, fromHex(e.link));
    assert.equal(toHex(h), e.head);
  }
  const t = V.receipt;
  assert.equal(toHex(receipts.messageHash(t.message)), t.msgHash);
  assert.equal(toHex(receipts.receiptSubject({ refSeq: t.refSeq, refHead: fromHex(t.refHead), code: t.code, msgHash: fromHex(t.msgHash) })), t.subject);
});

test('vectors: links decode to the fields Python packed, and re-encode byte for byte', () => {
  for (const e of V.chain) {
    const f = chain.decodeLink(fromHex(e.link));
    assert.equal(toHex(chain.encodeLink(f)), e.link);
    assert.ok(f.reservedZero);
  }
  const t = chain.decodeLink(fromHex(V.chain[4].link));
  assert.equal(t.op, codes.OP.RECEIPT);
  assert.equal(t.refSeq, 3);
  assert.equal(t.code, 0);
  const s = chain.decodeLink(fromHex(V.chain[3].link));
  assert.deepEqual([s.seq, s.op, s.decision, s.slot, s.grantId, s.grantStep], [3, codes.OP.SIGN, codes.DECISION.SELF_PRESS, 101, 7, 2]);
});

test('vectors: the budget genesis and every reveal + MAC check out', () => {
  const g = V.grant;
  assert.equal(toHex(grants.grantGenesis(fromHex(g.seed), g.uses)), g.genesis);
  for (const s of g.spends) {
    assert.equal(toHex(grants.reveal(fromHex(g.seed), g.uses, s.step)), s.value);
    const r = grants.checkSelfPress({ genesis: fromHex(g.genesis), uses: g.uses, step: s.step, value: fromHex(s.value), mac: fromHex(s.mac), subject: fromHex(s.subject) });
    assert.deepEqual(r, { ok: true });
  }
});

/* ---- verify: the good chain, then each tamper with its own reason ---- */

test('verify: the untouched chain is verified through the key\'s head', () => {
  const r = chain.verify(entries(), { deviceId, expectHead: keyHead() });
  assert.deepEqual(r, { ok: true, verifiedThrough: lastSeq, gaps: [] });
});

test('verify: links without stored heads still verify forward from genesis', () => {
  const r = chain.verify(entries().map((e) => e.link), { deviceId, expectHead: keyHead() });
  assert.deepEqual(r, { ok: true, verifiedThrough: lastSeq, gaps: [] });
});

test('tamper: a flipped byte breaks the weld at that link (hash-mismatch)', () => {
  const es = entries();
  es[2].link[20] ^= 1;
  const r = chain.verify(es, { deviceId, expectHead: keyHead() });
  assert.deepEqual(r.failure, { seq: 2, reason: 'hash-mismatch' });
  assert.equal(r.verifiedThrough, 1);
  assert.deepEqual(r.gaps, [{ from: 2, to: lastSeq }]); // everything past it is unverifiable
});

test('tamper: a flip with every later head recomputed no longer reaches the key (head-mismatch)', () => {
  const es = entries();
  es[2].link[20] ^= 1;
  chain.heads(es.slice(2).map((e) => e.link), es[1].head).forEach((h, i) => { es[2 + i].head = h; });
  const r = chain.verify(es, { deviceId, expectHead: keyHead() });
  assert.deepEqual(r.failure, { seq: lastSeq, reason: 'head-mismatch' });
});

test('tamper: a deleted link the key still holds is removal, not a gap (seq-gap)', () => {
  const es = entries();
  es.splice(3, 1);
  const r = chain.verify(es, { deviceId, expectHead: keyHead(), ringFrom: 0 });
  assert.deepEqual(r.failure, { seq: 3, reason: 'seq-gap' });
});

test('tamper: two links swapped in the mirror (seq-reorder)', () => {
  const es = entries();
  [es[2], es[3]] = [es[3], es[2]];
  assert.deepEqual(chain.verify(es, { deviceId, expectHead: keyHead() }).failure, { seq: 2, reason: 'seq-reorder' });
});

test('tamper: a replayed (duplicated) link (seq-reorder)', () => {
  const es = entries();
  es.splice(3, 0, es[2]);
  assert.deepEqual(chain.verify(es, { deviceId, expectHead: keyHead() }).failure, { seq: 2, reason: 'seq-reorder' });
});

test('tamper: the mirror truncated at the end, while the key still holds the tail (seq-gap)', () => {
  const r = chain.verify(entries().slice(0, 4), { deviceId, expectHead: keyHead(), ringFrom: 0 });
  assert.deepEqual(r.failure, { seq: 4, reason: 'seq-gap' });
});

test('tamper: an old ring replayed into the key - its head went back (rollback)', () => {
  const old = { seq: 3, head: fromHex(V.chain[3].head) };
  const r = chain.verify(entries().slice(0, 4), { deviceId, expectHead: old, lastSeen: keyHead() });
  assert.deepEqual(r.failure, { seq: 3, reason: 'rollback' });
  /* and a key whose history forked from what this host saw at the same seq */
  const forged = { seq: 3, head: new Uint8Array(32).fill(1) };
  const f = chain.verify(entries(), { deviceId, expectHead: keyHead(), lastSeen: forged });
  assert.deepEqual(f.failure, { seq: 3, reason: 'rollback' });
});

test('tamper: another key\'s links spliced in (hash-mismatch); another key\'s mirror (device-mismatch)', () => {
  /* a link with this chain's seq but made by another key, with its own heads */
  const other = fromHex(V.otherDeviceId);
  const es = entries();
  const alien = chain.encodeLink({ ...chain.decodeLink(es[2].link), subject: new Uint8Array(32).fill(9) });
  es[2] = { link: alien, head: chain.weld(chain.genesis(other), alien) };
  assert.deepEqual(chain.verify(es, { deviceId, expectHead: keyHead() }).failure, { seq: 2, reason: 'hash-mismatch' });
  const m = chain.verify(entries(), { deviceId, mirrorDeviceId: other, expectHead: keyHead() });
  assert.deepEqual(m.failure, { seq: 0, reason: 'device-mismatch' });
});

test('tamper: every failure reason the spec lists is produced by some case above', () => {
  assert.deepEqual([...chain.REASONS].sort(), ['device-mismatch', 'hash-mismatch', 'head-mismatch', 'rollback', 'seq-gap', 'seq-reorder']);
});

/* ---- gaps: missing past the ring is unverifiable, not tampered ---- */

test('gap: links gone from the key\'s ring are a gap; the stored heads verify the rest back from the key\'s head', () => {
  const es = entries();
  es.splice(1, 2); // 1 and 2 never mirrored and no longer on the key
  const r = chain.verify(es, { deviceId, expectHead: keyHead(), ringFrom: 3 });
  assert.equal(r.ok, true);
  assert.equal(r.verifiedThrough, 0);
  /* 3 itself cannot be checked: the head before it (after 2) is unknown */
  assert.deepEqual(r.gaps, [{ from: 1, to: 3 }]);
});

test('gap: a verified checkpoint resumes verification after the gap (spec B2)', () => {
  const es = entries().map((e) => ({ link: e.link })); // no stored heads at all
  es.splice(1, 2);
  const anchors = [{ seq: 2, head: fromHex(V.chain[2].head) }];
  const r = chain.verify(es, { deviceId, expectHead: keyHead(), anchors });
  assert.deepEqual(r, { ok: true, verifiedThrough: 0, gaps: [{ from: 1, to: 2 }] });
});

test('gap: with no head from the key, links past the mirror are simply not claimed', () => {
  const r = chain.verify(entries().slice(0, 3), { deviceId });
  assert.deepEqual(r, { ok: true, verifiedThrough: 2, gaps: [] });
});

/* ---- budgets ---- */

const G = () => fromHex(V.grant.genesis);
const spend = (i) => {
  const s = V.grant.spends[i];
  return { step: s.step, value: fromHex(s.value), mac: fromHex(s.mac), subject: fromHex(s.subject) };
};

test('budget: wrong budget, wrong step, wrong subject and past the cap each fail on their own', () => {
  const g = { genesis: G(), uses: V.grant.uses };
  assert.equal(grants.checkSelfPress({ ...g, ...spend(0), genesis: new Uint8Array(32).fill(3) }).reason, 'wrong-budget');
  const wrongStep = grants.checkSelfPress({ ...g, ...spend(0), step: 2 });
  assert.equal(wrongStep.reason, 'wrong-step');
  assert.equal(wrongStep.actualStep, 1);
  assert.equal(grants.checkSelfPress({ ...g, ...spend(0), subject: new Uint8Array(32) }).reason, 'mac-mismatch');
  assert.equal(grants.checkSelfPress({ ...g, ...spend(0), step: V.grant.uses + 1 }).reason, 'past-cap');
});

test('budget: one budget\'s chain is at most 1024 uses - 1024 accepted, 1025 refused (R11, Brad 2026-10-02)', () => {
  assert.equal(grants.MAX_USES, 1024);
  const seed = new Uint8Array(32).fill(1);
  assert.doesNotThrow(() => grants.grantGenesis(seed, 1024));
  assert.throws(() => grants.grantGenesis(seed, 1025), RangeError);
  assert.doesNotThrow(() => grants.encodeScopes([{ op: 1, slot: 101, cap: 1024 }]));
  assert.throws(() => grants.encodeScopes([{ op: 1, slot: 101, cap: 1025 }]), RangeError);
  const g = grants.grantGenesis(seed, 1024);
  /* the first reveal of a 1024-use budget hashes back to G in 1 step; the last in 1024 */
  assert.equal(grants.checkSelfPress({ genesis: g, uses: 1024, step: 1024, value: grants.reveal(seed, 1024, 1024), mac: grants.reveal(seed, 1024, 1024), subject: seed }).reason, 'mac-mismatch', 'step 1024 is a real step');
  assert.equal(grants.checkSelfPress({ genesis: g, uses: 1025, step: 1, value: seed, mac: seed, subject: seed }).reason, 'past-cap');
});

test('budget: spends must run 1, 2, 3... - a replayed reveal and a skipped step are caught', () => {
  assert.deepEqual(grants.checkSpends(G(), V.grant.uses, [spend(0), spend(1)]), { ok: true, spent: 2 });
  assert.equal(grants.checkSpends(G(), V.grant.uses, [spend(0), spend(0)]).failure.reason, 'step-reused');
  assert.equal(grants.checkSpends(G(), V.grant.uses, [spend(1)]).failure.reason, 'step-skipped');
});

test('budget: a value past the last step cannot be made from a revealed one', () => {
  /* the next value is a preimage of the last revealed one: hashing forward only goes back toward G */
  const v1 = spend(0).value;
  assert.equal(grants.checkSelfPress({ genesis: G(), uses: V.grant.uses, step: 2, value: require('../../src/vendor/exports/@noble/hashes/sha2.js').sha256(v1), mac: new Uint8Array(32), subject: new Uint8Array(32) }).reason, 'wrong-budget');
});

/* ---- the key's one signature: checkpoints, and a budget's opening through one ---- */

const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');

test('device id and checkpoint digest match the Python reading', () => {
  assert.equal(toHex(chain.deviceIdOf(fromHex(V.deviceFromPub.pub))), V.deviceFromPub.deviceId);
  const c = V.checkpoint;
  assert.equal(toHex(chain.checkpointDigest({ deviceId, seq: c.seq, head: fromHex(c.head) })), c.digest);
  assert.equal(toHex(grants.grantSubject({ scopes: V.grant.scopes, reasonHash: fromHex(V.grant.reasonHash), genesis: fromHex(V.grant.genesis), lifetime: V.grant.lifetime })), V.grant.subject);
  /* the lifetime is in the subject: another lifetime is another budget */
  assert.notEqual(toHex(grants.grantSubject({ scopes: V.grant.scopes, reasonHash: fromHex(V.grant.reasonHash), genesis: fromHex(V.grant.genesis), lifetime: 0 })), V.grant.subject);
});

test('TX start token (R13a) matches the Python reading, and binds both the head and the request', () => {
  const a = V.tx;
  /* with an intent: the 16 bytes intentOf() makes are in the token; none = 16 zero bytes, a different token */
  assert.equal(toHex(grants.intentOf(a.intentText)), a.intent);
  assert.equal(toHex(grants.txToken({ head: fromHex(a.head), subject: fromHex(a.subject), intent: fromHex(a.intent) })), a.tokenWithIntent);
  assert.equal(toHex(grants.txToken({ head: fromHex(a.head), subject: fromHex(a.subject), intent: new Uint8Array(16) })), a.token);
  assert.equal(toHex(grants.txToken({ head: fromHex(a.head), subject: fromHex(a.subject) })), a.token);
  assert.notEqual(toHex(grants.txToken({ head: fromHex(a.head), subject: new Uint8Array(32) })), a.token);
  assert.notEqual(toHex(grants.txToken({ head: new Uint8Array(32), subject: fromHex(a.subject) })), a.token);
  /* the vector's subject is the request subject of its bytes */
  assert.equal(toHex(grants.requestSubject(new TextEncoder().encode('the bytes the agent submits'))), a.subject);
});

test('checkpoint: Node\'s own ECDSA and the lib agree in both directions', () => {
  const nodeCrypto = require('node:crypto');
  const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = Uint8Array.from([...Buffer.from(jwk.x, 'base64url'), ...Buffer.from(jwk.y, 'base64url')]); // X||Y, as the key gives it
  const fields = { deviceId, seq: V.checkpoint.seq, head: fromHex(V.checkpoint.head) };
  /* Node signs the message (ECDSA-SHA256 hashes it itself): a signature over our digest */
  const nodeSig = nodeCrypto.sign('sha256', chain.checkpointMessage(fields), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  assert.ok(chain.verifyCheckpoint(fields, new Uint8Array(nodeSig), raw));
  const libSig = chain.signCheckpoint(fields, new Uint8Array(Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url')));
  assert.ok(nodeCrypto.verify('sha256', chain.checkpointMessage(fields), { key: publicKey, dsaEncoding: 'ieee-p1363' }, libSig));
  /* over THIS head only */
  assert.equal(chain.verifyCheckpoint({ ...fields, head: new Uint8Array(32).fill(1) }, new Uint8Array(nodeSig), raw), false);
});

/* what the key does at a press: link grant-create (subject commits to G), checkpoint over it */
function openBudget(secret, { prevSeq = 4, prevHead = fromHex(V.chain[4].head) } = {}) {
  const g = V.grant;
  const scopes = g.scopes;
  const reasonHash = fromHex(g.reasonHash);
  const genesis = fromHex(g.genesis);
  const seq = prevSeq + 1;
  const link = chain.encodeLink({
    seq, op: codes.OP.GRANT_CREATE, decision: codes.DECISION.APPROVE, flags: codes.FLAG.PRESS_OBSERVED,
    subject: grants.grantSubject({ scopes, reasonHash, genesis }), grantId: seq + 1,
  });
  const head = chain.weld(prevHead, link);
  const signature = chain.signCheckpoint({ deviceId, seq, head }, secret);
  return { deviceId, publicKey: p256.getPublicKey(secret, false).slice(1), link, prevHead, head, signature, scopes, reasonHash, genesis, uses: g.uses };
}

test('budget opening: a press-answered checkpoint over the grant-create link proves G on its own', () => {
  const proof = openBudget(new Uint8Array(32).fill(7));
  const r = grants.verifyBudgetOpening(proof);
  assert.deepEqual(r, { ok: true, grantId: 6, seq: 5 });
});

test('budget opening: every forged part fails with its own reason', () => {
  const secret = new Uint8Array(32).fill(7);
  const good = openBudget(secret);
  const cases = {
    'uses-mismatch': { ...good, uses: good.uses + 1 },
    'not-a-grant-create': { ...good, link: (() => { const l = Uint8Array.from(good.link); l[4] = codes.OP.SIGN; return l; })() },
    'subject-mismatch': { ...good, genesis: new Uint8Array(32).fill(3) },
    'weld-mismatch': { ...good, prevHead: new Uint8Array(32).fill(4) },
    'bad-signature': { ...good, publicKey: p256.getPublicKey(new Uint8Array(32).fill(8), false).slice(1) },
  };
  for (const [reason, proof] of Object.entries(cases)) {
    assert.equal(grants.verifyBudgetOpening(proof).reason, reason, reason);
  }
  /* another device's checkpoint over the same bytes */
  assert.equal(grants.verifyBudgetOpening({ ...good, deviceId: fromHex(V.otherDeviceId) }).reason, 'bad-signature');
});

/* ---- receipts ---- */

const T = V.receipt;

test('receipts: every budget use owes one - receipted, or waiting while the key owes it; the message only when it matches', () => {
  const r = receipts.pairReceipts(entries(), { [T.refSeq]: T.message });
  const by = Object.fromEntries(r.uses.map((u) => [u.seq, u]));
  assert.equal(by[1].status, 'receipted');
  assert.equal(by[3].status, 'receipted');
  assert.equal(by[3].receipt.name, 'OK');
  assert.equal(by[3].message, T.message);
  assert.equal(by[5].status, 'waiting', 'the key still owes #5');
  assert.deepEqual(r.orphans, []);
});

/* add links to a chain of {link, head} entries */
function grow(es, fields) {
  const l = chain.encodeLink({ seq: es.length, ...fields });
  es.push({ link: l, head: chain.weld(es[es.length - 1].head, l) });
  return es.length - 1;
}

/*
 * ONE OWED USE (Brad, 2026-10-10: "Drop the owed list = yes"): nothing starts while a receipt is
 * owed, so the key keeps one owed use, or none. A receipt for it pays it; a settle clears it.
 */
test('receipts: the key owes one use at a time - its receipt pays it, and then nothing is owed', () => {
  const es = entries();
  assert.deepEqual(receipts.keyDebts(es).owed, [5]);
  grow(es, { op: codes.OP.RECEIPT, decision: 0x00, grantId: 5, subject: receipts.receiptSubject({ refSeq: 5, refHead: es[5].head, code: 0, msgHash: receipts.messageHash('tagged') }) });
  assert.deepEqual(receipts.keyDebts(es).owed, []);
  assert.equal(receipts.pairReceipts(es).uses.find((u) => u.seq === 5).status, 'receipted');
});

/* the SETTLE link the key writes (SPEC.md R18): 0x8F, the press flag, grant_id = the settled seq, subject over it */
function settle(es, seq) {
  return grow(es, { op: codes.OP.RECEIPT, decision: 0x8f, flags: codes.FLAG.PRESS_OBSERVED, grantId: seq, subject: receipts.settleSubject(seq) });
}

test('receipts: the SETTLE subject matches the Python reading', () => {
  assert.equal(toHex(receipts.settleSubject(V.settle.seq)), V.settle.subject);
});

test('receipts: a SETTLE clears the owed use', () => {
  const es = entries();
  const w = settle(es, 5);
  const u = receipts.pairReceipts(es).uses.find((x) => x.seq === 5);
  assert.deepEqual([u.status, u.settledBy], ['settled', w]);
  assert.deepEqual(receipts.keyDebts(es).owed, []);
});

test('receipts: an agent\'s own 0x8F receipt is not a settle - it pays its use and is an alarm', () => {
  const es = entries();
  const ref = 5;
  grow(es, { op: codes.OP.RECEIPT, decision: 0x8f, grantId: ref, subject: receipts.receiptSubject({ refSeq: ref, refHead: es[ref].head, code: 0x8f, msgHash: receipts.messageHash('look at this') }) });
  const u = receipts.pairReceipts(es, { [ref]: 'look at this' }).uses.find((x) => x.seq === ref);
  assert.deepEqual([u.status, u.message, u.settledBy], ['alarm', 'look at this', null]);
});

test('receipts: a message that does not match its hash is never shown as text', () => {
  const r = receipts.pairReceipts(entries(), { [T.refSeq]: T.message + ' (edited)' });
  const u = r.uses.find((x) => x.seq === 3);
  assert.equal(u.message, null);
  assert.equal(u.messageStatus, 'mismatch');
});

/* the opening and use #1, then a receipt (seq 2) with this code for refSeq */
function withReceipt(code, refSeq) {
  const es = entries().slice(0, 2);
  const refHead = es[refSeq].head;
  const l = chain.encodeLink({
    seq: 2, op: codes.OP.RECEIPT, decision: code, grantId: refSeq,
    subject: receipts.receiptSubject({ refSeq, refHead, code, msgHash: receipts.messageHash('m') }),
  });
  es.push({ link: l, head: chain.weld(es[1].head, l) });
  return es;
}

test('receipts: bit 7 and an unknown code are both alarms (fails closed)', () => {
  for (const code of [0x81, 0x42, 0x0f]) {
    const u = receipts.pairReceipts(withReceipt(code, 1), { 1: 'm' }).uses.find((x) => x.seq === 1);
    assert.equal(u.status, 'alarm', `code 0x${code.toString(16)}`);
  }
  assert.equal(codes.receiptCode(0x42).known, false);
});

test('receipts: a receipt for the wrong seq is an orphan, and the use it skipped is still waiting', () => {
  const r = receipts.pairReceipts(withReceipt(0x00, 0)); // seq 0 is the grant-create, not a use
  assert.deepEqual(r.orphans, [{ seq: 2, refSeq: 0, reason: 'not-a-use' }]);
  assert.equal(r.uses.find((x) => x.seq === 1).status, 'waiting');
});

/* ---- Hermes ---- */

test('Hermes: the whole library runs with Buffer, TextEncoder/Decoder and crypto removed', () => {
  const saved = { Buffer: globalThis.Buffer, TextEncoder: globalThis.TextEncoder, TextDecoder: globalThis.TextDecoder, crypto: globalThis.crypto };
  for (const k of Object.keys(saved)) Object.defineProperty(globalThis, k, { value: undefined, configurable: true, writable: true });
  try {
    const r = chain.verify(entries(), { deviceId, expectHead: keyHead() });
    assert.equal(r.ok, true);
    const p = receipts.pairReceipts(entries(), { [T.refSeq]: T.message });
    assert.equal(p.uses.find((x) => x.seq === 3).message, T.message);
    assert.deepEqual(grants.checkSpends(G(), V.grant.uses, [spend(0), spend(1)]), { ok: true, spent: 2 });
  } finally {
    for (const [k, v] of Object.entries(saved)) Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
  }
});

/* R11a: an identity NAME becomes the derive label exactly as the agents hash it, and the grant subject commits to it */
test('grants: R11a - identityLabel is the agent\'s identity hash; the grant subject ends with derived scopes\' labels', () => {
  const { identityHash } = require('../../src/protocol/agent');
  const hex = (b) => Buffer.from(b).toString('hex');
  assert.equal(hex(grants.identityLabel('ssh://agent@nitro16')), hex(identityHash({ ssh: { user: 'agent', host: 'nitro16' } })));
  assert.equal(hex(grants.identityLabel('ssh://nitro16')), hex(identityHash({ ssh: { host: 'nitro16' } })));
  assert.equal(hex(grants.identityLabel('gpg://Agent <a@x>')), hex(identityHash({ gpg: 'Agent <a@x>' })));
  assert.throws(() => grants.identityLabel('agent@nitro16'), /ssh:\/\/user@host/);
  assert.equal(grants.isDerivedCode(201), true);
  assert.equal(grants.isDerivedCode(223), true);
  assert.equal(grants.isDerivedCode(102), false);
  const base = { reasonHash: new Uint8Array(32).fill(1), genesis: new Uint8Array(32).fill(2), lifetime: 0 };
  const agent = grants.grantSubject({ ...base, scopes: [{ op: 1, slot: 222, cap: 2, identity: 'ssh://agent@nitro16' }] });
  const brad = grants.grantSubject({ ...base, scopes: [{ op: 1, slot: 222, cap: 2, identity: 'ssh://bmatusiak@localhost' }] });
  assert.notEqual(hex(agent), hex(brad), 'the identity is in the subject');
  assert.throws(() => grants.grantSubject({ ...base, scopes: [{ op: 1, slot: 222, cap: 2 }] }), /must name its identity/);
  /* a stored slot: the subject is what it was before R11a */
  const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
  const stored = grants.grantSubject({ ...base, scopes: [{ op: 1, slot: 102, cap: 2 }] });
  const enc = grants.encodeScopes([{ op: 1, slot: 102, cap: 2 }]);
  const pre = sha256(Uint8Array.from([...Buffer.from('OKEDGE-GRANT-v1'), ...enc, ...base.reasonHash, ...base.genesis, 0, 0]));
  assert.equal(hex(stored), hex(pre));
});

/* a receipt's message check is kept with its link (ok-rn A13: pairing ~110 ms a sync) - never past a changed message */
test('receipts: the message check is kept per receipt link, and a changed message is checked again', () => {
  const provider = require('../../src/crypto/provider');
  let hashes = 0;
  provider.setCryptoProvider({ sha256: (b) => { hashes++; return provider.js.sha256(b); } }, 'counting');
  try {
    const es = entries();
    const first = receipts.pairReceipts(es, { [T.refSeq]: T.message });
    const firstHashes = hashes;
    assert.equal(first.uses.find((u) => u.seq === T.refSeq).messageStatus, 'match');
    hashes = 0;
    const again = receipts.pairReceipts(es, { [T.refSeq]: T.message });
    assert.equal(again.uses.find((u) => u.seq === T.refSeq).messageStatus, 'match');
    assert.ok(hashes < firstHashes, `kept: ${hashes} hashes, first time ${firstHashes}`);
    const changed = receipts.pairReceipts(es, { [T.refSeq]: T.message + ' (edited)' });
    assert.equal(changed.uses.find((u) => u.seq === T.refSeq).messageStatus, 'mismatch');
  } finally {
    provider.setCryptoProvider(null);
  }
});
