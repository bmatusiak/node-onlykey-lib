'use strict';

/*
 * Edge chain library (src/edge/). The vectors in test/vectors/edge-v1.json
 * come from onlykey-edge/vectors/make_vectors.py - stdlib Python written from
 * the spec text, not from this code - so agreeing with them means two
 * independent readings of the spec produce the same bytes.
 */
const test = require('node:test');
const assert = require('node:assert');
const V = require('./vectors/edge-v1.json');
const { codes, chain, grants, tickets } = require('../src/edge');
const { fromHex, toHex } = require('../src/bytes');

const deviceId = fromHex(V.deviceId);
const entries = () => V.chain.map((e) => ({ link: fromHex(e.link), head: fromHex(e.head) }));
const lastSeq = V.chain.length - 1;
const keyHead = () => ({ seq: lastSeq, head: fromHex(V.chain[lastSeq].head) });

/* ---- vectors ---- */

test('vectors: genesis, every weld and the ticket subject match the Python reading', () => {
  assert.equal(toHex(chain.genesis(deviceId)), V.genesis);
  let h = chain.genesis(deviceId);
  for (const e of V.chain) {
    h = chain.weld(h, fromHex(e.link));
    assert.equal(toHex(h), e.head);
  }
  const t = V.ticket;
  assert.equal(toHex(tickets.messageHash(t.message)), t.msgHash);
  assert.equal(toHex(tickets.ticketSubject({ refSeq: t.refSeq, refHead: fromHex(t.refHead), code: t.code, msgHash: fromHex(t.msgHash) })), t.subject);
});

test('vectors: links decode to the fields Python packed, and re-encode byte for byte', () => {
  for (const e of V.chain) {
    const f = chain.decodeLink(fromHex(e.link));
    assert.equal(toHex(chain.encodeLink(f)), e.link);
    assert.ok(f.reservedZero);
  }
  const t = chain.decodeLink(fromHex(V.chain[3].link));
  assert.equal(t.op, codes.OP.TICKET);
  assert.equal(t.refSeq, 2);
  assert.equal(t.code, 0);
  const s = chain.decodeLink(fromHex(V.chain[2].link));
  assert.deepEqual([s.seq, s.op, s.decision, s.slot, s.grantId, s.grantStep], [2, codes.OP.SIGN, codes.DECISION.SELF_PRESS, 101, 7, 2]);
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

test('budget: one budget\'s chain is at most 255 uses (owner, 2026-10-02)', () => {
  assert.equal(grants.MAX_USES, 255);
  const seed = new Uint8Array(32).fill(1);
  assert.doesNotThrow(() => grants.grantGenesis(seed, 255));
  assert.throws(() => grants.grantGenesis(seed, 256), RangeError);
  assert.throws(() => grants.encodeScopes([{ op: 1, slot: 101, cap: 256 }]), RangeError);
  const g = grants.grantGenesis(seed, 255);
  assert.equal(grants.checkSelfPress({ genesis: g, uses: 256, step: 1, value: seed, mac: seed, subject: seed }).reason, 'past-cap');
});

test('budget: spends must run 1, 2, 3... - a replayed reveal and a skipped step are caught', () => {
  assert.deepEqual(grants.checkSpends(G(), V.grant.uses, [spend(0), spend(1)]), { ok: true, spent: 2 });
  assert.equal(grants.checkSpends(G(), V.grant.uses, [spend(0), spend(0)]).failure.reason, 'step-reused');
  assert.equal(grants.checkSpends(G(), V.grant.uses, [spend(1)]).failure.reason, 'step-skipped');
});

test('budget: a value past the last step cannot be made from a revealed one', () => {
  /* the next value is a preimage of the last revealed one: hashing forward only goes back toward G */
  const v1 = spend(0).value;
  assert.equal(grants.checkSelfPress({ genesis: G(), uses: V.grant.uses, step: 2, value: require('../src/vendor/exports/@noble/hashes/sha2.js').sha256(v1), mac: new Uint8Array(32), subject: new Uint8Array(32) }).reason, 'wrong-budget');
});

/* ---- the key's one signature: checkpoints, and a budget's opening through one ---- */

const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');

test('device id and checkpoint digest match the Python reading', () => {
  assert.equal(toHex(chain.deviceIdOf(fromHex(V.deviceFromPub.pub))), V.deviceFromPub.deviceId);
  const c = V.checkpoint;
  assert.equal(toHex(chain.checkpointDigest({ deviceId, seq: c.seq, head: fromHex(c.head) })), c.digest);
  assert.equal(toHex(grants.grantSubject({ scopes: V.grant.scopes, reasonHash: fromHex(V.grant.reasonHash), genesis: fromHex(V.grant.genesis), lifetime: V.grant.lifetime })), V.grant.subject);
  /* the lifetime is in the subject: another lifetime is another budget */
  assert.notEqual(toHex(grants.grantSubject({ scopes: V.grant.scopes, reasonHash: fromHex(V.grant.reasonHash), genesis: fromHex(V.grant.genesis), lifetime: 0 })), V.grant.subject);
});

test('ARM token (R13a) matches the Python reading, and binds both the head and the request', () => {
  const a = V.arm;
  assert.equal(toHex(grants.armToken({ head: fromHex(a.head), subject: fromHex(a.subject) })), a.token);
  assert.notEqual(toHex(grants.armToken({ head: fromHex(a.head), subject: new Uint8Array(32) })), a.token);
  assert.notEqual(toHex(grants.armToken({ head: new Uint8Array(32), subject: fromHex(a.subject) })), a.token);
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

/* ---- tickets ---- */

const T = V.ticket;

test('tickets: every approved use owes one - ticketed, waiting, alarm, or owes none; the message only when it matches', () => {
  const r = tickets.pairTickets(entries(), { [T.refSeq]: T.message });
  const by = Object.fromEntries(r.uses.map((u) => [u.seq, u]));
  /* R16 (Brad, 2026-10-02): pressed or self-pressed, every approved use owes; the key keeps the latest 4 */
  assert.equal(by[1].status, 'waiting');
  assert.equal(by[2].status, 'ticketed');
  assert.equal(by[2].ticket.name, 'OK');
  assert.equal(by[2].message, T.message);
  assert.equal(by[4].status, 'no-ticket-owed'); // denied decrypt
  assert.equal(by[5].status, 'waiting'); // a human press owes too
  assert.deepEqual(r.orphans, []);
});

/* add links to a chain of {link, head} entries */
function grow(es, fields) {
  const l = chain.encodeLink({ seq: es.length, ...fields });
  es.push({ link: l, head: chain.weld(es[es.length - 1].head, l) });
  return es.length - 1;
}
const pressedUse = (es) => grow(es, { op: codes.OP.SIGN, decision: codes.DECISION.APPROVE, slot: 2, flags: 1, subject: new Uint8Array(32).fill(es.length) });

test('tickets: a deny does not clear a debt; past the key\'s 4, the oldest can only be waived (missing)', () => {
  const es = entries();
  grow(es, { op: codes.OP.DECRYPT, decision: codes.DECISION.DENY, slot: 1, subject: new Uint8Array(32) });
  let by = Object.fromEntries(tickets.pairTickets(es).uses.map((u) => [u.seq, u.status]));
  assert.equal(by[5], 'waiting', 'a deny in between does not clear the debt');
  /* 1 and 5 owe; three more uses make 5 owed - the oldest (1) falls off the key's list */
  pressedUse(es); pressedUse(es); pressedUse(es);
  by = Object.fromEntries(tickets.pairTickets(es).uses.map((u) => [u.seq, u.status]));
  assert.equal(by[1], 'missing');
  assert.deepEqual([by[5], by[7], by[8], by[9]], ['waiting', 'waiting', 'waiting', 'waiting']);
});

/* the WAIVE link the key writes (firmware R18): 0x8F, the press flag, grant_id = oldest waived, subject over the list */
function waive(es, seqs, overflow) {
  return grow(es, {
    op: codes.OP.TICKET, decision: 0x8f, flags: codes.FLAG.PRESS_OBSERVED, grantId: seqs[0],
    subject: tickets.waiveSubject(seqs, overflow),
  });
}

test('tickets: the WAIVE subject matches the Python reading', () => {
  assert.equal(toHex(tickets.waiveSubject(V.waive.seqs, Boolean(V.waive.overflow))), V.waive.subject);
  assert.equal(toHex(tickets.waiveSubject([5, 6, 7, 8], true)), V.waive.overflowSubject);
});

test('tickets: a WAIVE clears every use it lists - and, with overflow, the older ones too', () => {
  const es = entries();
  const w = waive(es, [1, 5], false);
  let by = Object.fromEntries(tickets.pairTickets(es).uses.map((u) => [u.seq, u]));
  assert.deepEqual([by[1].status, by[1].waivedBy, by[5].status], ['waived', w, 'waived']);
  /* overflow: five owed, the key lists the latest 4; the oldest is covered as "waived, not listed" */
  const es2 = entries();
  pressedUse(es2); pressedUse(es2); pressedUse(es2);
  const w2 = waive(es2, [5, 6, 7, 8], true);
  by = Object.fromEntries(tickets.pairTickets(es2).uses.map((u) => [u.seq, u]));
  assert.equal(by[1].status, 'waived-unlisted');
  assert.deepEqual([5, 6, 7, 8].map((q) => by[q].status), ['waived', 'waived', 'waived', 'waived']);
  assert.equal(by[8].waivedBy, w2);
});

test('tickets: an agent\'s own 0x8F ticket is not a waive - it pays one use and is an alarm', () => {
  const es = entries();
  const ref = 5;
  const l = chain.encodeLink({
    seq: es.length, op: codes.OP.TICKET, decision: 0x8f, grantId: ref,
    subject: tickets.ticketSubject({ refSeq: ref, refHead: es[ref].head, code: 0x8f, msgHash: tickets.messageHash('look at this') }),
  });
  es.push({ link: l, head: chain.weld(es[es.length - 1].head, l) });
  const by = Object.fromEntries(tickets.pairTickets(es, { [ref]: 'look at this' }).uses.map((u) => [u.seq, u]));
  assert.equal(by[5].status, 'alarm');
  assert.equal(by[5].message, 'look at this');
  assert.equal(by[1].status, 'waiting', 'it paid only its own use');
});

test('tickets: a message that does not match its hash is never shown as text', () => {
  const r = tickets.pairTickets(entries(), { [T.refSeq]: T.message + ' (edited)' });
  const u = r.uses.find((x) => x.seq === 2);
  assert.equal(u.message, null);
  assert.equal(u.messageStatus, 'mismatch');
});

function withTicket(code, refSeq) {
  const es = entries().slice(0, 3);
  const refHead = es[refSeq].head;
  const l = chain.encodeLink({
    seq: 3, op: codes.OP.TICKET, decision: code, grantId: refSeq,
    subject: tickets.ticketSubject({ refSeq, refHead, code, msgHash: tickets.messageHash('m') }),
  });
  es.push({ link: l, head: chain.weld(es[2].head, l) });
  return es;
}

test('tickets: bit 7 and an unknown code are both alarms (fails closed)', () => {
  for (const code of [0x81, 0x42, 0x0f]) {
    const u = tickets.pairTickets(withTicket(code, 2), { 2: 'm' }).uses.find((x) => x.seq === 2);
    assert.equal(u.status, 'alarm', `code 0x${code.toString(16)}`);
  }
  assert.equal(codes.ticketCode(0x42).known, false);
});

test('tickets: a ticket for the wrong seq is an orphan, and the use it skipped is still waiting', () => {
  const r = tickets.pairTickets(withTicket(0x00, 0)); // seq 0 is the grant-create, not a use
  assert.deepEqual(r.orphans, [{ seq: 3, refSeq: 0, reason: 'not-a-use' }]);
  assert.equal(r.uses.find((x) => x.seq === 2).status, 'waiting');
});

/* ---- Hermes ---- */

test('Hermes: the whole library runs with Buffer, TextEncoder/Decoder and crypto removed', () => {
  const saved = { Buffer: globalThis.Buffer, TextEncoder: globalThis.TextEncoder, TextDecoder: globalThis.TextDecoder, crypto: globalThis.crypto };
  for (const k of Object.keys(saved)) Object.defineProperty(globalThis, k, { value: undefined, configurable: true, writable: true });
  try {
    const r = chain.verify(entries(), { deviceId, expectHead: keyHead() });
    assert.equal(r.ok, true);
    const p = tickets.pairTickets(entries(), { [T.refSeq]: T.message });
    assert.equal(p.uses.find((x) => x.seq === 2).message, T.message);
    assert.deepEqual(grants.checkSpends(G(), V.grant.uses, [spend(0), spend(1)]), { ok: true, spent: 2 });
  } finally {
    for (const [k, v] of Object.entries(saved)) Object.defineProperty(globalThis, k, { value: v, configurable: true, writable: true });
  }
});

test('tickets: the key\'s list does not refill - 5 owed, one ticket: 3 waiting + 1 missing, as HEAD says 3 + overflow', () => {
  const es = entries();
  pressedUse(es); pressedUse(es); pressedUse(es); /* owed: 1, 5, 6, 7, 8 -> 1 fell off */
  let d = tickets.keyDebts(es);
  assert.deepEqual([d.owed, d.overflow, d.dropped], [[5, 6, 7, 8], true, [1]]);
  /* a ticket for 8 (refHead = head[8]) */
  grow(es, { op: codes.OP.TICKET, decision: 0x00, grantId: 8, subject: tickets.ticketSubject({ refSeq: 8, refHead: es[8].head, code: 0, msgHash: tickets.messageHash('x') }) });
  d = tickets.keyDebts(es);
  assert.deepEqual([d.owed, d.overflow], [[5, 6, 7], true]);
  const by = Object.fromEntries(tickets.pairTickets(es).uses.map((u) => [u.seq, u.status]));
  assert.deepEqual([by[1], by[5], by[6], by[7], by[8]], ['missing', 'waiting', 'waiting', 'waiting', 'ticketed']);
  /* the waive over exactly this list and overflow clears both */
  grow(es, { op: codes.OP.TICKET, decision: 0x8f, flags: codes.FLAG.PRESS_OBSERVED, grantId: 5, subject: tickets.waiveSubject([5, 6, 7], true) });
  d = tickets.keyDebts(es);
  assert.deepEqual([d.owed, d.overflow], [[], false]);
});
