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

/* ---- a budget's genesis, signed at the press ---- */

const genesisFields = () => ({
  deviceId,
  grantId: V.grant.grantId,
  genesis: fromHex(V.grant.genesis),
  uses: V.grant.uses,
  scopes: V.grant.scopes,
  reasonHash: fromHex(V.grant.reasonHash),
  chainSeq: V.grant.chainSeq,
  chainHead: fromHex(V.grant.chainHead),
});

test('budget genesis: the signed digest matches the Python reading', () => {
  assert.equal(toHex(grants.budgetGenesisDigest(genesisFields())), V.grant.genesisDigest);
});

test('budget genesis: Node\'s own ECDSA and the lib agree in both directions', () => {
  const nodeCrypto = require('node:crypto');
  const { privateKey, publicKey } = nodeCrypto.generateKeyPairSync('ec', { namedCurve: 'P-256' });
  const jwk = publicKey.export({ format: 'jwk' });
  const raw = Uint8Array.from([...Buffer.from(jwk.x, 'base64url'), ...Buffer.from(jwk.y, 'base64url')]); // X||Y, as the key gives it
  /* Node signs the message (ECDSA-SHA256 hashes it itself): that is a signature over our digest */
  const nodeSig = nodeCrypto.sign('sha256', grants.budgetGenesisMessage(genesisFields()), { key: privateKey, dsaEncoding: 'ieee-p1363' });
  assert.deepEqual(grants.verifyBudgetGenesis(genesisFields(), new Uint8Array(nodeSig), raw), { ok: true });
  /* and Node accepts what the lib signs */
  const secret = Buffer.from(privateKey.export({ format: 'jwk' }).d, 'base64url');
  const libSig = grants.signBudgetGenesis(genesisFields(), new Uint8Array(secret));
  assert.ok(nodeCrypto.verify('sha256', grants.budgetGenesisMessage(genesisFields()), { key: publicKey, dsaEncoding: 'ieee-p1363' }, libSig));
});

test('budget genesis: changing any signed field, or another key, breaks the signature', () => {
  const secret = new Uint8Array(32).fill(7);
  const pub = require('../src/vendor/exports/@noble/curves/nist.js').p256.getPublicKey(secret, false);
  const sig = grants.signBudgetGenesis(genesisFields(), secret);
  assert.deepEqual(grants.verifyBudgetGenesis(genesisFields(), sig, pub), { ok: true });
  const edits = {
    genesis: (f) => { f.genesis = new Uint8Array(32).fill(1); },
    reason: (f) => { f.reasonHash = new Uint8Array(32); },
    'chain head (a budget moved to another place in the chain)': (f) => { f.chainHead = new Uint8Array(32).fill(2); },
    'another device': (f) => { f.deviceId = fromHex(V.otherDeviceId); },
    'a bigger cap': (f) => { f.scopes = [{ ...f.scopes[0], cap: f.uses + 1 }]; f.uses += 1; },
  };
  for (const [what, edit] of Object.entries(edits)) {
    const f = genesisFields();
    edit(f);
    assert.equal(grants.verifyBudgetGenesis(f, sig, pub).reason, 'bad-signature', what);
  }
  const otherPub = require('../src/vendor/exports/@noble/curves/nist.js').p256.getPublicKey(new Uint8Array(32).fill(8), false);
  assert.equal(grants.verifyBudgetGenesis(genesisFields(), sig, otherPub).reason, 'bad-signature');
  assert.equal(grants.verifyBudgetGenesis({ ...genesisFields(), uses: V.grant.uses + 1 }, sig, pub).reason, 'uses-mismatch');
});

/* ---- tickets ---- */

const T = V.ticket;

test('tickets: each use is ticketed, waiting, missing, alarm or owes none; the message is shown only when it matches', () => {
  const r = tickets.pairTickets(entries(), { [T.refSeq]: T.message });
  const by = Object.fromEntries(r.uses.map((u) => [u.seq, u]));
  assert.equal(by[1].status, 'missing');
  assert.equal(by[2].status, 'ticketed');
  assert.equal(by[2].ticket.name, 'OK');
  assert.equal(by[2].message, T.message);
  assert.equal(by[4].status, 'no-ticket-owed'); // denied decrypt
  assert.equal(by[5].status, 'waiting'); // the latest use: the key still takes its ticket
  assert.deepEqual(r.orphans, []);
});

test('tickets: a newer use - even a denied one - turns a waiting use into missing (R16: only the latest takes a ticket)', () => {
  const es = entries();
  const add = (fields) => { const l = chain.encodeLink({ seq: es.length, ...fields }); es.push({ link: l, head: chain.weld(es[es.length - 1].head, l) }); };
  add({ op: codes.OP.DECRYPT, decision: codes.DECISION.DENY, slot: 1, subject: new Uint8Array(32) });
  const by = Object.fromEntries(tickets.pairTickets(es).uses.map((u) => [u.seq, u.status]));
  assert.equal(by[5], 'missing');
  assert.equal(by[6], 'no-ticket-owed');
  add({ op: codes.OP.SIGN, decision: codes.DECISION.APPROVE, slot: 2, subject: new Uint8Array(32) });
  const after = Object.fromEntries(tickets.pairTickets(es).uses.map((u) => [u.seq, u.status]));
  assert.equal(after[7], 'waiting');
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
