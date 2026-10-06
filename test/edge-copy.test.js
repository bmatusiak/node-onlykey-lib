'use strict';
/*
 * edge copy check (firmware.md R27): a host may ask for a budget or a resume
 * only when its own copy verifies up to the key's live HEAD. The chain here is
 * built the way the firmware builds it (the same link format, welds, budget
 * opening, reveals, tickets), so each failure below is one a real copy can
 * have.
 */
const test = require('node:test');
const assert = require('node:assert');
const { chain, codes, grants, tickets, copy } = require('../src/edge');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');

const SECRET = new Uint8Array(32).fill(5);
const PUB = p256.getPublicKey(SECRET, false).slice(1);
const DEVICE = chain.deviceIdOf(PUB);
const { OP, DECISION, FLAG } = codes;

/*
 * A key's story: a pressed use and its ticket, a budget of 2 opened at a press,
 * two self-presses each with its reveal and ticket. -> {links, openings, key}
 */
/* R3: scopes = the budget's, spendScopes = byte 46 on each spend (default: an older chain, all 0) */
function story({ scopes: given = null, spendScopes = [], openingScope = null } = {}) {
  const links = [];
  let head = chain.genesis(DEVICE);
  const add = (fields, reveal = null) => {
    const link = chain.encodeLink({ seq: links.length, ...fields });
    head = chain.weld(head, link);
    links.push({ link, head, reveal });
    return links.length - 1;
  };
  const ticketFor = (ref) => add({
    op: OP.TICKET, decision: 0x00, grantId: ref,
    subject: tickets.ticketSubject({ refSeq: ref, refHead: links[ref].head, code: 0, msgHash: tickets.messageHash(`did ${ref}`) }),
  });

  ticketFor(add({ op: OP.SIGN, decision: DECISION.APPROVE, slot: 2, flags: FLAG.PRESS_OBSERVED, subject: new Uint8Array(32).fill(1) }));

  const seed = new Uint8Array(32).fill(9);
  const uses = 2;
  const scopes = given || [{ op: OP.SIGN, slot: 222, cap: 2, identity: 'ssh://agent@edge-test' }]; /* R11a: a derived code names its identity */
  const reasonHash = new Uint8Array(32).fill(7);
  const genesis = grants.grantGenesis(seed, uses);
  const grantId = links.length + 1;
  /* R3: the opening's byte 46 = its scope count when its spends are scoped (a new budget), else 0 */
  const opening = openingScope !== null ? openingScope : spendScopes.some((x) => x) ? scopes.length : 0;
  const at = add({ op: OP.GRANT_CREATE, decision: DECISION.APPROVE, flags: FLAG.PRESS_OBSERVED, grantId, scope: opening, subject: grants.grantSubject({ scopes, reasonHash, genesis }) });
  const signature = chain.signCheckpoint({ deviceId: DEVICE, seq: at, head }, SECRET);
  const openings = { [grantId]: { scopes, reasonHash, genesis, uses, signature } };

  for (let step = 1; step <= uses; step++) {
    const use = add({ op: OP.SIGN, decision: DECISION.SELF_PRESS, slot: 222, flags: FLAG.BUDGET_SPENT, subject: new Uint8Array(32).fill(20 + step), grantId, grantStep: step, scope: spendScopes[step - 1] || 0 },
      grants.reveal(seed, uses, step));
    ticketFor(use);
  }
  const seq = links.length - 1;
  const key = {
    publicKey: PUB,
    head: { seq, head, owed: 0, overflow: false, restoring: false },
    checkpoint: { seq, head, signature: chain.signCheckpoint({ deviceId: DEVICE, seq, head }, SECRET) },
  };
  return { links, openings, key, grantId };
}

test('copy: a copy of the whole story verifies, through the live head', () => {
  const s = story();
  const v = copy.verifyCopy({ links: s.links, openings: s.openings }, s.key);
  assert.deepEqual(v, { ok: true, verifiedThrough: s.key.head.seq, head: s.key.head.head });
});

test('copy: every way a copy can fail is named, and the first one is the answer', () => {
  const s = story();
  const check = (c, key = s.key) => copy.verifyCopy({ links: s.links, openings: s.openings, ...c }, key);

  assert.equal(check({}, { ...s.key, head: { ...s.key.head, restoring: true } }).reason, 'restoring');

  const flipped = s.links.map((e, i) => (i === 2 ? { ...e, link: Uint8Array.from(e.link, (x, k) => (k === 8 ? x ^ 1 : x)) } : e));
  assert.equal(check({ links: flipped }).reason, 'chain');

  assert.equal(check({ links: s.links.slice(0, -1) }).reason, 'gap', 'a copy that stops short of the key\'s head');

  const badCp = { ...s.key, checkpoint: { ...s.key.checkpoint, signature: new Uint8Array(64).fill(1) } };
  assert.equal(check({}, badCp).reason, 'checkpoint');

  assert.equal(check({ openings: {} }).reason, 'budget-opening-missing');
  const wrongReason = { [s.grantId]: { ...s.openings[s.grantId], reasonHash: new Uint8Array(32).fill(8) } };
  assert.equal(check({ openings: wrongReason }).reason, 'budget-opening');

  const noReveal = s.links.map((e) => (e.reveal ? { ...e, reveal: null } : e));
  assert.equal(check({ links: noReveal }).reason, 'reveal-missing');
  const wrongReveal = s.links.map((e) => (e.reveal ? { ...e, reveal: new Uint8Array(32).fill(3) } : e));
  const r = check({ links: wrongReveal });
  assert.equal(JSON.stringify([r.reason, r.detail.reason]), JSON.stringify(['reveal', 'wrong-budget']));

  const owes = check({}, { ...s.key, head: { ...s.key.head, owed: 1 } });
  assert.equal(owes.reason, 'debts');
  assert.deepEqual(owes.detail, { copy: { owed: [], overflow: false }, key: { owed: 1, overflow: false } });
});

test('copy: an empty key verifies only an empty copy', () => {
  const genesis = chain.genesis(DEVICE);
  const key = { publicKey: PUB, head: { seq: null, head: genesis, owed: 0, overflow: false }, checkpoint: null };
  assert.equal(copy.verifyCopy({ links: [] }, key).ok, true);
  assert.equal(copy.verifyCopy({ links: story().links.slice(0, 1) }, key).reason, 'chain');
});

/* the story, then a pressed LOSS {from, to} the person accepted (R24) - the key's head moves on with it */
function withLoss(from, to, opts = {}) {
  const s = story(opts);
  const subject = new Uint8Array(32);
  new DataView(subject.buffer).setUint32(0, to, true);
  const seq = s.key.head.seq + 1;
  const link = chain.encodeLink({ seq, op: OP.LOSS, decision: DECISION.APPROVE, flags: FLAG.PRESS_OBSERVED, subject, grantId: from });
  const head = chain.weld(s.key.head.head, link);
  s.links.push({ link, head, reveal: null });
  s.key = {
    ...s.key,
    head: { ...s.key.head, seq, head },
    checkpoint: { seq, head, signature: chain.signCheckpoint({ deviceId: DEVICE, seq, head }, SECRET) },
  };
  return s;
}

test('copy: a gap verifies only when a LOSS link covers it (R24, R27) - never by a checkpoint alone', () => {
  /* the copy lost #0: it keeps #1 with its head, so everything after it still welds back from the key's head */
  const s = withLoss(0, 1);
  const missing = s.links.slice(1);
  assert.equal(copy.verifyCopy({ links: missing, openings: s.openings }, s.key).ok, true, 'a LOSS over #0-#1 covers the gap');
  /* a LOSS that falls short of the gap does not */
  const short = withLoss(0, 0);
  const r = copy.verifyCopy({ links: short.links.slice(1), openings: short.openings }, short.key);
  assert.equal(JSON.stringify([r.reason, r.seq]), JSON.stringify(['gap', 0]));
  /* and without any LOSS, a missing range is a gap, however good the checkpoint */
  const plain = story();
  assert.equal(copy.verifyCopy({ links: plain.links.slice(1), openings: plain.openings }, plain.key).reason, 'gap');
  assert.deepEqual(copy.lossesIn(s.links).map((l) => [l.from, l.to]), [[0, 1]]);
});

test('copy: a link the key still holds is not part of a loss - only what is really missing is (spec 4.3)', () => {
  /* the copy lost #0-#1 and can't weld #2 (its #1 is gone), but the key handed #2 over this session */
  const s = withLoss(0, 1);
  const copyLinks = s.links.slice(2);
  const plain = copy.verifyCopy({ links: copyLinks, openings: s.openings }, s.key);
  assert.equal(plain.reason, 'gap', 'without the key\'s own links, #2 is unverifiable too');
  const v = chain.verify(copyLinks, { deviceId: DEVICE, expectHead: { seq: s.key.head.seq, head: s.key.head.head } });
  const held = [s.links[2]];
  assert.deepEqual(copy.missingGaps(copyLinks, v.gaps, held), [{ from: 0, to: 1 }], 'the missing range stops before the link the key holds');
  assert.equal(copy.verifyCopy({ links: copyLinks, openings: s.openings }, { ...s.key, held }).ok, true, 'LOSS #0-#1 + the key\'s own #2 verify');
  /* a copy whose #2 differs from the key's is not helped */
  const forged = { ...s.links[2], link: Uint8Array.from(s.links[2].link, (x, i) => (i === 9 ? x ^ 1 : x)) };
  assert.equal(copy.missingGaps([forged, ...copyLinks.slice(1)], v.gaps, held).some((g) => g.from <= 2 && g.to >= 2), true);
});

/*
 * WHAT COUNTS AS VERIFIED (firmware.md R27, tab B2; found on the Pixel
 * 2026-10-02): anchors are the genesis, the key's live HEAD and every
 * checkpoint whose signature verifies under the KEY's public key. The copy here
 * lost #0 and #3-#5 (the key restarted, so it holds only its head #6), but keeps
 * #1-#2 with the budget opening's checkpoint at #2: from that anchor #2 verifies
 * (and #1's head with it), so only #0-#1 and #3-#5 are missing - not #0-#5.
 */
const OTHER_SECRET = new Uint8Array(32).fill(6);
const OTHER_PUB = p256.getPublicKey(OTHER_SECRET, false).slice(1);

test('copy: a verified checkpoint anchors the copy - the gap is only what no anchor reaches (R27)', () => {
  const s = story();
  const links = [s.links[1], s.links[2], s.links[6]];
  /* the key hands its head link #6 over itself (held), as on a real sync */
  const key = { ...s.key, held: [s.links[6]] };
  const a = copy.assess({ links, openings: s.openings }, key);
  assert.deepEqual(a.missing, [{ from: 0, to: 1 }, { from: 3, to: 5 }]);
  assert.deepEqual(a.anchors.map((x) => x.seq), [2, 6], 'the opening\'s checkpoint and the key\'s latest one');
  /* the banner and Approve read the same answer */
  const v = copy.verifyCopy({ links, openings: s.openings }, key);
  assert.equal(JSON.stringify([v.reason, v.seq, v.detail.gaps]), JSON.stringify(['gap', 0, a.open]));
});

test('copy: a checkpoint signed by any key but this one anchors nothing - the public key never comes from the copy', () => {
  const s = story();
  const links = [s.links[1], s.links[2], s.links[6]];
  const head2 = s.links[2].head;
  const selfSigned = { [s.grantId]: { ...s.openings[s.grantId], signature: chain.signCheckpoint({ deviceId: DEVICE, seq: 2, head: head2 }, OTHER_SECRET) } };
  const a = copy.assess({ links, openings: selfSigned, publicKey: OTHER_PUB, checkpoints: [{ seq: 2, head: head2, signature: selfSigned[s.grantId].signature }] }, { ...s.key, held: [s.links[6]] });
  assert.deepEqual(a.missing, [{ from: 0, to: 5 }], 'nothing the copy signed for itself narrows the gap');
  assert.deepEqual(a.anchors.map((x) => x.seq), [6]);
});

test('copy: a fake LOSS inside a gap does not unblock Approve - a LOSS counts only when verified and later than its gap', () => {
  const s = story();
  /* the copy lost #3-#5; someone who edits it puts a LOSS {3..5} at #4, where nothing can check it */
  const subject = new Uint8Array(32);
  new DataView(subject.buffer).setUint32(0, 5, true);
  const link = chain.encodeLink({ seq: 4, op: OP.LOSS, decision: DECISION.APPROVE, flags: FLAG.PRESS_OBSERVED, subject, grantId: 3 });
  const fake = { link, head: chain.weld(s.links[2].head, link), reveal: null };
  const links = [s.links[0], s.links[1], s.links[2], fake, s.links[6]];
  /* as on a real sync, the key hands its own head link over: the gap is then exactly #3-#5, which the fake claims */
  const key = { ...s.key, held: [s.links[6]] };
  const v = copy.verifyCopy({ links, openings: s.openings }, key);
  assert.equal(JSON.stringify([v.reason, v.seq]), JSON.stringify(['gap', 3]));
  assert.deepEqual(copy.assess({ links, openings: s.openings }, key).losses, [], 'the fake LOSS is not counted');
  /* the same LOSS, written by the key after the gap and so verified, does cover it */
  const real = withLoss(3, 5);
  const ok = copy.verifyCopy({ links: [...real.links.slice(0, 3), ...real.links.slice(6)], openings: real.openings }, { ...real.key, held: real.links.slice(6) });
  assert.equal(ok.ok, true, JSON.stringify(ok));
});

test('copy: a key with no public key anchors on its genesis and HEAD only', () => {
  const s = story();
  const links = [s.links[1], s.links[2], s.links[6]];
  const a = copy.assess({ links, openings: s.openings }, { deviceId: DEVICE, head: s.key.head, held: [s.links[6]], checkpoint: s.key.checkpoint });
  assert.deepEqual([a.anchors, a.missing], [[], [{ from: 0, to: 5 }]]);
});

/*
 * THE LINK AFTER A LOSS (firmware.md R24, Brad 2026-10-02): a LOSS {A..B}
 * written while the key held #B+1 carries the first 28 bytes of SHA-256(#B+1)
 * after `to`, from the key's own memory; the library counts #B+1 verified when
 * the copy's link hashes to it. Not held: zeros, and #B+1 stays in the range
 * (#A..#B+1). Never the copy's word alone.
 */
const nodeSha = (b) => new Uint8Array(require('node:crypto').createHash('sha256').update(b).digest());

/* the story, then LOSS links appended by the key: [{from, to, next?: link bytes to hash}] */
function withLosses(list) {
  const s = story();
  for (const { from, to, next } of list) {
    const subject = new Uint8Array(32);
    new DataView(subject.buffer).setUint32(0, to, true);
    if (next) subject.set(nodeSha(next).slice(0, 28), 4);
    const seq = s.key.head.seq + 1;
    const link = chain.encodeLink({ seq, op: OP.LOSS, decision: DECISION.APPROVE, flags: FLAG.PRESS_OBSERVED, subject, grantId: from });
    const head = chain.weld(s.key.head.head, link);
    s.links.push({ link, head, reveal: null });
    s.key = { ...s.key, head: { ...s.key.head, seq, head }, checkpoint: { seq, head, signature: chain.signCheckpoint({ deviceId: DEVICE, seq, head }, SECRET) } };
  }
  return s;
}
/* the copy lost #3-#4; the key holds none of its links any more (a later session) */
const lostThreeFour = (s) => [...s.links.slice(0, 3), ...s.links.slice(5)];

test('copy: the next link held at the LOSS is kept and verified by the hash the key put in it', () => {
  const s0 = story();
  const s = withLosses([{ from: 3, to: 4, next: s0.links[5].link }]);
  const a = copy.assess({ links: lostThreeFour(s), openings: s.openings }, s.key);
  assert.deepEqual([a.missing, a.open], [[{ from: 3, to: 4 }], []]);
  assert.deepEqual(copy.lossesIn(s.links).map((l) => [l.from, l.to, !!l.next]), [[3, 4, true]]);
});

test('copy: a next link the key did not hold stays in the range - #A..#B+1 is what is offered', () => {
  const s = withLosses([{ from: 3, to: 4 }]);
  const a = copy.assess({ links: lostThreeFour(s), openings: s.openings }, s.key);
  assert.deepEqual([a.missing, a.open], [[{ from: 3, to: 5 }], [{ from: 3, to: 5 }]]);
});

test('copy: a copy that swaps the next link\'s bytes gets nothing from the LOSS hash', () => {
  const s0 = story();
  const s = withLosses([{ from: 3, to: 4, next: s0.links[5].link }]);
  const links = lostThreeFour(s).map((e) => (chain.decodeLink(e.link).seq === 5 ? { ...e, link: Uint8Array.from(e.link, (x, i) => (i === 40 ? x ^ 1 : x)) } : e));
  const a = copy.assess({ links, openings: s.openings }, s.key);
  assert.deepEqual(a.open, [{ from: 3, to: 5 }]);
  assert.equal(copy.verifyCopy({ links, openings: s.openings }, s.key).reason, 'gap');
});

test('copy: overlapping or adjoining LOSS links cover a range together, cleanly', () => {
  /* #3-#4 accepted first; then #3-#5 once #5 could not be proven (the Pixel: #37-#47, then #37-#48) */
  const over = withLosses([{ from: 3, to: 4 }, { from: 3, to: 5 }]);
  const a = copy.assess({ links: lostThreeFour(over), openings: over.openings }, over.key);
  assert.deepEqual([a.missing, a.open, a.losses.length], [[{ from: 3, to: 5 }], [], 2]);
  /* #3-#4 and then #5 alone */
  const adj = withLosses([{ from: 3, to: 4 }, { from: 5, to: 5 }]);
  assert.deepEqual(copy.assess({ links: lostThreeFour(adj), openings: adj.openings }, adj.key).open, []);
});

/* R3 (2026-10-03): byte 46, the scope that paid */
const TWO = [
  { op: OP.SIGN, slot: 222, cap: 1, identity: 'ssh://agent@edge-test' },
  { op: OP.SIGN, slot: 222, cap: 1, identity: 'gpg://Agent <a@edge-test>' },
];
const verdict = (o) => { const s = story(o); return copy.verifyCopy({ links: s.links, openings: s.openings }, s.key); };

test('R3: each spend names its scope - in range, covering the op and slot - and verifies', () => {
  assert.equal(verdict({ scopes: TWO, spendScopes: [1, 2] }).ok, true);
});

test('R3: an older chain (byte 46 = 0 on every spend) still verifies', () => {
  assert.equal(verdict({ scopes: TWO, spendScopes: [0, 0] }).ok, true);
  assert.equal(verdict({}).ok, true);
});

test('R3: a forged spend - scope 0 among scoped ones, or past the scope count - fails', () => {
  let v = verdict({ scopes: TWO, spendScopes: [1, 0] });
  assert.equal(v.ok, false);
  assert.equal(v.detail.reason, 'missing');
  v = verdict({ scopes: TWO, spendScopes: [3, 1] });
  assert.equal(v.ok, false);
  assert.equal(v.detail.reason, 'out-of-range');
});

test('R3: one scope past its cap fails; a scope that does not cover the op+slot fails', () => {
  let v = verdict({ scopes: TWO, spendScopes: [1, 1] });
  assert.equal(v.ok, false);
  assert.equal(v.detail.reason, 'over-cap');
  v = verdict({ scopes: [{ op: OP.SIGN, slot: 221, cap: 1, identity: 'ssh://x@y' }, TWO[1]], spendScopes: [1, 2] });
  assert.equal(v.ok, false);
  assert.equal(v.detail.reason, 'does-not-cover');
});

test('R3 exact: an opening that says 2 with a spend at 0 fails; one that says 0 with a scoped spend fails; an old budget verifies', () => {
  let v = verdict({ scopes: TWO, spendScopes: [0, 0], openingScope: 2 });
  assert.equal(v.ok, false);
  assert.equal(v.detail.reason, 'missing');
  v = verdict({ scopes: TWO, spendScopes: [1, 2], openingScope: 0 });
  assert.equal(v.ok, false);
  assert.equal(v.detail.reason, 'unexpected');
  v = verdict({ scopes: TWO, spendScopes: [1, 2], openingScope: 3 });
  assert.equal(v.ok, false);
  assert.equal(v.detail.reason, 'opening-count');
  assert.equal(verdict({ scopes: TWO, spendScopes: [0, 0], openingScope: 0 }).ok, true, 'an old budget');
});

test('a LOSS over links the copy still holds sets them aside: a budget that fails R3, then a pressed LOSS over its links - the copy verifies (2026-10-04, budget 166)', () => {
  const bad = { scopes: TWO, spendScopes: [1, 2], openingScope: 0 };
  const s0 = story(bad);
  assert.equal(copy.verifyCopy({ links: s0.links, openings: s0.openings }, s0.key).reason, 'scope', 'the budget fails the exact rule');
  const opening = s0.grantId - 1;
  const s = withLoss(opening, s0.key.head.seq, bad);
  const v = copy.verifyCopy({ links: s.links, openings: s.openings }, s.key);
  assert.equal(v.ok, true, JSON.stringify(v));
});

/*
 * ONLY THE NEW LINKS (Brad, 2026-10-05): opts.from = a head the caller verified
 * in full earlier and holds in memory. Links after it weld onto it and reach
 * the live head; a checkpoint the key gives past it must verify.
 */
test('copy: from a verified head, only the new links are checked - and they verify', () => {
  const s = story();
  const mid = 3;
  const a = copy.assess({ links: s.links, openings: s.openings }, s.key, { from: { seq: mid, head: s.links[mid].head } });
  assert.equal(a.chain.ok, true);
  assert.equal(a.chain.verifiedThrough, s.key.head.seq);
  assert.deepEqual(a.open, []);
});

test('copy: from a head that is not the one the links weld onto, the new links fail', () => {
  const s = story();
  const a = copy.assess({ links: s.links, openings: s.openings }, s.key, { from: { seq: 3, head: new Uint8Array(32).fill(0xaa) } });
  assert.equal(a.chain.ok, false);
});

test('copy: an edited new link fails the from-check', () => {
  const s = story();
  const links = s.links.map((e) => ({ ...e }));
  const bad = Uint8Array.from(links[5].link);
  bad[20] ^= 1;
  links[5] = { ...links[5], link: bad };
  const a = copy.assess({ links, openings: s.openings }, s.key, { from: { seq: 3, head: s.links[3].head } });
  assert.equal(a.chain.ok, false);
});

test('copy: a checkpoint past the verified head that does not verify is a failure, not one anchor fewer', () => {
  const s = story();
  const key = { ...s.key, checkpoint: { ...s.key.checkpoint, signature: chain.signCheckpoint({ deviceId: DEVICE, seq: s.key.checkpoint.seq, head: s.key.checkpoint.head }, OTHER_SECRET) } };
  const a = copy.assess({ links: s.links, openings: s.openings }, key, { from: { seq: 3, head: s.links[3].head } });
  assert.equal(a.chain.ok, false);
  assert.equal(a.chain.failure.reason, 'bad-checkpoint');
});

/*
 * verifyCopyKept (Brad, 2026-10-06): the state of the last check, kept in
 * memory by the caller - same key head and copy = skipped; grown = only the new
 * links; anything else = the full check.
 */
function keyAt(s, seq) {
  const head = s.links[seq].head;
  return { ...s.key, head: { seq, head, owed: 0, overflow: false, restoring: false }, checkpoint: { seq, head, signature: chain.signCheckpoint({ deviceId: DEVICE, seq, head }, SECRET) }, held: [] };
}

test('kept: full first, then skipped, then only the new links - and the same answer as the full check', () => {
  const s = story();
  const early = { links: s.links.slice(0, 5), openings: s.openings };
  const k4 = keyAt(s, 4);
  const one = copy.verifyCopyKept(early, k4, null);
  assert.equal(one.path, 'full');
  assert.equal(one.result.ok, true);
  const two = copy.verifyCopyKept(early, k4, one.state);
  assert.equal(two.path, 'skipped');
  const all = { links: s.links, openings: s.openings };
  const three = copy.verifyCopyKept(all, s.key, two.state);
  assert.equal(three.path, 'new-links');
  assert.deepEqual(three.result, copy.verifyCopy(all, s.key));
});

test('kept: an earlier link edited is a full check, and it fails', () => {
  const s = story();
  const k4 = keyAt(s, 4);
  const one = copy.verifyCopyKept({ links: s.links.slice(0, 5), openings: s.openings }, k4, null);
  const links = s.links.map((e) => ({ ...e }));
  const bad = Uint8Array.from(links[1].link);
  bad[20] ^= 1;
  links[1] = { ...links[1], link: bad };
  assert.equal(one.why, 'first check');
  const r = copy.verifyCopyKept({ links, openings: s.openings }, s.key, one.state);
  assert.equal(r.path, 'full');
  assert.equal(r.why, 'an older link changed');
  assert.equal(r.result.ok, false);
  assert.equal(r.state, null);
});

test('kept: an opening record changed is a full check', () => {
  const s = story();
  const all = { links: s.links, openings: s.openings };
  const one = copy.verifyCopyKept(all, s.key, null);
  const openings = { [s.grantId]: { ...s.openings[s.grantId], uses: s.openings[s.grantId].uses + 1 } };
  const r = copy.verifyCopyKept({ links: s.links, openings }, s.key, one.state);
  assert.equal(r.path, 'full');
  assert.equal(r.why, 'openings changed');
  assert.equal(r.result.ok, false);
});
