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
function story() {
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
  const scopes = [{ op: OP.SIGN, slot: 222, cap: 2 }];
  const reasonHash = new Uint8Array(32).fill(7);
  const genesis = grants.grantGenesis(seed, uses);
  const grantId = links.length + 1;
  const at = add({ op: OP.GRANT_CREATE, decision: DECISION.APPROVE, flags: FLAG.PRESS_OBSERVED, grantId, subject: grants.grantSubject({ scopes, reasonHash, genesis }) });
  const signature = chain.signCheckpoint({ deviceId: DEVICE, seq: at, head }, SECRET);
  const openings = { [grantId]: { scopes, reasonHash, genesis, uses, signature } };

  for (let step = 1; step <= uses; step++) {
    const use = add({ op: OP.SIGN, decision: DECISION.SELF_PRESS, slot: 222, flags: FLAG.BUDGET_SPENT, subject: new Uint8Array(32).fill(20 + step), grantId, grantStep: step },
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
function withLoss(from, to) {
  const s = story();
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
