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
