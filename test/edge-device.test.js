'use strict';

/*
 * plugins/edge: the device calls, against a fake transport that answers the
 * way the soft-key firmware plugin does (ok-rn/android/okemu/plugins/edge) -
 * the same report layouts, the same "EDGE:xx" status codes, a real P-256 key
 * for the checkpoints. The firmware itself is tested by its own kit test on
 * the emulator; this pins the host's reading of those bytes.
 */
const test = require('node:test');
const assert = require('node:assert');
const setup = require('../plugins/edge');
const { chain, codes, grants, tickets } = require('../src/edge');
const { H } = require('../src/edge/hash');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const { IFACE } = require('../src/protocol/msg');

const { fakeKey, edgeOver, PUB, DEVICE, SECRET, report, status, u32 } = require('./helpers/fake-edge-key');

test('edge: HEAD, the public key and device id, PICKUP of a held link', async () => {
  const edge = edgeOver(fakeKey());
  const h = await edge.head();
  assert.equal(h.seq, 0);
  assert.equal(h.oldest, 0);
  assert.deepEqual(h.live, []);
  const { publicKey, deviceId } = await edge.publicKey();
  assert.deepEqual(Array.from(publicKey), Array.from(PUB));
  assert.deepEqual(Array.from(deviceId), Array.from(DEVICE));
  const [l] = await edge.pickup(0, 1);
  assert.equal(chain.decodeLink(l.link).op, codes.OP.SIGN);
  assert.equal(l.reveal, null, 'a pressed use has no reveal');
  assert.ok(chain.verify([l], { deviceId, expectHead: { seq: 0, head: h.head } }).ok);
});

test('edge: the checkpoint is read and verifies with the Edge key', async () => {
  const edge = edgeOver(fakeKey());
  const c = await edge.checkpoint();
  assert.ok(chain.verifyCheckpoint({ deviceId: DEVICE, seq: c.seq, head: c.head }, c.signature, PUB));
});

test('edge: a budget\'s opening comes back as a proof verifyBudgetOpening accepts', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32)); /* R10: no budget while a ticket is owed */
  const before = await edge.head();
  const scopes = [{ op: codes.OP.SIGN, slot: 2, cap: 4 }];
  const reasonHash = new Uint8Array(32).fill(7);
  let asked = false;
  const g = await edge.grant({ scopes, reasonHash, verifiedHead: before.head, onPress: () => { asked = true; } });
  assert.ok(asked, 'onPress tells the UI to ask for the press');
  assert.equal(g.uses, 4);
  assert.equal(g.seq, 2);
  assert.equal(g.checkpoint.seq, 2);
  const [l] = await edge.pickup(2, 1);
  const r = grants.verifyBudgetOpening({
    deviceId: DEVICE, publicKey: PUB, link: l.link, prevHead: before.head,
    head: g.checkpoint.head, signature: g.checkpoint.signature, scopes, reasonHash, genesis: g.genesis, uses: g.uses,
  });
  assert.deepEqual(r, { ok: true, grantId: g.grantId, seq: 2 });
  assert.deepEqual((await edge.head()).live, [g.grantId]);
  assert.equal(await edge.revoke(g.grantId), true);
});

/*
 * Measured on the Pixel (2026-10-03): the app's background copy ran a PICKUP
 * while an e2e test waited for its GRANT_CREATE on the same stack, and the
 * answers crossed - the grant read "3618 uses, opened at #4229928469". Two
 * callers at once must each get their own answer.
 */
test('edge: requests from two callers at once never swap answers (one Edge request at a time)', async () => {
  const transport = fakeKey({ delay: 30 });
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32)); /* R10: no budget while a ticket is owed */
  const before = await edge.head();
  const scopes = [{ op: codes.OP.SIGN, slot: 2, cap: 4 }];
  const [g, picked, h] = await Promise.all([
    edge.grant({ scopes, reasonHash: new Uint8Array(32).fill(7), verifiedHead: before.head }),
    edge.pickup(0, 1),
    edge.head(),
  ]);
  assert.equal(g.uses, 4, 'the grant read another request\'s answer');
  assert.equal(g.seq, 2);
  assert.equal(chain.decodeLink(picked[0].link).seq, 0, 'the pickup read another request\'s answer');
  assert.equal(chain.decodeLink(picked[0].link).op, codes.OP.SIGN);
  assert.ok(h.seq === 1 || h.seq === 2, `HEAD read another request's answer (seq ${h.seq})`);
  await edge.revoke(g.grantId);
});

test('edge: EDGE:xx refusals become named errors', async () => {
  const edge = edgeOver(fakeKey());
  await assert.rejects(edge.revoke(99), (e) => e instanceof edge.EdgeError && e.status === 'no-such-budget' && e.code === 7);
  await assert.rejects(edge.ticket(5, 0, new Uint8Array(32)), (e) => e.status === 'no-ticket-waiting');
  await assert.rejects(edge.pickup(3, 1), (e) => e.status === 'not-held');
  await assert.rejects(edge.grant({ scopes: [{ op: 1, slot: 2, cap: 1000 }, { op: 1, slot: 3, cap: 25 }], reasonHash: new Uint8Array(32), verifiedHead: new Uint8Array(32) }),
    (e) => e.status === 'too-many-uses');
  const t = await edge.ticket(0, 0, new Uint8Array(32));
  assert.equal(t.seq, 1, 'the ticket comes back with the seq and head the next arm() passes');
  assert.equal(t.head.length, 32);
});

test('edge: ARM, hold/resume and WAIVE - the spec change (R13a, R15a, R18)', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  const armedToken = () => transport.armed();
  let h = await edge.head();
  assert.equal(h.owed, 1, 'the approved use owes its ticket');
  /* nothing arms, and no budget opens, while a ticket is owed */
  const S = new Uint8Array(32).fill(4); /* the subject of the request an arm is for */
  await assert.rejects(edge.arm(h.head, S), (e) => e.status === 'ticket-owed');
  await assert.rejects(edge.grant({ scopes: [{ op: 1, slot: 2, cap: 2 }], reasonHash: new Uint8Array(32), verifiedHead: h.head }), (e) => e.status === 'ticket-owed');
  /* WAIVE clears it */
  const w = await edge.waive();
  assert.equal(w.seq, 1);
  h = await edge.head();
  assert.equal(h.owed, 0);
  /* no live budget: nothing to arm; a stale head: refused */
  await assert.rejects(edge.arm(h.head, S), (e) => e.status === 'nothing-to-arm');
  const g = await edge.grant({ scopes: [{ op: 1, slot: 2, cap: 2 }], reasonHash: new Uint8Array(32), verifiedHead: h.head });
  h = await edge.head();
  assert.equal(await edge.arm(h.head, S), true);
  assert.equal(Buffer.from(armedToken()).toString('hex'), Buffer.from(grants.armToken({ head: h.head, subject: S })).toString('hex'), 'ARM sends the token, not the head');
  /* hold: listed, nothing arms; resume: back */
  assert.equal(await edge.hold(g.grantId), true);
  h = await edge.head();
  assert.deepEqual(h.held, [g.grantId]);
  await assert.rejects(edge.arm(h.head, S), (e) => e.status === 'nothing-to-arm');
  let asked = false;
  await assert.rejects(edge.resume(g.grantId, { verifiedHead: new Uint8Array(32).fill(1) }), (e) => e.status === 'stale-head');
  assert.equal(await edge.resume(g.grantId, { verifiedHead: h.head, onPress: () => { asked = true; } }), true);
  assert.ok(asked, 'resume asks for the press');
  assert.deepEqual((await edge.head()).held, []);
});

/* everything the key holds, as a copy: links with heads (and reveals) from PICKUP */
async function copyOf(edge, openings = {}) {
  const h = await edge.head();
  const links = h.seq === null ? [] : await edge.pickup(0, h.seq + 1);
  return { links, openings };
}

test('edge: grants.create / resume verify the copy first, send the verified head, and fail closed (R27)', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  let copy = await copyOf(edge);
  assert.equal((await edge.grants.check(copy)).ok, true, 'a copy of exactly what the key holds verifies');
  await edge.waive();
  copy = await copyOf(edge);
  const scopes = [{ op: 1, slot: 2, cap: 2 }];
  const reasonHash = new Uint8Array(32).fill(7);
  const g = await edge.grants.create({ copy, scopes, reasonHash });
  const opening = { scopes, reasonHash, genesis: g.genesis, uses: g.uses, signature: g.checkpoint.signature };
  const requests = () => transport.writes.filter((w) => w === 0x10 || w === 0x14).length;
  const sent = requests();

  /* a copy without the budget's opening: refused before anything is sent */
  copy = await copyOf(edge);
  await assert.rejects(edge.grants.create({ copy, scopes, reasonHash }), (e) => e.code === 'EDGE_COPY_UNVERIFIED' && e.verdict.reason === 'budget-opening-missing');
  /* a flipped byte */
  copy = await copyOf(edge, { [g.grantId]: opening });
  const bad = { ...copy, links: copy.links.map((l, i) => (i === 1 ? { ...l, link: Uint8Array.from(l.link, (x, k) => (k === 9 ? x ^ 1 : x)) } : l)) };
  await assert.rejects(edge.grants.create({ copy: bad, scopes, reasonHash }), (e) => e.code === 'EDGE_COPY_UNVERIFIED' && e.verdict.reason === 'chain');
  /* a copy missing its last link */
  await assert.rejects(edge.grants.create({ copy: { ...copy, links: copy.links.slice(0, -1) }, scopes, reasonHash }), (e) => e.verdict.reason === 'gap');
  assert.equal(requests(), sent, 'a request went out from a copy that does not verify');

  /* the good copy: resume goes out with the full verified head */
  await edge.hold(g.grantId);
  copy = await copyOf(edge, { [g.grantId]: opening });
  assert.equal(await edge.grants.resume(g.grantId, { copy }), true);
  assert.equal(requests(), sent + 1);
});

test('edge: a restoring key fails the copy check; REPLAY is tentative and REPLAY_DONE commits only on the vouch tag the key issued (R26)', async () => {
  const edge = edgeOver(fakeKey({ restoring: true }));
  assert.equal((await edge.head()).restoring, true);
  assert.equal((await edge.grants.check(await copyOf(edge))).reason, 'restoring');
  const next = chain.encodeLink({ seq: 1, op: codes.OP.SIGN, decision: codes.DECISION.DENY, subject: new Uint8Array(32).fill(4) });
  const h0 = await edge.head();
  /* a copy whose head after the link is not the key's weld: forked */
  await assert.rejects(edge.replay(next, new Uint8Array(32).fill(6)), (e) => e.status === 'replay-mismatch');
  assert.equal(await edge.replay(next, chain.weld(h0.head, next)), true);
  const far = chain.encodeLink({ seq: 5, op: 1, decision: 2, subject: new Uint8Array(32) });
  await assert.rejects(edge.replay(far, chain.weld(h0.head, far)), (e) => e.status === 'replay-mismatch');
  /* R13b: only a sign/decrypt link may carry bytes 47-62 (its intent) - on any other link they are no key's */
  await assert.rejects(edge.replay(chain.encodeLink({ seq: 2, op: codes.OP.TICKET, decision: 0, subject: new Uint8Array(32), reserved: new Uint8Array(18).fill(1) }), new Uint8Array(32)),
    (e) => e.code === 'EDGE_NOT_A_KEY_LINK');
  /* the replay is tentative: HEAD still shows the restored head */
  assert.equal((await edge.head()).seq, 0, 'a replay moved the real head before it was vouched');
  let asked = false;
  /* a tag the key did not issue: thrown away (a real key also links the LOSS) */
  await assert.rejects(edge.replayDone({ seq: 1, tag: new Uint8Array(16).fill(1), onPress: () => { asked = true; } }), (e) => e.status === 'not-vouched');
  assert.ok(asked);
  assert.equal((await edge.head()).restoring, false);
});

test('edge: VOUCH gives seq, head and tag; a replay with a tag the key issued commits (R26)', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  const v = await edge.vouch();
  assert.equal(JSON.stringify([v.seq, v.head.length, v.tag.length]), JSON.stringify([0, 32, 16]));
  const t = await edge.ticket(0, 0, new Uint8Array(32));
  assert.equal(t.tag.length, 16, 'a ticket reply carries the vouch tag');
});

test('edge: a stray report on the bus is not taken as the answer (measured on the Pixel soft key)', async () => {
  /* the key leaves a report behind after an agent sign; the next Edge request must not read it */
  const transport = fakeKey({ delay: 60 }); /* a key slower than the stray: it lands between request and answer */
  const edge = edgeOver(transport);
  const listeners = [];
  const realOn = transport.on;
  transport.on = (ev, fn) => { const off = realOn.call(transport, ev, fn); listeners.push(fn); return off; };
  const stray = report([0x02, 0x0c, 0x79, 0xb1, ...new Uint8Array(60).fill(0xab)]); /* would read as seq 0xB1790C02 */
  setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: stray })), 20);
  const h = await edge.head();
  assert.equal(h.seq, 0, 'the stray report was taken as HEAD\'s answer');
});

test('edge: probe - edge, no-pin, or silence (never a hang)', async () => {
  assert.equal(await edgeOver(fakeKey()).probe(), 'edge');
  assert.equal(await edgeOver(fakeKey({ noPin: true })).probe(), 'no-pin');
  const t0 = Date.now();
  assert.equal(await edgeOver(fakeKey({ silent: true })).probe({ timeoutMs: 300 }), 'none');
  assert.ok(Date.now() - t0 < 2000, 'a silent key is answered by the timeout');
});

test('edge: status codes - every code the firmware sends has words on the host', () => {
  for (let c = 0; c <= 0x0a; c++) assert.ok(codes.STATUS[c], `code 0x${c.toString(16)}`);
  assert.deepEqual(codes.parseStatus('EDGE:07'), { code: 7, name: 'no-such-budget', text: codes.STATUS[7].text });
  assert.equal(codes.parseStatus('Error something'), null);
});

test('edge: LOSS {from, to} - a pressed loss link with the spec layout; a range past the head is refused (R24)', async () => {
  const edge = edgeOver(fakeKey());
  let asked = false;
  const r = await edge.loss({ from: 0, to: 0, onPress: () => { asked = true; } });
  assert.ok(asked, 'a loss asks for the press');
  const [l] = await edge.pickup(r.seq, 1);
  const f = chain.decodeLink(l.link);
  assert.equal(JSON.stringify([f.op, f.decision, f.flags, f.grantId, f.subject[0]]), JSON.stringify([codes.OP.LOSS, 1, 1, 0, 0]));
  /* R24: there was no #1 when it was written (the LOSS is #1), so nothing is named: zeros */
  assert.equal(f.subject.slice(4).some((x) => x), false);
  /* the same LOSS again: now the key holds #1, and the subject names it - the first 28 bytes of SHA-256(link 1) */
  const again = await edge.loss({ from: 0, to: 0 });
  const [l2] = await edge.pickup(again.seq, 1);
  const [next] = await edge.pickup(1, 1);
  assert.equal(Buffer.from(chain.decodeLink(l2.link).subject.slice(4)).toString('hex'), Buffer.from(H(next.link).slice(0, 28)).toString('hex'));
  await assert.rejects(edge.loss({ from: 0, to: 99 }), (e) => e.status === 'bad-range');
  await assert.rejects(edge.loss({ from: 3, to: 1 }), (e) => e instanceof RangeError);
});

/*
 * R11a: a scope on a derived code (agent sign 201-203 / 221-223) names one
 * identity. grant() stages its label with GRANT_LABEL before GRANT_CREATE, and
 * the budget's opening commits to it - so a budget for the agent's identity
 * cannot cover Brad's identity on the same code.
 */
test('edge: R11a - a derived-code scope stages its identity label first, and the opening commits to it', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32)); /* R10: no budget while a ticket is owed */
  const before = await edge.head();
  const scopes = [{ op: codes.OP.SIGN, slot: 222, cap: 3, identity: 'ssh://agent@nitro16' }];
  const reasonHash = new Uint8Array(32).fill(7);
  const writesBefore = transport.writes.length;
  const g = await edge.grant({ scopes, reasonHash, verifiedHead: before.head });
  assert.deepEqual(transport.writes.slice(writesBefore), [0x11, 0x10], 'GRANT_LABEL, then GRANT_CREATE');
  const [l] = await edge.pickup(g.seq, 1);
  const opening = (sc) => grants.verifyBudgetOpening({
    deviceId: DEVICE, publicKey: PUB, link: l.link, prevHead: before.head,
    head: g.checkpoint.head, signature: g.checkpoint.signature, scopes: sc, reasonHash, genesis: g.genesis, uses: g.uses,
  });
  assert.equal(opening(scopes).ok, true, 'the opening verifies with the identity named');
  assert.equal(opening([{ ...scopes[0], identity: 'ssh://bmatusiak@localhost' }]).ok, false, 'another identity on the same code is not this budget');
  await edge.revoke(g.grantId);
});

test('edge: R11a - a derived-code scope without an identity is refused before anything is sent; a stored slot needs none', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32));
  const before = await edge.head();
  const n = transport.writes.length;
  await assert.rejects(edge.grant({ scopes: [{ op: codes.OP.SIGN, slot: 201, cap: 1 }], reasonHash: new Uint8Array(32), verifiedHead: before.head }),
    /must name its identity \(R11a\)/);
  assert.equal(transport.writes.length, n, 'nothing reached the key');
  const g = await edge.grant({ scopes: [{ op: codes.OP.SIGN, slot: 102, cap: 1 }], reasonHash: new Uint8Array(32), verifiedHead: before.head });
  assert.ok(g.grantId, 'a stored slot (ECC2) is its own key - no label');
  await edge.revoke(g.grantId);
});

test('edge: grants.check with the key one link ahead of the copy takes the short path and keeps its state (A13, 2026-10-06)', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.waive();
  const first = await copyOf(edge);
  assert.equal((await edge.grants.check(first, { keyTail: true })).ok, true);
  assert.equal(edge.grants.lastPath, 'full: first check');
  /* a link lands on the key after the copy was read (an agent's ticket, between the sync and this check) */
  await edge.waive();
  const behind = { links: (await copyOf(edge)).links.slice(0, -1), openings: {} };
  assert.equal((await edge.grants.check(behind, { keyTail: true })).ok, true, 'for a display, the key\'s newest link is checked from the key, not called a gap');
  assert.equal(edge.grants.lastPath, 'new-links');
  /* the sync then stores it: the same head, the same links - nothing to check again */
  assert.equal((await edge.grants.check(await copyOf(edge), { keyTail: true })).ok, true);
  assert.equal(edge.grants.lastPath, 'skipped');
  /* R27 stays strict: a budget is never created or resumed from a copy short of the key */
  assert.equal((await edge.grants.check(behind)).reason, 'gap');
});

test('edge: grants.check reads one moment of the key - a link landing mid-check is checked again, not kept as a failure (Pixel, 2026-10-06)', async () => {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.waive();
  assert.equal((await edge.grants.check(await copyOf(edge), { keyTail: true })).ok, true);
  await edge.waive();
  const copy = await copyOf(edge);
  /* an agent's ticket lands between the head read and the checkpoint read, once */
  const checkpoint = edge.checkpoint.bind(edge);
  let raced = false;
  edge.checkpoint = async () => {
    if (!raced) { raced = true; await edge.waive(); }
    return checkpoint();
  };
  assert.equal((await edge.grants.check(copy, { keyTail: true })).ok, true, 'checked again over the new head');
  assert.ok(raced);
  assert.doesNotMatch(edge.grants.lastPath, /full|moving/);
  /* the state was kept: the stored copy catching up is nothing new to check */
  assert.equal((await edge.grants.check(await copyOf(edge), { keyTail: true })).ok, true);
  assert.equal(edge.grants.lastPath, 'skipped');
});
