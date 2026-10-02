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
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');
const { IFACE } = require('../src/protocol/msg');

const SECRET = new Uint8Array(32).fill(5);
const PUB = p256.getPublicKey(SECRET, false).slice(1);
const DEVICE = chain.deviceIdOf(PUB);

const u32 = (n) => [n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff];
const report = (bytes) => { const r = new Uint8Array(64); r.set(bytes.slice(0, 64)); return r; };
const status = (code) => report([...Buffer.from(`EDGE:${code.toString(16).toUpperCase().padStart(2, '0')}`)]);

/* a fake key: a tiny chain, one held link, answers by sub-op */
function fakeKey({ silent = false, noPin = false, delay = 1, restoring = false } = {}) {
  const listeners = new Set();
  let head = chain.genesis(DEVICE);
  const held = [];
  const live = [];
  const onHold = new Set();
  let owed = [];
  let armed = false;
  const writes = [];
  const emit = (r) => setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: r })), delay);
  const append = (fields) => {
    const seq = held.length;
    const link = chain.encodeLink({ seq, ...fields });
    head = chain.weld(head, link);
    held.push({ link, head });
    return seq;
  };
  const checkpoint = () => {
    const seq = held.length - 1;
    const sig = chain.signCheckpoint({ deviceId: DEVICE, seq, head }, SECRET);
    emit(report([...u32(seq), ...head]));
    emit(report([...sig]));
  };
  /* one approved use, so there is something to pick up and ticket */
  append({ op: codes.OP.SIGN, decision: codes.DECISION.APPROVE, slot: 2, flags: 1, subject: new Uint8Array(32).fill(9) });
  owed = [0];
  /* the fake's vouch tag: any MAC the fake can recompute (a real key keys it with K_vouch) */
  const tagOf = (seq, h) => require('node:crypto').createHmac('sha256', 'fake K_vouch').update(Buffer.concat([Buffer.from(u32(seq)), Buffer.from(h)])).digest().subarray(0, 16);
  const seqHead = () => report([...u32(held.length - 1), ...head, ...tagOf(held.length - 1, head)]);
  let tent = null; /* R26: the tentative replay */

  const transport = {
    open() {}, close() {}, isOpen: () => true, request() { throw new Error('not used'); },
    on(event, fn) { if (event === 'report') { listeners.add(fn); return () => listeners.delete(fn); } return () => {}; },
    write(iface, frame) {
      if (silent || frame[4] !== 0xf8) return;
      if (noPin) return emit(status(0x01));
      const sub = frame[5];
      const arg = frame.subarray(6);
      writes.push(sub);
      const same = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
      if (sub === 0x01) {
        const ids = [0, 1, 2, 3].map((i) => live[i] || 0);
        const mask = ids.reduce((m, id, i) => (id && onHold.has(id) ? m | (1 << i) : m), 0);
        emit(report([...u32(held.length - 1), ...head, ...u32(0), ...ids.flatMap(u32), mask, owed.length, 0, restoring ? 1 : 0]));
      } else if (sub === 0x04) {
        emit(report([...PUB]));
      } else if (sub === 0x03) {
        checkpoint();
      } else if (sub === 0x02) {
        const from = arg[0] | (arg[1] << 8);
        for (let s = from; s < from + arg[4]; s++) {
          if (!held[s]) return emit(status(0x09));
        }
        for (let s = from; s < from + arg[4]; s++) {
          emit(report([...held[s].link]));
          emit(report([...held[s].head, ...new Uint8Array(32)]));
        }
      } else if (sub === 0x20) {
        const ref = arg[0] | (arg[1] << 8);
        if (!owed.includes(ref)) return emit(status(0x08));
        append({ op: codes.OP.TICKET, decision: arg[4], subject: new Uint8Array(32), grantId: ref });
        owed = owed.filter((q) => q !== ref);
        emit(seqHead());
      } else if (sub === 0x22) {
        /* R13a: a token over head + the request's subject; the fake keeps it (a real key checks it at the sign) */
        if (owed.length) return emit(status(0x0c));
        if (!live.some((id) => !onHold.has(id))) return emit(status(0x0d));
        armed = arg.slice(0, 32);
        emit(status(0x00));
      } else if (sub === 0x13 || sub === 0x14) {
        const id = arg[0] | (arg[1] << 8);
        if (!live.includes(id)) return emit(status(0x07));
        if (sub === 0x14 && owed.length) return emit(status(0x0c));
        if (sub === 0x14 && !same(arg.slice(4, 36), head)) return emit(status(0x0b));
        if (sub === 0x13) onHold.add(id); else onHold.delete(id);
        emit(status(0x00));
      } else if (sub === 0x21) {
        append({ op: codes.OP.TICKET, decision: 0x8f, flags: 1, grantId: owed[0] || 0, subject: tickets.waiveSubject(owed, false) });
        owed = [];
        emit(seqHead());
      } else if (sub === 0x10) {
        const n = arg[0];
        const scopes = Array.from({ length: n }, (_, j) => ({ op: arg[1 + 4 * j], slot: arg[2 + 4 * j], cap: arg[3 + 4 * j] | (arg[4 + 4 * j] << 8) }));
        const uses = scopes.reduce((a, s) => a + s.cap, 0);
        if (uses > 255) return emit(status(0x04));
        if (owed.length) return emit(status(0x0c));
        if (!same(arg.slice(52, 58), head.slice(0, 6))) return emit(status(0x0b)); /* R27: the verified head */
        const lifetime = arg[50] | (arg[51] << 8);
        const genesis = grants.grantGenesis(new Uint8Array(32).fill(3), uses);
        const seq = held.length;
        const id = seq + 1;
        append({ op: codes.OP.GRANT_CREATE, decision: 1, flags: 1, grantId: id,
          subject: grants.grantSubject({ scopes, reasonHash: arg.slice(17, 49), genesis, lifetime }) });
        live.push(id);
        emit(report([...u32(id), uses & 0xff, uses >> 8, ...genesis, ...u32(seq)]));
        checkpoint();
      } else if (sub === 0x12) {
        const id = arg[0] | (arg[1] << 8);
        const i = live.indexOf(id);
        if (i < 0) return emit(status(0x07));
        live.splice(i, 1);
        emit(status(0x00));
      } else if (sub === 0x05) {
        if (restoring) return emit(status(0x0e));
        emit(seqHead());
      } else if (sub === 0x23) {
        /* R26: 46 bytes, zero-filled to a link; the next seq, welding onto the TENTATIVE head */
        if (!restoring) return emit(status(0x10));
        tent ??= { head, links: [] };
        const link = new Uint8Array(64);
        link.set(arg.slice(0, 46));
        const f = chain.decodeLink(link);
        if (f.seq !== held.length + tent.links.length) return emit(status(0x0f));
        const h2 = chain.weld(tent.head, link);
        if (!same(h2.slice(0, 8), arg.slice(46, 54))) return emit(status(0x0f));
        tent.head = h2;
        tent.links.push({ link, head: h2 });
        emit(status(0x00));
      } else if (sub === 0x24) {
        const seq = arg[0] | (arg[1] << 8) | (arg[2] << 16) | (arg[3] << 24);
        const ok = tent && seq === held.length + tent.links.length - 1 && same(arg.slice(4, 20), tagOf(seq, tent.head));
        if (ok) { held.push(...tent.links); head = tent.head; }
        tent = null;
        restoring = false;
        if (!ok) return emit(status(0x11));
        emit(seqHead());
      } else {
        emit(status(0x0a));
      }
    },
  };
  transport.writes = writes;
  transport.armed = () => armed;
  return transport;
}

function edgeOver(transport) {
  let edge = null;
  setup({ transport }, (err, services) => { if (err) throw err; edge = services.edge; });
  return edge;
}

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

test('edge: EDGE:xx refusals become named errors', async () => {
  const edge = edgeOver(fakeKey());
  await assert.rejects(edge.revoke(99), (e) => e instanceof edge.EdgeError && e.status === 'no-such-budget' && e.code === 7);
  await assert.rejects(edge.ticket(5, 0, new Uint8Array(32)), (e) => e.status === 'no-ticket-waiting');
  await assert.rejects(edge.pickup(3, 1), (e) => e.status === 'not-held');
  await assert.rejects(edge.grant({ scopes: [{ op: 1, slot: 2, cap: 200 }, { op: 1, slot: 3, cap: 100 }], reasonHash: new Uint8Array(32), verifiedHead: new Uint8Array(32) }),
    (e) => e.status === 'too-many-uses' || /255/.test(e.message));
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
  await assert.rejects(edge.replay(chain.encodeLink({ seq: 2, op: 1, decision: 2, subject: new Uint8Array(32), reserved: new Uint8Array(18).fill(1) }), new Uint8Array(32)),
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
