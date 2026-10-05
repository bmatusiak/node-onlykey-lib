'use strict';

/*
 * A fake Edge key: answers OKEDGE sub-ops the way the soft-key firmware plugin
 * does (ok-rn/android/okemu/plugins/edge) - the same report layouts, the same
 * "EDGE:xx" codes, a real P-256 key for the checkpoints. Moved out of
 * edge-device.test.js so the L7 tests (edge-l7.test.js) share it.
 *
 * transport.use(bytes) stands in for a sign the KEY decides (L7, 2026-10-03):
 * it pays when the ARM token matches this head and these bytes and a live
 * budget off hold has room (a self-press link with its reveal), and otherwise
 * it is a pressed use - as okplugin_edge_primed / _decision do.
 */
const { chain, codes, grants, tickets } = require('../../src/edge');
const { H } = require('../../src/edge/hash');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { IFACE } = require('../../src/protocol/msg');
const setup = require('../../plugins/edge');

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
  const peers = []; /* R20: X || Y, in index order */
  let peerX = null; /* PEER_ADD part 0, until part 1 */
  const live = [];
  const onHold = new Set();
  let owed = [];
  let armed = false;
  let refusedArms = 0; /* B7 stage 2: HEAD byte 60, as the firmware counts them */
  const writes = [];
  const emit = (r) => setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: r })), delay);
  const budgets = new Map(); /* id -> {uses, used, seed}: what a live budget can still pay */
  const same = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
  const append = (fields, reveal = null) => {
    const seq = held.length;
    const link = chain.encodeLink({ seq, ...fields });
    head = chain.weld(head, link);
    held.push({ link, head, reveal });
    armed = false; /* R13a: any link clears the arm */
    return seq;
  };
  const checkpoint = () => {
    const seq = held.length - 1;
    const sig = chain.signCheckpoint({ deviceId: DEVICE, seq, head }, SECRET);
    emit(report([...u32(seq), ...head]));
    emit(report([...sig]));
  };
  /* one approved use that owes (R16: the key marked it owes_ticket - a pressed use on a covered slot), so there is something to pick up and ticket */
  append({ op: codes.OP.SIGN, decision: codes.DECISION.APPROVE, slot: 2, flags: codes.FLAG.PRESS_OBSERVED | codes.FLAG.OWES_TICKET, subject: new Uint8Array(32).fill(9) });
  owed = [0];
  /* the fake's vouch tag: any MAC the fake can recompute (a real key keys it with K_vouch) */
  const tagOf = (seq, h) => require('node:crypto').createHmac('sha256', 'fake K_vouch').update(Buffer.concat([Buffer.from(u32(seq)), Buffer.from(h)])).digest().subarray(0, 16);
  const seqHead = () => report([...u32(held.length - 1), ...head, ...tagOf(held.length - 1, head)]);
  let tent = null; /* R26: the tentative replay */
  let staged = {}; /* R11a: GRANT_LABEL's labels, by scope index, for the next GRANT_CREATE */

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
        emit(report([...u32(held.length - 1), ...head, ...u32(0), ...ids.flatMap(u32), mask, owed.length, 0, restoring ? 1 : 0, refusedArms]));
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
          emit(report([...held[s].head, ...(held[s].reveal || new Uint8Array(32))]));
        }
      } else if (sub === 0x20) {
        const ref = arg[0] | (arg[1] << 8);
        if (!owed.includes(ref)) return emit(status(0x08));
        append({ op: codes.OP.TICKET, decision: arg[4], subject: new Uint8Array(32), grantId: ref });
        owed = owed.filter((q) => q !== ref);
        emit(seqHead());
      } else if (sub === 0x22) {
        /* R13a: a token over head + the request's subject; the fake keeps it (a real key checks it at the sign) */
        if (owed.length) { refusedArms = Math.min(255, refusedArms + 1); return emit(status(0x0c)); }
        /* as the firmware's any_budget_payable: live, off hold, with uses left */
        if (!live.some((id) => !onHold.has(id) && (!budgets.has(id) || budgets.get(id).used < budgets.get(id).uses))) { refusedArms = Math.min(255, refusedArms + 1); return emit(status(0x0d)); }
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
      } else if (sub === 0x11) {
        /* R11a: GRANT_LABEL {scope index, label 32} - no press, staged for the next GRANT_CREATE */
        if (arg[0] >= 4) return emit(status(0x02));
        staged[arg[0]] = Uint8Array.from(arg.slice(1, 33));
        emit(status(0x00));
      } else if (sub === 0x10) {
        const n = arg[0];
        const scopes = Array.from({ length: n }, (_, j) => ({ op: arg[1 + 4 * j], slot: arg[2 + 4 * j], cap: arg[3 + 4 * j] | (arg[4 + 4 * j] << 8) }));
        const labels = staged;
        staged = {}; /* consumed by this GRANT_CREATE */
        for (let j = 0; j < n; j++) {
          if (!grants.isDerivedCode(scopes[j].slot)) continue;
          if (!labels[j]) return emit(status(0x03)); /* R11a: a derived code must name its identity */
          scopes[j].label = labels[j];
        }
        const uses = scopes.reduce((a, s) => a + s.cap, 0);
        if (uses > 1024) return emit(status(0x04));
        if (owed.length) return emit(status(0x0c));
        if (!same(arg.slice(52, 58), head.slice(0, 6))) return emit(status(0x0b)); /* R27: the verified head */
        const lifetime = arg[50] | (arg[51] << 8);
        const genesis = grants.grantGenesis(new Uint8Array(32).fill(3), uses);
        const seq = held.length;
        const id = seq + 1;
        append({ op: codes.OP.GRANT_CREATE, decision: 1, flags: 1, grantId: id, scope: n, /* R3: the scope count */
          subject: grants.grantSubject({ scopes, reasonHash: arg.slice(17, 49), genesis, lifetime }) });
        live.push(id);
        budgets.set(id, { uses, used: 0, seed: new Uint8Array(32).fill(3), scopes });
        emit(report([...u32(id), uses & 0xff, uses >> 8, ...genesis, ...u32(seq)]));
        checkpoint();
      } else if (sub === 0x12) {
        const id = arg[0] | (arg[1] << 8);
        const i = live.indexOf(id);
        if (i < 0) return emit(status(0x07));
        live.splice(i, 1);
        budgets.delete(id);
        emit(status(0x00));
      } else if (sub === 0x34) {
        /* R24: {from, to}, pressed; refused while restoring or past the head */
        if (restoring) return emit(status(0x0e));
        const from = arg[0] | (arg[1] << 8), to = arg[4] | (arg[5] << 8);
        if (from > to || to > held.length - 1) return emit(status(0x12));
        const subject = new Uint8Array(32);
        subject.set(u32(to), 0);
        /* R24: the link after the range, when the key still holds it (its latest, or the ring of 8) */
        const next = to + 1;
        if (next <= held.length - 1 && next >= held.length - 8) subject.set(H(held[next].link).slice(0, 28), 4);
        append({ op: codes.OP.LOSS, decision: 1, flags: 1, grantId: from, subject });
        emit(seqHead());
      } else if (sub === 0x15) {
        /* 4.7a AGENT_ADD {agent key}, pressed; refused while restoring */
        if (restoring) return emit(status(0x0e));
        append({ op: codes.OP.AGENT_ADD, decision: 1, flags: 1, grantId: 0, subject: grants.agentSubject(arg.slice(0, 32)) });
        emit(seqHead());
      } else if (sub === 0x30) {
        /* R20 PEER_ADD: {0, X} staged, then {1, Y} pressed; refused while restoring, full, known or not a point */
        if (restoring) return emit(status(0x0e));
        if (arg[0] === 0) { peerX = arg.slice(1, 33); return emit(status(0x00)); }
        if (arg[0] !== 1 || !peerX) return emit(status(0x15));
        const xy = Uint8Array.from([...peerX, ...arg.slice(1, 33)]);
        peerX = null;
        try { p256.Point.fromBytes(Uint8Array.from([4, ...xy])).assertValidity(); } catch { return emit(status(0x15)); }
        if (peers.some((p) => same(p, xy))) return emit(status(0x14));
        if (peers.length >= 4) return emit(status(0x13));
        append({ op: codes.OP.PEER_ADD, decision: 1, flags: 1, slot: peers.length, grantId: 0, subject: grants.peerSubject(xy) });
        peers.push(xy);
        emit(seqHead());
      } else if (sub === 0x31) {
        /* R20 PEER_REMOVE {index}, pressed */
        if (restoring) return emit(status(0x0e));
        const i = arg[0];
        if (i >= peers.length) return emit(status(0x16));
        append({ op: codes.OP.PEER_REMOVE, decision: 1, flags: 1, slot: i, grantId: 0, subject: grants.peerSubject(peers[i]) });
        peers.splice(i, 1);
        emit(seqHead());
      } else if (sub === 0x32) {
        /* R20 PEER_LIST: header, then one report per slot - X || Y, zeros when empty */
        emit(report([peers.length, 0, 4]));
        for (let i = 0; i < 4; i++) emit(report(i < peers.length ? [...peers[i]] : []));
      } else if (sub === 0x05) {
        if (restoring) return emit(status(0x0e));
        emit(seqHead());
      } else if (sub === 0x23) {
        /* R26: 47 bytes (R3: through the scope byte), zero-filled to a link; the next seq, welding onto the TENTATIVE head */
        if (!restoring) return emit(status(0x10));
        tent ??= { head, links: [] };
        const link = new Uint8Array(64);
        link.set(arg.slice(0, 47));
        const f = chain.decodeLink(link);
        if (f.seq !== held.length + tent.links.length) return emit(status(0x0f));
        const h2 = chain.weld(tent.head, link);
        if (!same(h2.slice(0, 8), arg.slice(47, 55))) return emit(status(0x0f));
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
  /* the soft key's idle restart / a lock: live budgets live in RAM and are gone, with no link written */
  transport.restart = () => { live.length = 0; onHold.clear(); };
  /*
   * A sign the KEY decides (okplugin_edge_primed / _decision): it pays when the
   * ARM token is over THIS head and THESE bytes and a live budget off hold has
   * room - a self-press link with its reveal - and otherwise it is a pressed
   * use - owing when an arm was waiting, or when a live budget covers the
   * slot (R16: the agent's key used outside Edge; the fake matches the slot,
   * not the label).
   */
  transport.use = (bytes, { slot = 2 } = {}) => {
    const subject = grants.requestSubject(Uint8Array.from(bytes));
    const wasArmed = Boolean(armed);
    const match = wasArmed && same(armed, grants.armToken({ head, subject }));
    const id = match && !owed.length ? live.find((i) => !onHold.has(i) && budgets.get(i).used < budgets.get(i).uses) : null;
    if (id) {
      const b = budgets.get(id);
      b.used += 1;
      /* R3: byte 46 - the first of its scopes that covers this sign and has room (the firmware's budget_for) */
      const scopes = b.scopes || [];
      b.scopeUsed = b.scopeUsed || scopes.map(() => 0);
      /* the label too, as R11a: an agent request ends with its 32-byte identity label */
      const tail = Uint8Array.from(bytes).slice(-32);
      const labelOk = (sc) => !sc.label || same(Uint8Array.from(sc.label), tail.slice(0, sc.label.length));
      let si = scopes.findIndex((sc, j) => sc.op === codes.OP.SIGN && sc.slot === slot && labelOk(sc) && b.scopeUsed[j] < sc.cap);
      if (si < 0) si = 0;
      b.scopeUsed[si] += 1;
      const F = codes.FLAG;
      const seq = append({ op: codes.OP.SIGN, decision: codes.DECISION.SELF_PRESS, slot, flags: F.BUDGET_SPENT | F.OWES_TICKET | F.ARMED,
        subject, grantId: id, grantStep: b.used, scope: scopes.length ? si + 1 : 0 }, grants.reveal(b.seed, b.uses, b.used));
      owed.push(seq);
      return { seq, paid: true };
    }
    const F = codes.FLAG;
    const covered = live.some((i) => (budgets.get(i).scopes || []).some((sc) => sc.op === codes.OP.SIGN && sc.slot === slot));
    const owes = wasArmed || covered;
    const seq = append({ op: codes.OP.SIGN, decision: codes.DECISION.APPROVE, slot, subject,
      flags: F.PRESS_OBSERVED | (owes ? F.OWES_TICKET : 0) | (wasArmed ? F.ARMED : 0) });
    if (owes) owed.push(seq);
    return { seq, paid: false };
  };
  return transport;
}

function edgeOver(transport) {
  let edge = null;
  setup({ transport }, (err, services) => { if (err) throw err; edge = services.edge; });
  return edge;
}


module.exports = { fakeKey, edgeOver, SECRET, PUB, DEVICE, report, status, u32 };
