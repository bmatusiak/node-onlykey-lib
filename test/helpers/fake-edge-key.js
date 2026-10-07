'use strict';
const okmsg = require('../../src/protocol/okmsg');

/*
 * A fake Edge key: answers OKEDGE sub-ops the way the soft-key firmware plugin
 * does (ok-rn/android/okemu/plugins/edge) - the same report layouts, the same
 * "EDGE:xx" codes, a real P-256 key for the checkpoints. Moved out of
 * edge-device.test.js so the L7 tests (edge-l7.test.js) share it.
 *
 * transport.use(bytes) stands in for a sign the KEY decides (L7, 2026-10-03):
 * it pays when the TX start token matches this head and these bytes and a live
 * budget off hold has room (a self-press link with its reveal), and otherwise
 * it is a pressed use - as okplugin_edge_primed / _decision do.
 */
const { chain, codes, grants, tickets } = require('../../src/edge');
const { H } = require('../../src/edge/hash');
const { sha256 } = require('../../src/vendor/exports/@noble/hashes/sha2.js');
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
function fakeKey({ silent = false, noPin = false, delay = 1, restoring = false, secret = SECRET, intentCap = true } = {}) {
  /* each fake key its own Edge key (R29 siblings need two) - SECRET by default */
  const myPub = p256.getPublicKey(secret, false).slice(1);
  const myDevice = chain.deviceIdOf(myPub);
  const listeners = new Set();
  let head = chain.genesis(myDevice);
  const held = [];
  const peers = []; /* R20: X || Y, in index order */
  let peerX = null; /* PEER_ADD part 0, until part 1 */
  const siblings = []; /* R29: X || Y */
  let anchorParts = null; /* R30: ANCHOR parts 0-1, until part 2 */
  let sibX = null;
  let syncParts = 0; /* SYNC's parts received, in order */
  let syncFields = [];
  const live = [];
  const onHold = new Set();
  let owed = [];
  let started = false;
  /* R13a (2026-10-06): a TX start voided by a later link, kept with the head it was made over - its request is refused at the sign */
  let voided = null;
  let startedIntent = null; /* R13b: the intent a v2 start carried */
  let replayIntent = null; /* R13b: staged by REPLAY_INTENT for the next REPLAY */
  let refusedTx = 0; /* B7 stage 2: HEAD byte 60, as the firmware counts them */
  const writes = [];
  const emit = (r) => setTimeout(() => listeners.forEach((l) => l({ iface: IFACE.VENDOR, data: r })), delay);
  const budgets = new Map(); /* id -> {uses, used, seed}: what a live budget can still pay */
  const same = (a, b) => Buffer.compare(Buffer.from(a), Buffer.from(b)) === 0;
  const append = (fields, reveal = null) => {
    const seq = held.length;
    /* R3: every link this key writes is version 1 (unless a test builds an old one) */
    const link = chain.encodeLink({ seq, version: 1, ...fields });
    if (started && fields.decision !== codes.DECISION.SELF_PRESS) voided = { token: started, intent: startedIntent, head };
    head = chain.weld(head, link);
    held.push({ link, head, reveal });
    started = false; /* R13a: any link clears the TX start */
    return seq;
  };
  const checkpoint = () => {
    const seq = held.length - 1;
    const sig = chain.signCheckpoint({ deviceId: myDevice, seq, head }, secret);
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
        emit(report([...u32(held.length - 1), ...head, ...u32(0), ...ids.flatMap(u32), mask, owed.length, 0, restoring ? 1 : 0, refusedTx, intentCap ? 1 : 0]));
      } else if (sub === 0x04) {
        emit(report([...myPub]));
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
        if (owed.length) { refusedTx = Math.min(255, refusedTx + 1); return emit(status(0x0c)); }
        /* as the firmware's any_budget_payable: live, off hold, with uses left */
        /* R13b, budget or no go (Brad, 2026-10-06): with or without an intent, refused unless a budget can pay */
        if (!live.some((id) => !onHold.has(id) && (!budgets.has(id) || budgets.get(id).used < budgets.get(id).uses))) { refusedTx = Math.min(255, refusedTx + 1); return emit(status(0x0d)); }
        started = arg.slice(0, 32);
        voided = null; /* a new TX start replaces a voided one */
        /* R13b: a v2 start carries its intent; zeros = v1 */
        startedIntent = arg.slice(32, 48).some((x) => x) ? arg.slice(32, 48) : null;
        emit(status(0x00));
      } else if (sub === 0x13 || sub === 0x14) {
        const id = arg[0] | (arg[1] << 8);
        if (!live.includes(id)) return emit(status(0x07));
        if (sub === 0x14 && owed.length) return emit(status(0x0c));
        if (sub === 0x14 && !same(arg.slice(4, 36), head)) return emit(status(0x0b));
        if (sub === 0x13) onHold.add(id); else onHold.delete(id);
        /* as the firmware: hold and resume are links (grant-hold / grant-resume) */
        append({ op: sub === 0x13 ? codes.OP.GRANT_HOLD : codes.OP.GRANT_RESUME, decision: codes.DECISION.APPROVE, slot: 0, flags: sub === 0x14 ? codes.FLAG.PRESS_OBSERVED : 0, grantId: id, subject: new Uint8Array(32) });
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
      } else if (sub === 0x35) {
        /* R29 SIBLING_ADD: {0, X} staged, then {1, Y, id} pressed; refused: itself, a wrong id, known, full */
        if (restoring) return emit(status(0x0e));
        if (arg[0] === 0) { sibX = arg.slice(1, 33); return emit(status(0x00)); }
        if (arg[0] !== 1 || !sibX) return emit(status(0x15));
        const xy = Uint8Array.from([...sibX, ...arg.slice(1, 33)]);
        const id = arg.slice(33, 49);
        sibX = null;
        try { p256.Point.fromBytes(Uint8Array.from([4, ...xy])).assertValidity(); } catch { return emit(status(0x15)); }
        if (!same(chain.deviceIdOf(xy), id) || same(xy, myPub)) return emit(status(0x15));
        if (siblings.some((k) => same(k, xy))) return emit(status(0x18));
        if (siblings.length >= 4) return emit(status(0x19));
        append({ op: codes.OP.SIBLING_ADD, decision: 1, flags: 1, grantId: 0, subject: grants.siblingSubject(xy, id) });
        siblings.push(xy);
        emit(seqHead());
      } else if (sub === 0x36) {
        if (restoring) return emit(status(0x0e));
        const i = arg[0];
        if (i >= siblings.length) return emit(status(0x1a));
        append({ op: codes.OP.SIBLING_REMOVE, decision: 1, flags: 1, grantId: 0, subject: grants.siblingSubject(siblings[i], chain.deviceIdOf(siblings[i])) });
        siblings.splice(i, 1);
        emit(seqHead());
      } else if (sub === 0x38) {
        /* R30 ANCHOR: {0, index, seq, head}, {1, r}, {2, s} -> the checkpoint checked under that sibling's key, pressed */
        if (restoring) { anchorParts = null; return emit(status(0x0e)); }
        if (arg[0] === 0) {
          anchorParts = null;
          if (arg[1] >= siblings.length) return emit(status(0x1a));
          anchorParts = { index: arg[1], seq: arg[2] | (arg[3] << 8) | (arg[4] << 16) | (arg[5] << 24), head: arg.slice(6, 38) };
          return emit(status(0x00));
        }
        if (arg[0] === 1 && anchorParts && !anchorParts.r) { anchorParts.r = arg.slice(1, 33); return emit(status(0x00)); }
        if (arg[0] !== 2 || !anchorParts || !anchorParts.r) { anchorParts = null; return emit(status(0x17)); }
        const a = anchorParts;
        anchorParts = null;
        const sib = siblings[a.index];
        const deviceId = chain.deviceIdOf(sib);
        const signature = Uint8Array.from([...a.r, ...arg.slice(1, 33)]);
        if (!chain.verifyCheckpoint({ deviceId, seq: a.seq >>> 0, head: a.head }, signature, sib)) return emit(status(0x1b));
        append({ op: codes.OP.ANCHOR, decision: 1, flags: 1, slot: a.index, grantId: a.seq >>> 0, subject: grants.anchorSubject({ deviceId, seq: a.seq >>> 0, head: a.head, signature }) });
        emit(seqHead());
      } else if (sub === 0x37) {
        emit(report([siblings.length, 4]));
        for (let i = 0; i < 4; i++) emit(report(i < siblings.length ? [...siblings[i]] : []));
      } else if (sub === 0x39) {
        /*
         * sync phase 2, three parts as okplugin_edge: {0, peerHash, first, last} (a peer
         * on the list), {1, head}, {2, keychain}, then pressed; the KEY hashes the subject
         */
        if (restoring) { syncParts = 0; return emit(status(0x0e)); }
        const part = arg[0];
        if (part === 0) {
          syncParts = 0;
          if (!peers.some((p) => same(sha256(p), arg.slice(1, 33)))) return emit(status(0x16));
          const u = (o) => (arg[o] | (arg[o + 1] << 8) | (arg[o + 2] << 16) | (arg[o + 3] << 24)) >>> 0;
          if (u(33) > u(37)) return emit(status(0x12));
          syncFields = [arg.slice(1, 41)];
          syncParts = 1;
          return emit(status(0x00));
        }
        if (part === 1 && syncParts === 1) { syncFields.push(arg.slice(1, 33)); syncParts = 2; return emit(status(0x00)); }
        if (part !== 2 || syncParts !== 2) { syncParts = 0; return emit(status(0x17)); }
        syncParts = 0;
        const subject = H('OKEDGE-SYNC-v1', ...syncFields, arg.slice(1, 33));
        append({ op: codes.OP.SYNC, decision: 1, flags: 1, grantId: 0, subject });
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
      } else if (sub === 0x25) {
        /* R13b + R26: stage the next REPLAY's intent */
        if (!restoring) return emit(status(0x10));
        replayIntent = arg.slice(0, 16);
        emit(status(0x00));
      } else if (sub === 0x23) {
        /* R26: 47 bytes (R3: through the scope byte), zero-filled to a link; the next seq, welding onto the TENTATIVE head */
        if (!restoring) return emit(status(0x10));
        tent ??= { head, links: [] };
        const link = new Uint8Array(64);
        link.set(arg.slice(0, 47));
        /* R13b: the intent REPLAY_INTENT staged, for a sign/decrypt link; R3: the version byte after the head check */
        if (replayIntent && (link[4] === codes.OP.SIGN || link[4] === codes.OP.DECRYPT)) link.set(replayIntent, 47);
        replayIntent = null;
        link[63] = arg[55];
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
  transport.started = () => started;
  /* a test link that IS Edge's own (an approved sync, no ticket owed) - ordinary presses write none (2026-10-06) */
  transport.edgeRecord = () => append({ op: codes.OP.SYNC, decision: codes.DECISION.APPROVE, slot: 0, flags: codes.FLAG.PRESS_OBSERVED, subject: require('node:crypto').randomBytes(32) });
  /* the soft key's idle restart / a lock: live budgets live in RAM and are gone, with no link written */
  transport.restart = () => { live.length = 0; onHold.clear(); };
  /*
   * A sign the KEY decides (okplugin_edge_primed / _decision / _refused): it pays
   * when the TX start token is over THIS head and THESE bytes and a live budget off
   * hold has room - a self-press link with its reveal. A sign that does not match
   * a waiting TX start is REFUSED (R13a, 2026-10-06: EDGE:1C, the TX start used up, counted
   * in HEAD byte 60). Anything else is an ordinary press: not Edge, NO link, owes
   * nothing (spec session, 2026-10-06). -> {seq, paid} or {seq: null, paid: false}
   */
  transport.use = (bytes, { slot = 2 } = {}) => {
    const subject = grants.requestSubject(Uint8Array.from(bytes));
    const wasStarted = Boolean(started);
    const intent = startedIntent;
    const match = wasStarted && same(started, grants.txToken({ head, subject, intent }));
    /* R13a: the request whose TX start a later link voided (a hold in between) - refused, never pressed */
    if (!wasStarted && voided) {
      const v = voided;
      voided = null;
      if (same(v.token, grants.txToken({ head: v.head, subject, intent: v.intent }))) {
        refusedTx = Math.min(255, refusedTx + 1);
        throw okmsg.deviceError('EDGE:0D');
      }
    }
    const id = match && !owed.length ? live.find((i) => !onHold.has(i) && budgets.get(i).used < budgets.get(i).uses) : null;
    /* R13a (2026-10-06): the announced request, but no budget can pay it now (held, ended, expired) - refused, never pressed */
    if (match && !id) {
      started = false;
      startedIntent = null;
      refusedTx = Math.min(255, refusedTx + 1);
      throw okmsg.deviceError('EDGE:0D');
    }
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
      const seq = append({ op: codes.OP.SIGN, decision: codes.DECISION.SELF_PRESS, slot, flags: F.BUDGET_SPENT | F.OWES_TICKET | F.STARTED,
        subject, grantId: id, grantStep: b.used, scope: scopes.length ? si + 1 : 0, ...(intent ? { intent } : {}) }, grants.reveal(b.seed, b.uses, b.used));
      owed.push(seq);
      return { seq, paid: true };
    }
    started = false;
    startedIntent = null;
    if (wasStarted && !match) {
      refusedTx = Math.min(255, refusedTx + 1);
      throw okmsg.deviceError('EDGE:1C');
    }
    return { seq: null, paid: false };
  };
  return transport;
}

function edgeOver(transport) {
  let edge = null;
  setup({ transport }, (err, services) => { if (err) throw err; edge = services.edge; });
  return edge;
}


module.exports = { fakeKey, edgeOver, SECRET, PUB, DEVICE, report, status, u32 };
