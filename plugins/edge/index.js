/*
 * edge - the device calls for OnlyKey Edge (spec okrn-edge-tab.md L4/L5).
 *
 * The firmware half is minimal by design (owner, 2026-10-02): the key is a
 * notary that welds each decision, decides budget self-presses, makes one
 * kind of signature (a checkpoint) and links tickets. This plugin is the thin
 * wire layer over it; everything else - verifying, storing, pairing tickets,
 * tracking budgets - is ../../src/edge, which these calls feed.
 *
 * Wire: OKEDGE = 0xF8, sub-op in byte 5, arguments from byte 6 (okmsg.build
 * with `slot` = the sub-op). Text replies are "EDGE:xx" status codes only
 * (codes.STATUS); every other reply is binary, 64-byte reports.
 *
 * REMOVABLE, like the firmware plugin: nothing else in the library depends on
 * it, and a host that never composes it never sends 0xF8. Edge exists only on
 * soft keys and emulators built with the edge plugin, so a host decides to
 * use this from what IT knows about the key (ok-rn's buildInfo, a user's
 * setting) - see probe() for why the library does not guess.
 */
'use strict';
const { inLane } = require('../../src/transport/lane');

const okmsg = require('../../src/protocol/okmsg');
const { IFACE } = require('../../src/protocol/msg');
const { assertTransport } = require('../../src/transport/contract');
const { concat } = require('../../src/bytes');
const { codes, chain, tickets, copy: copyCheck } = require('../../src/edge');

const OKEDGE = 0xf8;
const SUB = Object.freeze({
  HEAD: 0x01, PICKUP: 0x02, CHECKPOINT: 0x03, PUBKEY: 0x04, VOUCH: 0x05,
  GRANT_CREATE: 0x10, GRANT_LABEL: 0x11, GRANT_REVOKE: 0x12, GRANT_HOLD: 0x13, GRANT_RESUME: 0x14,
  TICKET: 0x20, WAIVE: 0x21, ARM: 0x22, REPLAY: 0x23, REPLAY_DONE: 0x24, LOSS: 0x34,
  AGENT_ADD: 0x15,
});
/*
 * CHOSEN (pending the spec, 2026-10-02): a vendor report carries 58 argument
 * bytes. GRANT_CREATE (spec layout, 2026-10-02): [49] flags, [50..51] the
 * lifetime (u16 LE minutes, R15b), [52..57] the first 6 bytes of the verified
 * head (R27). CHOSEN, pending the spec: REPLAY the link's first 46 bytes (bytes 46-63 are
 * reserved and zero in every link a key writes; the key fills them back) plus
 * the first 8 bytes of the head the copy stored after it - the key's only way
 * to tell that the link welds where the copy says it does.
 */
const GRANT_HEAD_BYTES = 6;
/* R26: the vouch tag - HMAC-SHA256(K_vouch, "OKEDGE-VOUCH-v1" || seq || head), first 16 bytes */
const VOUCH_BYTES = 16;
/* seq . head . tag: TICKET's, WAIVE's, VOUCH's and REPLAY_DONE's answer */
const seqHeadTag = (r) => ({ seq: (r[0] | (r[1] << 8) | (r[2] << 16) | (r[3] << 24)) >>> 0, head: r.slice(4, 36), tag: r.slice(36, 36 + VOUCH_BYTES) });
/* R3: through byte 46 (the scope that paid); 47-63 stay reserved zero */
const REPLAY_BYTES = 47;
const REPLAY_HEAD_BYTES = 8;
const SEQ_NONE = 0xffffffff;
const HELD = 8;

/** A refusal from the key: `code` and `name` from codes.STATUS. */
class EdgeError extends Error {
  constructor(status) {
    super(status.text);
    this.name = 'EdgeError';
    this.code = status.code;
    this.status = status.name;
  }
}

const u32 = (n) => Uint8Array.of(n & 0xff, (n >>> 8) & 0xff, (n >>> 16) & 0xff, (n >>> 24) & 0xff);
const get32 = (b, o) => (b[o] | (b[o + 1] << 8) | (b[o + 2] << 16) | (b[o + 3] << 24)) >>> 0;
const get16 = (b, o) => b[o] | (b[o + 1] << 8);
const sameBytes = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

/*
 * Is this report a HEAD answer? The key pads its 60 bytes with zeros and its
 * flags are small: four zero bytes, a 4-bit hold mask, owed <= OWED_MAX, two
 * booleans. A signature passes all of that about once in 2^40.
 */
function isHeadReply(r) {
  if (r.length < 64 || r[60] | r[61] | r[62] | r[63]) return false;
  return r[56] < 16 && r[57] <= tickets.OWED_MAX && r[58] <= 1 && r[59] <= 1;
}

/*
 * PICKUP's answer, report by report: each link is the seq asked for, with its 17
 * reserved bytes zero (R3), and from the second link on, the head after it must
 * weld from the head before. The first head has nothing to weld from here; the
 * copy's own weld check is its test.
 */
function pickupReply(from) {
  return (bytes, got) => {
    const i = got.length;
    if (i % 2 === 0) {
      const f = chain.decodeLink(bytes);
      return f.reservedZero && f.seq === from + i / 2;
    }
    if (i < 3) return true;
    return sameBytes(chain.weld(got[i - 2].slice(0, 32), got[i - 1]), bytes.slice(0, 32));
  };
}

function setup(imports, register) {
  const { transport } = imports;
  assertTransport(transport, 'transport (consumed by edge)');

  /*
   * Send one OKEDGE request and collect `reports` vendor reports. Subscribe
   * BEFORE writing (contract.js: a fast key answers before a late listener),
   * and stop at the first "EDGE:xx" - a refusal comes instead of the data.
   * Nothing but our answer is expected right after the write; a report that
   * is not ours (a locked key's INITIALIZED broadcast) is skipped.
   */
  /*
   * Resolve once no vendor report has arrived for `quietMs` (capped).
   *
   * WHY, MEASURED ON THE PIXEL SOFT KEY: the key answers an agent sign with a
   * report AFTER the signature that okcrypto's reader does not take, and the
   * next Edge request took it as its own answer - a HEAD came back naming link
   * 0xB1790C02, and the PICKUP that followed was refused. Every OKEDGE reply is
   * binary with no marker to match on, so the only safe order is: let the bus
   * go quiet, subscribe, write. (The device plugin's busQuiet, for the same
   * reason: this bus carries traffic nobody asked for.)
   */
  function busQuiet(quietMs = 150, capMs = 1500) {
    return new Promise((resolve) => {
      let timer = null;
      const finish = () => { clearTimeout(timer); clearTimeout(giveUp); off(); resolve(); };
      const giveUp = setTimeout(finish, capMs);
      const off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        clearTimeout(timer);
        timer = setTimeout(finish, quietMs);
      });
      timer = setTimeout(finish, quietMs);
    });
  }

  /*
   * ONE EDGE REQUEST AT A TIME. Every OKEDGE reply is binary with no marker,
   * and callNow takes the next vendor reports as its own - so two requests in
   * flight on one stack swap answers. MEASURED ON THE PIXEL (2026-10-03): the
   * app's background copy ran a PICKUP while an e2e test waited for its
   * GRANT_CREATE, and the grant read link bytes as its answer ("budget
   * 2381801293: 3618 uses, opened at #4229928469"). busQuiet alone cannot stop
   * it: both callers see a quiet bus, then both write. So every request - the
   * pressed ones for their whole wait - runs after the one before it settles.
   */
  /* the KEY's lane, shared with every other plugin (src/transport/lane.js) - not one of Edge's own */
  function exclusive(fn) {
    return inLane(transport, fn);
  }

  function call(sub, args, opts = {}) {
    return exclusive(async () => {
      await busQuiet();
      return callNow(sub, args, opts);
    });
  }

  /* a request the key answers only after a physical press: onPress once it is written */
  function pressed(sub, args, opts, onPress) {
    return exclusive(async () => {
      await busQuiet();
      const pending = callNow(sub, args, opts); /* written synchronously */
      if (onPress) onPress(); /* the request is on the key: now ask for the press */
      return pending;
    });
  }

  /*
   * `accept(bytes, got)`: false = not ours, keep waiting. The vendor channel is
   * shared with a computer on the Bluetooth bridge, and its answers reach every
   * listener on this stack: a pressed ssh sign answers when the press lands,
   * long after the bus went quiet. MEASURED ON THE A13 (2026-10-04): Brad's
   * signature arrived while the tab's PICKUP waited, and the copy stored it as
   * link #447194052 - above the key's head, so the copy read as a rollback and
   * Sync, starting past it, read nothing. Replies whose shape can be checked
   * are checked; a report that fails is someone else's.
   */
  function callNow(sub, args, { reports = 1, timeoutMs = 6000, text = false, accept = null } = {}) {
    return new Promise((resolve, reject) => {
      const got = [];
      let off = null;
      const timer = setTimeout(() => {
        off();
        reject(Object.assign(new Error(`Edge: no answer to request ${sub} within ${timeoutMs} ms`), { code: 'ETIMEDOUT' }));
      }, timeoutMs);
      off = transport.on('report', (event) => {
        if (event.iface !== IFACE.VENDOR) return;
        const bytes = event.data instanceof Uint8Array ? event.data : Uint8Array.from(event.data);
        const status = codes.parseStatus(okmsg.text(bytes));
        if (status) {
          clearTimeout(timer);
          off();
          if (status.code === 0 && text) resolve(status);
          else if (status.code === 0) resolve(got);
          else reject(new EdgeError(status));
          return;
        }
        if (/^(UNLOCKED|INITIALIZED)/.test(okmsg.text(bytes))) return; /* a status broadcast, not ours */
        /*
         * The key gave up waiting for the press: the firmware says so in a
         * sentence ("Timeout occured while waiting for confirmation on
         * OnlyKey"), not an EDGE status. Taken as an answer, it was parsed as
         * a seq . head and the caller went looking for a link that was never
         * written (a registration's sheet sat on "Press" for good, 2026-10-03).
         */
        if (/^Timeout/i.test(okmsg.text(bytes))) {
          clearTimeout(timer);
          off();
          reject(Object.assign(new Error(`Edge: the key stopped waiting for the press (request ${sub})`), { code: 'ETIMEDOUT', pressTimeout: true }));
          return;
        }
        if (text) return;
        if (accept && !accept(bytes, got)) return;
        got.push(bytes);
        if (got.length >= reports) {
          clearTimeout(timer);
          off();
          resolve(got);
        }
      });
      try {
        transport.write(IFACE.VENDOR, okmsg.build({ msg: OKEDGE, slot: sub, payload: args || [] }));
      } catch (e) {
        clearTimeout(timer);
        off();
        reject(e);
      }
    });
  }

  const edge = {
    SUB,
    EdgeError,

    /**
     * {seq (null = no link yet), head, oldest (oldest pickable seq, or null),
     *  live: [budget ids], held: [the live ids on hold (R15a)], owed: number of
     *  uses owing a ticket (R16), overflow: an owed use fell off the key's list,
     *  restoring: restored from a backup and not yet finished (R26)}
     */
    async head(opts) {
      const [r] = await call(SUB.HEAD, null, { ...opts, accept: isHeadReply });
      const seq = get32(r, 0);
      const oldest = get32(r, 36);
      const ids = [0, 1, 2, 3].map((i) => get32(r, 40 + 4 * i));
      const mask = r[56];
      return {
        seq: seq === SEQ_NONE ? null : seq,
        head: r.slice(4, 36),
        oldest: oldest === SEQ_NONE ? null : oldest,
        live: ids.filter(Boolean),
        held: ids.filter((id, i) => id && (mask >> i) & 1),
        owed: r[57],
        overflow: Boolean(r[58]),
        restoring: Boolean(r[59]),
      };
    },

    /** The Edge public key (X||Y) and the device id derived from it. */
    async publicKey(opts) {
      const [r] = await call(SUB.PUBKEY, null, opts);
      const publicKey = r.slice(0, 64);
      return { publicKey, deviceId: chain.deviceIdOf(publicKey) };
    },

    /** Links the key still holds: [{link, head, reveal|null}] (reveal = a self-press's v_i). */
    async pickup(from, count = 1, opts) {
      if (count < 1 || count > HELD) throw new RangeError(`Edge: pick up 1 to ${HELD} links, not ${count}`);
      const rs = await call(SUB.PICKUP, concat([u32(from), Uint8Array.of(count)]), { ...opts, reports: 2 * count, accept: pickupReply(from) });
      const out = [];
      for (let i = 0; i < rs.length; i += 2) {
        const reveal = rs[i + 1].slice(32, 64);
        out.push({ link: rs[i], head: rs[i + 1].slice(0, 32), reveal: reveal.some((x) => x) ? reveal : null });
      }
      return out;
    },

    /** The key's one signature: {seq, head, signature} over (device_id, seq, head) - chain.verifyCheckpoint. */
    async checkpoint(opts) {
      const [c, s] = await call(SUB.CHECKPOINT, null, { ...opts, reports: 2 });
      return { seq: get32(c, 0), head: c.slice(4, 36), signature: s.slice(0, 64) };
    },

    /**
     * Ask for a budget. The key waits for a PHYSICAL press (no press, no
     * budget), so the wait is long: `timeoutMs` defaults to 30 s, past the
     * key's own 25 s. `onPress` is called once the request is on the key, for
     * the UI to say "press the key".
     * scopes: [{op, slot, cap}] (1-4, caps summing to <= 1024)
     * verifiedHead: the head the host verified its copy up to (R27); the key
     *   refuses with 'stale-head' when it is not its current head. This is the
     *   raw call: grants.create() runs the copy check first and fails closed.
     * ttlMinutes: the budget's lifetime (R15b), 1..65535; 0 = the key's default
     *   (12 hours). It is in the grant-create subject, so the chain records it.
     * -> {grantId, uses, genesis, lifetime, seq, checkpoint: {seq, head, signature}}
     */
    async grant({ scopes, reasonHash, verifiedHead, ttlMinutes = 0, onPress, timeoutMs = 30000 }) {
      if (!(verifiedHead instanceof Uint8Array) || verifiedHead.length !== 32) throw new TypeError('Edge: grant needs the 32-byte head the host verified (R27)');
      if (!Number.isInteger(ttlMinutes) || ttlMinutes < 0 || ttlMinutes > 0xffff) throw new RangeError(`Edge: ttlMinutes is 0..65535, not ${ttlMinutes}`);
      const { grants: g0 } = require('../../src/edge');
      const enc = g0.encodeScopes(scopes);
      /*
       * R11a: a scope on a derived code names one identity. A GRANT_CREATE
       * report has no room for labels, so each is staged first with
       * GRANT_LABEL {scope index, label} (no press); GRANT_CREATE consumes them
       * and refuses a derived scope without one (EDGE:03).
       */
      for (let j = 0; j < scopes.length; j++) {
        const label = g0.scopeLabel(scopes[j]);
        if (label) await call(SUB.GRANT_LABEL, concat([Uint8Array.of(j), label]), { text: true });
      }
      const args = new Uint8Array(52 + GRANT_HEAD_BYTES);
      args.set(enc, 0); /* count + up to 4 x (op, slot, cap u16) */
      args.set(reasonHash, 17);
      args[49] = 0; /* flags */
      args[50] = ttlMinutes & 0xff;
      args[51] = ttlMinutes >>> 8;
      args.set(verifiedHead.subarray(0, GRANT_HEAD_BYTES), 52);
      const pending = pressed(SUB.GRANT_CREATE, args, { reports: 3, timeoutMs }, onPress);
      const [g, c, s] = await pending;
      return {
        grantId: get32(g, 0),
        uses: get16(g, 4),
        genesis: g.slice(6, 38),
        lifetime: ttlMinutes,
        seq: get32(g, 38),
        checkpoint: { seq: get32(c, 0), head: c.slice(4, 36), signature: s.slice(0, 64) },
      };
    },

    /** End a live budget now (a grant-end link). */
    async revoke(grantId, opts) {
      await call(SUB.GRANT_REVOKE, u32(grantId), { ...opts, text: true });
      return true;
    },

    /**
     * File the ticket for an owed use (any of the key's up to 4, R16; the key
     * refuses another - EdgeError 'no-ticket-waiting'). msgHash =
     * tickets.messageHash(message); the message never goes to the key.
     * -> {seq, head, tag} after the ticket link: the head the next arm() passes
     * (R13a), and the key's vouch tag for it - keep it with the copy: a restore
     * commits a replay only up to a vouched head (R26).
     */
    async ticket(refSeq, code, msgHash, opts) {
      const [r] = await call(SUB.TICKET, concat([u32(refSeq), Uint8Array.of(code), msgHash]), opts);
      return seqHeadTag(r);
    },

    /**
     * R26: the key's vouch tag for its CURRENT head - HMAC with a key only it
     * holds, over (seq, head). No press; refused while restoring ('restoring').
     * A host keeps the newest tag with its copy. -> {seq, head, tag}
     */
    async vouch(opts) {
      const [r] = await call(SUB.VOUCH, null, opts);
      return seqHeadTag(r);
    },

    /**
     * R13a: arm ONE self-press for ONE request. `head` is the head the key
     * returned after the previous step (the grant's checkpoint for a budget's
     * first use, the ticket's reply after that); `subject` is SHA-256 of
     * exactly the bytes the next sign/decrypt will submit. The key gets only
     * the token SHA256("OKEDGE-ARM-v1" || head || subject) and pays for the next
     * request only if it recomputes the same token from its own head and that
     * request; anything else uses the arm up and needs a press. Refused -
     * EdgeError 'ticket-owed', 'nothing-to-arm', 'restoring' - when a ticket is
     * owed, no live budget off hold and unexpired could pay, or a restore is
     * unfinished. A stale head shows at the sign (as a press), not here.
     */
    async arm(head, subject, opts) {
      const { grants } = require('../../src/edge');
      await call(SUB.ARM, grants.armToken({ head, subject }), { ...opts, text: true });
      return true;
    },

    /** R15a: pause a live budget - it pays for nothing, nothing arms under it. No press. */
    async hold(grantId, opts) {
      await call(SUB.GRANT_HOLD, u32(grantId), { ...opts, text: true });
      return true;
    },

    /**
     * R15a: resume a held budget - the key waits for a PHYSICAL press (`onPress`
     * for the UI). verifiedHead as for grant() (R27); grants.resume() checks the
     * copy first.
     */
    async resume(grantId, { verifiedHead, onPress, timeoutMs = 30000 } = {}) {
      if (!(verifiedHead instanceof Uint8Array) || verifiedHead.length !== 32) throw new TypeError('Edge: resume needs the 32-byte head the host verified (R27)');
      const pending = pressed(SUB.GRANT_RESUME, concat([u32(grantId), verifiedHead]), { timeoutMs, text: true }, onPress);
      await pending;
      return true;
    },

    /**
     * R18: clear every owed ticket at once - a PHYSICAL press (the person's Yes
     * in the app first). Linked as a ticket 0x8F with the press flag
     * (tickets.waiveSubject). -> {seq, head, tag} after the waive link.
     */
    async waive({ onPress, timeoutMs = 30000 } = {}) {
      const pending = pressed(SUB.WAIVE, null, { timeoutMs }, onPress);
      const [r] = await pending;
      return seqHeadTag(r);
    },

    /**
     * R26: hand the key, while it is restoring, the next link of the newest copy
     * the host has, with the head the copy stored after it. The key takes it
     * only if it is its next seq and welding it onto the key's head gives that
     * head ('replay-mismatch' otherwise: where the copy forks or is from another
     * key - stop there and show it). It moves the head and applies the debt
     * rules; no press.
     */
    async replay(link, storedHead, opts) {
      if (!(link instanceof Uint8Array) || link.length !== chain.LINK_BYTES) throw new TypeError(`Edge: a link is ${chain.LINK_BYTES} bytes`);
      if (!(storedHead instanceof Uint8Array) || storedHead.length !== 32) throw new TypeError('Edge: replay needs the head the copy stored after the link');
      if (!chain.decodeLink(link).reservedZero) {
        throw Object.assign(new Error('Edge: this link has non-zero reserved bytes - no key wrote it'), { code: 'EDGE_NOT_A_KEY_LINK' });
      }
      await call(SUB.REPLAY, concat([link.subarray(0, REPLAY_BYTES), storedHead.subarray(0, REPLAY_HEAD_BYTES)]), { ...opts, text: true });
      return true;
    },

    /**
     * R26: finish a restore - a PHYSICAL press over "restored to #N, the newest
     * your copies hold". The replay is tentative until now: the key commits it
     * only if {seq, tag} is ITS vouch tag for exactly the replayed head - so
     * replay up to the newest vouched head you hold, and pass that tag. Anything
     * else is thrown away (EdgeError 'not-vouched'), and the LOSS covers
     * everything since the backup. newestSeq (optional) = the newest seq any copy
     * holds: past what is committed, the key links a LOSS over the rest
     * (grant_id = the first lost seq, the subject's first 4 bytes = newestSeq).
     * -> {seq, head, tag}
     */
    async replayDone({ seq, tag, newestSeq, onPress, timeoutMs = 30000 } = {}) {
      if (!Number.isInteger(seq) || seq < 0) throw new TypeError('Edge: replayDone needs the seq the vouch tag is for');
      if (!(tag instanceof Uint8Array) || tag.length !== VOUCH_BYTES) throw new TypeError(`Edge: replayDone needs the key's ${VOUCH_BYTES}-byte vouch tag`);
      const newest = Number.isInteger(newestSeq) && newestSeq >= 0 ? newestSeq : SEQ_NONE;
      const pending = pressed(SUB.REPLAY_DONE, concat([u32(seq), tag, u32(newest)]), { timeoutMs }, onPress);
      const [r] = await pending;
      return seqHeadTag(r);
    },

    /**
     * R27, the calls a host should use: run the copy check (src/edge/copy.js)
     * against what the key says NOW, and send the request only if it passes,
     * with the head it verified. A copy that does not verify throws
     * code 'EDGE_COPY_UNVERIFIED' with the verdict, and nothing reaches the key.
     * copy: {links: [{link, head, reveal}], openings: {[grantId]: {...}}}
     */
    grants: {
      async create({ copy, scopes, reasonHash, ttlMinutes, onPress, timeoutMs }) {
        const h = await verifiedHeadOf(copy);
        return edge.grant({ scopes, reasonHash, verifiedHead: h, ttlMinutes, onPress, timeoutMs });
      },
      async resume(grantId, { copy, onPress, timeoutMs } = {}) {
        const h = await verifiedHeadOf(copy);
        return edge.resume(grantId, { verifiedHead: h, onPress, timeoutMs });
      },
      /** The check alone, for a UI that shows why Yes is off: the verdict from src/edge/copy.js. */
      async check(copy) {
        const { publicKey } = await edge.publicKey();
        const head = await edge.head();
        const checkpoint = head.seq === null ? null : await edge.checkpoint();
        /* the key's own ring, this session: its links are trusted as they are (copy.missingGaps) */
        const held = head.seq === null || head.oldest === null ? [] : await edge.pickup(head.oldest, Math.min(HELD, head.seq - head.oldest + 1));
        return copyCheck.verifyCopy(copy, { publicKey, head, checkpoint, held });
      },
    },

    /**
     * R24: the person accepts #from..#to as unrecoverable - a PHYSICAL press
     * (the person's Yes in the app first). The key links op = loss, grant_id =
     * from, subject = to; it pays no debt. A copy then passes R27 with that gap
     * (copy.uncoveredGaps). Refused while restoring ('restoring') and for a
     * range past the key's head ('bad-range'). -> {seq, head, tag}
     */
    /**
     * mcp-service.md 4.7a: register an agent's key - the person's Yes in the
     * app first, then a PHYSICAL press; the key links op = agent-add with
     * subject grants.agentSubject(key). Refused while restoring.
     * -> {seq, head, tag}
     */
    async agentAdd(agentKey, { onPress, timeoutMs = 30000 } = {}) {
      if (!(agentKey instanceof Uint8Array) || agentKey.length !== 32) throw new TypeError('Edge: agentAdd needs a 32-byte Ed25519 key');
      const pending = pressed(SUB.AGENT_ADD, agentKey, { timeoutMs }, onPress);
      const [r] = await pending;
      return seqHeadTag(r);
    },

    async loss({ from, to, onPress, timeoutMs = 30000 } = {}) {
      if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < from) throw new RangeError(`Edge: a loss is #from..#to, not ${from}..${to}`);
      const pending = pressed(SUB.LOSS, concat([u32(from), u32(to)]), { timeoutMs }, onPress);
      const [r] = await pending;
      return seqHeadTag(r);
    },

    /**
     * L5: does this key answer Edge? 'edge' | 'no-pin' (Edge, but no Edge key
     * until a PIN is set) | 'none' (silence within timeoutMs).
     *
     * The caller decides whether to ask at all. Only builds with the edge
     * plugin know 0xF8; what an unmodified firmware does with an unknown vendor
     * id was not measured across every release, so a host should probe only a
     * key it has reason to think has Edge (ok-rn: its own soft-key build), and
     * never a hard key. A locked key answers nothing at all (B3: "unlock to
     * sync", not "unsupported") - unlocked first.
     */
    async probe({ timeoutMs = 1000 } = {}) {
      try {
        await edge.head({ timeoutMs });
        return 'edge';
      } catch (e) {
        if (e instanceof EdgeError && e.status === 'need-pin') return 'no-pin';
        if (e && e.code === 'ETIMEDOUT') return 'none';
        throw e;
      }
    },
  };

  async function verifiedHeadOf(copy) {
    const verdict = await edge.grants.check(copy || {});
    if (!verdict.ok) {
      const at = verdict.seq === undefined || verdict.seq === null ? '' : ` at #${verdict.seq}`;
      throw Object.assign(new Error(`Edge: your copy of the chain does not verify (${verdict.reason}${at}) - nothing was sent to the key`), {
        code: 'EDGE_COPY_UNVERIFIED', verdict,
      });
    }
    return verdict.head;
  }

  register(null, { edge });
}

setup.consumes = ['transport'];
setup.provides = ['edge'];

module.exports = setup;
