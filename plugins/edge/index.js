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
const { concat, toHex } = require('../../src/bytes');
const { codes, chain, tickets, copy: copyCheck } = require('../../src/edge');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');

/* a P-256 key as SEC1 bytes: X || Y (64, what the key gives) gets its 04; 65 or 33 pass as they are */
const sec1Bytes = (k) => (k.length === 64 ? concat([Uint8Array.of(4), k]) : Uint8Array.from(k));

const OKEDGE = 0xf8;
const SUB = Object.freeze({
  HEAD: 0x01, PICKUP: 0x02, CHECKPOINT: 0x03, PUBKEY: 0x04, VOUCH: 0x05,
  GRANT_CREATE: 0x10, GRANT_LABEL: 0x11, GRANT_REVOKE: 0x12, GRANT_HOLD: 0x13, GRANT_RESUME: 0x14,
  TICKET: 0x20, WAIVE: 0x21, ARM: 0x22, REPLAY: 0x23, REPLAY_DONE: 0x24, REPLAY_INTENT: 0x25, LOSS: 0x34,
  AGENT_ADD: 0x15,
  PEER_ADD: 0x30, PEER_REMOVE: 0x31, PEER_LIST: 0x32,
  /* sync phase 2 (Brad, 2026-10-05): the `sync` link; number CHOSEN, pending the spec */
  SYNC: 0x39,
  /* R29 siblings (P2b) */
  SIBLING_ADD: 0x35, SIBLING_REMOVE: 0x36, SIBLING_LIST: 0x37,
  /* R30 anchors (P2c) */
  ANCHOR: 0x38,
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
const PEER_SLOTS = 4; /* R20: up to 4 peers; PEER_LIST answers one report per slot (okplugin_edge MAX_PEERS) */
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

/* a report's first 12 bytes in hex, and its text when it reads as one - enough to name it in a log */
function hexHead(bytes) {
  const t = okmsg.text(bytes);
  if (/^[ -~]{4,}/.test(t)) return JSON.stringify(t.slice(0, 40));
  return toHex(bytes.subarray(0, 12));
}

/*
 * Is this report a HEAD answer? The key pads its 61 bytes with zeros and its
 * flags are small: three zero bytes, a 4-bit hold mask, owed <= OWED_MAX, two
 * booleans. A signature passes all of that about once in 2^32. (Byte 60 is the
 * refused-ARM counter since B7 stage 2; older firmware sends 0 there.)
 */
function isHeadReply(r) {
  /* byte 61 = capabilities (R13b: bit 0, intent) - no other bit is known; 62-63 zero */
  if (r.length < 64 || (r[61] & ~1) | r[62] | r[63]) return false;
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
  function exclusive(fn, laneOpts) {
    return inLane(transport, fn, laneOpts);
  }

  /* opts.urgent: to the front of the key's lane (rule 8 - a Hold or Revoke the person tapped) */
  function call(sub, args, opts = {}) {
    return exclusive(async () => {
      await busQuiet();
      return callNow(sub, args, opts);
    }, opts.urgent ? { urgent: true } : undefined);
  }

  /*
   * A pressed request that writes a link answers seq . head . tag - and only a
   * seq ABOVE the key's seq before the request can be that answer.
   *
   * MEASURED ON THE A13 (2026-10-04): an agent registration waited on a slow
   * press, took some other report as its answer, read a seq from it, and the
   * link there was not the registration ("invalid"; the key HAD written it).
   * A press wait is up to 30 s, and the A13's slow answers mean a late reply to
   * an earlier request can land inside it. A late answer (a HEAD, a PICKUP's
   * link, an older seq . head) can only carry a seq at or below the one read
   * here; the real one is padded with zeros past its 52 bytes (reply()).
   */
  function aboveSeq(before) {
    return (bytes) => {
      if (bytes.length < 64 || !bytes.subarray(52, 64).every((x) => x === 0)) return false;
      const seq = get32(bytes, 0);
      return seq !== SEQ_NONE && (before === null || seq > before);
    };
  }

  /* a request the key answers only after a physical press: onPress once it is written */
  function pressed(sub, args, opts, onPress) {
    return exclusive(async () => {
      await busQuiet();
      if (opts && opts.newLink) {
        const [h] = await callNow(SUB.HEAD, null, { accept: isHeadReply });
        const before = get32(h, 0);
        opts = { ...opts, accept: aboveSeq(before === SEQ_NONE ? null : before) };
      }
      const pending = callNow(sub, args, opts); /* written synchronously */
      if (onPress) onPress(); /* the request is on the key: now ask for the press */
      return pending;
    });
  }

  /*
   * `accept(bytes, got)`: false = not ours, keep waiting. Every vendor report
   * reaches every listener here, and nothing in an OKEDGE reply says which
   * request it answers. MEASURED ON THE A13 (2026-10-04, decoded from its
   * storage): a PICKUP timed out after link #86 but before #86's head; the late
   * head arrived first in the next PICKUP, every report after it shifted by
   * one, and the copy stored that head (32 bytes, then zeros) as "link
   * #447194052" - above the key's head, so the copy read as a rollback and
   * Sync, starting past it, read nothing. A report from another speaker (a
   * computer on the Bluetooth bridge) would land the same way. Replies whose
   * shape can be checked are checked; a report that fails is someone else's,
   * or late.
   */
  function callNow(sub, args, { reports = 1, timeoutMs = 6000, text = false, accept = null } = {}) {
    /* how long each key request takes, for a caller that asks (edge.onTiming; the agent's OKEDGE_TIMES) */
    const began = Date.now();
    const timed = (p) => (edge && typeof edge.onTiming === 'function'
      ? p.then((v) => { edge.onTiming(sub, Date.now() - began, true); return v; }, (e) => { edge.onTiming(sub, Date.now() - began, false); throw e; })
      : p);
    return timed(new Promise((resolve, reject) => {
      const got = [];
      let off = null;
      /*
       * The answer clock starts when the write has gone out, not before it: a
       * write on a dropped Bluetooth link reconnects first (scan, connect, Part T
       * hello - over 10 s on the A13, 2026-10-05), and a clock started earlier ran
       * out while the request had not even left. The listener is on before the
       * write all the same - a reply can come before the write is acknowledged.
       */
      let timer = null;
      let listening = true;
      /*
       * WHAT CAME INSTEAD. "No answer" alone could not tell the A13's slow
       * answers apart (2026-10-05): nothing at all arrived, another request's
       * answer did, or the phone's own traffic did. Every vendor report this
       * request passed over is kept (first bytes only) and named in the
       * timeout, so the log says which.
       */
      const passed = [];
      let passedMore = 0;
      const pass = (why, bytes) => {
        if (passed.length < 8) passed.push(`${why} ${hexHead(bytes)}`);
        else passedMore += 1;
      };
      const arm = () => {
        if (!listening) return; /* answered already */
        timer = setTimeout(() => {
          off();
          const more = passedMore ? ` +${passedMore} more` : '';
          const seen = passed.length ? `; meanwhile: ${passed.join(', ')}${more}` : '; nothing arrived';
          const part = got.length ? ` (${got.length} of ${reports} reports)` : '';
          reject(Object.assign(new Error(`Edge: no answer to request ${sub} within ${timeoutMs} ms${part}${seen}`), { code: 'ETIMEDOUT', passed: passed.slice(), partial: got.length }));
        }, timeoutMs);
      };
      const unsubscribe = transport.on('report', (event) => {
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
        if (/^(UNLOCKED|INITIALIZED)/.test(okmsg.text(bytes))) { pass('broadcast', bytes); return; } /* a status broadcast, not ours */
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
        /*
         * The firmware refuses a press in a sentence too. MEASURED ON THE PIXEL
         * (2026-10-05, the firmware console): the core closes every wait at
         * 20 s and clears what it waited for; a press after that, while the
         * plugin's own 25 s still ran, got "Error button press was not
         * accepted" - and the registration read "Erro" as a seq, found no link
         * there and answered "invalid" (the A13's 2026-10-04 registration). A
         * refused press is a timeout to the caller: no press counted.
         */
        const said = okmsg.text(bytes);
        if (/^Error [ -~]+$/.test(said)) {
          clearTimeout(timer);
          off();
          const press = /press|confirmation|challenge/i.test(said);
          reject(Object.assign(new Error(`Edge: the key said "${said}" (request ${sub})`), { code: press ? 'ETIMEDOUT' : 'EKEYREFUSED', keyText: said, pressRefused: press }));
          return;
        }
        if (text) { pass('not-status', bytes); return; }
        if (accept && !accept(bytes, got)) { pass('not-ours', bytes); return; }
        got.push(bytes);
        if (got.length >= reports) {
          clearTimeout(timer);
          off();
          resolve(got);
        }
      });
      off = () => { listening = false; unsubscribe(); };
      /*
       * The write is a PROMISE on a pipe (Bluetooth, USB): a plain try/catch
       * caught only a synchronous throw, so a write the phone refused rejected
       * with nobody listening - an unhandled rejection, which ends a Node
       * process. That is how one failed Bluetooth write took the whole
       * edge-agent down (twice, 2026-10-05): the request fails, the agent lives.
       */
      const failed = (e) => {
        clearTimeout(timer);
        off();
        reject(e);
      };
      try {
        Promise.resolve(transport.write(IFACE.VENDOR, okmsg.build({ msg: OKEDGE, slot: sub, payload: args || [] }))).then(arm, failed);
      } catch (e) {
        failed(e);
      }
    }));
  }

  const edge = {
    SUB,
    EdgeError,

    /**
     * {seq (null = no link yet), head, oldest (oldest pickable seq, or null),
     *  live: [budget ids], held: [the live ids on hold (R15a)], owed: number of
     *  uses owing a ticket (R16), overflow: an owed use fell off the key's list,
     *  restoring: restored from a backup and not yet finished (R26),
     *  refusedArms: ARMs the key refused since power-up, RAM only (B7 stage 2;
     *  0 on firmware before it) - a refused ARM writes no link, so this is the
     *  key's own evidence; the phone alarms when it rises}
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
        refusedArms: r[60],
        /* R13b: this build takes ARM {token, intent} (HEAD byte 61, bit 0) */
        canIntent: Boolean(r[61] & 1),
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
    /** R13a + R13b: ARM {token} - or {token, intent} when opts.intent (16 bytes, grants.intentOf) is given */
    async arm(head, subject, opts = {}) {
      const { grants } = require('../../src/edge');
      const intent = opts.intent || null;
      const token = grants.armToken({ head, subject, intent });
      await call(SUB.ARM, intent ? concat([token, intent]) : token, { ...opts, text: true });
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
      const pending = pressed(SUB.WAIVE, null, { timeoutMs, newLink: true }, onPress);
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
      /* R13b: a link with an intent sends it first (the key welds it in at the REPLAY); R3: the version byte rides after the head */
      const intent = link.subarray(47, 63);
      if (intent.some((x) => x)) await call(SUB.REPLAY_INTENT, intent, { ...opts, text: true });
      await call(SUB.REPLAY, concat([link.subarray(0, REPLAY_BYTES), storedHead.subarray(0, REPLAY_HEAD_BYTES), Uint8Array.of(link[63])]), { ...opts, text: true });
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
      /**
       * The check alone, for a UI that shows why Yes is off: the verdict from
       * src/edge/copy.js - against the key's LIVE head, every time.
       *
       * ONLY WHAT IS NEW (Brad, 2026-10-06): the last verified state is kept HERE,
       * in this session's memory only (copy.verifyCopyKept) - never stored, so a
       * restart checks in full. The same head and copy reuse it; a copy that grew
       * is checked from its last verified link. The key is read for what that
       * needs: its head always, its public key once a session, its checkpoint when
       * the head moved, its ring only before a full check.
       */
      async check(copy, opts = {}) {
        if (!publicKeyNow) publicKeyNow = (await edge.publicKey()).publicKey;
        /*
         * ONE MOMENT OF THE KEY (Pixel, 2026-10-06): the head, its newest links,
         * the checkpoint and the ring are separate reads; an agent's link (its
         * ticket) landing between them gave a checkpoint for a newer head than
         * the one checked - "full: new part: checkpoint", no state kept, and the
         * next checks from scratch. So the head is read again after the others:
         * if it moved, the check is done again (3 tries), and only a check the
         * key stood still for is kept.
         */
        for (let tries = 1; ; tries++) {
          const run = await checkOnce(copy || {}, opts);
          const moved = run.readMore && !sameHead(run.head, await edge.head());
          if (moved && tries < 3) continue;
          keptCheck = !moved && run.r.state ? { ...run.r.state, checkpoint: run.r.state === run.st ? run.st.checkpoint : run.checkpoint } : null;
          edge.grants.lastPath = (run.r.path === 'full' && run.r.why ? `full: ${run.r.why}` : run.r.path) + (moved ? ' (the key kept moving)' : '');
          return run.r.result;
        }
      },
      /** how the last check ran: 'skipped' | 'new-links' | 'full: <why>' (for the log) */
      lastPath: null,
      /** the next check is a full one, from the root (the app's Sync button; a restart does it anyway) */
      forget() {
        keptCheck = null;
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
      const pending = pressed(SUB.AGENT_ADD, agentKey, { timeoutMs, newLink: true }, onPress);
      const [r] = await pending;
      return seqHeadTag(r);
    },

    /**
     * R20: add a place that keeps copies (this PC's copy store; the Worker at
     * E5) - the person's Yes in the app first, then a PHYSICAL press. A sync
     * goes only to places added this way. The key links op = peer-add, slot =
     * its index, subject grants.peerSubject(X || Y). peerKey: P-256 as 64 bytes
     * X || Y, 65 with the 04, or 33 compressed.
     *
     * Two requests on the wire: X || Y does not fit beside the header and the
     * firmware's micro-ecc cannot decompress, so part 0 stages X (no press)
     * and part 1 brings Y and waits for the press.
     * Refused: 'peers-full', 'peer-known', 'bad-key', 'restoring'. -> {seq, head, tag}
     */
    async peerAdd(peerKey, { onPress, timeoutMs = 30000 } = {}) {
      const xy = p256.Point.fromBytes(sec1Bytes(peerKey)).toBytes(false).slice(1);
      await call(SUB.PEER_ADD, concat([Uint8Array.of(0), xy.slice(0, 32)]), { text: true });
      const [r] = await pressed(SUB.PEER_ADD, concat([Uint8Array.of(1), xy.slice(32)]), { timeoutMs, newLink: true }, onPress);
      return seqHeadTag(r);
    },

    /** R20: remove the place at `index` (a press); the later ones move down. -> {seq, head, tag} */
    async peerRemove(index, { onPress, timeoutMs = 30000 } = {}) {
      if (!Number.isInteger(index) || index < 0 || index > 255) throw new RangeError(`Edge: no peer index ${index}`);
      const [r] = await pressed(SUB.PEER_REMOVE, Uint8Array.of(index), { timeoutMs, newLink: true }, onPress);
      return seqHeadTag(r);
    },

    /**
     * R20: the places the key will sync with - no press (public keys only, R8).
     * The key always sends its header and one report per slot (max), so the
     * count of reports is known before asking.
     * -> {k (0 = not set until E5), max, peers: [{index, publicKey (X || Y)}]}
     * (backed_through comes with E5's receipts)
     */
    async peers(opts) {
      const [h, ...slots] = await call(SUB.PEER_LIST, null, { ...opts, reports: 1 + PEER_SLOTS });
      const peers = [];
      slots.slice(0, h[0]).forEach((r, index) => peers.push({ index, publicKey: r.slice(0, 64) }));
      return { k: h[1], max: h[2], peers };
    },

    /**
     * Sync phase 2: record an approved sync - the person's Yes on the sheet
     * first, then a PHYSICAL press; the key links op = sync with `subject`
     * (sync.syncSubject: SHA256 of what moved). Owes no ticket. Refused while
     * restoring. -> {seq, head, tag}
     */
    /**
     * R29: pair another key that is yours - the person's Yes (with the code
     * both phones show) first, then a PHYSICAL press; the key links op =
     * sibling with grants.siblingSubject(key, id). The id is the key's own
     * (chain.deviceIdOf): the key refuses any other, itself, a known one.
     * Two requests on the wire (X staged, then Y . id and the press).
     * -> {seq, head, tag}
     */
    async siblingAdd(key, { onPress, timeoutMs = 30000 } = {}) {
      const xy = p256.Point.fromBytes(sec1Bytes(key)).toBytes(false).slice(1);
      const id = chain.deviceIdOf(xy);
      await call(SUB.SIBLING_ADD, concat([Uint8Array.of(0), xy.slice(0, 32)]), { text: true });
      const [r] = await pressed(SUB.SIBLING_ADD, concat([Uint8Array.of(1), xy.slice(32), id]), { timeoutMs, newLink: true }, onPress);
      return seqHeadTag(r);
    },

    /** R29: unpair the sibling at `index` (a press); the later ones move down. -> {seq, head, tag} */
    async siblingRemove(index, { onPress, timeoutMs = 30000 } = {}) {
      if (!Number.isInteger(index) || index < 0 || index > 255) throw new RangeError(`Edge: no sibling index ${index}`);
      const [r] = await pressed(SUB.SIBLING_REMOVE, Uint8Array.of(index), { timeoutMs, newLink: true }, onPress);
      return seqHeadTag(r);
    },

    /** R29: the key's paired phones, no press. -> {max, siblings: [{index, publicKey (X || Y), deviceId}]} */
    /**
     * R30: anchor the sibling at `index` at its SIGNED checkpoint {seq, head,
     * signature} (the sibling key's own edge.checkpoint()). The key checks the
     * signature against that sibling's key (EDGE:1B if not), then waits for a
     * PHYSICAL press and links op 19 (grants.anchorSubject). Only inside a sync
     * the person approved (spec): the caller's sheet comes first.
     * Three requests on the wire: {index, seq, head}, r, s. -> {seq, head, tag}
     */
    async anchor(index, { seq, head, signature }, { onPress, timeoutMs = 30000 } = {}) {
      if (!Number.isInteger(index) || index < 0 || index > 255) throw new RangeError(`Edge: no sibling index ${index}`);
      const sig = Uint8Array.from(signature);
      const s4 = Uint8Array.of(seq & 0xff, (seq >>> 8) & 0xff, (seq >>> 16) & 0xff, (seq >>> 24) & 0xff);
      await call(SUB.ANCHOR, concat([Uint8Array.of(0, index), s4, Uint8Array.from(head)]), { text: true });
      await call(SUB.ANCHOR, concat([Uint8Array.of(1), sig.slice(0, 32)]), { text: true });
      const [r] = await pressed(SUB.ANCHOR, concat([Uint8Array.of(2), sig.slice(32, 64)]), { timeoutMs, newLink: true }, onPress);
      return seqHeadTag(r);
    },

    async siblings(opts) {
      const [h, ...slots] = await call(SUB.SIBLING_LIST, null, { ...opts, reports: 1 + PEER_SLOTS });
      return {
        max: h[1],
        siblings: slots.slice(0, h[0]).map((r, index) => ({ index, publicKey: r.slice(0, 64), deviceId: chain.deviceIdOf(r.slice(0, 64)) })),
      };
    },

    async sync(fields, { onPress, timeoutMs = 30000 } = {}) {
      /*
       * fields: sync.syncFields(...). Three requests (104 bytes do not fit one):
       * the key checks the peer hash is one of its peers, then computes the
       * subject itself and waits for the press. Refused: 'no-such-peer',
       * 'bad-range', 'sync-order', 'restoring'.
       */
      const { peerHash, first, last, head, keychain } = fields || {};
      if (![peerHash, head, keychain].every((b) => b instanceof Uint8Array && b.length === 32)) throw new TypeError('Edge: sync fields are sync.syncFields(...)');
      await call(SUB.SYNC, concat([Uint8Array.of(0), peerHash, u32(first), u32(last)]), { text: true });
      await call(SUB.SYNC, concat([Uint8Array.of(1), head]), { text: true });
      const [r] = await pressed(SUB.SYNC, concat([Uint8Array.of(2), keychain]), { timeoutMs, newLink: true }, onPress);
      return seqHeadTag(r);
    },

    async loss({ from, to, onPress, timeoutMs = 30000 } = {}) {
      if (!Number.isInteger(from) || !Number.isInteger(to) || from < 0 || to < from) throw new RangeError(`Edge: a loss is #from..#to, not ${from}..${to}`);
      const pending = pressed(SUB.LOSS, concat([u32(from), u32(to)]), { timeoutMs, newLink: true }, onPress);
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

  /* the last verified copy state - this session's memory only (grants.check) */
  let keptCheck = null;
  function sameHead(a, b) {
    return a.seq === b.seq && (a.owed || 0) === (b.owed || 0) && (a.head === b.head || (a.head && b.head && a.head.every((x, i) => x === b.head[i])));
  }
  /* one pass of grants.check over one set of key reads; readMore: it read more than the head */
  async function checkOnce(copy, opts) {
    let c = copy;
    const head = await edge.head();
    let readMore = false;
    /*
     * THE KEY AHEAD OF THE COPY (A13, 2026-10-06): an agent's link (its
     * ticket) lands on the key between the phone's sync and this check, so
     * the stored copy ends one link short of the live head. Both the short
     * path and the full check called that link a gap - the full check failed,
     * kept no state, and every later check started from scratch (13-16 s on
     * the A13, the app frozen meanwhile). The key's newest links are read
     * here and checked IN MEMORY after the copy (never stored - the sync
     * stores them); the chain still has to weld onto the copy's last link.
     * ONLY FOR A DISPLAY (opts.keyTail): R27 stays strict - a budget is
     * created or resumed only from a copy verified up to the key's own head,
     * so grants.create/resume and an approval never pass it.
     */
    const links = c.links || [];
    const last = links.length ? links[links.length - 1] : null;
    const lastIn = last ? chain.decodeLink(last instanceof Uint8Array ? last : last.link).seq : null;
    if (opts.keyTail && lastIn !== null && head.seq !== null && head.seq > lastIn && head.seq - lastIn <= HELD && (head.oldest === null || head.oldest <= lastIn + 1)) {
      const tail = await edge.pickup(lastIn + 1, head.seq - lastIn).catch(() => []);
      readMore = true;
      if (tail.length === head.seq - lastIn) c = { ...c, links: [...links, ...tail] };
    }
    const st = keptCheck;
    const same = st && st.keyHead.seq === head.seq && st.keyHead.owed === (head.owed || 0) && head.head && st.keyHead.head && st.keyHead.head.every((x, i) => x === head.head[i]);
    const grew = st && (c.links || []).length > st.count;
    let checkpoint = head.seq === null || same ? (same ? st.checkpoint : null) : await edge.checkpoint();
    if (!same && head.seq !== null) readMore = true;
    /* the key's own ring, this session: its links are trusted as they are (copy.missingGaps) - needed by the full check */
    const held = same || grew || head.seq === null || head.oldest === null ? [] : await edge.pickup(head.oldest, Math.min(HELD, head.seq - head.oldest + 1));
    let r = copyCheck.verifyCopyKept(c, { publicKey: publicKeyNow, head, checkpoint, held }, st);
    /* a full check after all (the copy changed under the same head): with the ring and a fresh checkpoint, as before */
    if (r.path === 'full' && head.seq !== null && head.oldest !== null && (same || grew)) {
      const ring = await edge.pickup(head.oldest, Math.min(HELD, head.seq - head.oldest + 1));
      checkpoint = await edge.checkpoint();
      readMore = true;
      const why = r.why;
      r = { ...copyCheck.verifyCopyKept(c, { publicKey: publicKeyNow, head, checkpoint, held: ring }, null), why };
    }
    return { r, st, head, checkpoint, readMore };
  }

  let publicKeyNow = null;

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
