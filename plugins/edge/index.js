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

const okmsg = require('../../src/protocol/okmsg');
const { IFACE } = require('../../src/protocol/msg');
const { assertTransport } = require('../../src/transport/contract');
const { concat } = require('../../src/bytes');
const { codes, chain } = require('../../src/edge');

const OKEDGE = 0xf8;
const SUB = Object.freeze({
  HEAD: 0x01, PICKUP: 0x02, CHECKPOINT: 0x03, PUBKEY: 0x04,
  GRANT_CREATE: 0x10, GRANT_REVOKE: 0x12, GRANT_HOLD: 0x13, GRANT_RESUME: 0x14,
  TICKET: 0x20, WAIVE: 0x21, ARM: 0x22,
});
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

  async function call(sub, args, opts = {}) {
    await busQuiet();
    return callNow(sub, args, opts);
  }

  function callNow(sub, args, { reports = 1, timeoutMs = 6000, text = false } = {}) {
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
        if (text) return;
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
     *  uses owing a ticket (R16), overflow: an owed use fell off the key's list}
     */
    async head(opts) {
      const [r] = await call(SUB.HEAD, null, opts);
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
      const rs = await call(SUB.PICKUP, concat([u32(from), Uint8Array.of(count)]), { ...opts, reports: 2 * count });
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
     * scopes: [{op, slot, cap}] (1-4, caps summing to <= 255)
     * -> {grantId, uses, genesis, seq, checkpoint: {seq, head, signature}}
     */
    async grant({ scopes, reasonHash, ticketRequired = false, onPress, timeoutMs = 30000 }) {
      const enc = require('../../src/edge').grants.encodeScopes(scopes);
      const args = new Uint8Array(50);
      args.set(enc, 0); /* count + up to 4 x (op, slot, cap u16) */
      args.set(reasonHash, 17);
      args[49] = ticketRequired ? 0x01 : 0;
      await busQuiet();
      const pending = callNow(SUB.GRANT_CREATE, args, { reports: 3, timeoutMs }); /* written synchronously */
      if (onPress) onPress(); /* the request is on the key: now ask for the press */
      const [g, c, s] = await pending;
      return {
        grantId: get32(g, 0),
        uses: get16(g, 4),
        genesis: g.slice(6, 38),
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
     * -> {seq, head} after the ticket link: what the next arm() passes (R13a).
     */
    async ticket(refSeq, code, msgHash, opts) {
      const [r] = await call(SUB.TICKET, concat([u32(refSeq), Uint8Array.of(code), msgHash]), opts);
      return { seq: get32(r, 0), head: r.slice(4, 36) };
    },

    /**
     * R13a: arm ONE self-press. `head` is the head the key returned after the
     * previous step (the grant's checkpoint for a budget's first use, the
     * ticket's reply after that). Refused - EdgeError 'stale-head',
     * 'ticket-owed', 'nothing-to-arm' - when the chain moved, a ticket is owed,
     * or no live budget that is not on hold exists. The next sign/decrypt uses
     * it; any other link clears it.
     */
    async arm(head, opts) {
      await call(SUB.ARM, head, { ...opts, text: true });
      return true;
    },

    /** R15a: pause a live budget - it pays for nothing, nothing arms under it. No press. */
    async hold(grantId, opts) {
      await call(SUB.GRANT_HOLD, u32(grantId), { ...opts, text: true });
      return true;
    },

    /** R15a: resume a held budget - the key waits for a PHYSICAL press (`onPress` for the UI). */
    async resume(grantId, { onPress, timeoutMs = 30000 } = {}) {
      await busQuiet();
      const pending = callNow(SUB.GRANT_RESUME, u32(grantId), { timeoutMs, text: true });
      if (onPress) onPress();
      await pending;
      return true;
    },

    /**
     * R18: clear every owed ticket at once - a PHYSICAL press (the person's Yes
     * in the app first). Linked as a ticket 0x8F with the press flag
     * (tickets.waiveSubject). -> {seq, head} after the waive link.
     */
    async waive({ onPress, timeoutMs = 30000 } = {}) {
      await busQuiet();
      const pending = callNow(SUB.WAIVE, null, { timeoutMs });
      if (onPress) onPress();
      const [r] = await pending;
      return { seq: get32(r, 0), head: r.slice(4, 36) };
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

  register(null, { edge });
}

setup.consumes = ['transport'];
setup.provides = ['edge'];

module.exports = setup;
