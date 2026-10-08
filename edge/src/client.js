'use strict';

/**
 * L7 - EDGE FROM AN APP (onlykey-edge okrn-edge-tab.md 4.1 L7; first users
 * apk-signer and the agent service). One small API, so an app never handles
 * TX start, heads or debts by hand:
 *
 *   const client = createEdgeClient({ edge, channel, signer });
 *   const budget = await client.request({ reason, scopes, ttlMinutes });
 *   const { result, link } = await budget.use(bytes, (b) => sign(b));
 *   await budget.receipt(link, { code: 'OK', message: 'signed it' });
 *   await budget.end();
 *
 * - The request goes through `channel` (send(EDGE_REQUEST) -> the app's
 *   answer: Bluetooth to ok-rn first, the Worker mailbox later), signed by the
 *   agent service's own key (`signer`). The answer is NOT taken on its word:
 *   the budget's opening is read back from the key and checked
 *   (grants.verifyBudgetOpening) against the scopes, reason and lifetime this
 *   client asked for.
 * - use() takes the exact bytes the operation will submit, TX starts with a token
 *   over the head it holds and SHA-256 of those bytes (R13a), runs the
 *   operation, and returns the link it caused - checked to be this use.
 *   It FAILS FAST: a refused TX start throws EEDGE_TX with the key's reason
 *   instead of sending an operation that would wait for a press nobody gives.
 * - use() refuses while this budget owes a receipt (EEDGE_TX 'receipt-owed').
 * - No Edge on this key: request() rejects EEDGE_UNSUPPORTED.
 * - The app answers nothing to a key it has not registered: EEDGE_NO_ANSWER.
 *   register(name) first - once, with a press on the phone.
 * - continue(id) ends the old budget first (4.7a: only an ended budget is
 *   continued; the app refuses a live one with 'still_live').
 * - A budget outlives one process: with a `store` ({get, set}, an app's own
 *   storage), request() saves it and resume(id) picks it up.
 *
 * Pure apart from the device service it is handed: no Node built-ins.
 */

const request = require('./request');
const grants = require('./grants');
const receipts = require('./receipts');
const chain = require('./chain');
const codes = require('./codes');
const note = require('./note');
const pingLib = require('./ping');
const { utf8ToBytes } = require('../../src/bytes');

/* at most `max` UTF-8 bytes, cut on a character (a note's reason is capped, not refused) */
function clip(text, max) {
  if (utf8ToBytes(text).length <= max) return text;
  let out = '';
  for (const ch of text) {
    if (utf8ToBytes(out + ch + '…').length > max) break;
    out += ch;
  }
  return out + '…';
}
const { toHex, fromHex } = require('../../src/bytes');

const fail = (code, message, extra = {}) => Object.assign(new Error(message), { code, ...extra });
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const storeKey = (grantId) => `okedge.budget.${grantId}`;

function createEdgeClient({ edge, channel, signer, store = null, noteTimeoutMs = 4000 }) {
  /*
   * B7 stage 2: EDGE_NOTE - the agent's words about a use, a receipt or a refused
   * TX start, to the phone. Changes nothing anywhere, so it never fails what it
   * describes: no channel, an old phone, no answer within noteTimeoutMs - all
   * the same, the use stands.
   */
  async function sendNote(fields) {
    if (!channel || !signer) return;
    try {
      const msg = await note.build({ signer, ...fields });
      let t = null;
      await Promise.race([channel.send(msg), new Promise((r) => { t = setTimeout(r, noteTimeoutMs); if (t && t.unref) t.unref(); })]).finally(() => clearTimeout(t));
    } catch { /* a note is never worth a failed use */ }
  }
  async function deviceIdentity() {
    /*
     * SILENCE IS NOT "NO EDGE". A key without the plugin is silent, but so is a
     * locked one, or a soft key whose app is starting - the phone's restart
     * (2026-10-04) read as "this key has no Edge" when it only had not answered
     * yet. Same code (callers branch on it), honest words.
     */
    /*
     * 4 s, not the probe's 1 s default: right after ok-rn starts, its background
     * Edge sync reads the whole chain from the soft key, and a HEAD that arrives
     * mid-read waits behind those reads. 1 failure in 8 restarts on the Pixel
     * (2026-10-04) - the likely cause, not a proven one; a key that answers costs
     * nothing extra, a silent one 3 s more.
     */
    const probed = await edge.probe({ timeoutMs: 4000 });
    if (probed === 'no-pin') throw fail('EEDGE_UNSUPPORTED', 'edge: this key has no PIN set yet, so it has no Edge key');
    if (probed !== 'edge') throw fail('EEDGE_UNSUPPORTED', 'edge: the key did not answer an Edge request - it may be locked, still starting (the phone app just opened?), or have no Edge (then sign with a press per use)');
    return edge.publicKey();
  }

  /* the head the key had just before link `seq` - the opening welds onto it */
  async function headBefore(seq, deviceId) {
    if (seq === 0) return chain.genesis(deviceId);
    const [prev] = await edge.pickup(seq - 1, 1);
    return prev.head;
  }

  function budgetOf(record) {
    const state = {
      head: fromHex(record.head),
      owed: [...(record.owed || [])],
      ended: false,
      /* the highest self-press step this budget paid: all uses spent at step == uses */
      spent: record.spent || 0,
    };
    const genesis = fromHex(record.genesis);
    const save = async () => {
      if (store) await store.set(storeKey(record.grantId), JSON.stringify({ ...record, head: toHex(state.head), owed: state.owed, ended: state.ended, spent: state.spent }));
    };

    return {
      grantId: record.grantId,
      uses: record.uses,
      reason: record.reason,
      scopes: record.scopes,
      /**
       * The head this budget holds (hex): what the agent's next use TX starts over,
       * and what `okedge exec --head` must name - proof the agent saw its own
       * last receipt's reply (mcp-service.md §4.2a).
       */
      head() {
        return toHex(state.head);
      },
      /** the uses still waiting for their receipt (seqs) */
      pending() {
        return [...state.owed];
      },
      /**
       * One use: TX start over the head this budget holds and SHA-256(bytes), run
       * op(bytes), and return the link it caused.
       * -> {result, link: {seq, paid, step, reveal}}
       */
      async use(bytes, op, { reason, intent = reason } = {}) {
        if (state.ended) throw fail('EEDGE_TX', 'edge: this budget has ended', { reason: 'ended' });
        if (state.owed.length) throw fail('EEDGE_TX', `edge: a receipt is owed for #${state.owed[0]} - receipt it first`, { reason: 'receipt-owed' });
        const data = Uint8Array.from(bytes);
        const subject = grants.requestSubject(data);
        /*
         * TX start over the KEY's head, read now - not the one this budget last saw.
         * Other links land between this budget's uses: a person's own pressed
         * sign, another agent, the key's own events. A TX start over the older head
         * makes the key treat the use as a press, and the budget would never
         * pay again (found 2026-10-03 by the agent service's test: another
         * process signing during an exec). "Did the agent see its last
         * receipt?" is asked separately (okedge exec --head vs head()).
         */
        const before = await edge.head();
        state.head = before.head;
        /* R13b: the text exactly as the note carries it - the phone hashes what it receives */
        const said = intent !== undefined && intent !== null ? clip(String(intent), note.MAX_REASON) : null;
        try {
          /* R13b: the reason goes into the link itself, before the signature exists */
          await edge.txStart(state.head, subject, said ? { intent: grants.intentOf(said) } : {});
        } catch (e) {
          await sendNote({ seq: (await edge.head().catch(() => ({ seq: 0 }))).seq ?? 0, txRefused: String(e.status || e.message || 'refused').slice(0, note.MAX_TX_REFUSED) });
          throw fail('EEDGE_TX', `edge: the key refused the TX start (${e.status || e.message})`, { reason: e.status || 'refused' });
        }
        /*
         * R13b: the text BEFORE the sign, for the link it is about to make - the
         * phone shows it with the press prompt ("the agent says:") when its hash
         * matches the started intent, and beside the link afterwards.
         */
        if (said) await sendNote({ seq: before.seq === null ? 0 : before.seq + 1, reason: said });
        const result = await op(data);
        /*
         * THIS USE'S LINK, WITHOUT A THIRD HEAD READ (Brad, 2026-10-06: each key
         * request is ~0.3-0.5 s over Bluetooth). It is the link after the head the
         * TX start was made over - picked up directly and checked by its subject (this
         * use's bytes). Anything else there (another link landed in between, or the
         * key refused the read) falls back to the newest link, as before.
         */
        const next = before.seq === null ? 0 : before.seq + 1;
        let l = await edge.pickup(next, 1).then((r) => r[0], () => null);
        if (!l || !same(chain.decodeLink(l.link).subject, subject)) {
          const h = await edge.head();
          [l] = await edge.pickup(h.seq, 1);
        }
        const f = chain.decodeLink(l.link);
        if (!same(f.subject, subject)) throw fail('EEDGE_LINK', `edge: the key's newest link (#${f.seq}) is not this use`);
        const paid = f.decision === codes.DECISION.SELF_PRESS && f.grantId === record.grantId;
        if (paid) {
          const mac = require('./hash').hmacSha256(l.reveal, subject);
          const r = grants.checkSelfPress({ genesis, uses: record.uses, step: f.grantStep, value: l.reveal, mac, subject });
          if (!r.ok) throw fail('EEDGE_LINK', `edge: the self-press's reveal does not belong to this budget (${r.reason})`);
        }
        if (f.flags & codes.FLAG.OWES_RECEIPT) state.owed.push(f.seq);
        if (paid) state.spent = Math.max(state.spent, f.grantStep);
        state.head = l.head;
        await save();
        /*
         * paidBy: the budget the KEY spent - it pays from the first live budget
         * that covers the request, so another of this agent's budgets (one a
         * continue left live) may pay instead of this one (seen 2026-10-03).
         */
        const paidBy = f.decision === codes.DECISION.SELF_PRESS ? f.grantId : null;
        /* the note went before the sign (R13b); again only if another link landed in between and took its seq */
        if (said && f.seq !== (before.seq === null ? 0 : before.seq + 1)) await sendNote({ seq: f.seq, reason: said });
        return { result, purpose: reason, link: { seq: f.seq, paid, paidBy, step: paid ? f.grantStep : null, reveal: paid ? l.reveal : null } };
      },
      /** File the receipt for a use; the new head is kept for the next use(). */
      async receipt(link, { code = 'OK', message }) {
        let r;
        try {
          /*
           * AN ANSWER THAT NEVER CAME (the A13, 2026-10-05: a receipt's answer took
           * over 6 s, twice). A RECEIPT changes the key, so it is NEVER sent twice
           * (Brad, 2026-10-06): the key is asked instead - its newest link. If that
           * is this use's receipt, it was filed and only the answer was lost;
           * otherwise the error stands and the caller decides.
           */
          r = await edge.receipt(link.seq, codes.receiptByte(code), receipts.messageHash(message)).catch(async (e) => {
            if (!/no answer to request/.test(String(e && e.message))) throw e;
            const h = await edge.head();
            const [newest] = h.seq === null ? [] : await edge.pickup(h.seq, 1);
            const f = newest && chain.decodeLink(newest.link);
            if (f && f.op === codes.OP.RECEIPT && f.grantId === link.seq) return { seq: h.seq, head: h.head, lostAnswer: true };
            throw e;
          });
        } catch (e) {
          /*
           * THE KEY IS THE TRUTH ON WHAT IS OWED. Found on the A13 (2026-10-05):
           * a receipt's answer came back after the 6 s wait, so the client kept
           * the use as owed - but the key had linked the receipt, and every
           * receipt after that answered "owes no receipt" while use() and exec
           * refused, stuck. When the key says this use owes nothing, the receipt
           * was filed (its answer lost): clear it and take the key's head.
           */
          if (!(e && e.status === 'no-receipt-waiting' && state.owed.includes(link.seq))) throw e;
          const h = await edge.head();
          r = { seq: h.seq, head: h.head, lostAnswer: true };
        }
        state.owed = state.owed.filter((s) => s !== link.seq);
        state.head = r.head;
        await save();
        if (message !== undefined && message !== null) await sendNote({ seq: link.seq, receiptMsg: String(message) });
        /*
         * R16 (spec 2026-10-04): a used-up budget still COVERS its identities until it
         * ends - a later pressed use of them owes a receipt - and it holds one of the
         * key's live slots. So the client ends it itself the moment its last use is
         * receipted: a grant-end link, the slot freed. (The key does not end it on its
         * own: "used up" must not quietly drop the coverage.)
         */
        if (!state.ended && !state.owed.length && state.spent >= record.uses) {
          await end();
          return { ...r, ended: true };
        }
        return r;
      },
      /**
       * Revoke what is left - only once every use is receipted (R16: the client
       * receipts first, then ends). Ending with a receipt owed left budget 351's
       * card waiting on a receipt after its end (Brad, 2026-10-06).
       */
      async end() {
        if (state.owed.length) throw fail('EEDGE_OWED', `edge: a receipt is owed for #${state.owed.join(', #')} - receipt it first, then end`);
        return end();
      },
    };
    /* revoke what is left (a grant-end link); also called by receipt() once the last use is receipted */
    async function end() {
      try {
        await edge.revoke(record.grantId);
      } catch (e) {
        if (!(e && e.status === 'no-such-budget')) throw e; /* already gone: expired, or a lock */
      }
      state.ended = true;
      await save();
    }
  }

  /*
   * AN OWED RECEIPT IS ALWAYS FILEABLE (spec okrn-edge-tab.md, Budgets, 2026-10-06):
   * after the budget ended - a lock, a reboot, its lifetime, or the client's own
   * end - the key still owes the use's receipt and checks only that the seq is
   * owed (R16). So it is filed straight to the key, no budget needed, and the
   * person never has to waive what the agent can answer.
   */
  async function receiptOwed(seq, { code = 'OK', message }) {
    const r = await edge.receipt(seq, codes.receiptByte(code), receipts.messageHash(message));
    if (message !== undefined && message !== null) await sendNote({ seq, receiptMsg: String(message) });
    return r;
  }

  async function open({ reason, scopes, ttlMinutes, continueOf = null }) {
    const { publicKey, deviceId } = await deviceIdentity();
    const msg = await request.build({ signer, reason, scopes, lifetime: ttlMinutes, continueOf });
    const c = request.check(msg);
    if (!c.ok) throw fail('EEDGE_INVALID', `edge: ${c.reason}`);
    const answer = await channel.send(msg);
    /* nothing back: the app DROPS a request it will not read - this key is not registered, or the request was replayed */
    if (!answer) throw fail('EEDGE_NO_ANSWER', 'edge: the app answered nothing - is this agent registered? (client.register)');
    if (!answer.ok) {
      const refusal = answer.refusal || 'declined';
      throw fail('EEDGE_REFUSED', `edge: the budget was refused - ${refusal}${answer.detail ? ` (${answer.detail})` : ''}`, { refusal });
    }
    const b = answer.budget;
    /* NOT taken on its word: the opening, from the key, against what THIS client asked for */
    const [opened] = await edge.pickup(b.seq, 1);
    const verdict = grants.verifyBudgetOpening({
      deviceId, publicKey, link: opened.link, prevHead: await headBefore(b.seq, deviceId),
      head: fromHex(b.checkpoint.head), signature: fromHex(b.checkpoint.signature),
      scopes: request.grantScopes(msg), reasonHash: request.reasonHash(reason),
      genesis: fromHex(b.genesis), uses: b.uses, lifetime: ttlMinutes,
    });
    if (!verdict.ok || verdict.grantId !== b.grantId) {
      throw fail('EEDGE_OPENING', `edge: the answer is not a budget the key opened as asked (${verdict.reason || 'another budget'})`);
    }
    const record = { grantId: b.grantId, uses: b.uses, genesis: b.genesis, head: b.checkpoint.head, reason, scopes: msg.scopes, lifetime: ttlMinutes, owed: [], ...(continueOf !== null ? { continues: continueOf } : {}) };
    if (store) await store.set(storeKey(b.grantId), JSON.stringify(record));
    return budgetOf(record);
  }

  return {
    /*
     * okedge ping (Brad, 2026-10-06): a pure link test - size random bytes out,
     * named by their SHA-256; the phone sends them straight back (testing mode,
     * encrypted session only) and the answer is checked byte for byte. Touches
     * no key and no budget. -> {exact, ms, bytes, wire, why?} (exact, not ok: the
     * control endpoint's answers carry their own ok)
     */
    async ping({ size = 1024, timeoutMs = 10000 } = {}) {
      if (!channel) throw fail('EEDGE_NO_CHANNEL', 'edge: no channel to the phone');
      const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
      const n = Math.max(1, Math.min(pingLib.PING_MAX, Math.floor(Number(size) || 0)));
      const msg = pingLib.buildPing(randomBytes(n));
      const wire = JSON.stringify(msg).length;
      const times = {};
      const t0 = Date.now();
      const answer = await channel.send(msg, { timeoutMs, times });
      const ms = Date.now() - t0;
      if (answer === null || answer === undefined) return { exact: false, ms, bytes: n, wire, why: 'no answer (the phone is not in testing mode, the session is not encrypted, or an older app)' };
      const c = pingLib.checkPong(msg, answer);
      /* each interval on ONE clock (the PC's or the phone's): the clocks differ, so nothing crosses them */
      const d = (a, b) => (typeof a === 'number' && typeof b === 'number' ? b - a : null);
      const parts = {
        queue: d(times.start, times.lane),
        pcWrite: d(times.lane, times.written),
        phoneIn: d(answer.firstAt, answer.rxAt),
        phoneHold: d(answer.rxAt, answer.txAt),
        phoneTotal: d(answer.firstAt, answer.txAt),
        pcIn: d(times.firstIn, times.done),
      };
      /* the receipt (Brad): the verdict back to the phone, one-way - both logs end with it */
      await channel.send({ type: pingLib.RECEIPT_TYPE, re: msg.id, exact: c.ok, why: c.why || null, ms, parts }, { oneWay: true }).catch(() => {});
      return { exact: c.ok, why: c.why, ms, bytes: n, wire, parts };
    },
    /** File an owed receipt with no budget (after it ended): the key checks only that the seq is owed. -> {seq, head} */
    receiptOwed,
    /**
     * Ask for a budget. scopes: [{op: 'sign'|'decrypt', slot, cap, identity?}]
     * (identity on a derived code, R11a). ttlMinutes: 1..1440.
     * Rejects EEDGE_UNSUPPORTED, EEDGE_INVALID, EEDGE_REFUSED (with .refusal:
     * declined, timeout, copy_unverified, receipt_owed, restoring, invalid),
     * EEDGE_NO_ANSWER (dropped: not registered, replayed) or EEDGE_OPENING
     * (the answer is not a budget the key opened as asked).
     */
    async request({ reason, scopes, ttlMinutes }) {
      return open({ reason, scopes, ttlMinutes });
    },

    /**
     * "Continues <budget>": the same scopes, new uses (caps: one per scope, in
     * the budget's order; the old caps when left out) and a new lifetime.
     * Opens with a press like a new budget; the agent checks the opening the
     * same way. Needs the store the budget was saved to.
     */
    async continue(grantId, { ttlMinutes, caps = null, reason = null }) {
      if (!store) throw fail('EEDGE_NO_STORE', 'edge: continue needs the store the budget was saved to');
      const raw = await store.get(storeKey(grantId));
      if (!raw) throw fail('EEDGE_UNKNOWN', `edge: no saved budget ${grantId}`);
      const was = JSON.parse(raw);
      /*
       * 4.7a: only an ended budget can be continued, so the old one is ended
       * FIRST (a revoke, no press) - two live budgets covering one identity
       * let the key pay from the older one (seen 2026-10-03: budget 93 paid a
       * use asked under its continuation 94). A declined continue leaves the
       * old one ended.
       */
      try {
        await edge.revoke(grantId);
      } catch (e) {
        if (!(e && e.status === 'no-such-budget')) throw e; /* already ended: expired, revoked, or the key locked */
      }
      await store.set(storeKey(grantId), JSON.stringify({ ...was, ended: true }));
      if (caps && caps.length !== was.scopes.length) throw fail('EEDGE_INVALID', `edge: budget ${grantId} has ${was.scopes.length} scopes - give one cap each`);
      const scopes = was.scopes.map((s, i) => ({ ...s, cap: caps ? caps[i] : s.cap }));
      /* no lifetime given (the agent's automatic continue after a key restart): the one it had */
      return open({ reason: reason === null ? was.reason : reason, scopes, ttlMinutes: ttlMinutes || was.lifetime, continueOf: grantId });
    },

    /**
     * Register this agent's key with the app, under `name` - once, with a
     * press on the phone. -> {already} ; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    async register(name) {
      const answer = await channel.send(await request.buildRegister({ signer, name }));
      if (!answer) throw fail('EEDGE_NO_ANSWER', 'edge: the app answered nothing - a bad signature or a replayed registration');
      if (!answer.ok) throw fail('EEDGE_REFUSED', `edge: the registration was refused - ${answer.refusal}${answer.detail ? ` (${answer.detail})` : ''}`, { refusal: answer.refusal });
      return { already: Boolean(answer.already) };
    },

    /**
     * The phone's own name (its Bluetooth / Android device name) as it says it
     * - asked with a HAVE. A label,
     * never trusted: the person can rename it on each phone. -> string | null
     */
    async phoneName(peerSigner, { deviceId, name = 'this computer' }) {
      const syncLib = require('./sync');
      const a = await channel.send(await syncLib.buildHave({ signer: peerSigner, deviceId, name }));
      const n = a && a.ok && typeof a.deviceName === 'string' ? a.deviceName.trim().slice(0, 64) : '';
      return n || null;
    },

    /**
     * R30 (P2c): the phone's own copy of its chain, every record it holds -
     * GIVE, BATCH at a time. peerSigner: this computer's own sync key (copy.peerSigner).
     * -> [{link, head, reveal}] ; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    async copyFromPhone(peerSigner, { deviceId }) {
      const syncLib = require('./sync');
      const out = [];
      for (let from = 0, guard = 0; from !== null && guard < 10000; guard += 1) {
        const a = await channel.send(await syncLib.buildGive({ signer: peerSigner, deviceId, from }));
        if (!a) throw fail('EEDGE_NO_ANSWER', 'edge: the phone answered nothing - is ok-rn open and logged in, and this computer paired with it (onlykey-js pair)?');
        if (!a.ok) throw fail('EEDGE_REFUSED', `edge: the phone gave no copy - ${a.refusal}${a.detail ? ` (${a.detail})` : ''}`, { refusal: a.refusal });
        const { fromHex } = require('../../src/bytes');
        for (const [l, h, r] of a.links || []) out.push({ link: fromHex(l), head: fromHex(h), reveal: r ? fromHex(r) : null });
        from = Number.isInteger(a.next) ? a.next : null;
      }
      return out;
    },

    /**
     * BLOCKS (BLOCKS.md §3, Brad 2026-10-07): the key's seals (the checkpoints that
     * close each block), as the phone keeps them - and the phone's own latest owner
     * statement (its nametag; 2026-10-08), so this computer can offer that phone's log to
     * your other devices. A phone that has no nametag yet gives none. A GIVE asked past the end: no links, just its last-batch fields.
     * Nothing is trusted here - each seal is checked against the key's own public
     * key when the blocks are built (block.verifyBlock).
     * -> {seals: [{seq, head, signature}], statement: {deviceId, publicKey, seq, nametag, signature} | null}
     */
    async sealsFromPhone(peerSigner, { deviceId }) {
      const syncLib = require('./sync');
      const { fromHex } = require('../../src/bytes');
      const a = await channel.send(await syncLib.buildGive({ signer: peerSigner, deviceId, from: 0xffffffff }));
      if (!a) throw fail('EEDGE_NO_ANSWER', 'edge: the phone answered nothing - is ok-rn open and logged in, and this computer paired with it (onlykey-js pair)?');
      if (!a.ok) throw fail('EEDGE_REFUSED', `edge: the phone gave no seals - ${a.refusal}${a.detail ? ` (${a.detail})` : ''}`, { refusal: a.refusal });
      return {
        seals: (a.seals || []).map(([seq, head, sig]) => ({ seq, head: fromHex(head), signature: fromHex(sig) })),
        statement: a.statement && typeof a.statement === 'object' ? {
          deviceId: fromHex(a.statement.deviceId), publicKey: fromHex(a.statement.publicKey),
          seq: a.statement.seq ?? null, nametag: String(a.statement.nametag), signature: fromHex(a.statement.signature),
        } : null,
      };
    },

    /**
     * OFFER ANOTHER DEVICE'S LOG (Brad, 2026-10-08: "if it has the private ecc key to sign
     * the block, then i want the log"): bring the phone whose key is `deviceId` the chain
     * `chain` (`records` up to that device's signed `checkpoint`) with its owner
     * `statement` - HAVE (what the phone holds of it), the LINKS it lacks, then OFFER. The
     * phone HOLDS it; the person approves the merge later from the Edge tab's banner.
     * -> {sent, held (true when the phone kept it), count}; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    async offerToPhone(peerSigner, { deviceId, chain, records, checkpoint, statement, name }) {
      const syncLib = require('./sync');
      const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
      const { toHex: hex } = require('../../src/bytes');
      const ask = async (msg, what) => {
        const a = await channel.send(msg);
        if (!a) throw fail('EEDGE_NO_ANSWER', `edge: the phone answered nothing to ${what} - is ok-rn open and logged in, and this computer paired with it (onlykey-js pair)?`);
        if (!a.ok) throw fail('EEDGE_REFUSED', `edge: the phone refused the log - ${a.refusal}${a.detail ? ` (${a.detail})` : ''}`, { refusal: a.refusal });
        return a;
      };
      const upTo = records.filter((r) => require('./chain').decodeLink(r.link).seq <= checkpoint.seq);
      const have = await ask(await syncLib.buildHave({ signer: peerSigner, deviceId, name, chain }), 'the offer');
      const lacks = syncLib.missing(upTo, have.ranges || []);
      const sid = hex(randomBytes(8));
      const linkMsgs = lacks.length ? await syncLib.buildLinks({ signer: peerSigner, deviceId, records: lacks, sid, chain }) : [];
      for (const m of linkMsgs) await ask(m, `part ${m.payload.part + 1} of ${m.payload.parts}`);
      const done = await ask(await syncLib.buildOffer({ signer: peerSigner, deviceId, sid, chain, linkParts: linkMsgs.length, checkpoint, statement }), 'the offer');
      return { sent: lacks.length, held: Boolean(done.held), count: done.count ?? lacks.length };
    },

    /**
     * okedge sync phase 2: bring the PHONE's copy of chain `deviceId` up to
     * date from `records` (this place's verified copy, [{link, head, reveal}])
     * and merge `keychain` (this place's public Key Chain list, entries) with
     * the phone's. Asks what the phone holds, sends only the links it lacks and
     * the whole list, in signed parts; COMMIT brings up ONE sheet on the phone;
     * TAKEs the merged list back. The links themselves are HELD on the phone until
     * the person approves them from the Edge tab's banner (Brad, 2026-10-08) - no key
     * press, no sync link. peerSigner: this computer's own sync key (copy.peerSigner).
     * -> {sent, seq (always null since 2026-10-08), count, keychainIn,
     *     keychainOut, keychain (the merged list, or null)}
     * rejects EEDGE_REFUSED (declined, timeout, a fork - with the phone's words) or EEDGE_NO_ANSWER.
     */
    async syncToPhone(peerSigner, { deviceId, records, name, keychain = null }) {
      const syncLib = require('./sync');
      const { randomBytes } = require('../../src/vendor/exports/@noble/ciphers/utils.js');
      const { toHex: hex } = require('../../src/bytes');
      const ask = async (msg, what) => {
        const a = await channel.send(msg);
        if (!a) throw fail('EEDGE_NO_ANSWER', `edge: the phone answered nothing to ${what} - is ok-rn open and logged in, and this computer paired with it (onlykey-js pair)?`);
        if (!a.ok) throw fail('EEDGE_REFUSED', `edge: the phone refused the sync - ${a.refusal}${a.detail ? ` (${a.detail})` : ''}`, { refusal: a.refusal });
        return a;
      };
      const have = await ask(await syncLib.buildHave({ signer: peerSigner, deviceId, name }), 'the sync');
      const lacks = syncLib.missing(records, have.ranges || []);
      const sid = hex(randomBytes(8));
      const linkMsgs = lacks.length ? await syncLib.buildLinks({ signer: peerSigner, deviceId, records: lacks, sid }) : [];
      /* the same list on both sides (the phone said its digest): nothing to send - an empty sync no longer carries the list both ways */
      const same = keychain && have.keychainDigest && hex(syncLib.keychainDigest(keychain)) === String(have.keychainDigest).toLowerCase();
      const kcMsgs = keychain && !same ? await syncLib.buildKeychain({ signer: peerSigner, deviceId, sid, entries: keychain }) : [];
      if (!linkMsgs.length && !kcMsgs.length) return { sent: 0, seq: null, count: 0, keychainIn: 0, keychainOut: 0, keychain: null };
      for (const m of [...linkMsgs, ...kcMsgs]) await ask(m, `part ${m.payload.part + 1} of ${m.payload.parts}`);
      const done = await ask(await syncLib.buildCommit({ signer: peerSigner, deviceId, sid, linkParts: linkMsgs.length, keychainParts: kcMsgs.length }), 'the commit');
      let merged = null;
      if (done.takeParts) {
        const plain = [];
        for (let part = 0; part < done.takeParts; part += 1) {
          const t = await ask(await syncLib.buildTake({ signer: peerSigner, deviceId, sid, part }), `the merged list, part ${part + 1}`);
          plain.push(...t.entries);
        }
        merged = syncLib.keychainEntriesOf(plain);
      }
      return { sent: lacks.length, seq: done.seq ?? null, count: done.count ?? 0, keychainIn: done.keychainIn ?? 0, keychainOut: done.keychainOut ?? 0, keychain: merged };
    },

    /**
     * Pick up a budget another process asked for (with the same store). The
     * key's HEAD must still list it; the head to TX start over is read from the key.
     */
    async resume(grantId) {
      if (!store) throw fail('EEDGE_NO_STORE', 'edge: resume needs the store the budget was saved to');
      const raw = await store.get(storeKey(grantId));
      if (!raw) throw fail('EEDGE_UNKNOWN', `edge: no saved budget ${grantId}`);
      const record = JSON.parse(raw);
      if (record.ended) throw fail('EEDGE_GONE', `edge: budget ${grantId} was ended`);
      await deviceIdentity();
      const h = await edge.head();
      if (!h.live.includes(grantId)) throw fail('EEDGE_GONE', `edge: budget ${grantId} is no longer live (revoked, expired, or the key locked)`);
      return budgetOf({ ...record, head: toHex(h.head) });
    },
  };
}

module.exports = { createEdgeClient };
