'use strict';

/**
 * L7 - EDGE FROM AN APP (onlykey-edge okrn-edge-tab.md 4.1 L7; first users
 * apk-signer and the agent service). One small API, so an app never handles
 * ARM, heads or debts by hand:
 *
 *   const client = createEdgeClient({ edge, channel, signer });
 *   const budget = await client.request({ reason, scopes, ttlMinutes });
 *   const { result, link } = await budget.use(bytes, (b) => sign(b));
 *   await budget.ticket(link, { code: 'OK', message: 'signed it' });
 *   await budget.end();
 *
 * - The request goes through `channel` (send(EDGE_REQUEST) -> the app's
 *   answer: Bluetooth to ok-rn first, the Worker mailbox later), signed by the
 *   agent service's own key (`signer`). The answer is NOT taken on its word:
 *   the budget's opening is read back from the key and checked
 *   (grants.verifyBudgetOpening) against the scopes, reason and lifetime this
 *   client asked for.
 * - use() takes the exact bytes the operation will submit, ARMs with a token
 *   over the head it holds and SHA-256 of those bytes (R13a), runs the
 *   operation, and returns the link it caused - checked to be this use.
 *   It FAILS FAST: a refused ARM throws EEDGE_ARM with the key's reason
 *   instead of sending an operation that would wait for a press nobody gives.
 * - use() refuses while this budget owes a ticket (EEDGE_ARM 'ticket-owed').
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
const tickets = require('./tickets');
const chain = require('./chain');
const codes = require('./codes');
const note = require('./note');
const { utf8ToBytes } = require('../bytes');

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
const { toHex, fromHex } = require('../bytes');

const fail = (code, message, extra = {}) => Object.assign(new Error(message), { code, ...extra });
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const storeKey = (grantId) => `okedge.budget.${grantId}`;

function createEdgeClient({ edge, channel, signer, store = null, noteTimeoutMs = 4000 }) {
  /*
   * B7 stage 2: EDGE_NOTE - the agent's words about a use, a ticket or a refused
   * ARM, to the phone. Changes nothing anywhere, so it never fails what it
   * describes: no channel, an old phone, no answer within noteTimeoutMs - all
   * the same, the use stands.
   */
  async function sendNote(fields) {
    if (!channel || !signer) return;
    try {
      const msg = await note.build({ signer, ...fields });
      let t = null;
      await Promise.race([channel.send(msg), new Promise((r) => { t = setTimeout(r, noteTimeoutMs); })]).finally(() => clearTimeout(t));
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
       * The head this budget holds (hex): what the agent's next use ARMs over,
       * and what `okedge exec --head` must name - proof the agent saw its own
       * last ticket's reply (mcp-service.md §4.2a).
       */
      head() {
        return toHex(state.head);
      },
      /** the uses still waiting for their ticket (seqs) */
      pending() {
        return [...state.owed];
      },
      /**
       * One use: ARM over the head this budget holds and SHA-256(bytes), run
       * op(bytes), and return the link it caused.
       * -> {result, link: {seq, paid, step, reveal}}
       */
      async use(bytes, op, { reason } = {}) {
        if (state.ended) throw fail('EEDGE_ARM', 'edge: this budget has ended', { reason: 'ended' });
        if (state.owed.length) throw fail('EEDGE_ARM', `edge: a ticket is owed for #${state.owed[0]} - ticket it first`, { reason: 'ticket-owed' });
        const data = Uint8Array.from(bytes);
        const subject = grants.requestSubject(data);
        /*
         * ARM over the KEY's head, read now - not the one this budget last saw.
         * Other links land between this budget's uses: a person's own pressed
         * sign, another agent, the key's own events. An ARM over the older head
         * makes the key treat the use as a press, and the budget would never
         * pay again (found 2026-10-03 by the agent service's test: another
         * process signing during an exec). "Did the agent see its last
         * ticket?" is asked separately (okedge exec --head vs head()).
         */
        state.head = (await edge.head()).head;
        try {
          await edge.arm(state.head, subject);
        } catch (e) {
          await sendNote({ seq: (await edge.head().catch(() => ({ seq: 0 }))).seq ?? 0, armRefused: String(e.status || e.message || 'refused').slice(0, note.MAX_ARM_REFUSED) });
          throw fail('EEDGE_ARM', `edge: the key refused the ARM (${e.status || e.message})`, { reason: e.status || 'refused' });
        }
        const result = await op(data);
        const h = await edge.head();
        const [l] = await edge.pickup(h.seq, 1);
        const f = chain.decodeLink(l.link);
        if (!same(f.subject, subject)) throw fail('EEDGE_LINK', `edge: the key's newest link (#${f.seq}) is not this use`);
        const paid = f.decision === codes.DECISION.SELF_PRESS && f.grantId === record.grantId;
        if (paid) {
          const mac = require('./hash').hmacSha256(l.reveal, subject);
          const r = grants.checkSelfPress({ genesis, uses: record.uses, step: f.grantStep, value: l.reveal, mac, subject });
          if (!r.ok) throw fail('EEDGE_LINK', `edge: the self-press's reveal does not belong to this budget (${r.reason})`);
        }
        if (f.flags & codes.FLAG.OWES_TICKET) state.owed.push(f.seq);
        if (paid) state.spent = Math.max(state.spent, f.grantStep);
        state.head = h.head;
        await save();
        /*
         * paidBy: the budget the KEY spent - it pays from the first live budget
         * that covers the request, so another of this agent's budgets (one a
         * continue left live) may pay instead of this one (seen 2026-10-03).
         */
        const paidBy = f.decision === codes.DECISION.SELF_PRESS ? f.grantId : null;
        if (reason !== undefined && reason !== null) await sendNote({ seq: f.seq, reason: clip(String(reason), note.MAX_REASON) });
        return { result, purpose: reason, link: { seq: f.seq, paid, paidBy, step: paid ? f.grantStep : null, reveal: paid ? l.reveal : null } };
      },
      /** File the ticket for a use; the new head is kept for the next use(). */
      async ticket(link, { code = 'OK', message }) {
        const r = await edge.ticket(link.seq, codes.ticketCode(code), tickets.messageHash(message));
        state.owed = state.owed.filter((s) => s !== link.seq);
        state.head = r.head;
        await save();
        if (message !== undefined && message !== null) await sendNote({ seq: link.seq, ticketMsg: String(message) });
        /*
         * R16 (spec 2026-10-04): a used-up budget still COVERS its identities until it
         * ends - a later pressed use of them owes a ticket - and it holds one of the
         * key's live slots. So the client ends it itself the moment its last use is
         * ticketed: a grant-end link, the slot freed. (The key does not end it on its
         * own: "used up" must not quietly drop the coverage.)
         */
        if (!state.ended && !state.owed.length && state.spent >= record.uses) {
          await end();
          return { ...r, ended: true };
        }
        return r;
      },
      /** Revoke what is left. */
      end,
    };
    /* revoke what is left (a grant-end link); also called by ticket() once the last use is ticketed */
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
    /**
     * Ask for a budget. scopes: [{op: 'sign'|'decrypt', slot, cap, identity?}]
     * (identity on a derived code, R11a). ttlMinutes: 1..1440.
     * Rejects EEDGE_UNSUPPORTED, EEDGE_INVALID, EEDGE_REFUSED (with .refusal:
     * declined, timeout, copy_unverified, ticket_owed, restoring, invalid),
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
      if (!answer.ok) throw fail('EEDGE_REFUSED', `edge: the registration was refused - ${answer.refusal}`, { refusal: answer.refusal });
      return { already: Boolean(answer.already) };
    },

    /**
     * R20: ask the phone to add a place that keeps copies (this PC's copy
     * store) as a known peer of the key - the person's Yes, then a press.
     * peerSigner: request.peerSignerFromSecret(the place's own P-256 secret),
     * not this agent's key. -> {already, seq?, index}; rejects EEDGE_REFUSED or
     * EEDGE_NO_ANSWER.
     */
    async peerAdd(peerSigner, name) {
      const answer = await channel.send(await request.buildPeerAdd({ signer: peerSigner, name }));
      if (!answer) throw fail('EEDGE_NO_ANSWER', 'edge: the app answered nothing - a bad signature or a replayed peer request');
      if (!answer.ok) throw fail('EEDGE_REFUSED', `edge: adding the peer was refused - ${answer.refusal}${answer.detail ? ` (${answer.detail})` : ''}`, { refusal: answer.refusal });
      return { already: Boolean(answer.already), seq: answer.seq ?? null, index: answer.index };
    },

    /**
     * R29 (P2b): ask the phone whose key is `deviceId` to pair it with the
     * key `key` (X || Y; its id is derived) - the code on its sheet, Yes, a
     * press. peerSigner: this place's own key (on that key's list). The caller
     * asks the OTHER phone the same, the other way round.
     * -> {already, seq?, index?}; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    async siblingAdd(peerSigner, { deviceId, key, name }) {
      const syncLib = require('./sync');
      const xy = Uint8Array.from(key).length === 65 ? Uint8Array.from(key).slice(1) : Uint8Array.from(key);
      const id = require('./chain').deviceIdOf(xy);
      const answer = await channel.send(await syncLib.buildSibling({ signer: peerSigner, deviceId, key: xy, id, name }));
      if (!answer) throw fail('EEDGE_NO_ANSWER', 'edge: the phone answered nothing - is this place on the key\'s list (okedge peer add)?');
      if (!answer.ok) throw fail('EEDGE_REFUSED', `edge: pairing was refused - ${answer.refusal}${answer.detail ? ` (${answer.detail})` : ''}`, { refusal: answer.refusal });
      return { already: Boolean(answer.already), seq: answer.seq ?? null, index: answer.index ?? null };
    },

    /**
     * R30 (P2c): the phone's own copy of its chain, every record it holds -
     * GIVE, BATCH at a time. peerSigner: this place (on that key's list).
     * -> [{link, head, reveal}] ; rejects EEDGE_REFUSED or EEDGE_NO_ANSWER.
     */
    async copyFromPhone(peerSigner, { deviceId }) {
      const syncLib = require('./sync');
      const out = [];
      for (let from = 0, guard = 0; from !== null && guard < 10000; guard += 1) {
        const a = await channel.send(await syncLib.buildGive({ signer: peerSigner, deviceId, from }));
        if (!a) throw fail('EEDGE_NO_ANSWER', 'edge: the phone answered nothing - is this place on the key\'s list (okedge peer add)?');
        if (!a.ok) throw fail('EEDGE_REFUSED', `edge: the phone gave no copy - ${a.refusal}${a.detail ? ` (${a.detail})` : ''}`, { refusal: a.refusal });
        const { fromHex } = require('../bytes');
        for (const [l, h, r] of a.links || []) out.push({ link: fromHex(l), head: fromHex(h), reveal: r ? fromHex(r) : null });
        from = Number.isInteger(a.next) ? a.next : null;
      }
      return out;
    },

    /**
     * R30 (P2c): bring the phone whose key is `deviceId` its sibling's chain
     * (`chain`, `records` up to the sibling's signed `checkpoint`) and ask
     * it to anchor it: HAVE (what it holds of that chain), the LINKS it lacks,
     * then ANCHOR - one sheet, Yes, a press, the anchor link.
     * -> {sent, seq} ; rejects EEDGE_REFUSED (declined, timeout, a rollback or
     * a changed history - with the phone's words) or EEDGE_NO_ANSWER.
     */
    async anchorToPhone(peerSigner, { deviceId, chain, records, checkpoint, name }) {
      const syncLib = require('./sync');
      const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
      const { toHex: hex } = require('../bytes');
      const ask = async (msg, what) => {
        const a = await channel.send(msg);
        if (!a) throw fail('EEDGE_NO_ANSWER', `edge: the phone answered nothing to ${what} - is this place on the key's list (okedge peer add)?`);
        if (!a.ok) throw fail('EEDGE_REFUSED', `edge: the phone refused the anchor - ${a.refusal}${a.detail ? ` (${a.detail})` : ''}`, { refusal: a.refusal });
        return a;
      };
      const upTo = records.filter((r) => require('./chain').decodeLink(r.link).seq <= checkpoint.seq);
      const have = await ask(await syncLib.buildHave({ signer: peerSigner, deviceId, name, chain }), 'the sync');
      const lacks = syncLib.missing(upTo, have.ranges || []);
      const sid = hex(randomBytes(8));
      const linkMsgs = lacks.length ? await syncLib.buildLinks({ signer: peerSigner, deviceId, records: lacks, sid, chain }) : [];
      for (const m of linkMsgs) await ask(m, `part ${m.payload.part + 1} of ${m.payload.parts}`);
      const done = await ask(await syncLib.buildAnchor({ signer: peerSigner, deviceId, sid, chain, linkParts: linkMsgs.length, checkpoint, name }), 'the anchor');
      return { sent: lacks.length, seq: done.seq ?? null };
    },

    /**
     * okedge sync phase 2: bring the PHONE's copy of chain `deviceId` up to
     * date from `records` (this place's verified copy, [{link, head, reveal}])
     * and merge `keychain` (this place's public Key Chain list, entries) with
     * the phone's. Asks what the phone holds, sends only the links it lacks and
     * the whole list, in signed parts; COMMIT brings up ONE sheet on the phone;
     * after its Yes and press, TAKEs the merged list back. peerSigner: this
     * place's own key (on the key's list).
     * -> {sent, seq (the sync link, or null when nothing moved), count, keychainIn,
     *     keychainOut, keychain (the merged list, or null)}
     * rejects EEDGE_REFUSED (declined, timeout, a fork - with the phone's words) or EEDGE_NO_ANSWER.
     */
    async syncToPhone(peerSigner, { deviceId, records, name, keychain = null }) {
      const syncLib = require('./sync');
      const { randomBytes } = require('../vendor/exports/@noble/ciphers/utils.js');
      const { toHex: hex } = require('../bytes');
      const ask = async (msg, what) => {
        const a = await channel.send(msg);
        if (!a) throw fail('EEDGE_NO_ANSWER', `edge: the phone answered nothing to ${what} - is this place on the key's list (okedge peer add)?`);
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
     * key's HEAD must still list it; the head to ARM over is read from the key.
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
