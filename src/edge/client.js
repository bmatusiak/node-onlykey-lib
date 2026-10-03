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
const { toHex, fromHex } = require('../bytes');

const fail = (code, message, extra = {}) => Object.assign(new Error(message), { code, ...extra });
const same = (a, b) => a.length === b.length && a.every((v, i) => v === b[i]);
const storeKey = (grantId) => `okedge.budget.${grantId}`;

function createEdgeClient({ edge, channel, signer, store = null }) {
  async function deviceIdentity() {
    if ((await edge.probe()) !== 'edge') throw fail('EEDGE_UNSUPPORTED', 'edge: this key has no Edge - sign with a press per use instead');
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
    };
    const genesis = fromHex(record.genesis);
    const save = async () => {
      if (store) await store.set(storeKey(record.grantId), JSON.stringify({ ...record, head: toHex(state.head), owed: state.owed, ended: state.ended }));
    };

    return {
      grantId: record.grantId,
      uses: record.uses,
      reason: record.reason,
      scopes: record.scopes,
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
        try {
          await edge.arm(state.head, subject);
        } catch (e) {
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
        state.head = h.head;
        await save();
        return { result, purpose: reason, link: { seq: f.seq, paid, step: paid ? f.grantStep : null, reveal: paid ? l.reveal : null } };
      },
      /** File the ticket for a use; the new head is kept for the next use(). */
      async ticket(link, { code = 'OK', message }) {
        const r = await edge.ticket(link.seq, codes.ticketCode(code), tickets.messageHash(message));
        state.owed = state.owed.filter((s) => s !== link.seq);
        state.head = r.head;
        await save();
        return r;
      },
      /** Revoke what is left. */
      async end() {
        try {
          await edge.revoke(record.grantId);
        } catch (e) {
          if (!(e && e.status === 'no-such-budget')) throw e; /* already gone: expired, or a lock */
        }
        state.ended = true;
        await save();
      },
    };
  }

  return {
    /**
     * Ask for a budget. scopes: [{op: 'sign'|'decrypt', slot, cap, identity?}]
     * (identity on a derived code, R11a). ttlMinutes: 1..1440.
     * Rejects EEDGE_UNSUPPORTED, EEDGE_INVALID, EEDGE_REFUSED (with .refusal:
     * declined, timeout, copy_unverified, ticket_owed, restoring, invalid) or
     * EEDGE_OPENING (the answer is not a budget the key opened as asked).
     */
    async request({ reason, scopes, ttlMinutes }) {
      const { publicKey, deviceId } = await deviceIdentity();
      const msg = await request.build({ signer, reason, scopes, lifetime: ttlMinutes });
      const c = request.check(msg);
      if (!c.ok) throw fail('EEDGE_INVALID', `edge: ${c.reason}`);
      const answer = await channel.send(msg);
      if (!answer || !answer.ok) {
        const refusal = (answer && answer.refusal) || 'declined';
        throw fail('EEDGE_REFUSED', `edge: the budget was refused - ${refusal}${answer && answer.detail ? ` (${answer.detail})` : ''}`, { refusal });
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
      const record = { grantId: b.grantId, uses: b.uses, genesis: b.genesis, head: b.checkpoint.head, reason, scopes: msg.scopes, lifetime: ttlMinutes, owed: [] };
      if (store) await store.set(storeKey(b.grantId), JSON.stringify(record));
      return budgetOf(record);
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
