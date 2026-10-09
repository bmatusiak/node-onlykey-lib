'use strict';

/**
 * THE APP'S SIDE OF A BUDGET REQUEST (onlykey-edge mcp-service.md 4.7a): what
 * ok-rn runs when an EDGE_REQUEST arrives - everything but the screen, which
 * comes in as `ask`. One implementation, so every app that approves budgets
 * applies the same rules:
 *
 *   1. drop a malformed request, or a nonce seen (who asks - the paired computer - the
 *      phone settled before: Brad, 2026-10-08, "so the claude key thing is overkill");
 *   2. check the caps (at most 300 uses, D4) and the lifetime;
 *   3. ask the person, showing the TEXT and the NAMES (the identities asked for);
 *   4. compute each label from the identity name and the reason hash from the
 *      text ITSELF - never a hash the agent sends;
 *   5. verify its copy of the chain (R27), then GRANT_LABEL + GRANT_CREATE on
 *      the key, and the person presses;
 *   6. answer with the budget, or a typed refusal.
 *
 * The key's own rules (the press, labels, R27, R18) are unchanged: this
 * only decides what to ask the key for, and words what came back.
 */

const request = require('./request');
const { toHex } = require('../../src/bytes');

const refuse = (refusal, detail) => ({ ok: false, refusal, ...(detail ? { detail } : {}) });

/**
 * @param {object} msg an EDGE_REQUEST
 * @param {object} o
 * @param {object} o.edge the Edge device service (edge/plugin) for THIS app's key
 * @param {string|null} [o.from] the paired computer that asked (its pairing id) - a continue must come from the same one
 * @param {Set<string>} o.seen nonces already taken (the caller keeps it)
 * @param {(view: object) => Promise<'approve'|'decline'|'timeout'|'copy_unverified'>} o.ask the screen
 *   ('timeout': nobody answered the sheet; 'copy_unverified': the sheet could
 *   not offer Approve, the app's copy did not verify)
 * @param {() => Promise<{ok: boolean, head: Uint8Array}>} o.verifyCopy R27: the
 *   app's copy checked; head = the key's head it verified up to
 * @param {(grantId: number) => ({from: string|null, scopes: object[]} | null)} [o.budgetOf]
 *   a continue: the app's own record of the budget it continues (who asked,
 *   which scopes) - null when the app never opened it
 * @param {(msg: object) => Promise<object[]>|object[]} [o.coverOf] the live
 *   budgets that already cover what this request names (view().covered)
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait (the key's own is 25 s)
 * @returns {Promise<{ok: true, budget: object} | {ok: false, refusal: string} | {dropped: string}>}
 *   dropped: nothing is answered (malformed, replayed)
 */
async function approveRequest(msg, { edge, from = null, seen, ask, verifyCopy, budgetOf = () => null, coverOf = () => [], onPress, timeoutMs = 30000 }) {
  const v = request.verify(msg, { seen });
  if (!v.ok) return { dropped: v.reason };
  seen.add(msg.nonce.toLowerCase()); /* taken now: a replay of it is dropped, whatever the person answers */

  const c = request.check(msg);
  if (!c.ok) return refuse('invalid', c.reason);

  if (msg.continue !== undefined) {
    /* "continues <budget>": one this app opened, for this same paired computer, with the same scopes */
    const was = budgetOf(msg.continue);
    if (!was) return refuse('invalid', `no budget ${msg.continue} to continue`);
    if (String(was.from ?? '').toLowerCase() !== String(from ?? '').toLowerCase()) return refuse('invalid', `budget ${msg.continue} was another computer's`);
    if (!request.sameScopes(was.scopes, msg.scopes)) return refuse('invalid', `a continue keeps the scopes of budget ${msg.continue}`);
    /* 4.7a: only an ENDED budget is continued - the agent ends it first (client.continue revokes, no press) */
    if ((await edge.head()).live.includes(msg.continue)) return refuse('still_live', `budget ${msg.continue} is still live - end it first`);
  }

  const answer = await ask(request.view(msg, { covered: await coverOf(msg) }));
  /* the sheet could not offer Approve: the copy did not verify when it was shown (nothing is sent to the key) */
  if (answer === 'copy_unverified') return refuse('copy_unverified');
  if (answer === 'timeout') return refuse('timeout', 'nobody answered on the phone');
  if (answer !== 'approve') return refuse('declined');

  const copy = await verifyCopy();
  if (!copy || !copy.ok || !(copy.head instanceof Uint8Array)) return refuse('copy_unverified');

  const h = await edge.head();
  if (h.owed || h.overflow) return refuse('receipt_owed');

  let g;
  try {
    g = await edge.grant({
      scopes: request.grantScopes(msg),
      reasonHash: request.reasonHash(msg.reason),
      verifiedHead: copy.head,
      ttlMinutes: msg.lifetime,
      onPress,
      timeoutMs,
    });
  } catch (e) {
    if (e && e.status === 'receipt-owed') return refuse('receipt_owed');
    if (e && e.status === 'stale-head') return refuse('copy_unverified', 'the chain moved since the copy was checked');
    if (e && e.code === 'ETIMEDOUT') return refuse('timeout', noPress(e));
    throw e;
  }
  return {
    ok: true,
    budget: {
      grantId: g.grantId,
      uses: g.uses,
      genesis: toHex(g.genesis),
      seq: g.seq,
      lifetime: g.lifetime,
      checkpoint: { seq: g.checkpoint.seq, head: toHex(g.checkpoint.head), signature: toHex(g.checkpoint.signature) },
    },
  };
}

/*
 * Why no press counted. The key closes its wait at 20 s (the core's own
 * timeout) and refuses a press after that in a sentence ("Error button press
 * was not accepted", Pixel 2026-10-05): say so, or the person who DID press
 * is told nobody pressed.
 */
function noPress(e) {
  return e && e.pressRefused ? `the key refused the press (${e.keyText}) - its 20 s wait had ended` : 'no press on the key';
}

module.exports = { approveRequest };
