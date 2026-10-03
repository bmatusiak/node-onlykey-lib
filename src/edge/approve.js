'use strict';

/**
 * THE APP'S SIDE OF A BUDGET REQUEST (onlykey-edge mcp-service.md 4.7a): what
 * ok-rn runs when an EDGE_REQUEST arrives - everything but the screen, which
 * comes in as `ask`. One implementation, so every app that approves budgets
 * applies the same rules:
 *
 *   1. drop a request not signed by a registered agent key, or a nonce seen;
 *   2. check the caps (at most 300 uses, D4) and the lifetime;
 *   3. ask the person, showing the TEXT and the NAMES - a request naming one of
 *      the person's own identities is marked for a red warning and a second
 *      confirm (the screen's job; view().ownWarning says when);
 *   4. compute each label from the identity name and the reason hash from the
 *      text ITSELF - never a hash the agent sends;
 *   5. verify its copy of the chain (R27), then GRANT_LABEL + GRANT_CREATE on
 *      the key, and the person presses;
 *   6. answer with the budget, or a typed refusal.
 *
 * The key's own rules (the press, labels, R27, R18, R26) are unchanged: this
 * only decides what to ask the key for, and words what came back.
 */

const request = require('./request');
const { toHex } = require('../bytes');

const refuse = (refusal, detail) => ({ ok: false, refusal, ...(detail ? { detail } : {}) });

/**
 * @param {object} msg an EDGE_REQUEST
 * @param {object} o
 * @param {object} o.edge the Edge device service (plugins/edge) for THIS app's key
 * @param {string[]} o.registered agent public keys (hex) registered with a press
 * @param {Set<string>} o.seen nonces already taken (the caller keeps it)
 * @param {string[]} [o.ownIdentities] the person's own identity names
 * @param {(view: object) => Promise<'approve'|'decline'>} o.ask the screen
 * @param {() => Promise<{ok: boolean, head: Uint8Array}>} o.verifyCopy R27: the
 *   app's copy checked; head = the key's head it verified up to
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait (the key's own is 25 s)
 * @returns {Promise<{ok: true, budget: object} | {ok: false, refusal: string} | {dropped: string}>}
 *   dropped: nothing is answered to the agent (unsigned, unregistered, replayed)
 */
async function approveRequest(msg, { edge, registered, seen, ownIdentities = [], ask, verifyCopy, onPress, timeoutMs = 30000 }) {
  const v = request.verify(msg, { registered, seen });
  if (!v.ok) return { dropped: v.reason };
  seen.add(msg.nonce.toLowerCase()); /* taken now: a replay of it is dropped, whatever the person answers */

  const c = request.check(msg);
  if (!c.ok) return refuse('invalid', c.reason);

  const answer = await ask(request.view(msg, { ownIdentities }));
  if (answer !== 'approve') return refuse('declined');

  const copy = await verifyCopy();
  if (!copy || !copy.ok || !(copy.head instanceof Uint8Array)) return refuse('copy_unverified');

  const h = await edge.head();
  if (h.restoring) return refuse('restoring');
  if (h.owed || h.overflow) return refuse('ticket_owed');

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
    if (e && e.status === 'ticket-owed') return refuse('ticket_owed');
    if (e && e.status === 'restoring') return refuse('restoring');
    if (e && e.status === 'stale-head') return refuse('copy_unverified', 'the chain moved since the copy was checked');
    if (e && e.code === 'ETIMEDOUT') return refuse('timeout');
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

module.exports = { approveRequest };
