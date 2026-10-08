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
 * The key's own rules (the press, labels, R27, R18) are unchanged: this
 * only decides what to ask the key for, and words what came back.
 */

const request = require('./request');
const grants = require('./grants');
const chain = require('./chain');
const codes = require('./codes');
const { toHex, fromHex } = require('../../src/bytes');

const refuse = (refusal, detail) => ({ ok: false, refusal, ...(detail ? { detail } : {}) });

/**
 * @param {object} msg an EDGE_REQUEST
 * @param {object} o
 * @param {object} o.edge the Edge device service (edge/plugin) for THIS app's key
 * @param {string[]} o.registered agent public keys (hex) registered with a press
 * @param {Set<string>} o.seen nonces already taken (the caller keeps it)
 * @param {string[]} [o.ownIdentities] the person's own identity names
 * @param {(view: object) => Promise<'approve'|'decline'|'timeout'|'copy_unverified'>} o.ask the screen
 *   ('timeout': nobody answered the sheet; 'copy_unverified': the sheet could
 *   not offer Approve, the app's copy did not verify)
 * @param {() => Promise<{ok: boolean, head: Uint8Array}>} o.verifyCopy R27: the
 *   app's copy checked; head = the key's head it verified up to
 * @param {(grantId: number) => ({agent: string, scopes: object[]} | null)} [o.budgetOf]
 *   a continue: the app's own record of the budget it continues (who asked,
 *   which scopes) - null when the app never opened it
 * @param {(msg: object) => Promise<object[]>|object[]} [o.coverOf] the live
 *   budgets that already cover what this request names (view().covered)
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait (the key's own is 25 s)
 * @returns {Promise<{ok: true, budget: object} | {ok: false, refusal: string} | {dropped: string}>}
 *   dropped: nothing is answered to the agent (unsigned, unregistered, replayed)
 */
async function approveRequest(msg, { edge, registered, seen, ownIdentities = [], ask, verifyCopy, budgetOf = () => null, coverOf = () => [], onPress, timeoutMs = 30000 }) {
  const v = request.verify(msg, { registered, seen });
  if (!v.ok) return { dropped: v.reason };
  seen.add(msg.nonce.toLowerCase()); /* taken now: a replay of it is dropped, whatever the person answers */

  const c = request.check(msg);
  if (!c.ok) return refuse('invalid', c.reason);

  if (msg.continue !== undefined) {
    /* "continues <budget>": one this app opened, for this agent, with the same scopes */
    const was = budgetOf(msg.continue);
    if (!was) return refuse('invalid', `no budget ${msg.continue} to continue`);
    if (String(was.agent).toLowerCase() !== msg.agent.toLowerCase()) return refuse('invalid', `budget ${msg.continue} was another agent's`);
    if (!request.sameScopes(was.scopes, msg.scopes)) return refuse('invalid', `a continue keeps the scopes of budget ${msg.continue}`);
    /* 4.7a: only an ENDED budget is continued - the agent ends it first (client.continue revokes, no press) */
    if ((await edge.head()).live.includes(msg.continue)) return refuse('still_live', `budget ${msg.continue} is still live - end it first`);
  }

  const answer = await ask(request.view(msg, { ownIdentities, covered: await coverOf(msg) }));
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

/**
 * An agent asks to be registered (EDGE_REGISTER, mcp-service.md 4.7a): signed
 * by the key it names, new, the person's Yes on the sheet, then a PHYSICAL
 * press - the key links it (AGENT_ADD, subject grants.agentSubject). Like a
 * known peer (R20). -> {ok: true, agent, name, seq} | {ok: false, refusal} | {dropped}
 *
 * @param {object} msg an EDGE_REGISTER
 * @param {object} o
 * @param {object} o.edge the Edge device service for THIS app's key
 * @param {string[]} [o.registered] agent keys (hex) already registered
 * @param {Set<string>} o.seen nonces already taken
 * @param {(view: {agent: string, name: string, fingerprint: string}) => Promise<'approve'|'decline'|'timeout'>} o.ask the sheet
 * @param {() => void} [o.onPress] told when the key waits for the press
 * @param {number} [o.timeoutMs] the press wait
 * @returns {Promise<any>}
 */
async function approveRegister(msg, { edge, registered = [], seen, ask, onPress, timeoutMs = 30000 }) {
  const v = request.verifyRegister(msg, { seen });
  if (!v.ok) return { dropped: v.reason };
  seen.add(msg.nonce.toLowerCase());
  const agent = msg.agent.toLowerCase();
  if (registered.some((k) => String(k).toLowerCase() === agent)) return { ok: true, agent, name: msg.name, already: true };
  const answer = await ask({ agent, name: msg.name, fingerprint: request.fingerprint(agent) });
  if (answer === 'timeout') return refuse('timeout', 'nobody answered on the phone');
  if (answer !== 'approve') return refuse('declined');
  let r;
  try {
    r = await edge.agentAdd(fromHex(agent), { onPress, timeoutMs });
  } catch (e) {
    if (e && e.code === 'ETIMEDOUT') return refuse('timeout', noPress(e));
    throw e;
  }
  /* the link the press wrote: this agent, pressed */
  const [l] = await edge.pickup(r.seq, 1);
  const f = chain.decodeLink(l.link);
  if (f.op !== codes.OP.AGENT_ADD || !(f.flags & codes.FLAG.PRESS_OBSERVED) || toHex(f.subject) !== toHex(grants.agentSubject(fromHex(agent)))) {
    return refuse('invalid', `the key's link #${r.seq} is not this agent's registration`);
  }
  return { ok: true, agent, name: msg.name, seq: r.seq };
}

/**
 * R15c (2026-10-03): is this agent registered - is its AGENT_ADD link, made at
 * a press, in the app's VERIFIED copy of the chain? The app's own list of
 * agents is a convenience; only the link counts. An agent in storage without
 * one (planted, or kept from before the press) is refused, unread.
 *
 * @param {Array<{fields: object, verified: boolean}>} rows the copy's links,
 *   decoded, each with whether R27 verified it (the app's copy view)
 * @param {string} agentHex the agent's key (hex)
 * @returns {number|null} the seq of its verified agent-add link, or null
 */
function agentInCopy(rows, agentHex) {
  let want;
  try { want = toHex(grants.agentSubject(fromHex(String(agentHex)))); } catch { return null; }
  for (const r of rows || []) {
    const f = r.fields;
    if (r.verified && f && f.op === codes.OP.AGENT_ADD && (f.flags & codes.FLAG.PRESS_OBSERVED) && toHex(f.subject) === want) return f.seq;
  }
  return null;
}

module.exports = { approveRequest, approveRegister, agentInCopy };
