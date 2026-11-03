'use strict';

/*
 * AN MCP PLAN, RUN ON A DEVICE OF ITS IDENTITY (the MCP plan, Step 4b; Brad, 2026-10-28: "the user puts a key into the
 * web app, and the AI agent builds the plan"). An agent built the plan on the server's /mcp (mcp-server core mcp.js:
 * plan_new, plan_add, plan_hold, plan_submit); the room told every device of the identity it was submitted. One device
 * runs it, here:
 *
 *   1. ONE BUDGET SIZED TO THE PLAN: a scope per (op, key) with a cap of its items, asked through `client` - the lib's
 *      budget client (client.js) whose channel is the device's OWN Edge host. So the plan meets the same sheet, the same
 *      copy check (R27) and the same one press as a computer's budget request, and the opening is checked against the
 *      key as the CLI checks it. Nothing here approves: a Decline, a timeout or a copy that does not verify ends it.
 *   2. EACH ITEM ONE PAID USE, IN ORDER: TX start over the budget's head and exactly the bytes the key signs, the sign,
 *      its receipt - then its result goes back (`update`, the agent reads it with plan_wait).
 *   3. A PLACEHOLDER (plan_hold) WAITS for its data (plan_fill, `events`) inside the open budget - no second press - with
 *      the plan 'paused' while it waits; plan_finish drops what is still waiting. The wait ends at the budget's own
 *      lifetime at the latest: the key closes the budget then anyway.
 *   4. THE END: every receipt filed, then the budget is ended (client.js end - it revokes what is left), and the plan is
 *      'done' (every item ran), 'ended' (finished early) or 'failed' (why says).
 *
 * KEY REQUESTS (dont-hammer-the-key): the request is the host's - its copy check, GRANT_LABEL + GRANT_CREATE and the
 * ONE press; then the opening read back (1); per item the TX start, the sign, the link read and the receipt (4, no
 * press); the end (1). Nothing is asked on a timer.
 *
 * Pure: no device access of its own. The caller gives the budget client and the signers (planSigners: the key's
 * agent-derived sign, the gpg identity the device keeps); the runner decides only order, sizing and what is told.
 */

const { identityHash } = require('../../src/protocol/agent');
const { utf8ToBytes, fromBase64, toBase64 } = require('../../src/bytes');

/* the agent-derived sign the Edge agent uses: ed25519, version 2 (cli/agent.js AGENT_DERIVE) on its sign code 221 */
const AGENT_DERIVE = { keyType: 1, version: 2 };
const SIGN_CODE = 221;
/* a plan's budget lives this long: long enough for an agent's placeholders, short enough that a stopped agent's budget goes */
const PLAN_LIFETIME_MINUTES = 15;

const fail = (code, message) => Object.assign(new Error(message), { code });

/*
 * THE KEY AN ITEM NAMES, AS EDGE NAMES IT: ssh "[ssh://]user@host" -> the scope name "ssh://user@host" and its derive
 * identity; gpg "Name <email>" (or "gpg://...") -> "gpg://Name <email>". The scope's name is what the sheet shows and
 * what the key's label is made from (grants.identityLabel), so the budget pays for that one identity only (R11a).
 */
function keyOf(key) {
  const kind = key && key.kind;
  const text = String((key && key.identity) || '').trim();
  if (kind === 'ssh') {
    const m = /^(?:ssh:\/\/)?(?:([^@/]+)@)?([^/:@]+)$/.exec(text);
    if (!m) throw fail('EPLAN_KEY', `"${text}" is not an ssh identity ([ssh://]user@host)`);
    const derive = { ssh: { user: m[1] || undefined, host: m[2] } };
    return { kind, name: `ssh://${m[1] ? `${m[1]}@` : ''}${m[2]}`, derive };
  }
  if (kind === 'gpg') {
    const uid = text.replace(/^gpg:\/\//, '');
    if (!uid) throw fail('EPLAN_KEY', 'a gpg key names its user ID');
    return { kind, name: `gpg://${uid}`, uid, derive: { gpg: uid } };
  }
  throw fail('EPLAN_KEY', `a key is ssh or gpg, not ${JSON.stringify(kind)}`);
}

/* an item's data as bytes: text as UTF-8, or base64 */
function dataOf(item) {
  if (item.data === null || item.data === undefined) return null;
  return item.encoding === 'base64' ? fromBase64(String(item.data)) : utf8ToBytes(String(item.data));
}

/*
 * What can run, and what is refused before the budget is asked: only signs (a derived decrypt is not built on a device
 * yet - said per item, never skipped silently), on a key Edge can name. -> {runnable: [{item, key}], refused: [results]}
 */
function sortItems(plan) {
  const runnable = [];
  const refused = [];
  for (const it of [...(plan.items || [])].sort((a, b) => a.item - b.item)) {
    if (it.op !== 'sign') { refused.push({ item: it.item, refusal: `${it.op} is not run by a device yet - only sign` }); continue; }
    try {
      runnable.push({ it, key: keyOf(it.key) });
    } catch (e) {
      refused.push({ item: it.item, refusal: e.message });
    }
  }
  return { runnable, refused };
}

/* one scope per key, capped at its items, in the order the plan first names them */
function scopesOf(runnable) {
  const by = new Map();
  for (const { key } of runnable) {
    const s = by.get(key.name) || { op: 'sign', slot: SIGN_CODE, cap: 0, identity: key.name };
    s.cap += 1;
    by.set(key.name, s);
  }
  return [...by.values()];
}

/* the words the person approves (the sheet shows them; the key holds their hash): the title, then each item's reason */
function reasonOf(plan, runnable) {
  const items = runnable.map(({ it }) => `${it.held ? '(later) ' : ''}${it.reason}`).join('; ');
  return `${plan.title || 'an MCP plan'} - ${runnable.length} sign${runnable.length === 1 ? '' : 's'}: ${items}`;
}

/*
 * The signers a device gives the runner: ssh signs the data itself, gpg makes a detached OpenPGP signature with the
 * certificate of the agent identity this device keeps (its record: gpgUid + cert {signPublic, created}) - the same
 * signDetached the CLI's gpg shim uses. Each calls pay(bytes, sign) exactly once: the use the budget pays.
 *   okcrypto: the device's okcrypto (okcrypto.agent.sign); openpgp: the lib's fork (src/crypto/pgp) - only for gpg
 *   identity: () => the kept agent identity record, or null
 */
function planSigners({ okcrypto, openpgp = null, identity = async () => null }) {
  const agentSign = (derive, message) => okcrypto.agent.sign(derive, message, AGENT_DERIVE);
  return {
    async ssh(key, data, pay) {
      const sig = await pay(new Uint8Array([...data, ...identityHash(key.derive)]), () => agentSign(key.derive, data));
      return { signature: toBase64(Uint8Array.from(sig)), encoding: 'base64' };
    },
    async gpg(key, data, pay) {
      const record = await identity();
      if (!record || record.gpgUid !== key.uid || !record.cert) {
        throw fail('EPLAN_GPG', `this device keeps no agent identity for gpg "${key.uid}"${record && record.gpgUid ? ` (it keeps "${record.gpgUid}")` : ''}`);
      }
      if (!openpgp) throw fail('EPLAN_GPG', 'no OpenPGP on this device');
      const { signDetached } = require('../../src/crypto/pgp-cert');
      const armored = await signDetached(openpgp, {
        data, signPublic: record.cert.signPublic, curve: 'ed25519', created: record.cert.created,
        sign: (digest) => pay(new Uint8Array([...digest, ...identityHash(key.derive)]), () => agentSign(key.derive, digest)),
      });
      return { signature: armored, encoding: 'text' };
    },
  };
}

/**
 * Run one submitted plan.
 * @param {object} o
 * @param {any} o.plan        the plan as the room told it ({id, title, agent, items, ...})
 * @param {any} o.client      createEdgeClient({edge, channel: <this device's Edge host>})
 * @param {any} o.signers     planSigners(...)
 * @param {(u: any) => Promise<void>} o.update  the plan's progress back to its room: {state?, results?, receipts?, why?}
 * @param {(l: (e: any) => void) => () => void} o.subscribe  this plan's fill / finish events
 * @param {number} [o.ttlMinutes]
 * @param {(line: string) => void} [o.log]
 * -> the end state: 'done' | 'ended' | 'declined' | 'failed'
 */
async function runPlan({ plan, client, signers, update, subscribe, ttlMinutes = PLAN_LIFETIME_MINUTES, log = () => {} }) {
  const told = (u) => update(u).catch((e) => log(`plan ${plan.id}: its update was not taken (${e.message})`));
  const { runnable, refused } = sortItems(plan);
  if (refused.length) await told({ results: refused });
  if (!runnable.length) {
    await told({ state: 'failed', why: 'nothing in the plan can run on this device' });
    return 'failed';
  }

  /* the fills and the finish, as they come - kept until the item asks for them */
  const fills = new Map();
  let finished = false;
  let wake = null;
  const unsubscribe = subscribe((e) => {
    if (e.ev === 'fill') fills.set(e.item, { data: e.data, encoding: e.encoding });
    if (e.ev === 'finish') finished = true;
    if (wake) wake();
  });

  let budget;
  try {
    /* plan.card: the agent card it is asked under (a plan with none is refused by the host - the MCP's plans name one, plan step 3) */
    budget = await client.request({ reason: reasonOf(plan, runnable), scopes: scopesOf(runnable), ttlMinutes, card: plan.card || null });
  } catch (e) {
    unsubscribe();
    const declined = e.refusal === 'declined';
    log(`plan ${plan.id}: no budget - ${e.message}`);
    await told({ state: declined ? 'declined' : 'failed', why: declined ? 'the owner declined it' : e.message });
    return declined ? 'declined' : 'failed';
  }
  log(`plan ${plan.id}: budget ${budget.grantId} open - ${budget.uses} use(s)`);
  await told({ state: 'running', why: '' });

  /* the wait for a placeholder ends at the budget's lifetime: the key closes the budget then */
  const until = Date.now() + ttlMinutes * 60000;
  let expired = false;
  const deadline = setTimeout(() => { expired = true; if (wake) wake(); }, ttlMinutes * 60000);
  if (deadline.unref) deadline.unref();
  const receipts = [];
  let end = 'done';
  let why = '';
  try {
    for (let n = 0; n < runnable.length; n++) {
      const { it, key } = runnable[n];
      let data = dataOf(it);
      if (data === null && fills.has(it.item)) data = dataOf({ ...it, ...fills.get(it.item) });
      if (data === null) {
        await told({ state: 'paused', why: `waiting for item ${it.item}'s data (plan_fill)` });
        while (!fills.has(it.item) && !finished && !expired) await new Promise((r) => { wake = r; });
        wake = null;
        if (!fills.has(it.item)) {
          const left = runnable.slice(n).map((x) => ({ item: x.it.item, refusal: finished ? 'dropped - the plan was finished before its data came' : 'dropped - the budget\'s lifetime ran out before its data came' }));
          await told({ results: left });
          end = 'ended';
          why = finished ? 'finished by the agent' : `the budget's ${ttlMinutes} minutes ran out (${new Date(until).toISOString()})`;
          break;
        }
        data = dataOf({ ...it, ...fills.get(it.item) });
        await told({ state: 'running', why: '' });
      }
      let link = null;
      const pay = async (bytes, sign) => {
        const used = await budget.use(bytes, sign, { reason: it.reason });
        link = used.link;
        return used.result;
      };
      let result;
      try {
        result = { item: it.item, ...(await signers[key.kind](key, data, pay)) };
      } catch (e) {
        result = { item: it.item, refusal: `not signed: ${e.message}` };
      }
      /* a use the key paid owes its receipt, signed or not (R16): filed before anything else is asked */
      const owed = link || (budget.pending().length ? { seq: budget.pending()[0] } : null);
      if (owed) {
        const code = result.refusal ? 'AGENT_ERROR' : 'OK';
        await budget.receipt(owed, { code, message: `${it.reason} - ${result.refusal ? result.refusal : 'signed'}` });
        receipts.push({ seq: owed.seq, code });
      }
      await told({ results: [result], receipts: [...receipts] });
      if (result.refusal && !link) {
        /* refused before the key paid (a gpg identity this device does not keep): the rest still runs */
        log(`plan ${plan.id}: item ${it.item} - ${result.refusal}`);
      }
    }
    await budget.end();
  } catch (e) {
    end = 'failed';
    why = e.message;
    log(`plan ${plan.id}: failed - ${e.message}`);
    /* the end is tried once every receipt is in: a budget left open with uses goes at its lifetime anyway */
    if (!budget.pending().length) await budget.end().catch(() => undefined);
  } finally {
    clearTimeout(deadline);
    unsubscribe();
  }
  log(`plan ${plan.id}: ${end}${why ? ` - ${why}` : ''} (${receipts.length} receipt(s))`);
  await told({ state: end, receipts: [...receipts], why });
  return end;
}

module.exports = { runPlan, planSigners, scopesOf, sortItems, keyOf, reasonOf, PLAN_LIFETIME_MINUTES, SIGN_CODE, AGENT_DERIVE };
