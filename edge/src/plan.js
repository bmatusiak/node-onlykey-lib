'use strict';

/*
 * AN MCP PLAN, RUN ON A DEVICE OF ITS IDENTITY (the MCP plan, Step 4b; Brad, 2026-10-28: "the user puts a key into the
 * web app, and the AI agent builds the plan"). An agent built the plan on the server's /mcp (mcp-server core mcp.js:
 * plan_new, plan_submit, plan_data); the room told every device of the identity it was submitted. One device runs it,
 * here.
 *
 * FINGERPRINTS FIRST, DATA AFTER (Brad, 2026-11-04: "all ready, hashed, fingerprinted before sending; on budget approval,
 * then the data passes to the desktop app ... then at the end of the budget, the results are sent back to the request"):
 *
 *   1. ONE BUDGET SIZED TO THE PLAN, under the agent's own card (plan.card - agents.budgetAllowed): a scope per key with a
 *      cap of its items, asked through `client` - the lib's budget client (client.js) whose channel is the device's OWN
 *      Edge host. So the plan meets the same sheet, the same copy check (R27) and the same one press as a computer's
 *      budget request. The person approves the item count and their fingerprints (SHA-256 of each item's data) - no
 *      data has reached the device yet. Nothing here approves: a Decline, a timeout or a copy that does not verify ends it.
 *   2. THE DATA, then (plan_data, `events`): every item's data must come and match its fingerprint BEFORE the key signs
 *      any of it - one that does not match ends the budget with nothing signed. The wait ends at the budget's lifetime at
 *      the latest (the key closes the budget then anyway), or at plan_finish.
 *   3. EACH ITEM ONE PAID USE, IN ORDER: TX start over the budget's head and exactly the bytes the key signs, the sign,
 *      its receipt.
 *   4. THE END: the budget is ended (client.js end - it revokes what is left) and every result goes back at once with the
 *      end state: 'done' (every item signed), 'ended' (finished or out of time before the data came) or 'failed'.
 *
 * KEY REQUESTS (dont-hammer-the-key): the request is the host's - its copy check, GRANT_LABEL + GRANT_CREATE and the
 * ONE press; then the opening read back (1); per item the TX start, the sign, the link read and the receipt (4, no
 * press); the end (1). Nothing is asked on a timer.
 *
 * Pure: no device access of its own. The caller gives the budget client and the signers (planSigners: the key's
 * agent-derived sign, a stored slot's sign, the gpg identity the device keeps); the runner decides only order, sizing,
 * the fingerprint check and what is told.
 */

const { identityHash } = require('../../src/protocol/agent');
const { utf8ToBytes, fromBase64, toBase64, toHex } = require('../../src/bytes');
const crypto = require('../../src/crypto/provider');

/* the agent-derived sign the Edge agent uses: ed25519, version 2 (cli/agent.js AGENT_DERIVE) on its sign code 221 */
const AGENT_DERIVE = { keyType: 1, version: 2 };
const SIGN_CODE = 221;
/* the RSA slots a budget may pay a sign on (okplugin_edge scope_allowed) */
const RSA_SLOTS = [1, 2, 3, 4];
/* a plan's budget lives this long: long enough for the agent to send its data, short enough that a stopped agent's budget goes */
const PLAN_LIFETIME_MINUTES = 15;

const fail = (code, message) => Object.assign(new Error(message), { code });

/*
 * THE KEY AN ITEM NAMES, AS EDGE NAMES IT: ssh "[ssh://]user@host" -> the scope name "ssh://user@host" and its derive
 * identity; gpg "Name <email>" (or "gpg://...") -> "gpg://Name <email>". The scope's name is what the sheet shows and
 * what the key's label is made from (grants.identityLabel), so the budget pays for that one identity only (R11a).
 * rsa {slot: 1-4, bits}: a stored key - its scope names the slot and no identity; bits (its modulus: 1024-4096) is the
 * signature's length, which the device must be told (okcrypto expectBytes: a 4096-bit signature is exactly 512 bytes,
 * one whole chunk, which the firmware's short-chunk end rule cannot tell from more to come).
 */
function keyOf(key) {
  const kind = key && key.kind;
  if (kind === 'rsa') {
    const slot = Number(key.slot);
    if (!RSA_SLOTS.includes(slot)) throw fail('EPLAN_KEY', `an rsa key is a stored slot 1-4, not ${JSON.stringify(key.slot)}`);
    const bits = Number(key.bits);
    if (![1024, 2048, 3072, 4096].includes(bits)) throw fail('EPLAN_KEY', `an rsa key names its size: bits 1024, 2048, 3072 or 4096, not ${JSON.stringify(key.bits)}`);
    return { kind, name: `slot ${slot}`, slot, bits };
  }
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
  throw fail('EPLAN_KEY', `a key is ssh, gpg or rsa, not ${JSON.stringify(kind)}`);
}

/* an item's data as bytes: text as UTF-8, or base64 */
function dataOf(item) {
  if (item.data === null || item.data === undefined) return null;
  return item.encoding === 'base64' ? fromBase64(String(item.data)) : utf8ToBytes(String(item.data));
}

/* the fingerprint an item's data must have: SHA-256 of its bytes, hex */
const fingerprintOf = (bytes) => toHex(crypto.sha256(bytes));

/*
 * What can run, and what is refused before the budget is asked: only signs (a derived decrypt is not built on a device
 * yet - said per item, never skipped silently), on a key Edge can name, with a fingerprint. -> {runnable: [{it, key}], refused}
 */
function sortItems(plan) {
  const runnable = [];
  const refused = [];
  for (const it of [...(plan.items || [])].sort((a, b) => a.item - b.item)) {
    if (it.op !== 'sign') { refused.push({ item: it.item, refusal: `${it.op} is not run by a device yet - only sign` }); continue; }
    if (!/^[0-9a-f]{64}$/.test(String(it.fingerprint || ''))) { refused.push({ item: it.item, refusal: 'no fingerprint (SHA-256 of its data, 64 hex)' }); continue; }
    try {
      runnable.push({ it, key: keyOf(it.key) });
    } catch (e) {
      refused.push({ item: it.item, refusal: e.message });
    }
  }
  return { runnable, refused };
}

/* one scope per key, capped at its items, in the order the plan first names them (a stored slot names no identity) */
function scopesOf(runnable) {
  const by = new Map();
  for (const { key } of runnable) {
    const s = by.get(key.name) || (key.kind === 'rsa' ? { op: 'sign', slot: key.slot, cap: 0 } : { op: 'sign', slot: SIGN_CODE, cap: 0, identity: key.name });
    s.cap += 1;
    by.set(key.name, s);
  }
  return [...by.values()];
}

/*
 * The words the person approves (the sheet shows them; the key holds their hash): the title, then each item's reason and
 * the start of its fingerprint - what the agent will send is fixed before the press.
 */
function reasonOf(plan, runnable) {
  const items = runnable.map(({ it }) => `${it.reason} (${it.fingerprint.slice(0, 16)})`).join('; ');
  return `${plan.title || 'an MCP plan'} - ${runnable.length} sign${runnable.length === 1 ? '' : 's'}: ${items}`;
}

/*
 * The signers a device gives the runner: ssh signs the data itself, gpg makes a detached OpenPGP signature with the
 * certificate of the agent identity this device keeps (its record: gpgUid + cert {signPublic, created}) - the same
 * signDetached the CLI's gpg shim uses; rsa signs the data - a digest (SHA-256, -384 or -512: the key's PKCS#1 v1.5 sign
 * picks the hash by its length) - with the stored slot's key. Each calls pay(bytes, sign) exactly once: the use the
 * budget pays.
 *   okcrypto: the device's okcrypto (okcrypto.agent.sign, okcrypto.sign); openpgp: the lib's fork (src/crypto/pgp) - only for gpg
 *   identity: () => the kept agent identity record, or null
 */
/*
 * PAID, so no press is said (box, 2026-11-04: blue-key's RSA signs under a plan's budget - the key paid them and asked
 * nothing, yet the lib said "press asked: signing - code 6 4 2", the host's sheet inspector found no sheet for it, and
 * the dry run stopped). Each sign runs inside pay(), after the key took its TX start, as the CLI agent's paid sign
 * (cli/agent.js). Should the budget be gone by the time the request lands, the key waits for an ordinary press no
 * one is shown: the sign times out unsigned - never signed without a press.
 */
const PAID = { paid: true };
function planSigners({ okcrypto, openpgp = null, identity = async () => null }) {
  const agentSign = (derive, message) => okcrypto.agent.sign(derive, message, { ...AGENT_DERIVE, ...PAID });
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
    async rsa(key, data, pay) {
      if (![32, 48, 64].includes(data.length)) throw fail('EPLAN_RSA', `an rsa item's data is its digest (32, 48 or 64 bytes), not ${data.length} bytes`);
      /* the key pays over SHA-256 of exactly what is submitted (okplugin_edge_primed); the signature is the modulus' length */
      const sig = await pay(data, () => okcrypto.sign(key.slot, data, { expectBytes: key.bits / 8, ...PAID }));
      if (sig.length !== key.bits / 8) throw fail('EPLAN_RSA', `slot ${key.slot} answered ${sig.length} bytes, not a ${key.bits}-bit signature`);
      return { signature: toBase64(Uint8Array.from(sig)), encoding: 'base64' };
    },
  };
}

/**
 * Run one submitted plan.
 * @param {object} o
 * @param {any} o.plan        the plan as the room told it ({id, title, agent, card, items: [{item, op, key, reason, fingerprint}], ...})
 * @param {any} o.client      createEdgeClient({edge, channel: <this device's Edge host>})
 * @param {any} o.signers     planSigners(...)
 * @param {(u: any) => Promise<void>} o.update  the plan's progress back to its room: {state?, results?, receipts?, why?}
 * @param {(l: (e: any) => void) => () => void} o.subscribe  this plan's data / finish events
 * @param {number} [o.ttlMinutes]
 * @param {(line: string) => void} [o.log]
 * -> the end state: 'done' | 'ended' | 'declined' | 'failed'
 */
async function runPlan({ plan, client, signers, update, subscribe, ttlMinutes = PLAN_LIFETIME_MINUTES, log = () => {} }) {
  const told = (u) => update(u).catch((e) => log(`plan ${plan.id}: its update was not taken (${e.message})`));
  const { runnable, refused } = sortItems(plan);
  if (refused.length) {
    /* the plan is approved whole or not at all: an item that cannot run fails it before any budget is asked */
    await told({ state: 'failed', results: refused, why: `${refused.length} item(s) cannot run: ${refused.map((r) => `item ${r.item}: ${r.refusal}`).join('; ')}` });
    return 'failed';
  }
  if (!runnable.length) {
    await told({ state: 'failed', why: 'an empty plan' });
    return 'failed';
  }

  /* the data and the finish, as they come - kept until every item has its data */
  const data = new Map();
  let finished = false;
  let wake = null;
  const unsubscribe = subscribe((e) => {
    if (e.ev === 'data') data.set(e.item, { data: e.data, encoding: e.encoding });
    if (e.ev === 'finish') finished = true;
    if (wake) wake();
  });

  let budget;
  try {
    /* plan.card: the agent's own card - the host refuses a plan with none, or another agent's (agents.budgetAllowed) */
    budget = await client.request({ reason: reasonOf(plan, runnable), scopes: scopesOf(runnable), ttlMinutes, card: plan.card || null });
  } catch (e) {
    unsubscribe();
    const declined = e.refusal === 'declined';
    log(`plan ${plan.id}: no budget - ${e.message}`);
    await told({ state: declined ? 'declined' : 'failed', why: declined ? 'the owner declined it' : e.message });
    return declined ? 'declined' : 'failed';
  }
  log(`plan ${plan.id}: budget ${budget.grantId} open - ${budget.uses} use(s); waiting for the data`);
  /* running: the agent sends the data now (plan_wait shows it waiting) */
  await told({ state: 'running', why: '' });

  const until = Date.now() + ttlMinutes * 60000;
  let expired = false;
  const deadline = setTimeout(() => { expired = true; if (wake) wake(); }, ttlMinutes * 60000);
  if (deadline.unref) deadline.unref();
  const results = [];
  const receipts = [];
  let end = 'done';
  let why = '';
  try {
    /* 2. every item's data, each matching its fingerprint - before anything is signed */
    const missing = () => runnable.filter(({ it }) => !data.has(it.item));
    while (missing().length && !finished && !expired) await new Promise((r) => { wake = r; });
    wake = null;
    const bytes = new Map();
    if (missing().length) {
      end = 'ended';
      why = `${finished ? 'finished by the agent' : `the budget's ${ttlMinutes} minutes ran out (${new Date(until).toISOString()})`} before the data of item(s) ${missing().map(({ it }) => it.item).join(', ')} came - nothing signed`;
    } else {
      for (const { it } of runnable) {
        const b = dataOf({ ...it, ...data.get(it.item) });
        if (fingerprintOf(b) !== it.fingerprint) {
          end = 'failed';
          why = `item ${it.item}'s data does not match its approved fingerprint ${it.fingerprint.slice(0, 16)} - nothing signed`;
          break;
        }
        bytes.set(it.item, b);
      }
    }
    /* 3. one paid use each, in order */
    for (const { it, key } of end === 'done' ? runnable : []) {
      let link = null;
      const pay = async (b, sign) => {
        const used = await budget.use(b, sign, { reason: it.reason });
        link = used.link;
        return used.result;
      };
      let result;
      try {
        result = { item: it.item, ...(await signers[key.kind](key, bytes.get(it.item), pay)) };
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
      results.push(result);
      if (result.refusal) log(`plan ${plan.id}: item ${it.item} - ${result.refusal}`);
    }
    if (results.some((r) => r.refusal)) { end = 'failed'; why = why || 'an item was not signed (its result says why)'; }
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
  /* 4. the results, all at once, with the end */
  await told({ state: end, results, receipts, why });
  return end;
}

module.exports = { runPlan, planSigners, scopesOf, sortItems, keyOf, reasonOf, fingerprintOf, PLAN_LIFETIME_MINUTES, SIGN_CODE, AGENT_DERIVE, RSA_SLOTS };
