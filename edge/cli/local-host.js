'use strict';

/**
 * edge/cli/local-host.js - THIS COMPUTER answers what a phone answers, for a hard key on USB
 * (ok-edge TODO B4, Brad, 2026-10-23).
 *
 * Every `onlykey-js edge` command talks to two parties: the key's Edge firmware (0xF8 - head,
 * grant, txStart, receipt, revoke ...) and the HOST that shows the person what is asked and keeps
 * the agent's identity (SPEC H2, H7). Over Bluetooth the host is the phone, reached on the wire
 * (0xF7, edge/src/wire.js): it keeps the identity record, shows the budget sheet, checks its copy
 * of the chain (R27) and waits for the press. A hard key on USB has no phone behind it, so nobody
 * answers the wire and every command stopped at "the phone did not answer the identity question".
 *
 * So the CLI is the host here: an object with the wire channel's own `send(message, opts)`
 * contract, answering in-process with the same library code the phone runs - approve.js's
 * approveRequest for a budget, identity.js for the record - and the same answer shapes. The client,
 * the agent and the commands cannot tell the difference, and do not need to.
 *
 * What the phone does, done here:
 *   - the sheet:        the request's view printed, then `approve? [y/N]` on this terminal
 *                       (Brad, 2026-10-23: the y/N is the phone's Yes; the press is still the key's)
 *   - the identity:     the `identity` store in this net's Edge home (the CLI's bucket), one record
 *   - the copy (R27):   this computer's own copy of the key's chain (copy.js), brought to the key's
 *                       head and checked by the key plugin's grants.check before anything is sent
 *   - the openings:     kept with that copy (copy.keepOpenings), as the phone keeps them, so the next
 *                       budget's check can verify this one's opening
 * What only a phone has (pings, the phone's own copy and other devices' logs for `edge sync`)
 * is answered "no phone here" at once instead of a wait.
 *
 * The net needs no check of its own: the stores live in the net's own home (`--test-mode` = the
 * testnet's), and the agent refuses a record whose certificate is not this key's derived key
 * (agent.js) - the live record on the testnet key, or the reverse, stops there.
 */

const bucketHome = require('../../bucket/cli/home');
const { approve, request, identity: identityLib, note: noteLib, receipts, codes } = require('../src');
const copy = require('./copy');
const { fromHex } = require('../../src/bytes');

/* who asked, for approveRequest's continue check: the same computer, always this one */
const LOCAL = 'this computer';

/* the phone's own words for a refusal it answers without a sheet */
const NO_PHONE = { ok: false, refusal: 'invalid', detail: 'no phone on this link (a hard key on USB): this computer is the host' };

function identityKv(home) {
  return bucketHome.kv(bucketHome.edgeAt(home, 'identity'));
}

/* a kept opening (copy.keepOpenings: reason text, hex) -> what grants.check reads (as the phone's openingOf) */
function openingOf(o) {
  return {
    scopes: o.scopes, reasonHash: receipts.messageHash(o.reason), genesis: fromHex(o.genesis),
    uses: o.uses, lifetime: o.lifetime || 0, signature: fromHex(o.signature),
  };
}

/* the request's words for an op, as a continue's scopes are compared (the phone's loadAgentBudgets) */
const opWord = (op) => (op === codes.OP.SIGN ? 'sign' : op === codes.OP.DECRYPT ? 'decrypt' : op);

/**
 * @param {object} o
 * @param {object} o.edge the key's Edge service (edge/plugin)
 * @param {string} o.home this net's Edge home (control.edgeHome())
 * @param {(question: string, o?: {details?: string, title?: string}) => Promise<boolean>} o.confirm the person's y/N:
 *   terminalConfirm, or cli/gui-prompt guiConfirm (--gui-prompt), which shows `details` in its dialog
 * @param {(line: string) => void} [o.say] what the phone's sheet would show
 */
function createLocalHost({ edge, home, confirm, say = () => {} }) {
  const seen = new Set();
  const kv = identityKv(home);
  const loadIdentity = () => {
    const t = kv.getItem('record');
    return t ? JSON.parse(t) : null;
  };

  /* this computer's copy of the key's chain: brought to the key's head, then R27 against the key NOW */
  async function verifyCopy() {
    const synced = await copy.sync(edge, home);
    if (synced.verdict.kind === 'tampered') {
      say(`this computer's copy of the chain does not verify: tampered at #${synced.verdict.seq} (${synced.verdict.reason})`);
      return { ok: false, head: new Uint8Array(0) };
    }
    const c = copy.load(home, fromHex(synced.deviceId));
    const openings = Object.fromEntries((c.openings || []).map((o) => [o.grantId, openingOf(o)]));
    const v = await edge.grants.check({ links: c.links, openings }).catch((e) => ({ ok: false, reason: e.message }));
    if (!v || !v.ok) {
      say(`this computer's copy of the chain does not verify (${v ? v.reason : 'no answer'}${v && v.seq !== undefined ? ` at #${v.seq}` : ''})`);
      return { ok: false, head: new Uint8Array(0) };
    }
    return { ok: true, head: v.head };
  }

  /* the opening, kept with the copy once the key wrote its link - what the next budget's R27 check reads */
  async function keepOpening(msg, budget) {
    await copy.sync(edge, home);
    const { deviceId } = await edge.publicKey();
    const kept = copy.keepOpenings(home, deviceId, [{
      grantId: budget.grantId, reason: msg.reason, scopes: request.grantScopes(msg), uses: budget.uses,
      lifetime: msg.lifetime, genesis: budget.genesis, signature: budget.checkpoint.signature, opened: Date.now(), from: LOCAL,
    }]);
    if (!kept.kept) say(`budget ${budget.grantId}: its opening did not check against this computer's copy - the next budget's copy check may refuse`);
  }

  /* a continue: one this computer opened, with its scopes in the request's words */
  async function budgetOfNow(grantId) {
    const { deviceId } = await edge.publicKey();
    const o = (copy.load(home, deviceId).openings || []).find((x) => x.grantId === grantId);
    return o ? { from: o.from || LOCAL, scopes: o.scopes.map((s) => ({ ...s, op: opWord(s.op) })) } : null;
  }

  async function answerRequest(msg) {
    const was = msg.continue === undefined ? null : await budgetOfNow(msg.continue);
    const r = await approve.approveRequest(msg, {
      edge, from: LOCAL, seen,
      ask: async (view) => {
        /* R27 before the question, as the phone greys out Approve: a copy that does not verify is refused unasked */
        const pre = await verifyCopy();
        if (!pre.ok) return 'copy_unverified';
        const lines = [
          `budget request${view.continues !== null ? ` (continues budget ${view.continues})` : ''}: "${view.reason}"`,
          `  ${view.uses} use${view.uses === 1 ? '' : 's'}, for ${view.lifetime} minute${view.lifetime === 1 ? '' : 's'}`,
          ...view.scopes.map((s) => `  ${s.op} on ${s.identity ? `${s.identity} (slot ${s.slot})` : `slot ${s.slot}`}: up to ${s.cap}`),
        ];
        for (const l of lines) say(l);
        /* the same lines for a dialog (--gui-prompt); the terminal has them printed already */
        const details = `${lines.join('\n')}\n\nAfter Yes, PRESS the key within 20 s (it pulses) - the budget opens with the press.`;
        return (await confirm('approve this budget? [y/N] ', { details, title: 'OnlyKey Edge: a budget request' })) ? 'approve' : 'decline';
      },
      verifyCopy,
      budgetOf: () => was,
      onPress: () => say('PRESS the key now - the budget opens with the press'),
    });
    if (r.ok) await keepOpening(msg, r.budget);
    return r.dropped ? null : r;
  }

  async function answerIdentity(msg) {
    const checked = identityLib.verify(msg, { seen });
    if (!checked.ok) {
      return checked.reason === 'malformed' || checked.reason === 'replayed'
        ? null
        : { ok: false, refusal: 'invalid', detail: `not a usable identity: ${checked.reason}` };
    }
    seen.add(String(msg.nonce).toLowerCase());
    if (msg.type === identityLib.GET_TYPE) return { ok: true, record: loadIdentity() };
    const record = identityLib.clean(msg.record);
    const lines = ['the agent identity this computer keeps for this key:', ...identityLib.rows(record).map(([k, v]) => `  ${k}: ${v}`)];
    for (const l of lines) say(l);
    if (!(await confirm('keep this agent identity? [y/N] ', { details: lines.join('\n'), title: 'OnlyKey Edge: the agent identity' }))) return { ok: false, refusal: 'declined' };
    kv.setItem('record', JSON.stringify(record));
    return { ok: true };
  }

  return {
    /* register.js and its texts: the host is here, not on a phone */
    local: true,
    async send(message, opts = {}) {
      if (opts && opts.oneWay) return null;
      const type = message && message.type;
      if (type === noteLib.TYPE) {
        /* what the phone would show beside the use: the intent, the receipt's words, a refused start */
        const text = message.reason || message.receiptMsg || message.txRefused;
        if (typeof text === 'string') say(`note #${message.seq}: ${text}`);
        /*
         * AND KEPT, as the phone keeps them (Brad, 2026-10-24: the budget history in the desktop app):
         * the intent and the receipt's words with this computer's copy, by seq - so a hard key's
         * history says what each use was for, here and in the desktop app (edge/src/history.js).
         */
        if (Number.isInteger(message.seq) && message.seq >= 0) {
          try {
            const { deviceId } = await edge.publicKey();
            const now = Date.now();
            copy.keepNotes(home, deviceId, {
              reasons: typeof message.reason === 'string' ? { [message.seq]: message.reason } : {},
              messages: typeof message.receiptMsg === 'string' ? { [message.seq]: message.receiptMsg } : {},
              seen: { [message.seq]: now },
            });
          } catch (_) { /* a note is shown even when it cannot be kept */ }
        }
        return { ok: true };
      }
      if (identityLib.TYPES.includes(type)) return answerIdentity(message);
      if (type === request.TYPE) return answerRequest(message);
      return NO_PHONE;
    },
  };
}

/*
 * The person's y/N on this terminal - the phone sheet's Approve. Asked on stderr, so a command's
 * own output stays clean; read from stdin, so a TESTNET run can pipe its answer in (automation is
 * for test budgets only - spec rule 10). Anything but y/yes is a No.
 */
function terminalConfirm(question, { input = process.stdin, output = process.stderr } = {}) {
  const readline = require('readline');
  return new Promise((resolve) => {
    const rl = readline.createInterface({ input, output, terminal: !!input.isTTY });
    let answered = false;
    /*
     * readline resumes the input and closing it does not pause it again: stdin kept the process
     * alive after the command was done (`edge setup` kept the identity, then never exited - the box,
     * 2026-10-23). Pausing is not enough for a PIPE: a paused pipe still holds node until its writer
     * closes it (measured: `(echo y; sleep 20) | node ...` exited after 20 s), and under the job
     * runner the writer never does - `edge budget` sat until its time limit. So the input is also
     * unref'd once the answer is in (and ref'd again for the next question).
     */
    if (typeof input.ref === 'function') input.ref();
    const done = (yes) => {
      rl.close();
      if (typeof input.pause === 'function') input.pause();
      if (typeof input.unref === 'function') input.unref();
      resolve(yes);
    };
    rl.question(question, (a) => { answered = true; done(/^\s*y(es)?\s*$/i.test(a)); });
    rl.on('close', () => { if (!answered) { answered = true; done(false); } });
  });
}

module.exports = { createLocalHost, terminalConfirm, identityKv, LOCAL };
