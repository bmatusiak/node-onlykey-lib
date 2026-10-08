'use strict';

/**
 * edge/cli/commands.js - `onlykey-js edge …` (CLI.md §2, decided 2026-10-06: one CLI;
 * `onlykey-js edge` is gone). Agents and scripts use these; people use the phone's Edge tab.
 *
 *   edge budget --reason "…" --ssh N [--gpg N] --ttl MIN    ask for the work budget (Yes + a press on the phone)
 *   edge continue --ttl MIN [--caps n,n]                    continue it after a lock (ends the old one first)
 *   edge exec --head H --intent "…" -- <command…>           run one command; its signature is paid by the budget,
 *                                                           its intent welded into the link (R13b)
 *   edge receipt <seq> [--code OK] --msg "…"                 file the receipt; prints the next head
 *   edge sync [--status] | sync --with <address>            the PC's copy of the key's chain (R27), and your other devices' logs offered;
 *                                                           a phone holds an offered log until you approve the merge
 *   edge status | end                                       the budget, its head, receipts owed | end it
 *   edge watch [--once]                                     follow the key's links live (read-only)
 *
 * Each command runs through `ask`: the optional `edge agent` service when one is
 * running, else an in-process stack for this one command (edge/cli/register.js) -
 * no service by default (CLI.md §4). Budget or no go (CLI.md §3): exec signs only
 * when a live budget pays; everything else is refused, never turned into a press.
 *
 * exec: the command runs with ITS OWN endpoints - SSH_AUTH_SOCK on a fresh
 * owner-only socket, and the gpg shim's one-shot endpoint, key and token - closed
 * when it exits. Exactly one signature on them is paid. The exit code is the
 * command's own.
 */

const { spawn } = require('child_process');
const { codes, grants } = require('../src');

/* edge watch: what each link's op is called */
const OP_NAME = {
  1: 'sign', 2: 'decrypt', 6: 'budget opened', 7: 'budget ended',
  8: 'receipt', 11: 'LOSS', 13: 'hold', 14: 'resume', 15: 'agent registered', 16: 'continue',
};
/* reasons and receipt messages are the agent's own untrusted text: one plain line, never interpreted */
const plain = (t) => String(t).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200);

/**
 * edge watch's lines for one feed (mcp-service.md: one line per use, its
 * reason, then its receipt; alarms highlighted - okrn-edge-tab.md B7): an alarm
 * receipt (bit 7 or an unknown code), a press asked for under a live budget, an
 * TX start that did not match its request, a refused exec, a budget ended, a LOSS or
 * a wipe, links lost from the key's ring.
 */
function watchLines(feed, { color = false, time = new Date() } = {}) {
  const red = (t) => (color ? `\u001b[31;1m${t}\u001b[0m` : t);
  const at = time.toTimeString().slice(0, 8);
  const lines = [];
  if (feed.missed) lines.push(red(`⚠ ${feed.missed} link(s) fell out of the key's ring before they were read`));
  for (const l of feed.links || []) {
    const n = l.note || {};
    if (l.op === codes.OP.RECEIPT) {
      const name = codes.RECEIPT[l.code];
      const alarm = (l.code & 0x80) || !name;
      const msg = n.receipt && n.receipt.message ? ` · "${plain(n.receipt.message)}"` : '';
      const line = `        ↳ #${l.seq} receipt for #${l.refSeq}: ${name || `0x${l.code.toString(16)}`}${msg}`;
      lines.push(alarm ? red(`${line}  ⚠ ALARM`) : line);
      continue;
    }
    if (l.op === codes.OP.SIGN || l.op === codes.OP.DECRYPT) {
      /* v1: the key links a sign or decrypt only when a budget paid it (R1, R16) */
      const how = `self-press · budget ${l.grantId}, use ${l.grantStep}`;
      /*
       * R13b: the intent welded into the link against the text the agent noted -
       * the text shows only when it hashes to the link's 16 bytes. "no intent" =
       * a link from before R13b (or a use that gave none).
       */
      let what = n.reason ? ` · "${plain(n.reason)}"` : '';
      let mismatch = false;
      if (l.intent) {
        if (!n.reason) what = ' · intent unknown';
        else if (Buffer.from(grants.intentOf(String(n.reason))).toString('hex') !== l.intent) { mismatch = true; what = ` · "${plain(n.reason)}" - intent does not match`; }
      } else what = ` · no intent${n.reason ? ` (noted: "${plain(n.reason)}")` : ''}`;
      const line = `#${l.seq} ${at} ${OP_NAME[l.op]} slot ${l.slot} · ${how}${what}`;
      lines.push(mismatch ? red(`${line}  ⚠ intent does not match its text`) : line);
      continue;
    }
    const line = `#${l.seq} ${at} ${OP_NAME[l.op] || `op ${l.op}`}${l.grantId ? ` ${l.grantId}` : ''}`;
    lines.push([codes.OP.GRANT_END, codes.OP.LOSS].includes(l.op) ? red(`${line}  ⚠`) : line);
  }
  for (const e of feed.events || []) lines.push(red(`⚠ agent: ${plain(e.message)}`));
  return lines;
}

function opt(args, name) {
  const i = args.indexOf(name);
  return i >= 0 ? args[i + 1] : undefined;
}

async function main(argv, { out = (s) => process.stdout.write(s + '\n'), err = (s) => process.stderr.write(s + '\n'), env = process.env, spawnFn = spawn, ask, dev = null } = {}) {
  if (typeof ask !== 'function') throw new Error('edge commands need ask (the service or the in-process stack)');
  const [cmd, ...args] = argv;
  try {
    /* the dev build's own commands (edge/cli/dev - left out of the published package, CLI.md §5) */
    if (dev && dev.commands && Object.prototype.hasOwnProperty.call(dev.commands, cmd)) return await dev.commands[cmd](args, { out, err, ask });
    if (cmd === 'status') {
      const s = await ask('status');
      if (!s.budget) out('no budget');
      else {
        const used = s.spent === null || s.spent === undefined ? `${s.uses} uses` : `${s.spent} of ${s.uses} used, ${s.uses - s.spent} left`;
        out(`budget ${s.budget}: ${used} · head ${s.head}`);
        const keyOwed = s.keyOwed || [];
        if (keyOwed.length || s.keyOwedOlder) {
          out(`the key owes ${keyOwed.length ? `receipts for #${keyOwed.join(', #')}` : ''}${keyOwed.length && s.keyOwedOlder ? ' and ' : ''}${s.keyOwedOlder ? `${s.keyOwedOlder} older (waive on the phone)` : ''}`);
          for (const q of keyOwed) out(`  #${q}: ${s.owed.includes(q) ? "this budget's use" : "a pressed sign with the agent's key (R16)"} - onlykey-js edge receipt ${q} --msg "…"`);
        } else if (s.owed.length) out(`receipt owed for #${s.owed.join(', #')}`);
      }
      if (s.link) out(`bluetooth: ${s.link.connects} connect(s), ${s.link.reconnects} reconnect(s), ${s.link.reconnectsFailed} failed${s.link.lastUpMs !== null ? `; last link up in ${s.link.lastUpMs} ms` : ''}`);
      return 0;
    }
    if (cmd === 'budget') {
      const reason = opt(args, '--reason');
      const ttl = Number(opt(args, '--ttl'));
      const uses = { ssh: Number(opt(args, '--ssh') || 0), gpg: Number(opt(args, '--gpg') || 0), identity: dev && dev.identityOption ? opt(args, '--identity') || null : null };
      if (!reason || !Number.isInteger(ttl)) { err('onlykey-js edge budget --reason "…" --ssh N [--gpg N] --ttl MINUTES'); return 2; }
      /* said only once the agent has the request (bug 2): with no agent, the error comes at once instead */
      const r = await ask('budget', { reason, uses, ttl }, { timeoutMs: 200000, onSent: () => out('Waiting for the phone - read the request there, then press…') });
      out(`budget ${r.budget}: ${r.uses} uses`);
      out(`head = ${r.head}`);
      return 0;
    }
    if (cmd === 'continue') {
      const ttl = Number(opt(args, '--ttl'));
      const caps = opt(args, '--caps') ? opt(args, '--caps').split(',').map(Number) : null;
      if (!Number.isInteger(ttl)) { err('onlykey-js edge continue --ttl MINUTES [--caps n,n]'); return 2; }
      const r = await ask('continue', { ttl, caps }, { timeoutMs: 200000, onSent: () => out('Waiting for the phone - read the request there, then press…') });
      out(`budget ${r.budget}: ${r.uses} uses (continues the last one)`);
      out(`head = ${r.head}`);
      return 0;
    }
    if (cmd === 'receipt') {
      const seq = Number(args[0]);
      const message = opt(args, '--msg');
      if (!Number.isInteger(seq) || !message) { err('onlykey-js edge receipt <seq> [--code OK] --msg "…"'); return 2; }
      const r = await ask('receipt', { seq, code: opt(args, '--code') || 'OK', message });
      out(`receipt filed for #${seq}`);
      out(`head = ${r.head}`);
      return 0;
    }
    if (cmd === 'sync') {
      /* mcp-service.md 4.2b: phase 1 reads the key into this PC's copy; phase 2 offers that copy to the phone, which holds it until the person approves the merge (2026-10-08) */
      if (args.includes('--with')) {
        /* each phone's log offered to the other - held there until you approve (2026-10-08) */
        const address = opt(args, '--with');
        if (!address || address.startsWith('--')) { err('onlykey-js edge sync --with <the other phone\'s Bluetooth address>'); return 2; }
        const r = await ask('sync-with', { address }, { timeoutMs: 300000 });
        for (const [what, x] of [['this phone', r.this], ['the other phone', r.other]]) {
          if (!x.ok) out(`${what} ("${x.nametag}"): not offered - ${x.error}`);
          else out(`${what} ("${x.nametag}"): holds "${x.offered.nametag}" up to #${x.offered.seq} (${x.sent} link${x.sent === 1 ? '' : 's'} sent) - approve it from its Edge tab banner`);
        }
        return r.this.ok && r.other.ok ? 0 : 1;
      }
      const status = args.includes('--status');
      const r = await ask('sync', { status }, { timeoutMs: 120000 });
      for (const l of require('./copy').lines(r, { status })) out(l);
      return r.verdict.kind === 'tampered' ? 1 : 0;
    }
    if (cmd === 'end') {
      const r = await ask('end');
      out(r.ended ? `budget ${r.ended} ended` : 'no budget');
      return 0;
    }
    if (cmd === 'exec') {
      const dd = args.indexOf('--');
      const head = opt(args, '--head');
      /* R13b: what this use is for - welded into its link before the signature exists (--reason, the older name) */
      const reason = opt(args, '--intent') || opt(args, '--reason');
      /* --press is gone (Brad, 2026-10-06, R13b: budget or no go): Edge signs only under a budget; a pressed sign is the ordinary ssh/gpg agent */
      if (args.slice(0, dd < 0 ? args.length : dd).includes('--press')) { err('onlykey-js edge: --press was removed - Edge signs only under a budget; for a pressed sign use the ordinary ssh/gpg agent'); return 2; }
      if (dd < 0 || !head || !reason || dd === args.length - 1) { err('onlykey-js edge exec --head H --intent "…" -- <command…>'); return 2; }
      const command = args.slice(dd + 1);
      const ex = await ask('exec-open', { head, reason });
      const gitEntries = Object.entries(ex.git || {});
      const childEnv = {
        ...env,
        SSH_AUTH_SOCK: ex.sshPath,
        OKEDGE_GPG_TOKEN: ex.token,
        ...(ex.gpg ? { OKEDGE_GPG_ENDPOINT: ex.gpg.path, OKEDGE_GPG_KEY: ex.gpg.key } : {}),
        ...(gitEntries.length ? {
          GIT_CONFIG_COUNT: String(gitEntries.length),
          ...Object.fromEntries(gitEntries.flatMap(([k, v], i) => [[`GIT_CONFIG_KEY_${i}`, k], [`GIT_CONFIG_VALUE_${i}`, v]])),
        } : {}),
        ...(ex.committer ? { GIT_COMMITTER_NAME: ex.committer.name, GIT_COMMITTER_EMAIL: ex.committer.email } : {}),
      };
      let code;
      try {
        code = await new Promise((resolve) => {
          const p = spawnFn(command[0], command.slice(1), { stdio: 'inherit', env: childEnv });
          p.on('error', (e) => { err(`onlykey-js edge: could not run ${command[0]}: ${e.message}`); resolve(127); });
          p.on('exit', (c) => resolve(c === null ? 1 : c));
        });
      } finally {
        const closed = await ask('exec-close', { token: ex.token });
        /*
         * A COMMAND THAT FAILED FILES A FAILED RECEIPT (Brad, 2026-10-07: "when a push
         * does not reach, it should give back a failed receipt"). Its uses get
         * TARGET_UNREACHABLE with the command and its exit code - not left owed, and
         * never OK. A command that succeeded leaves its receipts owed, as before:
         * whether it did what was meant is the agent's to say.
         */
        for (const l of closed.links) {
          if (code !== 0) {
            const why = `FAILED: ${command.join(' ')} exited ${code}${l.failed ? ` (the sign: ${l.failed})` : ''}`;
            try {
              const r = await ask('receipt', { seq: l.seq, code: 'TARGET_UNREACHABLE', message: why });
              out(`signed: link #${l.seq} (${l.what}) - the command failed: receipt filed (TARGET_UNREACHABLE)`);
              out(`head = ${r.head}`);
              continue;
            } catch (e) {
              err(`onlykey-js edge: the failed receipt for #${l.seq} was not filed: ${e.message}`);
            }
          }
          out(`signed: link #${l.seq} (${l.what})${l.paid ? '' : ' - not paid by the budget'} - receipt owed for #${l.seq}`);
        }
        if (!closed.links.length) out(code === 0 ? 'signed: nothing under the budget' : 'signed: nothing under the budget - the command failed before a sign');
      }
      return code;
    }
    if (cmd === 'watch') {
      /* read-only: it cannot approve, hold or waive - that stays on the phone */
      const once = args.includes('--once');
      const color = !once && Boolean(process.stdout.isTTY);
      out('watching the key - read-only (approve, hold and waive stay on the phone); Ctrl-C to stop');
      let from = -1;
      let since = 0;
      let liveBudget = null;
      for (;;) {
        const f = await ask('feed', { from, since });
        for (const l of watchLines(f, { color })) out(l);
        if (f.seq !== null && f.seq !== undefined) from = f.seq + 1;
        for (const e of f.events || []) since = Math.max(since, e.n);
        /* a budget spent, expired, ended or lost with a lock: once */
        if (f.budget && f.live) {
          if (f.live.includes(f.budget.id)) liveBudget = f.budget.id;
          else if (liveBudget === f.budget.id) {
            out(color ? `\u001b[31;1m⚠ budget ${liveBudget} is no longer live (spent, expired, ended, or the key locked)\u001b[0m` : `⚠ budget ${liveBudget} is no longer live (spent, expired, ended, or the key locked)`);
            liveBudget = null;
          }
        }
        if (once) return 0;
        await new Promise((r) => setTimeout(r, 2000));
      }
    }
    err('onlykey-js edge budget | continue | end | status | exec | receipt | watch | sync | register | agent');
    return 2;
  } catch (e) {
    err(`onlykey-js edge: ${e.message}`);
    return 1;
  }
}

module.exports = { main, watchLines };

