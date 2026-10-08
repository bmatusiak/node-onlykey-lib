'use strict';

/**
 * edge/cli/commands.js - `onlykey-js edge …` (CLI.md §2, decided 2026-10-06: one CLI;
 * `onlykey-js edge` is gone). Agents and scripts use these; people use the phone's Edge tab.
 *
 *   edge budget --reason "…" --ssh N [--gpg N] --ttl MIN    ask for the work budget (Yes + a press on the phone)
 *   edge continue --ttl MIN [--caps n,n]                    continue it after a lock (ends the old one first)
 *   edge exec --head H --intent "…" -- <command…>           run one command; its signature is paid by the budget,
 *                                                           its intent welded into the link (R13b)
 *   edge ticket <seq> [--code OK] --msg "…"                 file the ticket; prints the next head
 *   edge sync [--status] | sync --with <address>            the PC's own copy of the key's chain (R27, R30)
 *   edge peer add [--name "…"] | peer list                  places that keep copies (R20)
 *   edge sibling add <address> | sibling list               another key of yours (R29)
 *   edge status | end                                       the budget, its head, tickets owed | end it
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
const { codes, live, grants } = require('../src');

/* edge watch: what each link's op is called */
const OP_NAME = {
  1: 'sign', 2: 'decrypt', 3: 'fido register', 4: 'fido sign', 5: 'hmac', 6: 'budget opened', 7: 'budget ended',
  8: 'ticket', 9: 'peer added', 10: 'peer removed', 11: 'LOSS', 12: 'wipe', 13: 'hold', 14: 'resume', 15: 'agent registered',
  16: 'continue', 17: 'sibling added', 18: 'sibling removed', 19: 'anchor', 20: 'sync',
};
/* reasons and ticket messages are the agent's own untrusted text: one plain line, never interpreted */
const plain = (t) => String(t).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200);

/**
 * edge watch's lines for one feed (mcp-service.md: one line per use, its
 * reason, then its ticket; alarms highlighted - okrn-edge-tab.md B7): an alarm
 * ticket (bit 7 or an unknown code), a press asked for under a live budget, an
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
    if (l.op === codes.OP.TICKET) {
      const name = codes.TICKET[l.code];
      const alarm = (l.code & 0x80) || !name;
      const msg = n.ticket && n.ticket.message ? ` · "${plain(n.ticket.message)}"` : '';
      const line = `        ↳ #${l.seq} ticket for #${l.refSeq}: ${name || `0x${l.code.toString(16)}`}${msg}`;
      lines.push(alarm ? red(`${line}  ⚠ ALARM`) : line);
      continue;
    }
    if (l.op === codes.OP.SIGN || l.op === codes.OP.DECRYPT) {
      const { kind, alarm } = live.classifyUse(l);
      const how = kind === live.KIND.SELF_PRESS ? `self-press · budget ${l.grantId}, use ${l.grantStep}`
        : kind === live.KIND.DENIED ? 'denied' : kind === live.KIND.TIMED_OUT ? 'timed out' : 'pressed';
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
      lines.push(alarm || mismatch ? red(`${line}  ⚠ ${alarm || 'intent does not match its text'}`) : line);
      continue;
    }
    const line = `#${l.seq} ${at} ${OP_NAME[l.op] || `op ${l.op}`}${l.grantId ? ` ${l.grantId}` : ''}`;
    lines.push([codes.OP.GRANT_END, codes.OP.LOSS, codes.OP.WIPE].includes(l.op) ? red(`${line}  ⚠`) : line);
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
          out(`the key owes ${keyOwed.length ? `tickets for #${keyOwed.join(', #')}` : ''}${keyOwed.length && s.keyOwedOlder ? ' and ' : ''}${s.keyOwedOlder ? `${s.keyOwedOlder} older (waive on the phone)` : ''}`);
          for (const q of keyOwed) out(`  #${q}: ${s.owed.includes(q) ? "this budget's use" : "a pressed sign with the agent's key (R16)"} - onlykey-js edge ticket ${q} --msg "…"`);
        } else if (s.owed.length) out(`ticket owed for #${s.owed.join(', #')}`);
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
    if (cmd === 'ticket') {
      const seq = Number(args[0]);
      const message = opt(args, '--msg');
      if (!Number.isInteger(seq) || !message) { err('onlykey-js edge ticket <seq> [--code OK] --msg "…"'); return 2; }
      const r = await ask('ticket', { seq, code: opt(args, '--code') || 'OK', message });
      out(`ticket filed for #${seq}`);
      out(`head = ${r.head}`);
      return 0;
    }
    if (cmd === 'sync') {
      /* mcp-service.md 4.2b: phase 1 reads the key into this PC's copy; phase 2 offers that copy to the phone (its sheet + press). --with worker comes with E5 */
      if (args.includes('--with')) {
        /* R30 (P2c): with the key on another phone (paired both ways) - each anchors the other, a sheet + press on each */
        const address = opt(args, '--with');
        if (!address || address.startsWith('--') || address === 'worker') { err('onlykey-js edge sync --with <the other phone\'s Bluetooth address> (the Worker comes with E5)'); return 2; }
        const r = await ask('sync-with', { address, name: opt(args, '--name') || null, otherName: opt(args, '--other-name') || null },
          { timeoutMs: 600000, onSent: () => out('Waiting for the phones - each shows the other key\'s chain to anchor') });
        for (const [what, x] of [['this phone', r.this], ['the other phone', r.other]]) {
          if (!x.ok) out(`${what}: not anchored - ${x.error}`);
          else out(`${what}: anchored the other at #${x.anchored.seq} (link #${x.seq}, ${x.sent} link${x.sent === 1 ? '' : 's'} sent)`);
        }
        return r.this.ok && r.other.ok ? 0 : 1;
      }
      const status = args.includes('--status');
      /* phase 2 may wait on the phone's sheet (2 min) and the press (25 s): longer than a plain read */
      const r = await ask('sync', { status }, { timeoutMs: status ? 120000 : 240000 });
      for (const l of require('./copy').lines(r, { status })) out(l);
      return r.verdict.kind === 'tampered' ? 1 : 0;
    }
    if (cmd === 'peer') {
      /* sync phase 2, P2a (R20): the places a sync may send copies to - the key's list */
      const { request } = require('../src');
      const sub = args[0];
      if (sub === 'add') {
        const r0 = await ask('peers');
        const mine = r0.peers.find((p) => p.thisPc);
        if (mine) { out(`this PC's copy store is already peer ${mine.index} (${request.fingerprint(mine.key)})`); return 0; }
        out(`copy store key  ${request.fingerprint(r0.mine)}`);
        out('Check the phone shows the same key, Add there, then press the key...');
        const r = await ask('peer-add', { name: opt(args, '--name') || null });
        out(r.already ? `already peer ${r.index}` : `added as peer ${r.index} (link #${r.seq})`);
        return 0;
      }
      if (sub === 'list' || sub === undefined) {
        const r = await ask('peers');
        if (!r.peers.length) out('no places keep copies yet - onlykey-js edge peer add');
        for (const p of r.peers) out(`peer ${p.index}  ${request.fingerprint(p.key)}${p.thisPc ? '  (this PC)' : ''}`);
        out(`${r.peers.length} of ${r.max}; k ${r.k || 'not set (E5)'}`);
        return 0;
      }
      err('onlykey-js edge peer add [--name "…"] | onlykey-js edge peer list');
      return 2;
    }
    if (cmd === 'sibling') {
      /* sync phase 2, P2b (R29): another key of yours, paired with a press on each phone */
      const { request } = require('../src');
      const sub = args[0];
      if (sub === 'add' && args[1] && !args[1].startsWith('--')) {
        /* each phone may first ask to keep copies (peer), then both show the pairing sheet: minutes, not seconds */
        const r = await ask('sibling-add', { address: args[1], name: opt(args, '--name') || null, otherName: opt(args, '--other-name') || null },
          { timeoutMs: 600000, onSent: () => out('Waiting for the phones - each shows a code: pair only if the two codes match') });
        if (r.peersAdded.length) out(`this PC now keeps copies for: ${r.peersAdded.join(', ')} phone`);
        for (const [what, x] of [['this phone', r.this], ['the other phone', r.other]]) {
          if (!x.ok) out(`${what}: not paired - ${x.error}`);
          else out(`${what}: ${x.already ? 'already paired' : `paired (link #${x.seq})`}`);
        }
        return r.this.ok && r.other.ok ? 0 : 1;
      }
      if (sub === 'list') {
        const r = await ask('siblings');
        if (!r.siblings.length) out('no paired keys - onlykey-js edge sibling add <address>');
        for (const s of r.siblings) out(`sibling ${s.index}  ${request.fingerprint(s.key)}  device ${s.deviceId}`);
        out(`${r.siblings.length} of ${r.max}`);
        return 0;
      }
      err('onlykey-js edge sibling add <address> [--name "…"] [--other-name "…"] | onlykey-js edge sibling list');
      return 2;
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
         * A COMMAND THAT FAILED FILES A FAILED TICKET (Brad, 2026-10-07: "when a push
         * does not reach, it should give back a failed ticket"). Its uses get
         * TARGET_UNREACHABLE with the command and its exit code - not left owed, and
         * never OK. A command that succeeded leaves its tickets owed, as before:
         * whether it did what was meant is the agent's to say.
         */
        for (const l of closed.links) {
          if (code !== 0) {
            const why = `FAILED: ${command.join(' ')} exited ${code}${l.failed ? ` (the sign: ${l.failed})` : ''}`;
            try {
              const r = await ask('ticket', { seq: l.seq, code: 'TARGET_UNREACHABLE', message: why });
              out(`signed: link #${l.seq} (${l.what}) - the command failed: ticket filed (TARGET_UNREACHABLE)`);
              out(`head = ${r.head}`);
              continue;
            } catch (e) {
              err(`onlykey-js edge: the failed ticket for #${l.seq} was not filed: ${e.message}`);
            }
          }
          out(`signed: link #${l.seq} (${l.what})${l.paid ? '' : ' - not paid by the budget'} - ticket owed for #${l.seq}`);
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
    err('onlykey-js edge budget | continue | end | status | exec | ticket | watch | sync | peer | sibling | register | agent');
    return 2;
  } catch (e) {
    err(`onlykey-js edge: ${e.message}`);
    return 1;
  }
}

module.exports = { main, watchLines };

