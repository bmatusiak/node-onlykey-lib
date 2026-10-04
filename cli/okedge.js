#!/usr/bin/env node
'use strict';

/**
 * cli/okedge.js - the wrapper agents and scripts use (onlykey-edge
 * mcp-service.md §4.2a: "a wrapper, not a replacement", like sudo or time).
 * It talks to the running agent service (`onlykey-js edge-agent`) over its
 * control endpoint; people use the phone's Edge tab instead.
 *
 *   okedge budget --reason "…" --ssh N [--gpg N] --ttl MIN    ask for the work budget (Yes + a press on the phone)
 *   okedge continue --ttl MIN [--caps n,n]                    continue it after a lock (ends the old one first)
 *   okedge exec --head H --reason "…" -- <command…>           run one command; its signature is paid by the budget
 *   okedge ticket <seq> [--code OK] --msg "…"                 file the ticket; prints the next head
 *   okedge status                                             the budget, its head, tickets owed
 *   okedge end                                                end the budget
 *   okedge watch [--once]                                     follow the key's links live (read-only)
 *
 * exec: the command runs with ITS OWN endpoint - SSH_AUTH_SOCK on a fresh
 * owner-only socket, the gpg shim's one-time token, git's gpg.program and
 * signing key - closed when it exits. Exactly one signature on it is paid; the
 * rest, and anything signed elsewhere, get a press. The exit code is the
 * command's own.
 */

const { spawn } = require('child_process');
const { ask } = require('./edge-control');
const { codes } = require('../src/edge');

/* okedge watch: what each link's op is called */
const OP_NAME = {
  1: 'sign', 2: 'decrypt', 3: 'fido register', 4: 'fido sign', 5: 'hmac', 6: 'budget opened', 7: 'budget ended',
  8: 'ticket', 9: 'peer added', 10: 'peer removed', 11: 'LOSS', 12: 'wipe', 13: 'hold', 14: 'resume', 15: 'agent registered',
};
/* reasons and ticket messages are the agent's own untrusted text: one plain line, never interpreted */
const plain = (t) => String(t).replace(/[\u0000-\u001f\u007f]/g, ' ').slice(0, 200);

/**
 * okedge watch's lines for one feed (mcp-service.md: one line per use, its
 * reason, then its ticket; alarms highlighted - okrn-edge-tab.md B7): an alarm
 * ticket (bit 7 or an unknown code), a press asked for under a live budget, an
 * ARM that did not match its request, a refused exec, a budget ended, a LOSS or
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
      let how = 'pressed';
      let alarm = null;
      if (l.decision === codes.DECISION.SELF_PRESS) how = `self-press · budget ${l.grantId}, use ${l.grantStep}`;
      else if (l.decision === codes.DECISION.DENY) how = 'denied';
      else if (l.decision === codes.DECISION.TIMEOUT) how = 'timed out';
      else if (l.flags & codes.FLAG.ARMED) alarm = 'an ARM that did not match its request - someone else jumped in?';
      else if (l.flags & codes.FLAG.OWES_TICKET) alarm = 'a press asked for under a live budget (it owes a ticket, R16)';
      const line = `#${l.seq} ${at} ${OP_NAME[l.op]} slot ${l.slot} · ${how}${n.reason ? ` · "${plain(n.reason)}"` : ''}`;
      lines.push(alarm ? red(`${line}  ⚠ ${alarm}`) : line);
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

async function main(argv, { out = (s) => process.stdout.write(s + '\n'), err = (s) => process.stderr.write(s + '\n'), env = process.env, spawnFn = spawn } = {}) {
  const [cmd, ...args] = argv;
  try {
    if (cmd === 'status') {
      const s = await ask('status');
      if (!s.budget) out('no budget');
      else {
        const used = s.spent === null || s.spent === undefined ? `${s.uses} uses` : `${s.spent} of ${s.uses} used, ${s.uses - s.spent} left`;
        out(`budget ${s.budget}: ${used} · head ${s.head}`);
        const keyOwed = s.keyOwed || [];
        if (keyOwed.length || s.keyOwedOlder) {
          out(`the key owes ${keyOwed.length ? `tickets for #${keyOwed.join(', #')}` : ''}${keyOwed.length && s.keyOwedOlder ? ' and ' : ''}${s.keyOwedOlder ? `${s.keyOwedOlder} older (waive on the phone)` : ''}`);
          for (const q of keyOwed) out(`  #${q}: ${s.owed.includes(q) ? "this budget's use" : "a pressed sign with the agent's key (R16)"} - okedge ticket ${q} --msg "…"`);
        } else if (s.owed.length) out(`ticket owed for #${s.owed.join(', #')}`);
      }
      return 0;
    }
    if (cmd === 'budget') {
      const reason = opt(args, '--reason');
      const ttl = Number(opt(args, '--ttl'));
      const uses = { ssh: Number(opt(args, '--ssh') || 0), gpg: Number(opt(args, '--gpg') || 0) };
      if (!reason || !Number.isInteger(ttl)) { err('okedge budget --reason "…" --ssh N [--gpg N] --ttl MINUTES'); return 2; }
      out('Waiting for the phone - read the request there, then press…');
      const r = await ask('budget', { reason, uses, ttl }, { timeoutMs: 200000 });
      out(`budget ${r.budget}: ${r.uses} uses`);
      out(`head = ${r.head}`);
      return 0;
    }
    if (cmd === 'continue') {
      const ttl = Number(opt(args, '--ttl'));
      const caps = opt(args, '--caps') ? opt(args, '--caps').split(',').map(Number) : null;
      if (!Number.isInteger(ttl)) { err('okedge continue --ttl MINUTES [--caps n,n]'); return 2; }
      out('Waiting for the phone - read the request there, then press…');
      const r = await ask('continue', { ttl, caps }, { timeoutMs: 200000 });
      out(`budget ${r.budget}: ${r.uses} uses (continues the last one)`);
      out(`head = ${r.head}`);
      return 0;
    }
    if (cmd === 'ticket') {
      const seq = Number(args[0]);
      const message = opt(args, '--msg');
      if (!Number.isInteger(seq) || !message) { err('okedge ticket <seq> [--code OK] --msg "…"'); return 2; }
      const r = await ask('ticket', { seq, code: opt(args, '--code') || 'OK', message });
      out(`ticket filed for #${seq}`);
      out(`head = ${r.head}`);
      return 0;
    }
    if (cmd === 'end') {
      const r = await ask('end');
      out(r.ended ? `budget ${r.ended} ended` : 'no budget');
      return 0;
    }
    if (cmd === 'exec') {
      const dd = args.indexOf('--');
      const head = opt(args, '--head');
      const reason = opt(args, '--reason');
      if (dd < 0 || !head || !reason || dd === args.length - 1) { err('okedge exec --head H --reason "…" -- <command…>'); return 2; }
      const command = args.slice(dd + 1);
      const ex = await ask('exec-open', { head, reason });
      const gitEntries = Object.entries(ex.git || {});
      const childEnv = {
        ...env,
        SSH_AUTH_SOCK: ex.sshPath,
        OKEDGE_GPG_TOKEN: ex.token,
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
          p.on('error', (e) => { err(`okedge: could not run ${command[0]}: ${e.message}`); resolve(127); });
          p.on('exit', (c) => resolve(c === null ? 1 : c));
        });
      } finally {
        const closed = await ask('exec-close', { token: ex.token });
        for (const l of closed.links) {
          out(`signed: link #${l.seq} (${l.what})${l.paid ? '' : ' - not paid by the budget'} - ticket owed for #${l.seq}`);
        }
        if (!closed.links.length) out('signed: nothing under the budget');
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
    err('okedge budget | continue | exec | ticket | status | end | watch');
    return 2;
  } catch (e) {
    err(`okedge: ${e.message}`);
    return 1;
  }
}

module.exports = { main, watchLines };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
