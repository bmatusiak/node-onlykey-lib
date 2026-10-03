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
 *
 * exec: the command runs with ITS OWN endpoint - SSH_AUTH_SOCK on a fresh
 * owner-only socket, the gpg shim's one-time token, git's gpg.program and
 * signing key - closed when it exits. Exactly one signature on it is paid; the
 * rest, and anything signed elsewhere, get a press. The exit code is the
 * command's own.
 */

const { spawn } = require('child_process');
const { ask } = require('./edge-control');

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
      else out(`budget ${s.budget}: ${s.uses} uses · head ${s.head}${s.owed.length ? ` · ticket owed for #${s.owed.join(', #')}` : ''}`);
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
    err('okedge budget | continue | exec | ticket | status | end');
    return 2;
  } catch (e) {
    err(`okedge: ${e.message}`);
    return 1;
  }
}

module.exports = { main };

if (require.main === module) {
  main(process.argv.slice(2)).then((code) => { process.exitCode = code; });
}
