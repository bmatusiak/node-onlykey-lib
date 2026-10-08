'use strict';

/**
 * edge/cli/dev - EDGE'S DEV-BUILD test and development commands, options and switches,
 * in one place (CLI.md §5, decided 2026-10-06).
 *
 * edge/cli/register.js loads this folder only when it is there. The published package
 * leaves it out (package.json "files"), and scripts/release-check.js fails if any
 * of it is reachable from a packed install. Nothing here can be turned on in a
 * production package - not by an environment variable, not by a flag - because
 * the agent can set those itself.
 *
 * What lives here:
 *   --edge-home <dir> / OKEDGE_HOME   a test's scratch Edge home, or a second agent
 *   --identity <id>                   edge budget for another identity (rule-10 tests)
 *   OKEDGE_TIMES=1                    every key request, sign and phone message, timed
 *   OKEDGE_IDLE_MS                    the service's idle release (default 60 s)
 *   edge ping                         a Bluetooth link test (testing mode on the phone)
 */
const control = require('../control');

const opt = (args, name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };

/* the timing wrapper (Brad, 2026-10-06: where a signed commit's 7 s go) - times and request names only */
function timed({ edge, wired, okcrypto, say }) {
  if (process.env.OKEDGE_TIMES !== '1') return { channel: wired, okcrypto };
  const SUBNAMES = Object.fromEntries(Object.entries(edge.SUB || {}).map(([k, v]) => [v, k]));
  edge.onTiming = (sub, ms, ok) => say(`time key ${SUBNAMES[sub] || sub} ${ms} ms${ok ? '' : ' (failed)'}`);
  return {
    channel: { send: async (m, o) => { const t = Date.now(); try { return await wired.send(m, o); } finally { say(`time phone ${(m && m.type) || 'message'} ${Date.now() - t} ms`); } } },
    okcrypto: { ...okcrypto, agent: { ...okcrypto.agent, sign: async (...a) => { const t = Date.now(); try { return await okcrypto.agent.sign(...a); } finally { say(`time key SIGN ${Date.now() - t} ms`); } } } },
  };
}

/*
 * edge ping: a pure Bluetooth link test (Brad, 2026-10-06) - random bytes to the
 * phone and back, checked by their SHA-256; testing mode, encrypted session only.
 * No key, no budget, nothing signed or written.
 */
async function ping(args, { out, ask }) {
  const count = Math.max(1, Math.min(100, Number(opt(args, '--count')) || 1));
  const gap = Math.max(0, Number(opt(args, '--gap')) || 0);
  const size = Number(opt(args, '--size')) || 1024;
  const wait = Number(opt(args, '--wait')) || 0; /* seconds for each echo (default 10) */
  const t0 = Date.now();
  let ok = 0;
  for (let i = 1; i <= count; i++) {
    const r = await ask('ping', { size, wait }, { timeoutMs: (wait || 10) * 1000 + 30000 });
    if (r.exact) ok += 1;
    const p = r.parts || {};
    const part = (label, v) => (v === null || v === undefined ? '' : ` ${label} ${v}`);
    out(`#${i} ${r.bytes} bytes (${r.wire} on the wire) ${r.ms} ms ${r.exact ? 'OK - came back exact' : `FAILED - ${r.why}`}`
      + (r.exact ? ` |${part('queue', p.queue)}${part('pc write', p.pcWrite)}${part('phone in', p.phoneIn)}${part('phone hold', p.phoneHold)}${part('phone total', p.phoneTotal)}${part('pc in', p.pcIn)} ms` : ''));
    if (gap && i < count) await new Promise((res) => setTimeout(res, gap));
  }
  out(`${ok} of ${count} came back exact in ${Date.now() - t0} ms`);
  return ok === count ? 0 : 1;
}

/*
 * THE CLEAN START ON THIS COMPUTER (R31, firmware.md; Brad, 2026-10-07: "we are
 * doing a reset"): the Edge records of the chain the reset ended go - its budgets
 * (budgets.json) and its copies (copy-*.json). What stays: agent.key, peer.key,
 * control.key, agent-gpg.asc (keys and the agent's own certificate - R31 keeps every
 * key) and agent.json's settings (its old budget is dropped). The agent and this
 * PC's copy store then register again with a press each. Local: no phone.
 * -> the files removed
 */
function reset(home, out) {
  const fs = require('fs');
  const path = require('path');
  const removed = [];
  if (fs.existsSync(home)) {
    for (const n of fs.readdirSync(home)) {
      if (n === 'budgets.json' || /^copy-[0-9a-f]{16}\.json$/.test(n)) {
        fs.rmSync(path.join(home, n), { force: true });
        removed.push(n);
      }
    }
    const cfg = path.join(home, 'agent.json');
    if (fs.existsSync(cfg)) {
      const c = JSON.parse(fs.readFileSync(cfg, 'utf8'));
      if (c.budget !== undefined) {
        delete c.budget;
        fs.writeFileSync(cfg, JSON.stringify({ ...c, v: 1 }, null, 2), { mode: 0o600 });
        removed.push('agent.json: its budget');
      }
    }
  }
  out(removed.length ? `edge reset (${home}): removed ${removed.join(', ')}` : `edge reset (${home}): nothing of an old chain here`);
  out('kept: agent.key, peer.key, control.key, agent-gpg.asc and agent.json\'s settings - register the agent and this PC again (a press each)');
  return removed;
}

module.exports = {
  reset,
  identityOption: true,
  idleMs: Number(process.env.OKEDGE_IDLE_MS) || null,
  /* --edge-home <dir> (before any `--`), else OKEDGE_HOME: the Edge home for this run */
  prepare(argv) {
    const a = argv.slice();
    const dd = a.indexOf('--');
    const i = a.indexOf('--edge-home');
    let home = process.env.OKEDGE_HOME || null;
    if (i >= 0 && (dd < 0 || i < dd)) { home = a[i + 1]; a.splice(i, 2); }
    if (home) control.setHome(home);
    return a;
  },
  timed,
  commands: { ping },
};
