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
 *   OKEDGE_TIMES=1                    every key request, sign and host message, timed
 *   edge ping                         a wire link test, answered by a host that serves pings
 *                                     (the phone over Bluetooth did, until 2026-10-30)
 */
const control = require('../control');
const times = require('./times');

const opt = (args, name) => { const i = args.indexOf(name); return i >= 0 ? args[i + 1] : undefined; };

/*
 * the timing wrapper (Brad, 2026-10-06: where a signed commit's 7 s go) - times and request names only: printed with
 * OKEDGE_TIMES=1, and onto the ship's timeline (times.js) when a ship named one for this process
 */
function timed({ edge, wired, okcrypto, say }) {
  const print = process.env.OKEDGE_TIMES === '1';
  if (!print && !process.env.OKEDGE_TIMES_FILE) return { channel: wired, okcrypto };
  const SUBNAMES = Object.fromEntries(Object.entries(edge.SUB || {}).map(([k, v]) => [v, k]));
  const note = (what, ms, ok) => {
    if (print) say(`time ${what} ${ms} ms${ok ? '' : ' (failed)'}`);
    times.took(what, ms, { failed: !ok });
  };
  edge.onTiming = (sub, ms, ok) => note(`key ${SUBNAMES[sub] || sub}`, ms, ok);
  const timedCall = async (what, fn) => {
    const t = Date.now();
    let ok = false;
    try { const v = await fn(); ok = true; return v; } finally { note(what, Date.now() - t, ok); }
  };
  /* the channel keeps everything else it has (openStack reads channel.local): only send is timed */
  const channel = Object.create(wired);
  channel.send = (m, o) => timedCall(`host ${(m && m.type) || 'message'}`, () => wired.send(m, o));
  return {
    channel,
    okcrypto: { ...okcrypto, agent: { ...okcrypto.agent, sign: (...a) => timedCall('key SIGN', () => okcrypto.agent.sign(...a)) } },
  };
}

/*
 * edge ping: a pure link test (Brad, 2026-10-06) - random bytes to the host and
 * back, checked by their SHA-256. No key, no budget, nothing signed or written.
 * Only a host that serves pings answers (neither the desktop app nor local-host.js does).
 */
/*
 * edge wipe --yes (dev): the key's DEBUG-only Edge wipe (R31) - a fresh chain, a new device id;
 * private keys untouched. A production key refuses it. Brad, 2026-10-08: "need to reset the
 * blockchain on the live to clear the contaminate" - "no bumping protocol or schema version".
 */
async function wipe(args, { out, ask }) {
  if (!args.includes('--yes')) {
    out('edge wipe erases this key\'s Edge chain (a new chain, a new device id; no private key touched). DEBUG firmware only. Add --yes.');
    return 1;
  }
  await ask('wipe-debug', {}, { timeoutMs: 30000 });
  out('the key\'s Edge region is wiped: a fresh chain starts at its next request (then: onlykey-js edge reset on this computer)');
  return 0;
}

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
 * THE CLEAN START ON THIS COMPUTER (R31, SPEC.md; Brad, 2026-10-07: "we are
 * doing a reset"): the Edge records of the chain the reset ended go - its budgets
 * (budgets.json), its copies (copy-*.json) and the budgets this computer held on
 * each key (pointers.json). What stays: peer.key, control.key and agent-gpg.asc
 * (keys and the agent's own certificate - R31 keeps every key). The agent's
 * identity is its host's (SPEC H7): a reset here leaves it. Local: no key.
 * -> the files removed
 */
function reset(home, out) {
  const fs = require('fs');
  const path = require('path');
  const removed = [];
  if (fs.existsSync(home)) {
    for (const n of fs.readdirSync(home)) {
      if (n === 'budgets.json' || n === 'pointers.json' || /^copy-[0-9a-f]{16}\.json$/.test(n)) {
        fs.rmSync(path.join(home, n), { force: true });
        removed.push(n);
      }
    }
  }
  out(removed.length ? `edge reset (${home}): removed ${removed.join(', ')}` : `edge reset (${home}): nothing of an old chain here`);
  out('kept: peer.key, control.key and agent-gpg.asc; the agent identity is its host\'s');
  return removed;
}

module.exports = {
  reset,
  identityOption: true,
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
  /* the ship's timeline (times.js): the steps of every process a ship runs */
  times,
  commands: { ping, wipe },
};
