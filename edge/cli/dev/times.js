'use strict';

/**
 * edge/cli/dev/times.js - THE SHIP'S TIMELINE (Brad, 2026-10-29: "add measuring code so we can measure stuff better,
 * so next time we sign and push we can look at that"). A ship runs two CLI processes for every commit (`edge exec`,
 * then `edge receipt`) and git runs the gpg shim, a third, inside the exec: 14.5 s a commit on key 3 (2026-10-28), and
 * nothing said where it went. Every one of those processes appends what it did, and when, to one file the ship names
 * (OKEDGE_TIMES_FILE, set by `edge control ship` for its children); the ship prints the summary at its end.
 *
 *   node edge/cli/dev/times.js <file>     the summary of a ship's timeline again
 *
 * Times and names only - never a request's bytes, an intent or a reason (they can carry what was signed).
 * A dev-build switch (CLI.md §5): this folder is left out of the published package, so nothing here runs there.
 */
const fs = require('fs');
const path = require('path');
const { performance } = require('perf_hooks');

let WHO = `pid ${process.pid}`;
const file = () => process.env.OKEDGE_TIMES_FILE || null;

function write(ev) {
  const f = file();
  if (!f) return;
  /* a timeline that cannot be written never fails the work it times */
  try { fs.appendFileSync(f, `${JSON.stringify({ pid: process.pid, who: WHO, ...ev })}\n`); } catch (_) { /* no timeline */ }
}

/** one moment: { at, ev } */
function mark(ev, at = Date.now()) { write({ at, ev }); }

/** fn's run as one step: { at (its start), ev, ms } - the step's result or throw as fn gave it */
async function span(ev, fn) {
  if (!file()) return fn();
  const at = Date.now();
  let ok = true;
  try { return await fn(); } catch (e) { ok = false; throw e; } finally { write({ at, ev, ms: Date.now() - at, ...(ok ? {} : { failed: true }) }); }
}

/** a step already timed by its caller (the Edge plugin's onTiming, the ship's spawnSync) */
function took(ev, ms, { failed = false, at = Date.now() - ms } = {}) { write({ at, ev, ms, ...(failed ? { failed: true } : {}) }); }

/*
 * THIS PROCESS ON THE TIMELINE: when node itself started (performance.timeOrigin - before any require), when this
 * code got control (the gap is node's start and the CLI's requires), and when it exits.
 */
function started(who) {
  WHO = who;
  if (!file()) return;
  mark('process start', Math.round(performance.timeOrigin));
  mark('cli ready');
  process.once('exit', () => mark('process exit'));
}

/** a fresh timeline for one ship, under the Edge home's times/ folder; its children write to it through the env */
function begin(home) {
  const dir = path.join(home, 'times');
  fs.mkdirSync(dir, { recursive: true });
  const f = path.join(dir, `ship-${new Date().toISOString().replace(/[:.]/g, '-')}.jsonl`);
  process.env.OKEDGE_TIMES_FILE = f;
  started('ship');
  return f;
}

/** this process off the timeline: what runs after this (and its children) writes nothing */
function end() { delete process.env.OKEDGE_TIMES_FILE; }

const median = (xs) => { const s = xs.slice().sort((a, b) => a - b); return s.length ? s[Math.floor((s.length - 1) / 2)] : 0; };
const secs = (ms) => `${(ms / 1000).toFixed(2)} s`;

/*
 * THE SUMMARY: per kind of process (edge exec, edge receipt, gpg-shim), each step's median and the share of the
 * process it took - steps nest ("exec: open the use" holds the "open: …" steps the first request made), so the shares
 * do not add up to 100. Then the ship's own view: each kind of child it ran, spawn to exit, summed and median.
 */
function summary(f) {
  const evs = fs.readFileSync(f, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l));
  if (!evs.length) return ['times: nothing recorded'];
  const procs = new Map();
  for (const e of evs) {
    if (!procs.has(e.pid)) procs.set(e.pid, { who: e.who, evs: [] });
    const p = procs.get(e.pid);
    p.who = e.who;
    p.evs.push(e);
  }
  const lines = [];
  const all = evs.map((e) => e.at);
  lines.push(`times: ${procs.size} processes over ${secs(Math.max(...all.map((a, i) => a + (evs[i].ms || 0))) - Math.min(...all))} - ${f}`);
  /* kinds: every process of one kind (edge exec, edge receipt, gpg-shim) has the same steps */
  const kinds = new Map();
  for (const p of procs.values()) {
    if (p.who === 'ship') continue;
    const at = (name) => (p.evs.find((e) => e.ev === name) || {}).at;
    const start = at('process start');
    const exit = at('process exit');
    if (start === undefined || exit === undefined) continue;
    const k = kinds.get(p.who) || { n: 0, total: [], steps: new Map() };
    k.n += 1;
    k.total.push(exit - start);
    const step = (name, ms) => { if (!k.steps.has(name)) k.steps.set(name, []); k.steps.get(name).push(ms); };
    step('node start + requires', at('cli ready') - start);
    /* a step named twice in one process (two key requests of one kind) is summed for that process */
    const per = new Map();
    for (const e of p.evs) if (e.ms !== undefined) per.set(e.ev, (per.get(e.ev) || 0) + e.ms);
    for (const [name, ms] of per) step(name, ms);
    kinds.set(p.who, k);
  }
  for (const [who, k] of kinds) {
    const tot = median(k.total);
    lines.push(`  ${who} x${k.n}: median ${secs(tot)} a process`);
    const rows = [...k.steps.entries()].map(([name, ms]) => [name, median(ms), ms.length]).sort((a, b) => b[1] - a[1]);
    for (const [name, ms, n] of rows) lines.push(`    ${secs(ms).padStart(8)}  ${String(Math.round((100 * ms) / (tot || 1))).padStart(3)}%  ${name}${n < k.n ? ` (in ${n} of ${k.n})` : ''}`);
  }
  /* the ship's side: each child it ran, spawn to exit, against the child's own life - the start-up nobody else sees */
  const ship = [...procs.values()].find((p) => p.who === 'ship');
  if (ship) {
    const runs = new Map();
    for (const e of ship.evs) {
      if (e.ms === undefined) continue;
      if (!runs.has(e.ev)) runs.set(e.ev, []);
      runs.get(e.ev).push(e.ms);
    }
    lines.push('  ship, as it ran them (spawn to exit):');
    const rows = [...runs.entries()].map(([name, ms]) => [name, median(ms), ms.length, ms.reduce((a, b) => a + b, 0)]).sort((a, b) => b[3] - a[3]);
    for (const [name, ms, n, sum] of rows) lines.push(`    ${secs(sum).padStart(8)} total  ${secs(ms).padStart(8)} median  x${n}  ${name}`);
  }
  return lines;
}

module.exports = { mark, span, took, started, begin, end, summary };

if (require.main === module) {
  const f = process.argv[2];
  if (!f) { process.stderr.write('node edge/cli/dev/times.js <ship-….jsonl>\n'); process.exit(2); }
  for (const l of summary(f)) process.stdout.write(`${l}\n`);
}
