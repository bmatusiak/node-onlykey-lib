'use strict';
/**
 * edge/cli/progress-feed.js - A SHIP'S CHILD PROCESS WRITES INTO THE SHIP'S PROGRESS WINDOW, AS THINGS HAPPEN
 * (Brad, 2026-10-29: "i dont want the log to be ahead of the action"; "i want the 'press key' to happen as soon as the
 * request is sent to the key, and after the press i want the press result in the log"; "the key is doing stuff, and no
 * log happens").
 *
 * The ship (edge-control.js, --gui-prompt) opens one progress window (cli/gui-prompt.js guiProgress) and runs each step
 * as a child `onlykey-js edge …` in spawnSync - it waits, blind, while the child works the key. Only the child knows
 * the moments: the budget's dialog, the request reaching the key (the press, now), the press's result, each use. The
 * terminal had them right all along (the child's own `edge:` lines, in order); this puts the same lines in the window,
 * from the same place, at the same time - and a line for each step where the key works silently (open, the chain
 * check, a use's open and close, the receipt), with how it ended and how long it took.
 *
 * On only when the ship named its window's file for its children (OKJS_PROGRESS_FILE): lines of status text, names and
 * times - nothing the terminal does not show already.
 */
const fs = require('fs');

const file = () => process.env.OKJS_PROGRESS_FILE || null;

/* one line into the window ("# text": its step and log, gui-prompt's format); never "done"/"STOP" - those end the run */
function line(text) {
  const f = file();
  if (!f) return;
  /* the leading indent stays: a result line sits under its step */
  let t = String(text).replace(/[\r\n]+/g, ' ').replace(/^edge: /, '').trimEnd();
  if (!t.trim()) return;
  if (/^(done|STOP)/.test(t)) t = `- ${t}`;
  /* stamped as the ship's own lines are (gui-prompt stamp): a gap no line explains is a wait to find */
  try { fs.appendFileSync(f, `# [${require('../../cli/gui-prompt').stamp()}] ${t}\n`); } catch (_) { /* the window is a convenience; the work goes on */ }
}

/*
 * THE SILENT STEPS, in the person's words - the timeline's span points (edge/cli/dev/times.js names them the same), so
 * one set of points says where the time goes and what the key is doing. A point not listed writes nothing.
 */
const WORDS = {
  'open: connect': 'the key: connecting',
  'open: whose bucket': 'the key: reading whose bucket this is',
  'open: edge public key': 'the key: reading its Edge public key',
  'open: start agent': 'starting the agent on this computer',
  'close: copy - read + verify': "the key: checking this computer's copy of its chain",
  'exec: open the use (the key opened first)': 'the key: opening a use (the budget pays it - no press)',
  'exec: close the use': 'the key: closing the use',
  'exec: file the receipt': 'the key: filing the receipt',
  'receipt: file it (the key opened first)': 'the key: filing the receipt',
};
const wordsFor = (name) => WORDS[name] || (/^exec: run git$/.test(name) ? 'git: running - the key signs' : null);

/*
 * THE STEP RUNNING NOW, ITS OWN BAR (Brad, 2026-10-29: "we can add a 2nd progress bar for the current operation - if
 * it takes 15 seconds to verify the block chain, then we need to show progress; users hate being blind of whats
 * happening"). Lines the window reads and does not log (gui-prompt PROGRESS_PS): `@ go <words>` - a step began (the
 * bar moves, its clock ticks); `@ k/n` - how far it is, when it can count; `@ end` - it is over. Steps nest (the copy
 * check holds its reads and its checks): when an inner one ends, the outer one's bar comes back.
 */
function raw(text) {
  const f = file();
  if (!f) return;
  try { fs.appendFileSync(f, `${text}\n`); } catch (_) { /* the window is a convenience */ }
}
const running = [];
let lastPart = 0;

/** fn as one step in the window: its words before, its bar while it runs, its result and time after */
async function step(words, fn) {
  if (!file()) return fn();
  line(`${words}…`);
  running.push(words);
  raw(`@ go ${words}`);
  const t = Date.now();
  const took = () => `${((Date.now() - t) / 1000).toFixed(1)} s`;
  try {
    const v = await fn();
    line(`  ok (${took()})`);
    return v;
  } catch (e) {
    line(`  failed (${took()}): ${e && e.message ? e.message : e}`);
    throw e;
  } finally {
    running.pop();
    raw(running.length ? `@ go ${running[running.length - 1]}` : '@ end');
  }
}

/** how far the step running now is (k of n): at most 4 a second, and always the last */
function part(k, n) {
  if (!file() || !running.length) return;
  const now = Date.now();
  if (k < n && now - lastPart < 250) return;
  lastPart = now;
  raw(`@ ${k}/${n}`);
}

/** a span point (register.js / commands.js span) as a step when it has words; else fn alone */
function span(name, fn) {
  const words = file() && wordsFor(name);
  return words ? step(words, fn) : fn();
}

/** every `edge:` line this process says also goes to the window (the io a command runs with) */
function teeErr(io) {
  if (!file() || !io || typeof io.err !== 'function') return;
  const was = io.err;
  io.err = (s) => { was(s); line(s); };
}

module.exports = { on: () => Boolean(file()), line, step, part, span, teeErr, WORDS };
