'use strict';

/*
 * A ship's child process writes into the ship's progress window as things happen (edge/cli/progress-feed.js; Brad,
 * 2026-10-29: "i dont want the log to be ahead of the action"; "the key is doing stuff, and no log happens"): only when
 * the ship named its window's file; each line stamped; a silent step gets its words, then its result and time; a line
 * never ends the run by starting with done/STOP; every `edge:` line said goes in too.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const feed = require('../cli/progress-feed');

const withWindow = (fn) => async () => {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-feed-')), 'progress.txt');
  const was = process.env.OKJS_PROGRESS_FILE;
  process.env.OKJS_PROGRESS_FILE = file;
  try {
    /* the log's lines ("# …"): the step bar's own (@) are not logged */
    await fn(file, () => (fs.existsSync(file) ? fs.readFileSync(file, 'utf8').trim().split('\n').filter((l) => l.startsWith('#')).map((l) => l.replace(/^# \[\d\d:\d\d:\d\d\.\d\] /, '')) : []));
  } finally {
    if (was === undefined) delete process.env.OKJS_PROGRESS_FILE; else process.env.OKJS_PROGRESS_FILE = was;
  }
};

test('no window named: nothing written, the step runs as it is', async () => {
  delete process.env.OKJS_PROGRESS_FILE;
  assert.equal(feed.on(), false);
  assert.equal(await feed.span('close: copy - read + verify', async () => 7), 7);
});

test('a line is stamped, loses its edge: prefix, and never starts with done/STOP', withWindow(async (file, lines) => {
  feed.line('edge: PRESS the key now - it waits 20 s');
  feed.line('done: this is not the ship ending');
  feed.line('STOP: nor this');
  const raw = fs.readFileSync(file, 'utf8').trim().split('\n');
  assert.ok(raw.every((l) => /^# \[\d\d:\d\d:\d\d\.\d\] /.test(l)), raw.join(' | '));
  assert.deepEqual(lines(), ['PRESS the key now - it waits 20 s', '- done: this is not the ship ending', '- STOP: nor this']);
}));

test('a silent step: its words before; a failure says so, with its time, and still throws', withWindow(async (file, lines) => {
  assert.equal(await feed.span('close: copy - read + verify', async () => 'v'), 'v');
  await assert.rejects(feed.span('exec: close the use', async () => { throw new Error('the key went away'); }), /went away/);
  /* a point with no words writes nothing */
  await feed.span('open: lib + USB', async () => 1);
  /* a step that ends well says nothing more - its time is the next stamp; a failure says so */
  const l = lines();
  assert.equal(l.length, 3, l.join(' | '));
  assert.equal(l[0], "the key: checking this computer's copy of its chain…");
  assert.equal(l[1], 'the key: closing the use…');
  assert.match(l[2], /^ {2}failed \(\d+\.\d s\): the key went away$/);
}));

test('the step running now: its bar starts, counts when it can, and the outer step comes back when an inner one ends', withWindow(async (file) => {
  await feed.step('outer', async () => {
    await feed.step('inner', async () => { feed.part(3, 10); feed.part(10, 10); });
  });
  /* the window's own lines (@), in order; the part lines at most 4 a second, the last always */
  const at = fs.readFileSync(file, 'utf8').trim().split('\n').filter((l) => l.startsWith('@'));
  assert.deepEqual(at, ['@ go outer', '@ go inner', '@ 3/10', '@ 10/10', '@ go outer', '@ end']);
}));

test('every edge: line the command says goes to the window too, and still to the terminal', withWindow(async (file, lines) => {
  const said = [];
  const io = { err: (s) => said.push(s) };
  feed.teeErr(io);
  io.err('edge: budget request: "sign 2 commits"');
  assert.deepEqual(said, ['edge: budget request: "sign 2 commits"']);
  assert.deepEqual(lines(), ['budget request: "sign 2 commits"']);
}));
