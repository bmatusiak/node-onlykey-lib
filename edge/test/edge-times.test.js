'use strict';

/*
 * The ship's timeline (edge/cli/dev/times.js): nothing is written without a ship naming the file; with one, every
 * step lands in it, a failed step says so, and the summary gives each kind of process its steps by median.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

const TIMES = path.join(__dirname, '..', 'cli', 'dev', 'times.js');
const times = require(TIMES);

test('times: no file named, nothing written - the step runs as it is', async () => {
  times.end();
  assert.strictEqual(await times.span('a step', async () => 7), 7);
  times.took('a timed step', 5);
});

test('times: a ship\'s children on one timeline, summed per process and summarised per kind', async () => {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-times-'));
  try {
    const file = times.begin(dir);
    assert.ok(file.startsWith(path.join(dir, 'times')) && file.endsWith('.jsonl'));
    /* two children of one kind, as a ship's two `edge exec`s: each a process of its own */
    const child = `
      const t = require(${JSON.stringify(TIMES)});
      t.started('edge exec');
      (async () => {
        await t.span('open: connect', () => new Promise((r) => setTimeout(r, 30)));
        t.took('key SIGN', 12);
        t.took('key SIGN', 8);
        await t.span('exec: run git', async () => { throw new Error('git failed'); }).catch(() => {});
      })();`;
    for (let i = 0; i < 2; i++) {
      const r = spawnSync(process.execPath, ['-e', child], { env: process.env, encoding: 'utf8' });
      assert.strictEqual(r.status, 0, r.stderr);
    }
    times.took('run edge exec', 400);
    times.took('run edge exec', 500);

    const evs = fs.readFileSync(file, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const exec = evs.filter((e) => e.who === 'edge exec');
    assert.deepStrictEqual([...new Set(exec.map((e) => e.ev))].sort(),
      ['cli ready', 'exec: run git', 'key SIGN', 'open: connect', 'process exit', 'process start'].sort());
    assert.ok(exec.find((e) => e.ev === 'exec: run git').failed, 'a step that threw is marked failed');
    const start = exec.find((e) => e.ev === 'process start');
    assert.ok(start.at <= exec.find((e) => e.ev === 'cli ready').at, 'node\'s own start comes before the code got control');

    const lines = times.summary(file);
    const text = lines.join('\n');
    assert.match(lines[0], /^times: 3 processes over /);
    assert.match(text, /edge exec x2: median /);
    /* one process's two SIGNs are one step of 20 ms */
    assert.match(text, /0\.02 s .* key SIGN\n/);
    assert.match(text, /node start \+ requires/);
    assert.match(text, /0\.90 s total +0\.40 s median +x2 +run edge exec/);
  } finally {
    times.end();
    fs.rmSync(dir, { recursive: true, force: true });
  }
});
