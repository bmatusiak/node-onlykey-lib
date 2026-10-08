'use strict';
/*
 * BUG 2 (2026-10-05): with no live edge-agent, okedge says "no edge-agent is
 * running" AT ONCE - never "Waiting for the phone" and a 200 s hang. Both of
 * the day's hangs were an agent dying WHILE handling the request: the socket
 * closed with no answer, and nothing listened for that.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const net = require('net');
const path = require('path');

const HOME = fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-ask-'));
require('../cli/control').setHome(HOME); /* a test home: setHome, never the env (CLI.md §5) */
const { ask, controlKey, controlPath } = require('../cli/control');
/* onlykey-js edge's commands (edge/cli/commands.js; okedge is gone, 2026-10-06) over the real control endpoint, with the dev set */
const okedge = { main: (args, io = {}) => require('../cli/commands').main(args, { ask: require('../cli/control').ask, dev: require('../cli/dev'), ...io }) };

const capture = () => {
  const lines = [];
  return { lines, io: { out: (s) => lines.push(s), err: (s) => lines.push(`ERR ${s}`) } };
};

test('never set up here (no control key): "no edge agent is running", at once', async () => {
  const t0 = Date.now();
  await assert.rejects(() => ask('status'), (e) => e.code === 'EEDGE_NO_AGENT' && /^no edge agent is running/.test(e.message));
  assert.ok(Date.now() - t0 < 1000);
});

test('set up, but no agent listening: okedge budget says "no edge agent is running" at once, and never "Waiting for the phone"', async () => {
  controlKey({ create: true });
  const cap = capture();
  const t0 = Date.now();
  const code = await okedge.main(['budget', '--reason', 'work', '--ssh', '1', '--ttl', '30'], cap.io);
  assert.notEqual(code, 0);
  assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
  assert.ok(cap.lines.some((l) => /no edge agent is running/.test(l)), cap.lines.join('\n'));
  assert.ok(!cap.lines.some((l) => /Waiting for the phone/.test(l)), 'said "Waiting for the phone" with nothing waiting');
});

test('the agent takes the request and dies without answering: okedge says the agent stopped, at once - no 200 s hang', async () => {
  controlKey({ create: true });
  const where = controlPath();
  /* an "agent" that reads the request, then goes away - as a crash mid-request does */
  const server = net.createServer((sock) => sock.once('data', () => sock.destroy()));
  await new Promise((r) => server.listen(where, r));
  try {
    const cap = capture();
    const t0 = Date.now();
    const code = await okedge.main(['budget', '--reason', 'work', '--ssh', '1', '--ttl', '30'], cap.io);
    assert.notEqual(code, 0);
    assert.ok(Date.now() - t0 < 2000, `took ${Date.now() - t0} ms`);
    assert.ok(cap.lines.some((l) => /the edge agent stopped/.test(l)), cap.lines.join('\n'));
    /* it DID take the request, so "waiting" was true while it lasted */
    assert.ok(cap.lines.some((l) => /Waiting for the phone/.test(l)), cap.lines.join('\n'));
  } finally {
    await new Promise((r) => server.close(r));
    if (process.platform !== 'win32') fs.rmSync(where, { force: true });
  }
});
