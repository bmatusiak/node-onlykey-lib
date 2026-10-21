/*
 * `onlykey-js edge reset` (dev; R31, the clean start): the old chain's budgets and
 * copies go; every key and the person's settings stay. No agent.key since 2026-10-08
 * (Brad: "so the claude key thing is overkill") - nothing to register again after it.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { main } = require('../../cli/index');

test('edge reset removes budgets.json, pointers.json and copy-*.json, keeps the keys and the certificate', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'okreset-'));
  try {
    const files = { 'peer.key': 'bb', 'control.key': 'cc', 'agent-gpg.asc': 'cert', 'budgets.json': '{}', 'pointers.json': '{"v":1}', 'copy-0123456789abcdef.json': '{}' };
    for (const [n, v] of Object.entries(files)) fs.writeFileSync(path.join(home, n), v);
    const out = [];
    const code = await main(['edge', '--edge-home', home, 'reset'], { out: (l) => out.push(l), err: () => {}, start: () => { throw new Error('opened a device'); } });
    assert.equal(code, 0);
    assert.deepEqual(fs.readdirSync(home).sort(), ['agent-gpg.asc', 'control.key', 'peer.key']);
    for (const n of ['peer.key', 'control.key', 'agent-gpg.asc']) assert.equal(fs.readFileSync(path.join(home, n), 'utf8'), files[n]);
    assert.match(out.join('\n'), /removed /);
    for (const n of ['budgets.json', 'pointers.json', 'copy-0123456789abcdef.json']) assert.match(out.join('\n'), new RegExp(n.replace(/\./g, '\\.')));
    assert.match(out.join('\n'), /kept: peer\.key, control\.key and agent-gpg\.asc; the agent identity is the phone's$/m);
    assert.doesNotMatch(out.join('\n'), /register|agent\.key/, 'no registration to redo');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
