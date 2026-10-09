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

test('edge reset removes budgets.json and copy-*.json, keeps the keys, the certificate and agent.json\'s settings', async () => {
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'okreset-'));
  try {
    const files = { 'peer.key': 'bb', 'control.key': 'cc', 'agent-gpg.asc': 'cert', 'budgets.json': '{}', 'copy-0123456789abcdef.json': '{}' };
    for (const [n, v] of Object.entries(files)) fs.writeFileSync(path.join(home, n), v);
    fs.writeFileSync(path.join(home, 'agent.json'), JSON.stringify({ ssh: 'ssh://claude@nitro16', budget: { grantId: 4 } }));
    const out = [];
    const code = await main(['edge', '--edge-home', home, 'reset'], { out: (l) => out.push(l), err: () => {}, start: () => { throw new Error('opened a device'); } });
    assert.equal(code, 0);
    assert.deepEqual(fs.readdirSync(home).sort(), ['agent-gpg.asc', 'agent.json', 'control.key', 'peer.key']);
    for (const n of ['peer.key', 'control.key', 'agent-gpg.asc']) assert.equal(fs.readFileSync(path.join(home, n), 'utf8'), files[n]);
    const cfg = JSON.parse(fs.readFileSync(path.join(home, 'agent.json'), 'utf8'));
    assert.equal(cfg.ssh, 'ssh://claude@nitro16');
    assert.equal(cfg.budget, undefined);
    assert.match(out.join('\n'), /removed budgets\.json, copy-0123456789abcdef\.json, agent\.json: its budget/);
    assert.match(out.join('\n'), /kept: peer\.key, control\.key, agent-gpg\.asc and agent\.json's settings$/m);
    assert.doesNotMatch(out.join('\n'), /register|agent\.key/, 'no registration to redo');
  } finally {
    fs.rmSync(home, { recursive: true, force: true });
  }
});
