/*
 * The PC's Edge files are version 1 since the clean start (Brad, 2026-10-07: "we
 * change all the schemas to V1, because we are doing a reset"). A file from before
 * it belongs to the chain the reset ended: a copy or a budget store is read as
 * empty; agent.json keeps the person's settings and drops its budget.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const copy = require('../cli/copy');
const { loadConfig, agentKeys } = require('../cli/register');

const id = new Uint8Array(16).fill(3);
const home = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okv1-'));

test('a copy from before the clean start is read as no copy; a saved one is v1', () => {
  const h = home();
  try {
    fs.writeFileSync(copy.copyFile(h, id), JSON.stringify({ deviceId: '03'.repeat(16), links: [{ link: '00'.repeat(64), head: '00'.repeat(32) }], lastSeen: null }));
    assert.equal(copy.load(h, id).links.length, 0);
    copy.keepSeals(h, id, { seals: [] });
    assert.equal(JSON.parse(fs.readFileSync(copy.copyFile(h, id), 'utf8')).v, 1);
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});

test('a budget store from before the clean start is read as empty; what is written is v1', async () => {
  const h = home();
  try {
    fs.mkdirSync(h, { recursive: true });
    fs.writeFileSync(path.join(h, 'budgets.json'), JSON.stringify({ 'okedge.budget.7': '{"grantId":7}' }));
    const { store } = agentKeys(h);
    assert.equal(await store.get('okedge.budget.7'), null);
    await store.set('okedge.budget.9', '{"grantId":9}');
    const all = JSON.parse(fs.readFileSync(path.join(h, 'budgets.json'), 'utf8'));
    assert.deepEqual(all, { v: 1, 'okedge.budget.9': '{"grantId":9}' });
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});

test('agent.json from before the clean start keeps the settings and drops the old chain\'s budget', () => {
  const h = home();
  try {
    fs.mkdirSync(h, { recursive: true });
    fs.writeFileSync(path.join(h, 'agent.json'), JSON.stringify({ ssh: 'ssh://claude@nitro16', gpgUid: 'Claude <c@x>', budget: { grantId: 5 } }));
    const { config, save } = loadConfig(h);
    assert.equal(config.ssh, 'ssh://claude@nitro16');
    assert.equal(config.gpgUid, 'Claude <c@x>');
    assert.equal(config.budget, undefined);
    save(config);
    assert.equal(JSON.parse(fs.readFileSync(path.join(h, 'agent.json'), 'utf8')).v, 1);
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});
