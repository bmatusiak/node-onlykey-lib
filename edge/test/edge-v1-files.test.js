/*
 * The PC's Edge files are version 1 since the clean start (Brad, 2026-10-07: "we
 * change all the schemas to V1, because we are doing a reset"). A file from before
 * it belongs to the chain the reset ended: a copy or a budget store is read as
 * empty. The agent identity is not a file here any more (SPEC H7: the phone keeps it).
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const copy = require('../cli/copy');
const { fileKv, budgetStore } = require('../cli/register');

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
    /* budgetStore was agentKeys until 2026-10-08 (Brad: "lets cut it out") - the store only, no agent.key */
    const { store } = budgetStore(h);
    assert.equal(await store.get('okedge.budget.7'), null);
    await store.set('okedge.budget.9', '{"grantId":9}');
    const all = JSON.parse(fs.readFileSync(path.join(h, 'budgets.json'), 'utf8'));
    assert.deepEqual(all, { v: 1, 'okedge.budget.9': '{"grantId":9}' });
    assert.equal(fs.existsSync(path.join(h, 'agent.key')), false, 'no agent key is made any more');
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});

test('pointers.json (the budget held per key) is v1; a file without it is read as empty', async () => {
  const h = home();
  try {
    fs.mkdirSync(h, { recursive: true });
    const { createPointerStore } = require('../src/store');
    fs.writeFileSync(path.join(h, 'pointers.json'), JSON.stringify({ [`okedge.pointer.budget.${'a'.repeat(32)}`]: 'old' }));
    const p = createPointerStore(fileKv(h, 'pointers.json'));
    assert.equal(await p.budget('a'.repeat(32)), null, 'not v1: empty');
    await p.setBudget('b'.repeat(32), 21);
    assert.strictEqual(await p.budget('b'.repeat(32)), 21, 'a number stays a number through the file');
    assert.equal(JSON.parse(fs.readFileSync(path.join(h, 'pointers.json'), 'utf8')).v, 1);
    await p.setBudget('b'.repeat(32), null);
    assert.equal(await p.budget('b'.repeat(32)), null);
    assert.equal(fs.existsSync(path.join(h, 'agent.json')), false, 'the identity is the phone\'s: no agent.json');
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});
