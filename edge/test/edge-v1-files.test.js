/*
 * The PC's Edge state is version 1 since the clean start (Brad, 2026-10-07: "we
 * change all the schemas to V1, because we are doing a reset"). State from before it
 * belongs to the chain the reset ended: a copy is read as no copy, and a budgets or
 * pointers file without v: 1 is never moved into the bucket - read as empty. The agent
 * identity is not kept here any more (SPEC H7: the phone keeps it). Since stage 3 it all
 * lives in the CLI's bucket (bucket/cli/home.js); a home of its own keeps its own bucket.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const copy = require('../cli/copy');
const { pointerKv, budgetStore } = require('../cli/register');
const bucketHome = require('../../bucket/cli/home');

const id = new Uint8Array(16).fill(3);
const home = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okv1-'));
const stored = (h, name) => bucketHome.read(path.join(h, bucketHome.FILE)).stores[`edge.${name}`] || {};

test('a copy from before the clean start is read as no copy; a saved one is v1', () => {
  const h = home();
  try {
    copy.store(h).setItem('03'.repeat(8), JSON.stringify({ deviceId: '03'.repeat(16), links: [{ link: '00'.repeat(64), head: '00'.repeat(32) }], lastSeen: null }));
    assert.equal(copy.load(h, id).links.length, 0);
    copy.keepSeals(h, id, { seals: [] });
    assert.equal(JSON.parse(copy.store(h).getItem('03'.repeat(8))).v, 1);
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});

test('a budgets file from before the clean start is not moved and reads as empty; what is written goes to the bucket', async () => {
  const h = home();
  try {
    fs.writeFileSync(path.join(h, 'budgets.json'), JSON.stringify({ 'okedge.budget.7': '{"grantId":7}' }));
    const { store } = budgetStore(h);
    assert.equal(await store.get('okedge.budget.7'), null);
    assert.ok(fs.existsSync(path.join(h, 'budgets.json')), 'a pre-v1 file is left where it was, not moved');
    await store.set('okedge.budget.9', { grantId: 9 });
    assert.deepEqual(await store.get('okedge.budget.9'), { grantId: 9 });
    assert.equal(stored(h, 'budgets')['okedge.budget.9'].v, '{"grantId":9}');
    assert.equal(fs.existsSync(path.join(h, 'agent.key')), false, 'no agent key is made any more');
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});

test('pointers: a file without v1 reads as empty; a number stays a number through the bucket', async () => {
  const h = home();
  try {
    const { createPointerStore } = require('../src/store');
    fs.writeFileSync(path.join(h, 'pointers.json'), JSON.stringify({ [`okedge.pointer.budget.${'a'.repeat(32)}`]: 'old' }));
    const p = createPointerStore(pointerKv(h));
    assert.equal(await p.budget('a'.repeat(32)), null, 'not v1: empty');
    await p.setBudget('b'.repeat(32), 21);
    assert.strictEqual(await p.budget('b'.repeat(32)), 21, 'a number stays a number through the bucket');
    await p.setBudget('b'.repeat(32), null);
    assert.equal(await p.budget('b'.repeat(32)), null);
    assert.equal(fs.existsSync(path.join(h, 'agent.json')), false, 'the identity is the phone\'s: no agent.json');
  } finally {
    fs.rmSync(h, { recursive: true, force: true });
  }
});
