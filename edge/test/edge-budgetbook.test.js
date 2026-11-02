'use strict';

/*
 * The approving host's budget book (edge/src/budgetbook.js; S4 step 7): the keys stay the app's own
 * (<prefix><dev>.<grantId>), a patch changes only what it names and never makes a record, list reads one device's
 * records in grant order (another device's and another net's never mixed in), and a bad record reads as none.
 */
const test = require('node:test');
const assert = require('node:assert');
const { createBudgetBook } = require('../src/budgetbook');

function memoryKv() {
  const m = new Map();
  return {
    m,
    getItem: async (k) => (m.has(k) ? m.get(k) : null),
    setItem: async (k, v) => { m.set(k, String(v)); },
    getAllKeys: async () => [...m.keys()],
  };
}
const DEV = 'AB'.repeat(16);

test('the same keys as the app kept them; get / put / patch', async () => {
  const kv = memoryKv();
  let net = 'okrn.edge.budgets.';
  const book = createBudgetBook({ kv, prefix: () => net });
  await book.put(DEV, 7, { reason: 'ship', uses: 3 });
  assert.ok(kv.m.has(`okrn.edge.budgets.${DEV.toLowerCase()}.7`), 'lowercase device, the grant id after it');
  assert.deepEqual(await book.get(DEV, 7), { reason: 'ship', uses: 3 });
  assert.deepEqual(await book.patch(DEV, 7, { endedAt: 5 }), { reason: 'ship', uses: 3, endedAt: 5 });
  assert.equal(await book.patch(DEV, 8, { dismissed: true }), null, 'no record: nothing written');
  assert.equal(kv.m.size, 1);
  /* the net is the prefix's: another net reads its own records */
  net = 'okrn.edge.test.budgets.';
  assert.equal(await book.get(DEV, 7), null);
});

test('list: one device\'s records by grant id - not another device\'s, not a bad record, keys read once may be given', async () => {
  const kv = memoryKv();
  const book = createBudgetBook({ kv, prefix: () => 'p.' });
  await book.put(DEV, 12, { reason: 'b' });
  await book.put(DEV, 3, { reason: 'a' });
  await book.put('cd'.repeat(16), 4, { reason: 'other device' });
  kv.m.set(`p.${DEV.toLowerCase()}.9`, '{not json');
  kv.m.set(`p.${DEV.toLowerCase()}.notes`, '{}');
  assert.deepEqual((await book.list(DEV)).map((e) => [e.grantId, e.record.reason]), [[3, 'a'], [12, 'b']]);
  const keys = await kv.getAllKeys();
  assert.deepEqual((await book.list(DEV, { keys })).map((e) => e.grantId), [3, 12]);
});

test('a store without getItem / setItem, or a prefix that is not a function, is refused', () => {
  assert.throws(() => createBudgetBook({ kv: {}, prefix: () => '' }), /getItem/);
  assert.throws(() => createBudgetBook({ kv: memoryKv(), prefix: 'p.' }), /prefix is a function/);
});
