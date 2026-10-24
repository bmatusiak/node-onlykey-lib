'use strict';

/*
 * B3.0: the records from before identities copied into a key's identity home - only what is provably
 * that key's; nothing old changed; once; a dry run writes nothing (edge/cli/migrate-identity.js).
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bucketHome = require('../../bucket/cli/home');
const { migrateToIdentity, needsMigration, MARK } = require('../cli/migrate-identity');

const DEV = 'aa'.repeat(16);
const ID = 'bb'.repeat(16);
const MINE = 'cc'.repeat(32);

function scratch() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-mig-'));
  bucketHome.setRoot(root);
  const netHome = path.join(root, 'edge');
  const idHome = path.join(netHome, ID);
  const kv = (home, name) => bucketHome.kv(bucketHome.edgeAt(home, name));
  /* the records from before identities */
  kv(netHome, 'identity').setItem('record', JSON.stringify({ gpgUid: 'Agent <a@x>', cert: { signPublic: MINE, fingerprint: 'F1' } }));
  kv(netHome, 'copies').setItem(DEV.slice(0, 16), JSON.stringify({ deviceId: DEV, links: [], openings: [{ grantId: 7, genesis: 'ab12' }] }));
  kv(netHome, 'copies').setItem('dd'.repeat(8), JSON.stringify({ deviceId: 'dd'.repeat(16), links: [] }));
  kv(netHome, 'budgets').setItem('okedge.budget.7', JSON.stringify(JSON.stringify({ grantId: 7, genesis: 'AB12' })));
  kv(netHome, 'budgets').setItem('okedge.budget.9', JSON.stringify(JSON.stringify({ grantId: 9, genesis: 'ff00' })));
  kv(netHome, 'pointers').setItem(`okedge.pointer.budget.${DEV}`, '7');
  return { root, netHome, idHome, kv, done: () => { bucketHome.setRoot(null); fs.rmSync(root, { recursive: true, force: true }); } };
}

test('migrate: copies only this key\'s - its identity record, its device\'s copy, its budgets by genesis, its pointer; old stores untouched; once', async () => {
  const s = scratch();
  try {
    assert.equal(needsMigration(s.netHome, s.idHome), true);
    const dry = await migrateToIdentity({ netHome: s.netHome, idHome: s.idHome, deviceIdHex: DEV, signPublicOf: async () => MINE, dryRun: true });
    assert.deepEqual([dry.identity, dry.copy, dry.budgets, dry.pointers, dry.done], [true, true, [7], 1, false]);
    assert.equal(s.kv(s.idHome, 'identity').getItem('record'), null, 'a dry run writes nothing');

    const r = await migrateToIdentity({ netHome: s.netHome, idHome: s.idHome, deviceIdHex: DEV, signPublicOf: async () => MINE });
    assert.deepEqual([r.identity, r.copy, r.budgets, r.pointers, r.done], [true, true, [7], 1, true]);
    assert.ok(s.kv(s.idHome, 'identity').getItem('record'));
    assert.ok(s.kv(s.idHome, 'copies').getItem(DEV.slice(0, 16)));
    assert.equal(s.kv(s.idHome, 'copies').getItem('dd'.repeat(8)), null, 'another device\'s copy is not this key\'s');
    const b = JSON.parse(JSON.parse(s.kv(s.idHome, 'budgets').getItem(`okedge.budget.${DEV}.7`)));
    assert.equal(b.deviceId, DEV, 're-filed by device + id, the device inside');
    assert.equal(s.kv(s.idHome, 'budgets').getItem(`okedge.budget.${DEV}.9`), null, 'a budget with no matching opening stays behind');
    assert.equal(s.kv(s.idHome, 'pointers').getItem(`okedge.pointer.budget.${DEV}`), '7');
    /* nothing old changed */
    assert.ok(s.kv(s.netHome, 'identity').getItem('record'));
    assert.ok(s.kv(s.netHome, 'budgets').getItem('okedge.budget.7'));
    /* once */
    assert.ok(s.kv(s.idHome, 'identity').getItem(MARK));
    assert.equal(needsMigration(s.netHome, s.idHome), false);
    assert.equal((await migrateToIdentity({ netHome: s.netHome, idHome: s.idHome, deviceIdHex: DEV, signPublicOf: async () => MINE })).already, true);
  } finally { s.done(); }
});

test('migrate: another key\'s identity record (its certificate is not this key\'s derive) is left where it is', async () => {
  const s = scratch();
  try {
    const r = await migrateToIdentity({ netHome: s.netHome, idHome: s.idHome, deviceIdHex: DEV, signPublicOf: async () => 'ee'.repeat(32) });
    assert.equal(r.identity, false);
    assert.match(r.skipped.join('\n'), /another key's certificate/);
    assert.equal(s.kv(s.idHome, 'identity').getItem('record'), null);
  } finally { s.done(); }
});

test('migrate: an identity home is its own bucket store, beside the net\'s, in the same file', () => {
  const s = scratch();
  try {
    const at = bucketHome.edgeAt(s.idHome, 'copies');
    assert.equal(at.store, `edge.${ID}.copies`);
    assert.equal(at.file, path.join(s.root, 'bucket.json'));
    assert.equal(bucketHome.edgeAt(path.join(s.root, 'edge-test', ID), 'budgets').store, `edge-test.${ID}.budgets`);
  } finally { s.done(); }
});
