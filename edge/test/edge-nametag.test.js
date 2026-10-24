'use strict';

/* "my device name": set and changed through the key's signed statement, kept per identity (edge/cli/nametag.js) */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bucketHome = require('../../bucket/cli/home');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const { setName, getName, listNames } = require('../cli/nametag');

async function homeOf(edge) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-name-'));
  bucketHome.setRoot(root);
  return { root, home: path.join(root, 'edge', await edge.identityId()) };
}

test('nametag: set, read back, changed - the key\'s signed statement kept under its identity, by device', async () => {
  const edge = edgeOver(fakeKey());
  const { root, home } = await homeOf(edge);
  try {
    const a = await setName({ edge, home, nametag: '  key 1 (desk)  ' });
    assert.equal(a.nametag, 'key 1 (desk)', 'trimmed, as the key signs it');
    assert.equal(getName(home, a.deviceId).nametag, 'key 1 (desk)');
    const b = await setName({ edge, home, nametag: 'key 1' });
    assert.equal(getName(home, b.deviceId).nametag, 'key 1', 'changed');
    assert.equal(listNames(home).length, 1, 'one device, one name');
    await assert.rejects(setName({ edge, home, nametag: '   ' }), /at least one character/);
  } finally { bucketHome.setRoot(null); fs.rmSync(root, { recursive: true, force: true }); }
});

test('nametag: a key of another identity cannot file its name under this identity', async () => {
  const mine = edgeOver(fakeKey());
  const other = edgeOver(fakeKey({ ownerSecret: new Uint8Array(32).fill(0x42) }));
  const { root, home } = await homeOf(mine);
  try {
    await assert.rejects(setName({ edge: other, home, nametag: 'not mine' }), /not this identity's/);
    assert.deepEqual(listNames(home), []);
  } finally { bucketHome.setRoot(null); fs.rmSync(root, { recursive: true, force: true }); }
});
