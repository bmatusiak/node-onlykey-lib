'use strict';

/*
 * "my device name": set and changed through the key's certification (a press), kept where the app reads it - the device's
 * copy in the identity bucket and its edge-names history (edge/cli/nametag.js, copy.keepNametag)
 */

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('fs');
const os = require('os');
const path = require('path');
const bucketHome = require('../../bucket/cli/home');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const { setName, getName, listNames } = require('../cli/nametag');
const copy = require('../cli/copy');

async function homeOf(edge) {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-name-'));
  bucketHome.setRoot(root);
  /* a command that read the key's bucket identity: its Edge records go in that identity's bucket */
  copy.useIdentityBucket({ id: '0123456789abcdef0123456789abcdef', net: 'live' });
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
    /* the old name is kept: the device's names, every certification once */
    assert.deepEqual(copy.nametagHistory().map((r) => r.statement.nametag).sort(), ['key 1', 'key 1 (desk)']);
    await assert.rejects(setName({ edge, home, nametag: '   ' }), /at least one character/);
  } finally { copy.useIdentityBucket(null); bucketHome.setRoot(null); fs.rmSync(root, { recursive: true, force: true }); }
});

test('nametag: a key of another identity cannot file its name under this identity', async () => {
  const mine = edgeOver(fakeKey());
  const other = edgeOver(fakeKey({ ownerSecret: new Uint8Array(32).fill(0x42) }));
  const { root, home } = await homeOf(mine);
  try {
    await assert.rejects(setName({ edge: other, home, nametag: 'not mine' }), /not this identity's/);
    assert.deepEqual(listNames(home), []);
  } finally { copy.useIdentityBucket(null); bucketHome.setRoot(null); fs.rmSync(root, { recursive: true, force: true }); }
});
