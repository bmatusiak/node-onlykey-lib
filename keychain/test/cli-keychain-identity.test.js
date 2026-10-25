/*
 * The CLI's Key Chain list in the identity's bucket (ok-edge plan S2; Brad, 2026-10-24: "cli and desktop decrypt
 * once, share same bucket stored in filesystem"): a derive is recorded into the bucket of the key's identity that
 * this computer keeps - the file the desktop app reads too; the first identity kept takes the list from before;
 * a key with no Edge identity keeps the computer's list. Every test runs in a scratch root.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const home = require('../../bucket/cli/home');
const rec = require('../cli/record');
const list = require('../src/list');

const ID = '0a87b456efdaa086a2523475e745443b';
const OTHER = '797110eb49a3' + '0'.repeat(20);

function scratch() {
  delete process.env.ONLYKEY_KEYCHAIN;
  home.setRoot(fs.mkdtempSync(path.join(os.tmpdir(), 'okkc-identity-')));
  rec.setFile(null);
}
test.afterEach(() => { home.setRoot(null); rec.setFile(null); });

/* a started app as the CLI's start returns it: okcrypto's agent derive, and the Edge plugin (or none) */
const fakeStart = ({ edge }) => async () => ({
  edge,
  services: { okcrypto: { agent: { publicKey: async () => new Uint8Array(32).fill(7) } } },
});
const derive = async (app) => app.services.okcrypto.agent.publicKey({ ssh: { user: 'me', host: 'host' } }, { keyType: 1 });
const listOf = (id, store = 'keychain') => {
  const text = home.kv(home.identityAt(id, store === 'keychain-test' ? 'test' : 'live', store)).getItem('list');
  return text ? list.parse(text) : [];
};

test('a derive on a key with an Edge identity is recorded in that identity\'s kept bucket; the old list moves in once', async () => {
  scratch();
  /* the list this computer kept before identities */
  rec.save([list.createEntry({ kind: 'derived', scheme: 'ssh', label: 'old@host', type: 'ed25519', publicKey: new Uint8Array(32).fill(1), firstSeen: 'x', lastSeen: 'x', tools: [] })]);
  const edge = { probe: async () => 'edge', identityId: async () => ID };
  const app = await rec.recordingStart(fakeStart({ edge }), { tool: 'test' })({});
  await derive(app);
  assert.deepEqual(home.keptIdentities('live'), [ID]);
  assert.deepEqual(listOf(ID).map((e) => e.label).sort(), ['me@host', 'old@host'], 'the old list moved in, the derive beside it');
  assert.equal(home.kv(home.at('keychain')).getItem('list'), null, 'the computer\'s old list is gone from bucket.json');
  /* no key now: keychain list reads the one identity kept */
  rec.setFile(null);
  assert.equal(rec.load().length, 2);
  assert.match(String(rec.keychainFile()), new RegExp(`${ID}\\.json`));
});

test('two identities kept: a list with no key asks which; --identity takes an id\'s first characters', async () => {
  scratch();
  for (const id of [ID, OTHER]) {
    const app = await rec.recordingStart(fakeStart({ edge: { probe: async () => 'edge', identityId: async () => id } }), { tool: 'test' })({});
    await derive(app);
    rec.setFile(null);
  }
  assert.throws(() => rec.load(), /more than one identity/);
  rec.setIdentity(ID.slice(0, 12));
  assert.equal(rec.load().length, 1);
  rec.setIdentity('ffff');
  assert.throws(() => rec.load(), /no identity ffff/);
});

test('a key with no Edge identity keeps the computer\'s list (bucket.json); the testnet\'s is its own', async () => {
  scratch();
  const app = await rec.recordingStart(fakeStart({ edge: { probe: async () => 'none', identityId: async () => ID } }), { tool: 'test' })({});
  await derive(app);
  assert.deepEqual(home.keptIdentities('live'), []);
  assert.equal(list.parse(home.kv(home.at('keychain')).getItem('list')).length, 1);
  rec.setFile(rec.testFile());
  const t = await rec.recordingStart(fakeStart({ edge: { probe: async () => 'edge', identityId: async () => ID } }), { tool: 'test' })({});
  await derive(t);
  assert.deepEqual(home.keptIdentities('test'), [ID]);
  assert.equal(listOf(ID, 'keychain-test').length, 1);
  assert.deepEqual(home.keptIdentities('live'), [], 'the live net keeps no identity from a testnet derive');
});
