/**
 * Where sealed vault blobs live between launches.
 *
 * Two things are being checked, and only one of them is the happy path.
 *
 * The first is the RECORD SHAPE, which is the web app's and is not ours to
 * choose: an export written here has to import at onlykey.github.io and the
 * other way round. A tidier shape would make this app the only client able to
 * read its own backups.
 *
 * The second is what happens when the store is in a state nothing wrote on
 * purpose - a half-finished delete, a corrupt index, a record that will not
 * parse. Storage that only works when it was left tidy is storage that loses
 * data, and none of those states throws an error a caller could act on.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const {
  createVaultStore, memoryStore, INDEX_KEY, RECORD_PREFIX, EXPORT_VERSION,
} = require('../src/crypto/vault_store');

/** A record as vault.seal would leave it - the blob is opaque here. */
const entry = (serviceId, encrypted = 'c2VhbGVk') => ({ serviceId, encrypted });

function freshStore(startAt = 1000) {
  let clock = startAt;
  const store = memoryStore();
  const vault = createVaultStore({ store, now: () => clock });
  return { store, vault, tick: (by = 1) => { clock += by; return clock; } };
}

/* ------------------------------------------------------------ the basics */

test('a credential saves and comes back', async () => {
  const { vault } = freshStore();
  const saved = await vault.put(entry('github.com'));

  assert.equal(saved.serviceId, 'github.com');
  assert.equal(saved.encrypted, 'c2VhbGVk');
  assert.equal(saved.createdAt, 1000);
  assert.equal(saved.updatedAt, 1000);

  const back = await vault.get('github.com');
  assert.deepEqual(back, saved);
});

test('a missing credential is null, not an error', async () => {
  const { vault } = freshStore();
  assert.equal(await vault.get('never-stored'), null);
});

test('createdAt survives an update and updatedAt does not', async () => {
  /*
   * That difference is the only thing that makes "when did I first store this"
   * answerable after an edit.
   */
  const { vault, tick } = freshStore();
  await vault.put(entry('site', 'first'));
  tick(500);
  const updated = await vault.put(entry('site', 'second'));

  assert.equal(updated.createdAt, 1000, 'createdAt moved');
  assert.equal(updated.updatedAt, 1500);
  assert.equal(updated.encrypted, 'second');
});

test('a record without a sealed blob is refused', async () => {
  /*
   * The blob IS the record. Storing one without it would leave a name in the
   * list that opens to nothing, which reads as data loss rather than as the
   * caller error it is.
   */
  const { vault } = freshStore();
  await assert.rejects(() => vault.put({ serviceId: 'x' }), /sealed blob/);
  await assert.rejects(() => vault.put({ encrypted: 'y' }), /serviceId/);
});

test('list is oldest first, and remove takes one out', async () => {
  const { vault, tick } = freshStore();
  await vault.put(entry('one'));
  tick(10);
  await vault.put(entry('two'));
  tick(10);
  await vault.put(entry('three'));

  assert.deepEqual((await vault.list()).map((r) => r.serviceId), ['one', 'two', 'three']);

  await vault.remove('two');
  assert.deepEqual(await vault.serviceIds(), ['one', 'three']);
  assert.equal(await vault.get('two'), null);
});

test('removing something that was never there is not an error', async () => {
  const { vault } = freshStore();
  await vault.remove('nothing');
  assert.deepEqual(await vault.serviceIds(), []);
});

/* -------------------------------------------------- the untidy store cases */

test('an index entry with no record is dropped rather than returned as null', async () => {
  /*
   * The state a delete interrupted between its two writes leaves behind. A
   * caller iterating the list would otherwise hit a null where a record should
   * be, somewhere far from here.
   */
  const { store, vault } = freshStore();
  await vault.put(entry('real'));
  await vault.put(entry('ghost'));

  await store.removeItem(`${RECORD_PREFIX}ghost`);

  const list = await vault.list();
  assert.deepEqual(list.map((r) => r.serviceId), ['real']);
  assert.ok(list.every(Boolean), 'no nulls in the list');

  // And the index was repaired, so it does not have to be discovered twice.
  assert.deepEqual(JSON.parse(await store.getItem(INDEX_KEY)), ['real']);
});

test('a corrupt index does not strand the records it was pointing at', async () => {
  /*
   * Throwing here would be the worst outcome: the ciphertext is all still
   * present, and a store that refuses to start cannot be repaired by writing
   * to it.
   */
  const { store, vault } = freshStore();
  await vault.put(entry('kept'));
  await store.setItem(INDEX_KEY, 'this is not json');

  assert.deepEqual(await vault.list(), [], 'a corrupt index lists nothing');

  // Writing rebuilds it, and the original record is still readable directly.
  assert.ok(await vault.get('kept'), 'the record itself survived');
  await vault.put(entry('added'));
  assert.deepEqual(await vault.serviceIds(), ['added']);
});

test('a record that will not parse reads as absent, so it can be overwritten', async () => {
  const { store, vault } = freshStore();
  await vault.put(entry('broken'));
  await store.setItem(`${RECORD_PREFIX}broken`, '{ not json');

  assert.equal(await vault.get('broken'), null);
  const fixed = await vault.put(entry('broken', 'new'));
  assert.equal(fixed.encrypted, 'new');
});

test('clear removes only what this store wrote', async () => {
  const { store, vault } = freshStore();
  await store.setItem('someone-elses-key', 'keep me');
  await vault.put(entry('a'));
  await vault.put(entry('b'));

  assert.equal(await vault.clear(), 2);
  assert.deepEqual(await vault.serviceIds(), []);
  assert.equal(await store.getItem('someone-elses-key'), 'keep me');
});

/* ------------------------------------------------------ export and import */

test('an export carries the envelope the web app writes', async () => {
  const { vault } = freshStore();
  await vault.put(entry('github.com'));

  const parsed = JSON.parse(await vault.exportJSON());
  assert.equal(parsed.version, EXPORT_VERSION);
  assert.equal(typeof parsed.exportedAt, 'string');
  assert.ok(Array.isArray(parsed.credentials));
  assert.deepEqual(Object.keys(parsed.credentials[0]).sort(),
    ['createdAt', 'encrypted', 'serviceId', 'updatedAt']);
});

test('an export imports into an empty vault', async () => {
  const source = freshStore();
  await source.vault.put(entry('one', 'blob-one'));
  await source.vault.put(entry('two', 'blob-two'));
  const json = await source.vault.exportJSON();

  const target = freshStore(9000);
  const result = await target.vault.importJSON(json);

  assert.deepEqual(result, { imported: 2, skipped: 0, total: 2 });
  assert.equal((await target.vault.get('one')).encrypted, 'blob-one');
});

test('an import does NOT overwrite by default', async () => {
  /*
   * Importing a backup over a live vault must not quietly replace a newer
   * credential with an older one. The count says what happened rather than
   * hiding it.
   */
  const source = freshStore();
  await source.vault.put(entry('site', 'old'));
  const json = await source.vault.exportJSON();

  const target = freshStore();
  await target.vault.put(entry('site', 'current'));

  const result = await target.vault.importJSON(json);
  assert.deepEqual(result, { imported: 0, skipped: 1, total: 1 });
  assert.equal((await target.vault.get('site')).encrypted, 'current');
});

test('force overwrites, and only when asked', async () => {
  const source = freshStore();
  await source.vault.put(entry('site', 'incoming'));
  const json = await source.vault.exportJSON();

  const target = freshStore();
  await target.vault.put(entry('site', 'current'));

  const result = await target.vault.importJSON(json, { force: true });
  assert.deepEqual(result, { imported: 1, skipped: 0, total: 1 });
  assert.equal((await target.vault.get('site')).encrypted, 'incoming');
});

test('entries missing a blob are skipped, not imported empty', async () => {
  const { vault } = freshStore();
  const json = JSON.stringify({
    version: 1,
    credentials: [
      { serviceId: 'good', encrypted: 'blob' },
      { serviceId: 'no-blob' },
      { encrypted: 'no-id' },
      null,
    ],
  });

  const result = await vault.importJSON(json);
  assert.deepEqual(result, { imported: 1, skipped: 3, total: 4 });
  assert.deepEqual(await vault.serviceIds(), ['good']);
});

test('something that is not a vault export is refused by name', async () => {
  const { vault } = freshStore();
  await assert.rejects(() => vault.importJSON('not json at all'), /not JSON/);
  await assert.rejects(() => vault.importJSON('{"hello":true}'), /no credentials array/);
  await assert.rejects(
    () => vault.importJSON('{"version":99,"credentials":[]}'),
    /export version 99/,
  );
});

/* ------------------------------------------------------------ the contract */

test('a store missing a method is refused when the vault is built', async () => {
  /*
   * At construction, not at the first write. A host that wired this wrong
   * should find out when it starts, not the first time someone saves a
   * credential.
   */
  assert.throws(() => createVaultStore({ store: null }), /no store supplied/);
  assert.throws(
    () => createVaultStore({ store: { getItem: () => {} } }),
    /missing setItem, removeItem/,
  );
});

test('two vaults over the same store see the same records', async () => {
  // What "it survived a relaunch" means when the store is the thing that
  // persists and the vault object is not.
  const store = memoryStore();
  await createVaultStore({ store }).put(entry('shared'));

  const second = createVaultStore({ store });
  assert.equal((await second.get('shared')).encrypted, 'c2VhbGVk');
});

test('a vault written by the WEB APP imports, and exports back the same way', async () => {
  /*
   * The envelope is an INTERFACE, not an internal shape: a vault exported by
   * the reference has to import here and back again
   * (onlykey.github.io/src/plugins/vault/vault.js:127-152).
   *
   * Asserted by importing a document written the way the reference writes one,
   * rather than by exporting ours and reading it back - which would agree with
   * itself whatever shape it had. A standing plan claimed these had diverged;
   * they have not, and this is what says so.
   */
  const store = memoryStore();
  const vault = createVaultStore({ store });

  const fromTheWebApp = JSON.stringify({
    version: 1,
    exportedAt: '2026-01-02T03:04:05.000Z',
    credentials: [
      { serviceId: 'openai', encrypted: 'AAECAw==', policy: 'session:8h' },
      { serviceId: 'github', encrypted: 'BAUGBw==', policy: 'always' },
    ],
  });

  const result = await vault.importJSON(fromTheWebApp);
  assert.equal(result.imported, 2, 'a reference export did not import');
  assert.deepEqual((await vault.serviceIds()).sort(), ['github', 'openai']);

  const back = JSON.parse(await vault.exportJSON());
  assert.equal(back.version, EXPORT_VERSION);
  assert.equal(typeof back.exportedAt, 'string');
  assert.equal(back.credentials.length, 2);
  for (const entry of back.credentials) {
    assert.ok(entry.serviceId, 'a record without a serviceId is skipped on import');
    assert.ok(entry.encrypted, 'a record without ciphertext is skipped on import');
  }

  /*
   * The reference skips a record missing either field rather than throwing, so
   * a partially damaged export still restores what it can.
   */
  const damaged = JSON.stringify({
    version: 1,
    credentials: [{ serviceId: 'nociphertext' }, { encrypted: 'AAA=' }],
  });
  assert.deepEqual(
    await vault.importJSON(damaged),
    { imported: 0, skipped: 2, total: 2 },
  );
});
