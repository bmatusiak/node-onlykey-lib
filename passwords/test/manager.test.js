'use strict';

/*
 * The Password Manager's core (passwords/src): sealed entries under one manager key, a store per
 * key identity, the swapped-blob refusal, history, export/import, the per-entry key and the old
 * vault's import. No device: the manager key and the derive public key are fixed bytes here.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { memoryStore, createVaultStore } = require('../../src/crypto/vault_store');
const { manager: m, inner, legacy } = require('../src');

const randomBytes = (n) => new Uint8Array(nodeCrypto.randomBytes(n));
const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const KEY_A = bytes(32, 1);
const KEY_B = bytes(32, 2);
const PUB_A = bytes(65, 0xa1);
const PUB_B = bytes(65, 0xb2);

/* one phone's storage, with each key's store under its own prefix */
function phone() {
  const raw = memoryStore();
  const storeFor = (pub) => m.prefixedStore(raw, `okrn.passwords.${m.storeIdOf(pub)}/`);
  return { raw, storeFor };
}

test('an entry sealed under the manager key comes back after the store is opened again', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  const e = await a.put({ kind: 'login', title: 'GitHub', username: 'brad', password: 'p1', urls: ['https://github.com'] });
  assert.match(e.id, /^[0-9a-f]{32}$/);
  const again = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  assert.deepEqual(again.list().map((x) => [x.title, x.username, x.password]), [['GitHub', 'brad', 'p1']]);
  /* nothing readable is stored: the raw values hold no title, username or password */
  const stored = [...p.raw._map.values()].join('\n');
  for (const s of ['GitHub', 'brad', 'p1"']) assert.equal(stored.includes(s), false, s);
});

test('a blob swapped onto another record is refused, not shown under that record', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  const x = await a.put({ kind: 'login', title: 'Bank', password: 'b' });
  const y = await a.put({ kind: 'login', title: 'Mail', password: 'm' });
  const vs = createVaultStore({ store: p.storeFor(PUB_A) });
  const rx = await vs.get(x.id);
  const ry = await vs.get(y.id);
  await vs.put({ serviceId: x.id, encrypted: ry.encrypted });
  await vs.put({ serviceId: y.id, encrypted: rx.encrypted });
  const again = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  assert.equal(again.size, 0);
  assert.deepEqual(again.refused().map((r) => r.reason).sort(), ['id-mismatch', 'id-mismatch']);
});

test('the wrong key opens nothing: every record is refused, none listed', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  await a.put({ kind: 'note', title: 'Secret', notes: 'n' });
  const wrong = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_B, randomBytes });
  assert.equal(wrong.size, 0);
  assert.deepEqual(wrong.refused().map((r) => r.reason), ['does-not-open']);
});

test('keys split by identity: the same derive public key shares one store, another key sees none of it', async () => {
  const p = phone();
  assert.equal(m.storeIdOf(PUB_A), m.storeIdOf(Uint8Array.from(PUB_A)), 'a key restored from the same backup gives the same id');
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  await a.put({ kind: 'login', title: 'Shared', password: 's' });
  const restored = await m.openManager({ store: p.storeFor(Uint8Array.from(PUB_A)), key: Uint8Array.from(KEY_A), randomBytes });
  assert.deepEqual(restored.list().map((x) => x.title), ['Shared']);
  const other = await m.openManager({ store: p.storeFor(PUB_B), key: KEY_B, randomBytes });
  assert.equal(other.size, 0);
  assert.deepEqual(other.refused(), [], "another key's store is empty, not a list of refusals");
});

test('a changed password goes to the history, the last five only', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  let e = await a.put({ kind: 'login', title: 'Site', password: 'v0' });
  for (let i = 1; i <= 7; i += 1) e = await a.put({ ...e, password: `v${i}` });
  assert.equal(e.password, 'v7');
  assert.deepEqual(e.history.map((h) => h.password), ['v6', 'v5', 'v4', 'v3', 'v2']);
});

test('export / import: the envelope stays sealed; another key imports nothing from it', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  await a.put({ kind: 'login', title: 'One', password: '1' });
  const env = await a.exportJSON();
  assert.equal(JSON.stringify(env).includes('One'), false);
  const q = phone();
  const fresh = await m.openManager({ store: q.storeFor(PUB_A), key: KEY_A, randomBytes });
  assert.equal((await fresh.importJSON(env)).imported, 1);
  assert.deepEqual(fresh.list().map((x) => x.title), ['One']);
  const b = await m.openManager({ store: q.storeFor(PUB_B), key: KEY_B, randomBytes });
  const r = await b.importJSON(env);
  assert.equal(r.imported, 0);
  assert.equal(r.unreadable, 1);
});

test('only this release\'s kinds are written; a locked manager does nothing', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  await assert.rejects(a.put({ kind: 'wifi', title: 'Later' }), /kind must be one of login, note, card/);
  a.lock();
  assert.throws(() => a.list(), /locked/);
});

test('a per-entry key: derived, or a passphrase with the manager key - neither alone opens it', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  const entryKey = bytes(32, 9);
  const ref = inner.newRef(randomBytes);
  assert.equal(inner.entryLabel(ref), `entry:${ref}`);
  assert.throws(() => inner.sealInner({ kind: 'login', title: 'B', password: 'x' }, entryKey, randomBytes, { seal: 'entry-derive' }), /ref/);
  const sealed = inner.sealInner({ kind: 'login', title: 'Bank', username: 'u', password: 'secret' }, entryKey, randomBytes, { seal: 'entry-derive', ref });
  assert.equal(sealed.inner.ref, ref);
  assert.equal(sealed.password, undefined);
  const saved = await a.put(sealed);
  const again = (await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes })).get(saved.id);
  assert.equal(again.password, undefined, 'the manager key alone does not show it');
  assert.equal(inner.openInner(again, entryKey).password, 'secret');
  assert.throws(() => inner.openInner(again, KEY_A));

  const salt = bytes(16, 3);
  const k1 = await inner.passphraseKey({ passphrase: 'horse battery', salt, managerKey: KEY_A });
  const k2 = await inner.passphraseKey({ passphrase: 'horse battery', salt, managerKey: KEY_B });
  const k3 = await inner.passphraseKey({ passphrase: 'other words', salt, managerKey: KEY_A });
  const p1 = inner.sealInner({ kind: 'note', title: 'N', notes: 'x' }, k1, randomBytes, { seal: 'entry-passphrase', salt });
  assert.equal(inner.openInner(p1, k1).notes, 'x');
  assert.throws(() => inner.openInner(p1, k2), undefined, 'the passphrase with another key');
  assert.throws(() => inner.openInner(p1, k3), undefined, 'the key with another passphrase');
  assert.deepEqual(inner.saltOf(p1), salt);
});

test('the old vault comes in as login entries; one that does not open is counted, not guessed', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  const old = { list: async () => [{ serviceId: 'example.com' }, { serviceId: 'old-firmware.org' }] };
  const r = await legacy.importLegacy({ legacy: old, manager: a, openOne: async (id) => { if (id === 'old-firmware.org') throw new Error('tag mismatch'); return 'pw-' + id; } });
  assert.equal(r.imported, 1);
  assert.deepEqual(r.failed, [{ serviceId: 'old-firmware.org', reason: 'tag mismatch' }]);
  assert.deepEqual(a.list().map((x) => [x.kind, x.title, x.password]), [['login', 'example.com', 'pw-example.com']]);
});

test('sealed again, an authenticator setup key goes inside too; the entry still saves', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  const k = bytes(32, 5);
  const sealed = inner.sealInner({ kind: 'totp', title: 'GitHub 2FA', totp: { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' } }, k, randomBytes, { seal: 'entry-derive', ref: inner.newRef(randomBytes) });
  assert.equal(sealed.totp, undefined);
  const saved = await a.put(sealed);
  assert.equal(saved.totp, undefined);
  assert.equal(inner.openInner(saved, k).totp.secret, 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ');
});

test('a passphrase key from the host PBKDF2 (OkSSL in ok-rn) equals the lib one', async () => {
  const salt = bytes(16, 3);
  const host = async (pw, sl, rounds, len) => new Uint8Array(nodeCrypto.pbkdf2Sync(Buffer.from(pw), Buffer.from(sl), rounds, len, 'sha256'));
  const viaHost = await inner.passphraseKey({ passphrase: 'horse battery', salt, managerKey: KEY_A, pbkdf2: host });
  const viaLib = await inner.passphraseKey({ passphrase: 'horse battery', salt, managerKey: KEY_A });
  assert.deepEqual(viaHost, viaLib);
});

test('sealing a plain entry again leaves no old password outside the seal', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  const e = await a.put({ kind: 'login', title: 'Bank', password: 'old-secret' });
  const k = bytes(32, 7);
  const sealed = inner.sealInner({ ...e, password: 'new-secret' }, k, randomBytes, { seal: 'entry-derive', ref: inner.newRef(randomBytes) });
  const saved = await a.put(sealed);
  assert.equal(saved.history, undefined);
  assert.equal(JSON.stringify(saved).includes('old-secret'), false);
  assert.equal(inner.openInner(saved, k).password, 'new-secret');
});

test('an app a login fills: its package and its signing certificate, both checked', async () => {
  const p = phone();
  const a = await m.openManager({ store: p.storeFor(PUB_A), key: KEY_A, randomBytes });
  const cert = 'ab'.repeat(32);
  const e = await a.put({ kind: 'login', title: 'Bank app', password: 'p', androidApps: [{ package: 'com.example.bank', cert: cert.toUpperCase() }] });
  assert.deepEqual(e.androidApps, [{ package: 'com.example.bank', cert }]);
  await assert.rejects(a.put({ kind: 'login', title: 'x', androidApps: [{ package: 'not a package', cert }] }), /package name/);
  await assert.rejects(a.put({ kind: 'login', title: 'x', androidApps: [{ package: 'com.example.bank', cert: 'abc' }] }), /SHA-256/);
});
