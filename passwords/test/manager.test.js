'use strict';

/*
 * The Password Manager's core (passwords/src) in the derived-key format: every record sealed under
 * the store key (the key's touchless derive), the labels inside it, every secret inside the entry's
 * own seal (the touch derive of its id - a press), a moved record or seal refused, export/import,
 * and the old vault's import. No device: the derives are a fake key below.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { memoryStore } = require('../../src/crypto/vault_store');
const { manager: m, inner, legacy } = require('../src');

const randomBytes = (n) => new Uint8Array(nodeCrypto.randomBytes(n));
const bytes = (n, fill) => new Uint8Array(n).fill(fill);
const KEY_A = bytes(32, 1);
const KEY_B = bytes(32, 2);
const ID = 'a1b2c3';

/* a key's derive_secret: HMAC of its seed, the mode and the label - and the presses it was asked for */
function fakeKey(seed) {
  const presses = [];
  return {
    presses,
    async deriveSecret(label, opts = {}) {
      if (opts.touch) presses.push(label);
      return new Uint8Array(nodeCrypto.createHmac('sha256', seed).update(`${opts.touch ? 'touch' : 'touchless'}/${label}`).digest());
    },
  };
}

/* a new login with its secrets sealed, as a host makes one: a ref first, then its press */
async function sealedLogin(key, fields) {
  const ref = inner.newRef(randomBytes);
  const k = await inner.entryKey(key, ID, ref);
  return inner.sealInner(fields, k, randomBytes, { ref });
}

test('the store key opens the list: labels back, nothing readable stored, no secret without its press', async () => {
  const raw = memoryStore();
  const key = fakeKey('A');
  const a = await m.openStore({ store: m.prefixedStore(raw, 'p/'), key: KEY_A, randomBytes });
  const e = await a.put(await sealedLogin(key, { kind: 'login', title: 'GitHub', username: 'brad', password: 'p1', urls: ['https://github.com'] }));
  assert.equal(e.id, e.inner.ref, 'a sealed entry is stored under its seal\'s ref');
  const again = await m.openStore({ store: m.prefixedStore(raw, 'p/'), key: KEY_A, randomBytes });
  assert.deepEqual(again.list().map((x) => [x.title, x.username, x.password]), [['GitHub', 'brad', undefined]]);
  const stored = [...raw._map.values()].join('\n');
  for (const s of ['GitHub', 'brad', 'p1']) assert.equal(stored.includes(s), false, s);
  key.presses.length = 0;
  const open = inner.openInner(again.get(e.id), await inner.entryKey(key, ID, e.id));
  assert.equal(open.password, 'p1');
  assert.deepEqual(key.presses, [inner.entryLabel(ID, e.id)], 'one press, for that entry');
});

test('a secret outside its seal is refused, whatever the host - and an authenticator is only its seal', async () => {
  const a = await m.openStore({ store: memoryStore(), key: KEY_A, randomBytes });
  for (const f of [{ password: 'x' }, { notes: 'x' }, { history: [] }, { totp: { secret: 'GEZDGNBVGY3TQOJQ' } }]) {
    await assert.rejects(a.put({ kind: 'login', title: 'T', ...f }), /only inside the entry's seal/, Object.keys(f)[0]);
  }
  await assert.rejects(a.put({ kind: 'totp', title: 'no key' }), /setup key is sealed/);
  /* labels alone are fine: a login with a username and no password yet */
  assert.equal((await a.put({ kind: 'login', title: 'Only a name', username: 'u' })).username, 'u');
});

test('the touch secret is not the touchless one: the store key never opens an entry, another entry\'s key neither', async () => {
  const key = fakeKey('A');
  const s = await sealedLogin(key, { kind: 'login', title: 'Bank', password: 'secret' });
  const touchless = await key.deriveSecret(inner.entryLabel(ID, s.inner.ref), {});
  assert.throws(() => inner.openInner(s, touchless));
  const other = await inner.entryKey(key, ID, inner.newRef(randomBytes));
  assert.throws(() => inner.openInner(s, other));
  assert.throws(() => inner.openInner(s, KEY_A));
  assert.notEqual(m.storeLabel(ID), inner.entryLabel(ID, s.inner.ref));
  assert.match(m.storeLabel(ID), /^okedge\/passwords\/v1\/a1b2c3\/list$/);
});

test('a record moved onto another id, or a seal moved onto another entry, is refused', async () => {
  const raw = memoryStore();
  const key = fakeKey('A');
  const st = m.prefixedStore(raw, 'p/');
  const a = await m.openStore({ store: st, key: KEY_A, randomBytes });
  const x = await a.put(await sealedLogin(key, { kind: 'login', title: 'Bank', password: 'b' }));
  const y = await a.put(await sealedLogin(key, { kind: 'login', title: 'Mail', password: 'm' }));
  /* the seal of Mail under Bank's title: it opens with Mail's key, and says it is not Bank's */
  const swapped = { ...x, inner: y.inner };
  await assert.rejects(a.put(swapped), /keeps its seal's ref as its id/);
  const yKey = await inner.entryKey(key, ID, y.id);
  assert.throws(() => inner.openInner(swapped, yKey), /another entry/);
  /* whole records swapped in storage */
  const rx = await st.getItem(`entries/${x.id}`);
  const ry = await st.getItem(`entries/${y.id}`);
  await st.setItem(`entries/${x.id}`, ry);
  await st.setItem(`entries/${y.id}`, rx);
  const again = await m.openStore({ store: st, key: KEY_A, randomBytes });
  assert.equal(again.size, 0);
  assert.deepEqual(again.refused().map((r) => r.reason).sort(), ['id-mismatch', 'id-mismatch']);
});

test('reload: entries another copy wrote (a sync) show with the key already held', async () => {
  const raw = memoryStore();
  const here = await m.openStore({ store: raw, key: KEY_A, randomBytes });
  const there = await m.openStore({ store: raw, key: KEY_A, randomBytes });
  await there.put({ kind: 'login', title: 'From the phone', username: 'p' });
  assert.equal(here.size, 0);
  await here.reload();
  assert.deepEqual(here.list().map((e) => e.title), ['From the phone']);
  here.lock();
  await assert.rejects(here.reload(), /locked/);
});

test('the wrong store key opens nothing: every record is refused, none listed', async () => {
  const raw = memoryStore();
  const a = await m.openStore({ store: raw, key: KEY_A, randomBytes });
  await a.put({ kind: 'login', title: 'Secret', username: 'n' });
  const wrong = await m.openStore({ store: raw, key: KEY_B, randomBytes });
  assert.equal(wrong.size, 0);
  assert.deepEqual(wrong.refused().map((r) => r.reason), ['does-not-open']);
});

test('export / import: sealed under the store key; another key imports nothing; secrets stay in their seals', async () => {
  const key = fakeKey('A');
  const a = await m.openStore({ store: memoryStore(), key: KEY_A, randomBytes });
  const e = await a.put(await sealedLogin(key, { kind: 'login', title: 'One', password: '1' }));
  const file = a.exportJSON();
  assert.equal(file.includes('One'), false);
  const fresh = await m.openStore({ store: memoryStore(), key: KEY_A, randomBytes });
  assert.deepEqual(await fresh.importJSON(file), { imported: 1, skipped: 0, unreadable: 0 });
  assert.equal(fresh.get(e.id).password, undefined);
  assert.equal(inner.openInner(fresh.get(e.id), await inner.entryKey(key, ID, e.id)).password, '1');
  assert.equal((await fresh.importJSON(file)).skipped, 1);
  const b = await m.openStore({ store: memoryStore(), key: KEY_B, randomBytes });
  await assert.rejects(b.importJSON(file), /does not open/);
});

test('only this release\'s kinds are written; a locked store does nothing', async () => {
  const a = await m.openStore({ store: memoryStore(), key: KEY_A, randomBytes });
  await assert.rejects(a.put({ kind: 'wifi', title: 'Later' }), /kind must be one of login, note, card/);
  a.lock();
  assert.throws(() => a.list(), /locked/);
  await assert.rejects(a.put({ kind: 'login', title: 'x' }), /locked/);
});

test('the seal checks what goes in: text sizes, the history, an authenticator setup key', async () => {
  const k = bytes(32, 5);
  const ref = inner.newRef(randomBytes);
  assert.throws(() => inner.sealInner({ kind: 'login', title: 'B', password: 'x' }, k, randomBytes, {}), /ref/);
  assert.throws(() => inner.sealInner({ kind: 'login', title: 'B', password: 5 }, k, randomBytes, { ref }), /password must be text/);
  const t = inner.sealInner({ kind: 'totp', title: 'GitHub 2FA', totp: { secret: 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ' } }, k, randomBytes, { ref });
  assert.equal(t.totp, undefined);
  assert.equal(inner.openInner({ ...t, id: ref }, k).totp.period, 30);
  assert.throws(() => inner.entryLabel('not a scope!', ref), /bucket identity/);
});

test('the old vault comes in as login entries, each sealed; one that does not open is counted, not guessed', async () => {
  const key = fakeKey('A');
  const a = await m.openStore({ store: memoryStore(), key: KEY_A, randomBytes });
  const old = { list: async () => [{ serviceId: 'example.com' }, { serviceId: 'old-firmware.org' }] };
  const r = await legacy.importLegacy({
    legacy: old,
    manager: a,
    openOne: async (id) => { if (id === 'old-firmware.org') throw new Error('tag mismatch'); return 'pw-' + id; },
    seal: (e) => sealedLogin(key, e),
  });
  assert.equal(r.imported, 1);
  assert.deepEqual(r.failed, [{ serviceId: 'old-firmware.org', reason: 'tag mismatch' }]);
  const [e] = a.list();
  assert.deepEqual([e.kind, e.title, e.password], ['login', 'example.com', undefined]);
  assert.equal(inner.openInner(e, await inner.entryKey(key, ID, e.id)).password, 'pw-example.com');
});

test('an app a login fills: its package and its signing certificate, both checked', async () => {
  const a = await m.openStore({ store: memoryStore(), key: KEY_A, randomBytes });
  const cert = 'ab'.repeat(32);
  const e = await a.put({ kind: 'login', title: 'Bank app', androidApps: [{ package: 'com.example.bank', cert: cert.toUpperCase() }] });
  assert.deepEqual(e.androidApps, [{ package: 'com.example.bank', cert }]);
  await assert.rejects(a.put({ kind: 'login', title: 'x', androidApps: [{ package: 'not a package', cert }] }), /package name/);
  await assert.rejects(a.put({ kind: 'login', title: 'x', androidApps: [{ package: 'com.example.bank', cert: 'abc' }] }), /SHA-256/);
});
