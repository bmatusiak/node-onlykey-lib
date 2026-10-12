'use strict';

/*
 * Refresh against a fake network (the fake-fetch pattern of ok-rn __tests__/keySearch.test.ts):
 * same / updated / changed per source, missing and error never touch the pin, two sources that
 * disagree wait as a conflict, a served private key is refused, and the person's three answers.
 */

const test = require('node:test');
const assert = require('node:assert');
const nodeCrypto = require('crypto');

const openpgp = require('../../src/crypto/pgp');
const sshPub = require('../../src/crypto/ssh-pub');
const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
const { formats, store, refresh, sources } = require('../src');

function fakeFetch(table) {
  const asked = [];
  const fn = async (url) => {
    asked.push(url);
    const hit = table[url];
    if (hit instanceof Error) throw hit;
    if (!hit) return { ok: false, status: 404, url, text: async () => '' };
    const status = hit.status || 200;
    return { ok: status < 400, status, url: hit.url || url, text: async () => hit.body };
  };
  fn.asked = asked;
  return fn;
}

const gb = store.createGuestBook({ storage: { getItem: async () => null, setItem: async () => {} }, randomBytes: (n) => new Uint8Array(nodeCrypto.randomBytes(n)) });
const KEYBASE = (u) => `https://keybase.io/${u}/pgp_keys.asc`;
const PROTON = (a) => `https://api.protonmail.ch/pks/lookup?op=get&search=${encodeURIComponent(a)}`;

let keys = null;
async function pgpKeys() {
  if (!keys) {
    const a = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'Alice', email: 'alice@example.com' }], format: 'object', date: new Date(Date.now() - 3600 * 1000) });
    const other = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'Mallory', email: 'alice@example.com' }], format: 'armored' });
    const third = await openpgp.generateKey({ type: 'ecc', curve: 'curve25519', userIDs: [{ name: 'Eve', email: 'alice@example.com' }], format: 'armored' });
    keys = { a, other: other.publicKey, third: third.publicKey, otherPrivate: other.privateKey };
  }
  return keys;
}

async function aliceContact(srcs) {
  const { a } = await pgpKeys();
  const { found } = await formats.detectAll(a.publicKey.armor(), { openpgp });
  let c = gb.newContact({ name: 'Alice', found, source: srcs[0] });
  for (const s of srcs.slice(1)) c = gb.addKeys(c, found, s);
  return c;
}

test('same key served: "same"; a new subkey served: merged, "updated"; the pin never moves', async () => {
  const { a } = await pgpKeys();
  const c = await aliceContact([{ kind: 'keybase', handle: 'alice' }]);
  let r = await refresh.refreshContact(c, { fetchFn: fakeFetch({ [KEYBASE('alice')]: { body: a.publicKey.armor() } }), openpgp });
  assert.equal(r.contact.keys[0].sources[0].lastResult, 'same');
  assert.deepEqual(r.changes, []);
  const withSub = await a.privateKey.addSubkey({ type: 'ecc', curve: 'curve25519' });
  r = await refresh.refreshContact(c, { fetchFn: fakeFetch({ [KEYBASE('alice')]: { body: withSub.toPublic().armor() } }), openpgp });
  assert.equal(r.contact.keys[0].sources[0].lastResult, 'updated');
  assert.equal(r.contact.keys[0].fingerprint, c.keys[0].fingerprint);
  assert.equal((await openpgp.readKey({ armoredKey: r.contact.keys[0].text })).getSubkeys().length, 2);
});

test('another key served: held as pending, the pinned key untouched', async () => {
  const { other } = await pgpKeys();
  const c = await aliceContact([{ kind: 'keybase', handle: 'alice' }]);
  const r = await refresh.refreshContact(c, { fetchFn: fakeFetch({ [KEYBASE('alice')]: { body: other } }), openpgp });
  const k = r.contact.keys[0];
  assert.equal(k.text, c.keys[0].text);
  assert.equal(k.sources[0].lastResult, 'changed');
  assert.equal(k.pending.conflict, false);
  assert.equal(k.pending.candidates.length, 1);
  assert.match(r.changes[0], /changed - waiting for you/);
});

test('two sources serving two different keys: both wait, as a conflict', async () => {
  const { other, third } = await pgpKeys();
  const c = await aliceContact([{ kind: 'keybase', handle: 'alice' }, { kind: 'protonmail', handle: 'alice@example.com' }]);
  const r = await refresh.refreshContact(c, { fetchFn: fakeFetch({ [KEYBASE('alice')]: { body: other }, [PROTON('alice@example.com')]: { body: third } }), openpgp });
  assert.equal(r.contact.keys[0].pending.conflict, true);
  assert.equal(r.contact.keys[0].pending.candidates.length, 2);
});

test('404 is missing, 500 / oversize / http redirect / a network failure are errors - the key stays', async () => {
  const c = await aliceContact([{ kind: 'keybase', handle: 'alice' }]);
  const cases = [
    [{}, 'missing'],
    [{ [KEYBASE('alice')]: { status: 500, body: '' } }, 'error'],
    [{ [KEYBASE('alice')]: { body: 'x'.repeat(formats.MAX_TEXT + 1) } }, 'error'],
    [{ [KEYBASE('alice')]: { body: 'x', url: 'http://keybase.io/alice/pgp_keys.asc' } }, 'error'],
    [{ [KEYBASE('alice')]: new Error('offline') }, 'error'],
  ];
  for (const [table, expected] of cases) {
    const r = await refresh.refreshContact(c, { fetchFn: fakeFetch(table), openpgp });
    assert.equal(r.contact.keys[0].sources[0].lastResult, expected, JSON.stringify(Object.values(table)[0] && Object.keys(Object.values(table)[0])));
    assert.equal(r.contact.keys[0].text, c.keys[0].text, 'the pinned key changed');
    assert.equal(r.contact.keys[0].pending, undefined);
  }
});

test('PUBLIC ONLY: a source serving a private key is an error, nothing taken from it', async () => {
  const { otherPrivate } = await pgpKeys();
  const c = await aliceContact([{ kind: 'url', handle: 'https://alice.example/key.asc' }]);
  const r = await refresh.refreshContact(c, { fetchFn: fakeFetch({ 'https://alice.example/key.asc': { body: otherPrivate } }), openpgp });
  assert.equal(r.contact.keys[0].sources[0].lastResult, 'error');
  assert.equal(r.contact.keys[0].pending, undefined);
  assert.equal(r.contact.keys[0].text, c.keys[0].text);
});

test('GitHub .keys: the pinned SSH key listed is "same", no longer listed is "missing" (never "changed")', async () => {
  const mine = sshPub.publicKeyLine('ed25519', ed25519.getPublicKey(new Uint8Array(32).fill(7)), 'alice@laptop');
  const another = sshPub.publicKeyLine('ed25519', ed25519.getPublicKey(new Uint8Array(32).fill(8)), 'alice@new');
  const { found } = await formats.detectAll(mine);
  const c = gb.newContact({ name: 'Alice', found, source: { kind: 'github', handle: 'alice' } });
  let r = await refresh.refreshContact(c, { fetchFn: fakeFetch({ 'https://github.com/alice.keys': { body: `${another}\n${mine}\n` } }) });
  assert.equal(r.contact.keys[0].sources[0].lastResult, 'same');
  r = await refresh.refreshContact(c, { fetchFn: fakeFetch({ 'https://github.com/alice.keys': { body: `${another}\n` } }) });
  assert.equal(r.contact.keys[0].sources[0].lastResult, 'missing');
  assert.equal(r.contact.keys[0].pending, undefined);
});

test('the person\'s answers: accept (verified cleared), keep current, keep and remove the source', async () => {
  const { other } = await pgpKeys();
  let c = await aliceContact([{ kind: 'keybase', handle: 'alice' }, { kind: 'paste', handle: '' }]);
  c = gb.setVerified(c, c.keys[0].id, true);
  const waiting = (await refresh.refreshContact(c, { fetchFn: fakeFetch({ [KEYBASE('alice')]: { body: other } }), openpgp })).contact;
  const fp = waiting.keys[0].pending.candidates[0].fingerprint;
  const accepted = refresh.acceptPending(waiting, waiting.keys[0].id, fp);
  assert.equal(accepted.keys[0].fingerprint, fp);
  assert.equal(accepted.keys[0].verified, false, 'a verified mark carried over to an unchecked key');
  assert.equal(accepted.keys[0].pending, undefined);
  const kept = refresh.keepCurrent(waiting, waiting.keys[0].id);
  assert.equal(kept.keys[0].fingerprint, c.keys[0].fingerprint);
  assert.equal(kept.keys[0].pending, undefined);
  const removed = refresh.keepAndRemoveSources(waiting, waiting.keys[0].id);
  assert.deepEqual(removed.keys[0].sources.map((s) => s.kind), ['paste']);
});

test('refreshAll: one contact at a time, recently checked ones skipped; lookup is https only', async () => {
  const { a } = await pgpKeys();
  const c1 = await aliceContact([{ kind: 'keybase', handle: 'alice' }]);
  const fetchFn = fakeFetch({ [KEYBASE('alice')]: { body: a.publicKey.armor() } });
  const first = await refresh.refreshAll([c1, c1], { fetchFn, openpgp, delayMs: 0 });
  assert.equal(fetchFn.asked.length, 2);
  const again = await refresh.refreshAll(first.contacts, { fetchFn, openpgp, delayMs: 0, skipWithinMs: 3600 * 1000 });
  assert.equal(fetchFn.asked.length, 2, 'a contact checked within the hour was fetched again');
  assert.equal(again.contacts.length, 2);
  await assert.rejects(sources.lookup('url', 'http://example.com/key.asc', fetchFn), /only https/);
});

test('lookup (add): Keybase search then each user\'s key, Proton bare name -> @protonmail.com, GitHub .keys', async () => {
  const { a } = await pgpKeys();
  const armored = a.publicKey.armor();
  const fetchFn = fakeFetch({
    'https://keybase.io/_/api/1.0/user/user_search.json?q=ali': { body: JSON.stringify({ list: [{ keybase: { username: 'alice', full_name: 'Alice A' } }, { keybase: { username: 'alinokey' } }] }) },
    [KEYBASE('alice')]: { body: armored },
    [PROTON('ali@protonmail.com')]: { body: armored },
    'https://github.com/ali.keys': { body: 'ssh-ed25519 AAAA x\n' },
  });
  const kb = await sources.lookup('keybase', 'ali', fetchFn);
  assert.deepEqual(kb.map((f) => [f.label, f.source.handle]), [['alice (Alice A)', 'alice']]);
  const pm = await sources.lookup('protonmail', 'ali', fetchFn);
  assert.deepEqual(pm[0].source, { kind: 'protonmail', handle: 'ali@protonmail.com' });
  const gh = await sources.lookup('github', '@ali', fetchFn);
  assert.deepEqual(gh[0].source, { kind: 'github', handle: 'ali' });
  await assert.rejects(sources.lookup('keybase', '  ', fetchFn), /type a name/);
});
