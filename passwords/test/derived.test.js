'use strict';

/*
 * Derived passwords (passwords/src/derived.js). The key is a stub: deriveSharedSecretFor(label)
 * is SHA-256 of a seed, the label and the press flag. The known-answer values pin the draw: a code
 * change that would hand out a different password for a saved recipe fails here first.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { memoryStore } = require('../../src/crypto/vault_store');
const { derived: d, manager: m } = require('../src');

const fakeKey = (seed) => ({
  async deriveSharedSecretFor(label, opts) {
    return new Uint8Array(nodeCrypto.createHash('sha256').update(`${seed}|${label}|${opts.pressForSecret}`).digest());
  },
});
const ALL = ['upper', 'lower', 'digits', 'symbols'];

test('known answers: a fixed secret gives these passwords (the draw must never change)', () => {
  assert.equal(d.passwordFrom(new Uint8Array(32).fill(0x11), 20, ALL), 'eg,s?&?JDVze8DvOR2}A');
  assert.equal(d.passwordFrom(new Uint8Array(32).fill(0x22), 12, ['lower', 'digits']), 'inuqn3z3hudu');
});

test('every chosen class is in it, nothing else, at the length asked', () => {
  for (let i = 0; i < 50; i += 1) {
    const secret = new Uint8Array(nodeCrypto.createHash('sha256').update(String(i)).digest());
    const p = d.passwordFrom(secret, 8, ALL);
    assert.equal(p.length, 8);
    for (const c of ALL) assert.ok([...p].some((ch) => d.CHARSETS[c].includes(ch)), `${c} missing from ${p}`);
    const digitsOnly = d.passwordFrom(secret, 16, ['digits']);
    assert.match(digitsOnly, /^[0-9]{16}$/);
  }
});

test('same key + name + settings: the same password; another name or key: another', async () => {
  const a = await d.derivePasswordFor({ okcrypto: fakeKey('A'), name: 'github', press: false });
  const again = await d.derivePasswordFor({ okcrypto: fakeKey('A'), name: ' github ', press: false });
  assert.equal(again.password, a.password);
  assert.deepEqual(again.recipe, a.recipe);
  assert.notEqual((await d.derivePasswordFor({ okcrypto: fakeKey('A'), name: 'github-2', press: false })).password, a.password);
  assert.notEqual((await d.derivePasswordFor({ okcrypto: fakeKey('B'), name: 'github', press: false })).password, a.password);
  assert.deepEqual(a.recipe, { label: 'password:github', out: 'password', length: 20, classes: ALL, press: false, check: a.recipe.check });
  assert.equal(await d.openRecipe({ okcrypto: fakeKey('A'), recipe: a.recipe }), a.password);
});

test('a key that no longer gives the saved password: refused, nothing shown', async () => {
  const { recipe } = await d.derivePasswordFor({ okcrypto: fakeKey('A'), name: 'bank', press: false });
  await assert.rejects(d.openRecipe({ okcrypto: fakeKey('drifted'), recipe }), (e) => e instanceof d.DerivedDriftError);
});

test('bad settings are refused', () => {
  const s = new Uint8Array(32);
  assert.throws(() => d.passwordFrom(s, 7, ALL), /length/);
  assert.throws(() => d.passwordFrom(s, 57, ALL), /length/);
  assert.throws(() => d.passwordFrom(s, 20, []), /at least one/);
  assert.throws(() => d.labelOf(''), /1 to 64/);
  assert.throws(() => d.shapeRecipe({ label: 'mnemonic:x', out: 'password', length: 20, classes: ALL, press: false, check: '00112233' }), /password:/);
});

test('a derived entry stores only its recipe', async () => {
  const raw = memoryStore();
  const a = await m.openStore({ store: m.prefixedStore(raw, 'p/'), key: new Uint8Array(32).fill(1), randomBytes: (n) => new Uint8Array(nodeCrypto.randomBytes(n)) });
  const { password, recipe } = await d.derivePasswordFor({ okcrypto: fakeKey('A'), name: 'site', press: false });
  const e = await a.put({ kind: 'derived', title: 'Site', username: 'brad', urls: ['https://site.example'], recipe });
  assert.deepEqual(e.recipe, recipe);
  assert.equal(JSON.stringify(e).includes(password), false);
  await assert.rejects(a.put({ kind: 'derived', title: 'x', recipe, password }), /stores no secret/);
});
