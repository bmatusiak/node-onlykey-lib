'use strict';

/*
 * Wallet phrases derived from the key (passwords/src/mnemonic.js). The key is a stub here: its
 * deriveSharedSecretFor(label) is SHA-256 of a seed, the label and the press flag - deterministic,
 * press-dependent, like the device. The word step is checked against the official BIP39 vectors,
 * the HKDF step against Node's own HKDF (another implementation).
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const nodeCrypto = require('node:crypto');
const { memoryStore } = require('../../src/crypto/vault_store');
const { mnemonic: mn, manager: m } = require('../src');

const fakeKey = (seed) => {
  const calls = [];
  return {
    calls,
    async deriveSharedSecretFor(label, opts) {
      calls.push({ label, press: opts.pressForSecret });
      return new Uint8Array(nodeCrypto.createHash('sha256').update(`${seed}|${label}|${opts.pressForSecret}`).digest());
    },
  };
};

test('BIP39 English: the official all-zero vectors', () => {
  assert.equal(mn.wordsOf(new Uint8Array(16)).join(' '), `${'abandon '.repeat(11)}about`);
  assert.equal(mn.wordsOf(new Uint8Array(32)).join(' '), `${'abandon '.repeat(23)}art`);
  assert.equal(mn.wordsOf(new Uint8Array(16).fill(0xff)).join(' '), `${'zoo '.repeat(11)}wrong`);
});

test('the entropy is HKDF-SHA256(secret, info okrn-mnemonic-v1), as Node computes it', () => {
  const secret = new Uint8Array(32).fill(0x11);
  for (const [out, n] of [['bip39-12', 16], ['bip39-24', 32]]) {
    const want = new Uint8Array(nodeCrypto.hkdfSync('sha256', secret, new Uint8Array(0), 'okrn-mnemonic-v1', n));
    assert.deepEqual(mn.entropyFrom(secret, out), want);
  }
});

test('same key + same name: the same words; another name or another key: other words', async () => {
  const a = await mn.deriveMnemonic({ okcrypto: fakeKey('A'), name: 'wallet-1', out: 'bip39-24', press: false });
  const again = await mn.deriveMnemonic({ okcrypto: fakeKey('A'), name: ' wallet-1 ', out: 'bip39-24', press: false });
  const other = await mn.deriveMnemonic({ okcrypto: fakeKey('A'), name: 'wallet-2', out: 'bip39-24', press: false });
  const otherKey = await mn.deriveMnemonic({ okcrypto: fakeKey('B'), name: 'wallet-1', out: 'bip39-24', press: false });
  assert.equal(a.words.length, 24);
  assert.ok(mn.isValidPhrase(a.words));
  assert.deepEqual(again.words, a.words);
  assert.deepEqual(again.recipe, a.recipe);
  assert.notDeepEqual(other.words, a.words);
  assert.notDeepEqual(otherKey.words, a.words);
  assert.deepEqual(a.recipe, { label: 'mnemonic:wallet-1', out: 'bip39-24', press: false, check: a.recipe.check });
  const twelve = await mn.deriveMnemonic({ okcrypto: fakeKey('A'), name: 'wallet-1', out: 'bip39-12', press: false });
  assert.equal(twelve.words.length, 12);
});

test('the press flag is an input, recorded in the recipe and used again', async () => {
  const key = fakeKey('A');
  const touchFree = await mn.deriveMnemonic({ okcrypto: key, name: 'w', press: false });
  const pressed = await mn.deriveMnemonic({ okcrypto: key, name: 'w', press: true });
  assert.notDeepEqual(pressed.words, touchFree.words);
  assert.equal(pressed.recipe.press, true);
  key.calls.length = 0;
  assert.deepEqual(await mn.openRecipe({ okcrypto: key, recipe: pressed.recipe }), pressed.words);
  assert.deepEqual(key.calls, [{ label: 'mnemonic:w', press: true }]);
  await assert.rejects(mn.deriveMnemonic({ okcrypto: key, name: 'w' }), /press is true or false/);
});

test('a key that no longer gives the saved phrase: refused, nothing shown', async () => {
  const { recipe } = await mn.deriveMnemonic({ okcrypto: fakeKey('A'), name: 'savings', press: false });
  await assert.rejects(mn.openRecipe({ okcrypto: fakeKey('drifted'), recipe }), (e) => e instanceof mn.PhraseDriftError);
});

test('names: trimmed, printable, at most 64; a recipe is checked before use', () => {
  assert.equal(mn.labelOf('  my wallet '), 'mnemonic:my wallet');
  assert.throws(() => mn.labelOf(''), /1 to 64/);
  assert.throws(() => mn.labelOf('a\nb'), /printable/);
  assert.throws(() => mn.labelOf('x'.repeat(65)), /1 to 64/);
  assert.throws(() => mn.shapeRecipe({ label: 'vault:x', out: 'bip39-12', press: false, check: '00112233' }), /mnemonic:/);
  assert.throws(() => mn.shapeRecipe({ label: 'mnemonic:x', out: 'bip39-18', press: false, check: '00112233' }), /out must be/);
  assert.equal(mn.nameOf({ label: 'mnemonic:my wallet' }), 'my wallet');
});

test('a phrase entry stores only its recipe: no words, no secret', async () => {
  const raw = memoryStore();
  const a = await m.openManager({ store: m.prefixedStore(raw, 'p/'), key: new Uint8Array(32).fill(1), randomBytes: (n) => new Uint8Array(nodeCrypto.randomBytes(n)) });
  const { words, recipe } = await mn.deriveMnemonic({ okcrypto: fakeKey('A'), name: 'cold', press: false });
  const e = await a.put({ kind: 'mnemonic', title: 'Cold wallet', recipe });
  assert.deepEqual(e.recipe, recipe);
  assert.equal(e.password, undefined);
  const plain = JSON.stringify(e);
  for (const w of new Set(words)) assert.equal(plain.includes(` ${w} `), false);
  await assert.rejects(a.put({ kind: 'mnemonic', title: 'x', recipe, password: words.join(' ') }), /stores no secret/);
  await assert.rejects(a.put({ kind: 'login', title: 'x', recipe }), /only a phrase entry/);
});
