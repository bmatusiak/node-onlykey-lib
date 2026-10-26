/*
 * keychain/composite - where a composite key is NOW: the list says where it was, the key says what each slot holds,
 * and the slot used is worked out from both (locate); a slot that holds something else marks its entry gone, never
 * dropped (reconcile, list.present); a slot the key proved is recorded (seen). Found on the Windows desktop and the
 * A13: the list said slot 4, an RSA key had since been put there, the composite key was in slot 3.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');

const composite = require('../src/composite');
const list = require('../src/list');

const T0 = '2026-10-25T10:00:00.000Z';
const T1 = '2026-10-25T11:00:00.000Z';
const T2 = '2026-10-25T12:00:00.000Z';
const mine = { pgp: '-----BEGIN PGP PUBLIC KEY BLOCK-----\nmine\n-----END PGP PUBLIC KEY BLOCK-----', pgpFingerprint: 'AA11', name: 'Qtwo' };
const theirs = { pgp: '-----BEGIN PGP PUBLIC KEY BLOCK-----\ntheirs\n-----END PGP PUBLIC KEY BLOCK-----', pgpFingerprint: 'BB22', name: 'Other' };
const at = (key, slot, extra = {}) => composite.entry({ slot, ...key, firstSeen: T0, lastSeen: T0, ...extra });
const probe = (kinds, labels = {}) => Object.entries(kinds).map(([slot, kind]) => ({ slot: Number(slot), kind, label: labels[slot] || '' }));

test('locate: the slot the list names, when it still holds a composite key', () => {
  const r = composite.locate([at(mine, 4)], mine, probe({ 1: 'empty', 2: 'empty', 3: 'composite', 4: 'composite' }));
  assert.strictEqual(r.slot, 4);
});

test('locate: the list is out of date (slot 4 now RSA) - the composite slot labelled with its name', () => {
  const slots = probe({ 1: 'empty', 2: 'composite', 3: 'composite', 4: 'rsa' }, { 3: 'pqc:Qtwo', 2: 'pqc:Zed' });
  const r = composite.locate([at(mine, 4)], mine, slots);
  assert.strictEqual(r.slot, 3);
  assert.deepStrictEqual(r.candidates, [3, 2]);
});

test('locate: a composite slot the list gives to another key is never chosen - the user is using it', () => {
  const r = composite.locate([at(mine, 4), at(theirs, 3)], mine, probe({ 1: 'empty', 2: 'empty', 3: 'composite', 4: 'rsa' }));
  assert.strictEqual(r.slot, null);
  assert.match(r.why, /another key in your Key Chain/);
  assert.strictEqual(r.reason, 'claimed', 'adopting is still a choice');
});

test('locate: no composite key on this OnlyKey says so', () => {
  const r = composite.locate([at(mine, 4)], mine, probe({ 1: 'empty', 2: 'empty', 3: 'rsa', 4: 'rsa' }));
  assert.strictEqual(r.slot, null);
  assert.match(r.why, /no composite key/);
  assert.strictEqual(r.reason, 'none', 'nothing to adopt: only making one helps');
});

test('reconcile: a slot holding another kind marks the entry gone; one still matching is left alone', () => {
  const entries = [at(mine, 4), at(theirs, 3)];
  const next = composite.reconcile(entries, probe({ 3: 'composite', 4: 'rsa' }), T1);
  assert.strictEqual(next[0].gone, T1);
  assert.strictEqual(list.present(next[0]), false);
  assert.strictEqual(next[1].gone, undefined);
  assert.strictEqual(composite.reconcile(next, probe({ 3: 'composite', 4: 'rsa' }), T2), null, 'nothing new to mark');
});

test('seen: a proven slot gets the key, last seen now - the old entry stays, still gone', () => {
  const gone = composite.reconcile([at(mine, 4)], probe({ 4: 'rsa' }), T1);
  const next = composite.seen(gone, mine, 3, T2);
  const in3 = next.find((e) => e.slot === 3);
  assert.ok(in3 && list.present(in3));
  assert.strictEqual(in3.lastSeen, T2);
  assert.strictEqual(next.find((e) => e.slot === 4).gone, T1);
  assert.strictEqual(composite.locate(next, mine, probe({ 1: 'empty', 2: 'empty', 3: 'composite', 4: 'rsa' })).slot, 3);
});

test('adopt: the slot proves the certificate by one Ed25519 signature; another key is refused, nothing listed', async () => {
  const crypto = require('crypto');
  const openpgp = require('../../src/vendor/openpgp/openpgp.js');
  const compositePgp = require('../../src/crypto/composite_pgp');
  const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');
  const onKey = await composite.make(openpgp, { name: 'Qtwo' });
  const other = await composite.make(openpgp, { name: 'Elsewhere' });
  const secret = compositePgp.unpackBlob(onKey.blob).ed25519Sk;
  const asked = [];
  const okcrypto = {
    async composite_sign(slot, half, digest) {
      asked.push({ slot, half, len: digest.length });
      return ed25519.sign(digest, secret);
    },
  };
  const rnd = (n) => new Uint8Array(crypto.randomBytes(n));
  const cert = await composite.certificate(openpgp, onKey.pgp);
  assert.strictEqual(cert.pgpFingerprint, onKey.pgpFingerprint.toUpperCase());
  assert.strictEqual(await composite.certificate(openpgp, 'not a key'), null);

  const e = await composite.adopt(okcrypto, openpgp, { slot: 3, pgp: onKey.pgp, randomBytes: rnd, when: T1 });
  assert.deepStrictEqual(asked, [{ slot: 3, half: compositePgp.HALF_ECC, len: 32 }], 'one press: the Ed25519 half');
  assert.strictEqual(e.type, 'composite');
  assert.deepStrictEqual(e.slots, [3]);
  assert.strictEqual(e.lastSeen, T1);

  await assert.rejects(
    composite.adopt(okcrypto, openpgp, { slot: 3, pgp: other.pgp, randomBytes: rnd }),
    (err) => err.code === 'EWRONGSLOT' && /RSA3 holds a different composite key/.test(err.message),
  );
  composite.discard(onKey);
  composite.discard(other);
});

test('merge: gone and lastSeen both go to the later time, so two devices end with one answer', () => {
  const here = composite.reconcile([at(mine, 4)], probe({ 4: 'rsa' }), T1);
  const there = [at(mine, 4)];
  const a = list.merge(here, there).entries;
  const b = list.merge(there, here).entries;
  assert.strictEqual(list.serialize(a), list.serialize(b));
  assert.strictEqual(a[0].gone, T1);
  /* seen again in that slot later: present again */
  const back = list.merge(a, [at(mine, 4, { lastSeen: T2 })]).entries;
  assert.strictEqual(list.present(back[0]), true);
});
