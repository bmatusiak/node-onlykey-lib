'use strict';

/*
 * SPEC H7 (2026-10-20): the agent identity the phone keeps - the record's checks, the two
 * messages, the words every screen shows. What the computer builds is exactly what the
 * phone accepts, and what the phone answers is exactly what the computer reads back.
 */
const test = require('node:test');
const assert = require('node:assert');
const identity = require('../src/identity');

const ARMORED = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEZ...\n-----END PGP PUBLIC KEY BLOCK-----\n';
const record = (over = {}) => ({
  ssh: 'ssh://claude@nitro16',
  gpgUid: 'Claude (nitro16) <bmatusiak+agent@gmail.com>',
  committer: { name: 'Claude (nitro16)', email: 'bmatusiak+agent@gmail.com' },
  expires: 31536000,
  cert: { armored: ARMORED, fingerprint: '7fbf276c85dd192794b46cc4f75a92949d5603ca', created: 1791085347, expires: 31536000, signPublic: 'AB'.repeat(32) },
  ...over,
});

test('a well formed record passes; each bad field is named', () => {
  assert.deepEqual(identity.checkRecord(record()), { ok: true });
  const bad = [
    [{ ssh: 'claude@nitro16' }, /^ssh/],
    [{ gpgUid: ' ' }, /^gpgUid/],
    [{ committer: { name: 'x' } }, /^committer/],
    [{ expires: -1 }, /^expires/],
    [{ cert: { ...record().cert, fingerprint: 'abc' } }, /^cert\.fingerprint/],
    [{ cert: { ...record().cert, created: 0 } }, /^cert\.created/],
    [{ cert: { ...record().cert, expires: 0 } }, /^cert\.expires/],
    [{ cert: { ...record().cert, signPublic: '00' } }, /^cert\.signPublic/],
    [{ cert: { ...record().cert, armored: 'not a key' } }, /^cert\.armored/],
  ];
  for (const [over, why] of bad) {
    const r = identity.checkRecord(record(over));
    assert.equal(r.ok, false, JSON.stringify(over));
    assert.match(r.reason, why);
  }
  assert.equal(identity.checkRecord(record({ committer: null })).ok, true, 'no committer is fine');
});

test('SET: what the computer builds is what the phone accepts, and only the record\'s own fields travel', () => {
  const msg = identity.buildSet({ record: { ...record(), extra: 'dropped' } });
  assert.equal(msg.type, identity.SET_TYPE);
  assert.deepEqual(identity.verify(msg), { ok: true });
  assert.equal(msg.record.extra, undefined);
  assert.equal(msg.record.cert.fingerprint, '7FBF276C85DD192794B46CC4F75A92949D5603CA', 'upper case');
  assert.equal(msg.record.cert.signPublic, 'ab'.repeat(32), 'lower case');
  assert.throws(() => identity.buildSet({ record: record({ ssh: 'nope' }) }), /edge identity: ssh/);
});

test('the phone refuses a malformed message, a bad record, and a replay', () => {
  const msg = identity.buildSet({ record: record() });
  assert.equal(identity.verify({ ...msg, v: 2 }).reason, 'malformed');
  assert.equal(identity.verify({ ...msg, type: 'EDGE_NOTE' }).reason, 'malformed');
  assert.match(identity.verify({ ...msg, record: record({ gpgUid: '' }) }).reason, /^gpgUid/);
  const seen = new Set([msg.nonce]);
  assert.equal(identity.verify(msg, { seen }).reason, 'replayed');
  assert.deepEqual(identity.verify(identity.buildGet()), { ok: true });
});

test('the words the sheet, the drawer and the CLI show are the same rows', () => {
  const rows = identity.rows(record());
  assert.deepEqual(rows.map(([k]) => k), ['ssh', 'gpg', 'committer', 'certificate', 'made', 'expires']);
  assert.equal(rows[3][1], '7FBF 276C 85DD 1927 94B4 6CC4 F75A 9294 9D56 03CA');
  assert.equal(rows[4][1], '2026-10-04');
  assert.equal(identity.rows(record({ expires: 0, cert: { ...record().cert, expires: 0 } }))[5][1], 'never');
  assert.deepEqual(identity.rows(null), []);
});

test('same(): same labels and certificate, whatever the case of the hex', () => {
  const a = record();
  const b = record({ cert: { ...record().cert, fingerprint: a.cert.fingerprint.toUpperCase(), signPublic: a.cert.signPublic.toLowerCase() } });
  assert.equal(identity.same(a, b), true);
  assert.equal(identity.same(a, record({ ssh: 'ssh://claude@zbox' })), false);
  assert.equal(identity.same(a, null), false);
});
