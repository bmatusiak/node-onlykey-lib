/*
 * Key Chain L5 + L6: derived public keys, every shareable form of a public
 * key, and the public-only list that keeps them - and refuses private data.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');
const { derive, list, artifacts } = require('../src/keychain');
const { ed25519, x25519 } = require('../src/vendor/exports/@noble/curves/ed25519.js');
const { p256 } = require('../src/vendor/exports/@noble/curves/nist.js');

const random = (n) => Uint8Array.from(crypto.randomBytes(n));
const fixed = () => new Date('2026-10-01T00:00:00Z');

/* A stand-in okcrypto: the real derive paths are tested in okcrypto.test.js. */
function stubOkcrypto(store = {}) {
  const calls = [];
  return {
    calls,
    async derivePublicKey(label, opts) { calls.push(['label', label, opts.keytype]); return { publicKey: store[`l:${label}:${opts.keytype}`] }; },
    deviceAge: { async identity(label) { calls.push(['xwing', label]); return { recipient: store[`x:${label}`] }; } },
    agent: { async publicKey(identity, opts) { calls.push(['agent', identity, opts.keyType, opts.version]); return store[`a:${JSON.stringify(identity)}:${opts.keyType}`]; } },
  };
}

test('artifacts: SSH lines, age recipients, hex and base64 from a public key', () => {
  const ed = ed25519.getPublicKey(random(32));
  const a = artifacts.forKey({ type: 'ed25519', publicKey: ed, comment: 'me@host' });
  assert.match(a.ssh, /^ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAI[\w+/=]+ me@host$/);
  const p = p256.getPublicKey(random(32).fill(7, 0, 1), false).slice(1);
  assert.match(artifacts.forKey({ type: 'p256', publicKey: p }).ssh, /^ecdsa-sha2-nistp256 /);
  const x = x25519.getPublicKey(random(32));
  assert.match(artifacts.forKey({ type: 'x25519', publicKey: x }).age, /^age1[02-9ac-hj-np-z]{58}$/);
  assert.equal(artifacts.forKey({ type: 'mlkem768', publicKey: random(1184) }).ssh, undefined);
});

test('derivePublic: label, X-Wing, SSH and GPG identities - each through the device, nothing private kept', async () => {
  const p = p256.getPublicKey(random(32).fill(9, 0, 1), false);
  const x = x25519.getPublicKey(random(32));
  const ed = ed25519.getPublicKey(random(32));
  const xw = random(1216);
  const ok = stubOkcrypto({
    'l:example.com:1': p, 'l:inbox:3': x, 'x:backups': xw,
    'a:"me@host":1': ed, 'a:{"gpg":"Me <me@x>"}:1': ed,
  });
  const e1 = await derive.derivePublic(ok, { scheme: 'label', label: 'example.com', type: 'p256', now: fixed });
  assert.equal(e1.publicKey.length, 64, '0x04 prefix dropped, X||Y like the slots');
  assert.equal(e1.created, '2026-10-01T00:00:00.000Z');
  const e2 = await derive.derivePublic(ok, { scheme: 'label', label: 'inbox', type: 'x25519' });
  assert.match(e2.artifacts.age, /^age1/);
  const e3 = await derive.derivePublic(ok, { scheme: 'label', label: 'backups', type: 'xwing' });
  assert.match(e3.artifacts.age, /^age1onlykey/);
  const e4 = await derive.derivePublic(ok, { scheme: 'ssh', label: 'me@host', type: 'ed25519', version: 2 });
  assert.match(e4.artifacts.ssh, / me@host$/);
  assert.equal(e4.version, 2);
  await derive.derivePublic(ok, { scheme: 'gpg', label: 'Me <me@x>', type: 'ed25519' });
  assert.deepEqual(ok.calls.map((c) => c[0]), ['label', 'label', 'xwing', 'agent', 'agent']);
  for (const e of [e1, e2, e3, e4]) assert.doesNotThrow(() => list.createEntry(e), 'a derived entry is list-ready');
  await assert.rejects(derive.derivePublic(ok, { scheme: 'label', label: 'x', type: 'rsa' }), /derives p256/);
  await assert.rejects(derive.derivePublic(ok, { scheme: 'ssh', label: 'x', type: 'x25519' }), /ed25519 or p256/);
});

test('the list: file round trip, stable ids, merge keeps what is there', async () => {
  const ed = ed25519.getPublicKey(random(32));
  const a = list.createEntry({ kind: 'slot', slot: 101, label: 'ssh:laptop', type: 'ed25519', publicKey: ed });
  const b = list.createEntry({ kind: 'external', name: 'server key', type: 'rsa', publicKey: random(256) });
  const file = list.serialize([a, b]);
  assert.match(file, /"format": "onlykey-keychain"/);
  const back = list.parse(file);
  assert.deepEqual(back.map((e) => e.id), [a.id, b.id]);
  assert.deepEqual([...back[0].publicKey], [...ed]);
  assert.match(back[0].artifacts.ssh, /^ssh-ed25519 /);
  const again = list.createEntry({ kind: 'slot', slot: 101, label: 'ssh:laptop', type: 'ed25519', publicKey: ed });
  const merged = list.merge([a], [again, b]);
  assert.deepEqual([merged.added, merged.kept, merged.entries.length], [1, 1, 2]);
  assert.match(list.fingerprint(ed), /^[0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4} [0-9a-f]{4}$/);
});

test('the list refuses anything private - fields, PEM, armored private blocks, age secret keys', () => {
  const pub = ed25519.getPublicKey(random(32));
  const base = { kind: 'external', name: 'x', type: 'ed25519', publicKey: pub };
  assert.throws(() => list.createEntry({ ...base, secret: random(32) }), /public data only.*secret/);
  assert.throws(() => list.createEntry({ ...base, p: random(128) }), /public data only/);
  assert.throws(() => list.createEntry({ ...base, note: '-----BEGIN ENCRYPTED PRIVATE KEY-----' }), /private key text/);
  assert.throws(() => list.createEntry({ ...base, pgp: '-----BEGIN PGP PRIVATE KEY BLOCK-----' }), /private key text/);
  assert.throws(() => list.createEntry({ ...base, note: 'AGE-SECRET-KEY-1ABC' }), /private key text/);
  const smuggled = JSON.stringify({ format: 'onlykey-keychain', version: 1, entries: [{ ...base, publicKey: '00', nested: { d: 'ff' } }] });
  assert.throws(() => list.parse(smuggled), /public data only/);
  assert.throws(() => list.parse('{"format":"other"}'), /not a Key Chain file/);
});
