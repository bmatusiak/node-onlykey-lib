/*
 * onlykey-js keychain - Key Chain's core commands, through main() against the
 * fake firmware: what reaches the key, what a person sees, what is written.
 */
'use strict';

const test = require('node:test');
const assert = require('node:assert');
const crypto = require('node:crypto');

const { main } = require('../../cli/index');
const { startDesktop } = require('../../cli/desktop');
const { fakeFirmware } = require('../../test/helpers/fake-firmware');
const { MSG } = require('../../src/protocol/msg');
const { ed25519 } = require('../../src/vendor/exports/@noble/curves/ed25519.js');

const PASS = 'a passphrase of twenty-five characters or more';
const NO_DEVICE = () => { throw new Error('opened a device'); };

async function run(argv, firmwareOpts = {}, extra = {}) {
  const out = [];
  const err = [];
  const files = {};
  const answers = (extra.answers || []).slice();
  const firmware = fakeFirmware(firmwareOpts);
  const code = await main(argv, {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    prompt: async () => answers.shift(),
    writeFile: async (file, text) => { files[file] = text; },
    start: extra.start || ((opts) => startDesktop({ ...opts, pipe: firmware })),
  });
  return { code, out, err, files, firmware };
}
const sent = (fw, msg) => fw.writes.filter((w) => w.data[4] === msg).map((w) => w.data);

test('keychain slots: every key slot, what it holds, its label and fingerprint', async () => {
  const ed = ed25519.getPublicKey(crypto.randomBytes(32));
  const r = await run(['keychain', 'slots'], {
    pubKeys: { 101: ed, 2: Buffer.from(crypto.generateKeyPairSync('rsa', { modulusLength: 2048 }).publicKey.export({ format: 'jwk' }).n, 'base64url') },
    keyLabels: { 29: 'ssh:laptop', 26: 'Work key' },
    keyKinds: { 101: 'ed25519' },
    converted: { 101: crypto.randomBytes(32) },
  });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out.length, 20, 'RSA1-4 and ECC1-16');
  assert.match(r.out[1], /^RSA2\s+rsa 2048\s+Work key\s+[0-9a-f]{4} /);
  assert.match(r.out[4], /^ECC1\s+ed25519\s+ssh:laptop\s+[0-9a-f]{4} /);
  assert.match(r.out[5], /^ECC2\s+empty$/);
});

test('keychain pub: the slot\'s public key as an SSH line and hex', async () => {
  const ed = ed25519.getPublicKey(crypto.randomBytes(32));
  const r = await run(['keychain', 'pub', 'ECC1'], {
    pubKeys: { 101: ed }, keyKinds: { 101: 'ed25519' }, converted: { 101: crypto.randomBytes(32) },
  });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out[0], 'ECC1 ed25519');
  assert.match(r.out[1], /^ssh {5}ssh-ed25519 AAAA/);
  assert.equal(r.out[2], `hex     ${Buffer.from(ed).toString('hex')}`);
});

test('keychain derive ssh: the agent identity\'s public key, as an SSH line', async () => {
  const K132 = new Uint8Array(32).map((_, i) => (i * 29 + 7) & 0xff);
  const r = await run(['keychain', 'derive', 'ssh', 'ed25519', 'me@host'], { agent: { k132: K132 } });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out[0], 'derived ssh ed25519 "me@host"');
  assert.match(r.out[1], /^ssh {5}ssh-ed25519 AAAA\S+ me@host$/);
  const bad = await run(['keychain', 'derive', 'ssh', 'x25519', 'me@host'], { agent: { k132: K132 } });
  assert.equal(bad.code, 2);
});

test('keychain gen on the OnlyKey: the trigger and the label; a named slot needs --yes', async () => {
  let r = await run(['keychain', 'gen', 'ed25519', '--slot', 'ECC3', '--label', 'ssh:work']);
  assert.equal(r.code, 0, r.err.join('\n'));
  const [frame] = sent(r.firmware, MSG.OKSETPRIV);
  assert.equal(frame[5], 103);
  assert.equal(frame[6] & 0x0f, 1);
  assert.ok(frame.subarray(7, 15).every((b) => b === 0xff), 'the generate trigger');
  assert.equal(sent(r.firmware, MSG.OKSETSLOT).length, 1, 'the label after the key');
  assert.match(r.out.join('\n'), /keychain pub ECC3/);

  r = await run(['keychain', 'gen', 'p256', '--slot', 'ECC1'], { keyLabels: { 29: 'pgp:alice' } });
  assert.notEqual(r.code, 0);
  assert.match(r.err.join('\n'), /named "pgp:alice".*--yes/);
  assert.equal(sent(r.firmware, MSG.OKSETPRIV).length, 0, 'nothing generated');

  r = await run(['keychain', 'gen', 'rsa', '--slot', 'RSA1'], {}, { start: NO_DEVICE });
  assert.equal(r.code, 2);
  assert.match(r.err[0], /use --host/);
});

test('keychain gen --host: stored and exported encrypted; OpenSSL opens the copy', async () => {
  const r = await run(['keychain', 'gen', 'p256', '--host', '--slot', 'ECC2', '--export-pem', 'k.pem'], {},
    { answers: [PASS, PASS] });
  assert.equal(r.code, 0, r.err.join('\n'));
  const pem = r.files['k.pem'];
  assert.match(pem, /^-----BEGIN ENCRYPTED PRIVATE KEY-----/);
  const opened = crypto.createPrivateKey({ key: pem, passphrase: PASS });
  const [frame] = sent(r.firmware, MSG.OKSETPRIV);
  assert.equal(frame[5], 102);
  /* The scalar the key got is the one in the copy. */
  const d = Buffer.from(opened.export({ format: 'jwk' }).d, 'base64url');
  assert.deepEqual(Buffer.from(frame.subarray(7, 39)), d);
  assert.match(r.out.join('\n'), /ssh {5}ecdsa-sha2-nistp256 /);
});

test('keychain gen --host refuses a key that would be made and dropped, and a bad passphrase writes nothing', async () => {
  let r = await run(['keychain', 'gen', 'ed25519', '--host'], {}, { start: NO_DEVICE });
  assert.equal(r.code, 2);
  assert.match(r.err[0], /made and lost/);
  r = await run(['keychain', 'gen', 'ed25519', '--host', '--export-pem', 'x.pem'], {},
    { answers: ['short', 'short'], start: NO_DEVICE });
  assert.equal(r.code, 2);
  assert.deepEqual(r.files, {});
});

test('keychain gen pgp --host: an encrypted armored copy and the public certificate', async () => {
  const r = await run(['keychain', 'gen', 'pgp', '--host', '--user-id', 'Kc <kc@example.org>', '--export-pgp', 'k.asc'], {},
    { answers: [PASS, PASS], start: NO_DEVICE });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.match(r.files['k.asc'], /^-----BEGIN PGP PRIVATE KEY BLOCK-----/);
  assert.match(r.out.join('\n'), /-----BEGIN PGP PUBLIC KEY BLOCK-----/);
  const openpgp = require('../../src/crypto/pgp');
  const key = await openpgp.readPrivateKey({ armoredKey: r.files['k.asc'] });
  assert.equal(key.isDecrypted(), false);
});
