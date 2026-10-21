'use strict';

/*
 * The host's Key Chain list (cli/keychain-record.js; spec session, 2026-10-03):
 * every derived public key a command makes is recorded - label, type, code,
 * public key, fingerprint, first/last seen, which tool - and `keychain list |
 * show` read it back, with --json for agents. "Yours" is the phone's alone: a
 * CLI or agent write that tries to set it is ignored, and a file cannot bring it.
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');

const FILE = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'okjs-keychain-')), 'keychain.json');
process.env.ONLYKEY_KEYCHAIN = FILE;

const { main } = require('../../cli/index');
const { startDesktop } = require('../../cli/desktop');
const { fakeFirmware } = require('../../test/helpers/fake-firmware');
const rec = require('../cli/record');
const list = require('../src/list');

const K132 = new Uint8Array(32).map((_, i) => (i * 29 + 7) & 0xff);

async function run(argv, { record = true } = {}) {
  const out = [];
  const err = [];
  const firmware = fakeFirmware({ agent: { k132: K132 } });
  const code = await main(argv, {
    out: (line) => out.push(line),
    err: (line) => err.push(line),
    start: (opts) => startDesktop({ ...opts, pipe: firmware }),
    keychainRecord: record ? (f) => rec.record(f) : null,
  });
  return { code, out, err };
}

test('a derive is recorded once, with its label, type, code, fingerprint and tool; the next one updates last seen', async () => {
  fs.rmSync(FILE, { force: true });
  let r = await run(['keychain', 'derive', 'ssh', 'ed25519', 'me@host']);
  assert.equal(r.code, 0, r.err.join('\n'));
  let [e] = rec.load();
  assert.equal(e.label, 'me@host', 'filed bare, beside its scheme');
  assert.equal(e.scheme, 'ssh');
  assert.equal(require('../src').derive.labelHashOf(e), require('crypto').createHash('sha256').update('me@host').digest('hex'),
    'the label hash the key sees for it, so the phone can name the key');
  assert.equal(e.type, 'ed25519');
  assert.equal(e.code, 132, 'v1 getpubkey');
  assert.deepEqual(e.tools, ['onlykey-js keychain']);
  assert.ok(/^[0-9a-f]{4}( [0-9a-f]{4}){3}$/.test(e.fingerprint));
  const first = e.firstSeen;
  r = await run(['keychain', 'derive', 'ssh', 'ed25519', 'me@host']);
  const all = rec.load();
  assert.equal(all.length, 1, 'the same key from the same label: one entry');
  assert.equal(all[0].firstSeen, first);
  assert.ok(all[0].lastSeen >= first);
  if (process.platform !== 'win32') assert.equal(fs.statSync(FILE).mode & 0o777, 0o600, 'owner-only');
});

test('keychain list / show read the recorded list - plain and --json, no device', async () => {
  let r = await run(['keychain', 'list', '--json'], { record: false });
  assert.equal(r.code, 0, r.err.join('\n'));
  const rows = JSON.parse(r.out.join('\n'));
  assert.equal(rows[0].name, 'ssh://me@host', 'shown by its full name');
  assert.equal(rows[0].label, 'me@host');
  assert.equal(rows[0].publicKey.length, 64, 'ed25519 public key, hex');
  r = await run(['keychain', 'show', 'ssh://me@host', '--json'], { record: false });
  assert.match(JSON.parse(r.out.join('\n')).artifacts.ssh || '', /^ssh-ed25519 /);
  r = await run(['keychain', 'list'], { record: false });
  assert.match(r.out[0], /^ssh:\/\/me@host\s+ed25519\s+[0-9a-f ]+\s+onlykey-js keychain$/);
  r = await run(['keychain', 'show', 'ssh://nobody@nowhere'], { record: false });
  assert.equal(r.code, 1);
});

test('"yours" is the phone\'s: a CLI or agent write that sets it is ignored, and a file cannot bring it', () => {
  fs.rmSync(FILE, { force: true });
  const pub = new Uint8Array(32).fill(5);
  const e = rec.record({ scheme: 'ssh', label: 'ssh://agent@host', type: 'ed25519', publicKey: pub, tool: 'an agent', yours: true, own: true });
  assert.equal(e.yours, undefined);
  assert.equal(rec.load()[0].yours, undefined, 'not stored');
  const doc = JSON.parse(list.serialize(rec.load()));
  doc.entries[0].yours = true;
  doc.entries[0].ownIdentity = true;
  const [back] = list.parse(JSON.stringify(doc));
  assert.equal(back.yours, undefined, 'an imported file cannot set it');
  assert.equal(back.ownIdentity, undefined);
});

test('recordingStart: any command\'s agent.publicKey is recorded (ssh and gpg names), and a failing write never fails the command', async () => {
  const seen = [];
  const app = { services: { okcrypto: { agent: { publicKey: async () => new Uint8Array(32).fill(7) } } } };
  const start = rec.recordingStart(async () => app, { tool: 'onlykey-js edge-agent', recordFn: (f) => seen.push(f) });
  const { okcrypto } = (await start({})).services;
  await okcrypto.agent.publicKey({ ssh: { user: 'claude', host: 'nitro16' } }, { keyType: 1, version: 2 });
  await okcrypto.agent.publicKey({ gpg: 'Claude (nitro16) 2026 <a@b>' }, { keyType: 4, version: 2 });
  assert.deepEqual(seen.map((f) => [f.label, f.type, f.tool]), [
    ['claude@nitro16', 'ed25519', 'onlykey-js edge-agent'],
    ['Claude (nitro16) 2026 <a@b>', 'x25519', 'onlykey-js edge-agent'],
  ]);
  const errs = [];
  const broken = rec.recordingStart(async () => app, { tool: 't', err: (l) => errs.push(l), recordFn: () => { throw new Error('disk full'); } });
  const raw = await (await broken({})).services.okcrypto.agent.publicKey({ ssh: { user: 'a', host: 'b' } }, {});
  assert.equal(raw.length, 32, 'the derive still answers');
  assert.match(errs[0], /could not record/);
});

test('keychain export --ssh / --age / --pgp: what the list saved; no certificate yet names the cert command', async () => {
  fs.rmSync(FILE, { force: true });
  await run(['keychain', 'derive', 'ssh', 'ed25519', 'me@host']);
  let r = await run(['keychain', 'export', 'ssh://me@host', '--ssh'], { record: false });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.match(r.out[0], /^ssh-ed25519 /);
  /* a label x25519 derive goes over CTAP, which this fake firmware does not answer: recorded directly */
  rec.record({ scheme: 'label', label: 'age:personal', type: 'x25519', publicKey: new Uint8Array(32).fill(0x42), tool: 'test' });
  r = await run(['keychain', 'export', 'age:personal', '--age'], { record: false });
  assert.match(r.out[0], /^age1/);
  r = await run(['keychain', 'export', 'ssh://me@host', '--pgp'], { record: false });
  assert.equal(r.code, 1);
  assert.match(r.err.join('\n'), /keychain cert/);
  r = await run(['keychain', 'cert', 'gpg://Test <t@t>', '--expires', '1y']);
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.ok(r.out.some((l) => /saved/.test(l)));
  r = await run(['keychain', 'export', 'gpg://Test <t@t>', '--pgp'], { record: false });
  assert.match(r.out.join('\n'), /BEGIN PGP PUBLIC KEY BLOCK/);
  assert.doesNotMatch(r.out.join('\n'), /PRIVATE/);
});

/*
 * One label, several keys: gpg init writes the uid's ed25519 and x25519 keys
 * (v1), the Edge agent derives the same uid as v2. Every reader by name must
 * refuse to guess, and --type / --v1 / --v2 must reach each key.
 */
test('one label, several keys: show, export and cert refuse to guess; --type, --v1, --v2 pick one', async () => {
  fs.rmSync(FILE, { force: true });
  const L = 'gpg://Agent <a@x>';
  const key = (b) => new Uint8Array(32).fill(b);
  rec.record({ scheme: 'gpg', label: L, type: 'ed25519', publicKey: key(1), code: 132, tool: 'onlykey-js gpg' });
  rec.record({ scheme: 'gpg', label: L, type: 'x25519', publicKey: key(2), code: 132, tool: 'onlykey-js gpg' });
  rec.record({ scheme: 'gpg', label: L, type: 'ed25519', publicKey: key(3), code: 232, tool: 'onlykey-js edge agent' });
  const v1 = rec.load().find((e) => e.type === 'ed25519' && e.code === 132);

  let r = await run(['keychain', 'show', L], { record: false });
  assert.equal(r.code, 1);
  assert.match(r.err.join('\n'), /3 keys .* match .* --type <type> and\/or --v1 \/ --v2/s);
  r = await run(['keychain', 'show', L, '--type', 'ed25519'], { record: false });
  assert.equal(r.code, 1, 'still two ed25519 keys');
  assert.match(r.err.join('\n'), /2 keys/);
  r = await run(['keychain', 'show', L, '--v2', '--json'], { record: false });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(JSON.parse(r.out.join('\n')).publicKey, '03'.repeat(32));
  r = await run(['keychain', 'show', L, '--type', 'x25519', '--json'], { record: false });
  assert.equal(JSON.parse(r.out.join('\n')).publicKey, '02'.repeat(32));

  r = await run(['keychain', 'export', L, '--ssh'], { record: false });
  assert.equal(r.code, 1, 'two ed25519 keys have an ssh form');
  assert.match(r.err.join('\n'), /2 keys/);
  r = await run(['keychain', 'export', L, '--ssh', '--v1'], { record: false });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(r.out[0], v1.artifacts.ssh);

  r = await run(['keychain', 'cert', L], { record: false });
  assert.equal(r.code, 1, 'v1 and v2 under one uid: refused before the device');
  assert.match(r.err.join('\n'), /2 keys/);
  r = await run(['keychain', 'show', L, '--v1', '--v2'], { record: false });
  assert.equal(r.code, 2);

  /* the phone's spelling (scheme gpg, the bare uid) is the same name; a fingerprint tells two keys apart */
  rec.record({ scheme: 'gpg', label: 'Agent <a@x>', type: 'ed25519', publicKey: key(4), code: 232, tool: 'soft key' });
  r = await run(['keychain', 'show', L, '--v2'], { record: false });
  assert.equal(r.code, 1, 'two v2 ed25519 keys under the one name now');
  assert.match(r.err.join('\n'), /or give its fingerprint/);
  const fp = rec.load().find((e) => e.tools.includes('soft key')).fingerprint;
  r = await run(['keychain', 'show', fp, '--json'], { record: false });
  assert.equal(r.code, 0, r.err.join('\n'));
  assert.equal(JSON.parse(r.out.join('\n')).publicKey, '04'.repeat(32));
});

test('keychain import pairs the phone hash entry with the named one: one entry per key, under the name', async () => {
  fs.rmSync(FILE, { force: true });
  await run(['keychain', 'derive', 'ssh', 'ed25519', 'me@host']);
  const named = rec.load()[0];
  const hash = require('crypto').createHash('sha256').update('me@host').digest('hex');
  const phone = [
    list.createEntry({ kind: 'derived', scheme: 'agent-v1', label: 'hash:' + hash, type: 'ed25519', publicKey: named.publicKey, transport: 'vendor', tools: ['soft key'], firstSeen: '2026-10-01T00:00:00Z', lastSeen: '2026-10-01T00:00:00Z' }),
    list.createEntry({ kind: 'derived', scheme: 'web', label: 'hash:' + 'ab'.repeat(32), type: 'x25519', publicKey: new Uint8Array(32).fill(3), transport: 'fido', rpIdHash: 'cd'.repeat(32), tools: ['soft key'] }),
  ];
  const file = path.join(path.dirname(FILE), 'phone-export.json');
  fs.writeFileSync(file, list.serialize(phone));
  const out = [];
  const code = await main(['keychain', 'import', file], { out: (l) => out.push(l), err: (l) => out.push(l), start: () => { throw new Error('no device needed'); }, keychainRecord: null });
  assert.equal(code, 0, out.join('\n'));
  assert.match(out[0], /1 added, 1 paired/);
  const all = rec.load();
  assert.equal(all.length, 2, 'one entry per key');
  const one = all.find((e) => e.label === 'me@host');
  assert.equal(one.labelHash, hash, 'the hash the phone saw, kept beside the name');
  assert.equal(one.transport, 'vendor');
  assert.deepEqual(one.tools.sort(), ['onlykey-js keychain', 'soft key']);
  assert.equal(one.firstSeen, '2026-10-01T00:00:00Z', 'first seen: the earliest');
  assert.ok(all.some((e) => e.rpIdHash === 'cd'.repeat(32)));
});
