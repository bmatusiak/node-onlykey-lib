'use strict';

/*
 * The agent identity sets itself up (edge/cli/register.js setUpIdentity, defaultIdentity; Brad, 2026-10-29: "edge
 * setup should be checking itself to see if its setup and autosetup itself - plug it in and go - but we dont want to
 * remove best security practices"): a first identity is named from the person's own git name and email (never a
 * guessed email), an identity the host keeps is left as it is with nothing sent, and with no git email it stops and
 * says what to set. The certificate's presses and the person's Yes are the same as `edge setup`'s (not faked here).
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const reg = require('../cli/register');
const identity = require('../src/identity');
const agents = require('../src/agents');
const bucketHome = require('../../bucket/cli/home');
const { testCard } = require('./helpers/cards');

/* git's global config pointed at a scratch file for the test (GIT_CONFIG_GLOBAL) */
function withGit(text, fn) {
  const file = path.join(fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-git-')), 'gitconfig');
  fs.writeFileSync(file, text);
  const was = process.env.GIT_CONFIG_GLOBAL;
  process.env.GIT_CONFIG_GLOBAL = file;
  return Promise.resolve().then(fn).finally(() => { if (was === undefined) delete process.env.GIT_CONFIG_GLOBAL; else process.env.GIT_CONFIG_GLOBAL = was; });
}
const ARMORED = '-----BEGIN PGP PUBLIC KEY BLOCK-----\n\nxjMEZ...\n-----END PGP PUBLIC KEY BLOCK-----\n';
const kept = {
  ssh: 'ssh://claude@nitro16', gpgUid: 'Claude (nitro16) <bmatusiak+agent@gmail.com>', committer: null, expires: 31536000,
  cert: { armored: ARMORED, fingerprint: '7fbf276c85dd192794b46cc4f75a92949d5603ca', created: 1791085347, expires: 31536000, signPublic: 'AB'.repeat(32) },
};
/*
 * a host (this computer for a key on USB) that keeps `record` - the identity of before cards - and `card` ({card, certs},
 * or none), and what it was sent: the types, and the CREATE it was asked (the card it would certify at a press)
 */
const hostWith = (record, card = null) => {
  const sent = [];
  const created = [];
  const send = async (m) => {
    sent.push(m.type);
    if (m.type === identity.GET_TYPE) return { ok: true, record };
    if (m.type === agents.CREATE_TYPE) { created.push(m); return { ok: true, agent: { label: m.info.label } }; }
    if (m.type === agents.GET_TYPE) return card && m.label === card.card.thing.label ? { ok: true, agent: card } : { ok: false, refusal: 'invalid', detail: `no agent identity "${m.label}"` };
    return { ok: true };
  };
  return { sent, created, channel: { local: true, send } };
};
/* this computer's Edge home, where it keeps its card's label */
const homeDir = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-home-'));
const cardLabel = (home) => bucketHome.kv(bucketHome.edgeAt(home, 'card')).getItem('card');
const h = { usage: (m) => Object.assign(new Error(m), { usage: true }), CliError: Error };
const io = { out: () => {}, err: () => {} };

test('a first identity is named from git: ssh://agent@<computer>, and the git name and email for the gpg user ID', () => withGit('[user]\n\tname = Brad M\n\temail = brad@example.com\n', () => {
  const d = reg.defaultIdentity();
  assert.match(d.ssh, /^ssh:\/\/agent@[a-z0-9.-]+$/);
  assert.match(d.gpgUid, /^Brad M \(agent on [a-z0-9.-]+\) <brad@example\.com>$/);
}));

test('no git email: no default - an email is never guessed', () => withGit('[user]\n\tname = Brad M\n', () => {
  assert.equal(reg.defaultIdentity(), null);
}));

/*
 * THE OLD IDENTITY BECOMES A CARD (Brad, 2026-11-03: "the OLD way is still there, and the new way is not used yet"): the
 * identity the host kept before cards is sent as this computer's agent card - its labels and its certificate as they are
 * (nothing remade, the same gpg fingerprint), named for its ssh name - and the label is kept here.
 */
test('the identity the host keeps becomes this computer\'s agent card: its labels and certificate kept, named for its ssh name', async () => {
  const host = hostWith(kept);
  const home = homeDir();
  const r = await reg.setUpIdentity(io, { channel: host.channel, say: () => {}, home }, h, {});
  assert.equal(r.changed, true);
  assert.deepEqual(host.sent, [identity.GET_TYPE, agents.CREATE_TYPE], 'the old record asked, then the card - no certificate made');
  const [m] = host.created;
  assert.equal(m.info.label, 'claude@nitro16');
  assert.deepEqual(m.info.derive, { ssh: kept.ssh, gpg: kept.gpgUid });
  assert.equal(m.info.created, kept.cert.created, 'the created time the gpg key and its fingerprint are made from');
  assert.equal(m.certs.gpg.fingerprint, kept.cert.fingerprint.toUpperCase());
  assert.equal(cardLabel(home), 'claude@nitro16', 'the label kept here');
  assert.equal(r.record.label, 'claude@nitro16');
});

test('a card this computer already has stays as it is: nothing made, nothing sent but the questions', async () => {
  const card = await testCard({ label: 'claude@nitro16', ssh: kept.ssh, gpg: kept.gpgUid, committer: kept.committer, created: kept.cert.created, expires: kept.expires });
  const host = hostWith(kept, { card, certs: agents.certsFromRecord(kept) });
  const home = homeDir();
  bucketHome.kv(bucketHome.edgeAt(home, 'card')).setItem('card', 'claude@nitro16');
  const r = await reg.setUpIdentity(io, { channel: host.channel, say: () => {}, home }, h, {});
  assert.equal(r.changed, false);
  assert.equal(r.record.cert.fingerprint.toLowerCase(), kept.cert.fingerprint);
  assert.deepEqual(host.sent, [identity.GET_TYPE, agents.GET_TYPE]);
});

test('none kept and no git email: it stops and says what to set - nothing sent to keep', () => withGit('', async () => {
  const host = hostWith(null);
  await assert.rejects(reg.setUpIdentity(io, { channel: host.channel, say: () => {}, home: homeDir() }, h, {}), /git config --global user\.name \/ user\.email/);
  assert.deepEqual(host.sent, [identity.GET_TYPE]);
}));
