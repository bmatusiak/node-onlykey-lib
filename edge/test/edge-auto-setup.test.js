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
/* a host (this computer for a key on USB) that keeps `record`, and what it was sent */
const hostWith = (record) => {
  const sent = [];
  return { sent, channel: { local: true, send: async (m) => { sent.push(m.type); return m.type === identity.GET_TYPE ? { ok: true, record } : { ok: true }; } } };
};
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

test('an identity the host keeps stays as it is: nothing made, nothing sent but the question', async () => {
  const host = hostWith(kept);
  const r = await reg.setUpIdentity(io, { channel: host.channel, say: () => {} }, h, {});
  assert.equal(r.changed, false);
  assert.equal(r.record.cert.fingerprint.toLowerCase(), kept.cert.fingerprint);
  assert.deepEqual(host.sent, [identity.GET_TYPE]);
});

test('none kept and no git email: it stops and says what to set - nothing sent to keep', () => withGit('', async () => {
  const host = hostWith(null);
  await assert.rejects(reg.setUpIdentity(io, { channel: host.channel, say: () => {} }, h, {}), /git config --global user\.name \/ user\.email/);
  assert.deepEqual(host.sent, [identity.GET_TYPE]);
}));
