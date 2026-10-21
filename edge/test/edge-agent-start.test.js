'use strict';

/*
 * The agent's start against the identity the phone keeps (SPEC H7, 2026-10-20), and the
 * certificate `edge setup` makes for it. A fake okcrypto stands in for the key.
 *
 *   - the certificate is made by setup (two signatures) with the lifetime asked for;
 *     the agent's start makes NONE (audit F9: it used to remake it whenever the derived
 *     key differed - new fingerprint, presses nobody was waiting for);
 *   - the same key and the same creation time give the same fingerprint (`setup
 *     --created`: how an identity moves without changing a key on GitHub);
 *   - a key that derives a different gpg key is refused, not "fixed";
 *   - the budget a computer holds is kept per key (audit F8).
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

require('../cli/control').setHome(fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-start-'))); /* setHome, never the env (CLI.md §5) */

const openpgp = require('../../src/vendor/openpgp/openpgp.js');
const { startEdgeAgent } = require('../cli/agent');
const { makeCertificate } = require('../../keychain/src/cert');
const { createPointerStore, memoryStore } = require('../src/store');

function fakeOkcrypto() {
  const keys = new Map();
  const keyOf = (identity, keyType) => {
    const k = `${JSON.stringify(identity)}/${keyType}`;
    if (!keys.has(k)) keys.set(k, crypto.generateKeyPairSync(keyType === 4 ? 'x25519' : 'ed25519'));
    return keys.get(k);
  };
  const okcrypto = {
    signs: 0,
    agent: {
      async publicKey(identity, { keyType }) {
        return new Uint8Array(keyOf(identity, keyType).publicKey.export({ format: 'der', type: 'spki' }).subarray(12));
      },
      async sign(identity, message) {
        okcrypto.signs += 1;
        return new Uint8Array(crypto.sign(null, Buffer.from(message), keyOf(identity, 1).privateKey));
      },
    },
  };
  return okcrypto;
}

const UID = 'Claude (test) <claude@test>';

/* what `edge setup` sends the phone */
async function setupRecord(okcrypto, { expires = 0, created } = {}) {
  const made = await makeCertificate(okcrypto, openpgp, { label: UID, version: 2, expires, ...(created ? { created } : {}) });
  return {
    ssh: 'ssh://claude@test', gpgUid: UID, committer: null, expires,
    cert: { armored: made.armored, fingerprint: made.fingerprint, created: made.created, expires: made.expires, signPublic: Buffer.from(made.signPublic).toString('hex') },
  };
}

async function expiryOf(armored) {
  const key = await openpgp.readKey({ armoredKey: armored });
  return key.getExpirationTime();
}

test('setup makes the certificate with the lifetime asked for; the agent\'s start makes none', async () => {
  const okcrypto = fakeOkcrypto();
  const year = await setupRecord(okcrypto, { expires: 365 * 86400 });
  assert.equal(okcrypto.signs, 2, 'two self-signatures by the key, at setup');
  const until = await expiryOf(year.cert.armored);
  assert.equal(Math.round((until.getTime() / 1000 - year.cert.created) / 86400), 365, 'one year after it was made');

  const svc = await startEdgeAgent({ okcrypto, client: {}, identity: year, openpgp, serve: false });
  assert.equal(okcrypto.signs, 2, 'the start pressed nothing');
  assert.equal(svc.certArmored, year.cert.armored, 'the phone\'s certificate, as kept');
  assert.equal(svc.fingerprint, year.cert.fingerprint);
  await svc.close();

  const never = await setupRecord(okcrypto, { expires: 0 });
  assert.equal(await expiryOf(never.cert.armored), Infinity, 'expires 0: it never expires');
});

test('setup --created: the same key and creation time give the same fingerprint; another time, another', async () => {
  const okcrypto = fakeOkcrypto();
  const a = await setupRecord(okcrypto, { created: 1791085347 });
  const b = await setupRecord(okcrypto, { created: 1791085347 });
  const c = await setupRecord(okcrypto, { created: 1791085348 });
  assert.equal(a.cert.created, 1791085347);
  assert.equal(b.cert.fingerprint, a.cert.fingerprint, 'remade with the same creation time: the same fingerprint');
  assert.notEqual(c.cert.fingerprint, a.cert.fingerprint, 'the creation time is part of the fingerprint');
});

test('a key that derives a different gpg key is refused with what to do - nothing is remade, nothing pressed', async () => {
  const record = await setupRecord(fakeOkcrypto());
  const other = fakeOkcrypto();
  await assert.rejects(() => startEdgeAgent({ okcrypto: other, client: {}, identity: record, openpgp, serve: false }),
    (e) => e.code === 'EIDENTITY_KEY' && /edge setup/.test(e.message));
  assert.equal(other.signs, 0);
});

test('no usable identity from the phone: the agent does not start, and says how to set one', async () => {
  await assert.rejects(() => startEdgeAgent({ okcrypto: fakeOkcrypto(), client: {}, identity: null, openpgp, serve: false }),
    (e) => e.code === 'EIDENTITY' && /edge setup --ssh/.test(e.message));
});

test('audit F8: the budget a computer holds is kept per key - a start on another key leaves it alone', async () => {
  const okcrypto = fakeOkcrypto();
  const record = await setupRecord(okcrypto);
  const pointers = createPointerStore(memoryStore());
  const A = 'a'.repeat(32);
  const B = 'b'.repeat(32);
  await pointers.setBudget(A, 21);
  assert.strictEqual(await pointers.budget(A), 21, 'the id comes back a number, as the client gave it');
  await pointers.setBudget(A, 'grant-on-a');
  const asked = [];
  const client = { async resume(id) { asked.push(id); throw new Error('not live'); } };

  const onB = await startEdgeAgent({ okcrypto, client, identity: record, openpgp, serve: false, pointers, deviceId: B });
  await onB.close();
  assert.deepEqual(asked, [], 'key B holds no budget of this computer\'s: nothing resumed');
  assert.equal(await pointers.budget(A), 'grant-on-a', 'key A\'s budget was not touched by a start on key B');

  const onA = await startEdgeAgent({ okcrypto, client, identity: record, openpgp, serve: false, pointers, deviceId: A });
  await onA.close();
  assert.deepEqual(asked, ['grant-on-a'], 'key A: its own budget is resumed');
  assert.equal(await pointers.budget(A), null, 'not live any more: forgotten, on A only');
});
