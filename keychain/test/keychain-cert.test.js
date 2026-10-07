'use strict';

/*
 * `keychain cert` (keychain/src/cert.js; spec session, 2026-10-03): the certificate
 * of a derived gpg identity, its renewal and its revocation are self-signatures by
 * the OnlyKey - each a press. Key Chain needs no Edge (step 3a); that a press under
 * a live budget writes no link is Edge's test (test/edge-keychain-cert.test.js).
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const openpgp = require('../../src/vendor/openpgp/openpgp.js');
const agentProto = require('../../src/protocol/agent');
const certLib = require('../src/cert');

const hex = (b) => Buffer.from(b).toString('hex');
const UID = 'Claude (test) 2026 <claude+agent@test>';
const LABEL = `gpg://${UID}`;

function stack() {
  const keys = new Map();
  const keyOf = (identity, keyType) => {
    const k = `${hex(agentProto.identityHash(identity))}/${keyType}`;
    if (!keys.has(k)) keys.set(k, crypto.generateKeyPairSync(keyType === 4 ? 'x25519' : 'ed25519'));
    return keys.get(k);
  };
  const presses = [];
  const okcrypto = {
    agent: {
      async publicKey(identity, { keyType }) { return new Uint8Array(keyOf(identity, keyType).publicKey.export({ format: 'der', type: 'spki' }).subarray(12)); },
      async sign(identity, digest, o) {
        if (o.confirm) o.confirm();
        presses.push(o);
        return new Uint8Array(crypto.sign(null, Buffer.from(digest), keyOf(identity, 1).privateKey));
      },
    },
  };
  return { okcrypto, presses };
}

test('renewal keeps the fingerprint; a revocation (one press) revokes that key', async () => {
  const s = stack();
  const first = await certLib.makeCertificate(s.okcrypto, openpgp, { label: LABEL, expires: 30 * 86400 });
  const renewed = await certLib.makeCertificate(s.okcrypto, openpgp, { label: LABEL, created: first.created, expires: 365 * 86400 });
  assert.equal(renewed.fingerprint, first.fingerprint, 'the same key, a new expiry');
  const before = s.presses.length;
  const r = await certLib.makeRevocation(s.okcrypto, openpgp, { label: LABEL, created: first.created, reason: 3 });
  assert.equal(s.presses.length - before, 1);
  const revoked = await openpgp.revokeKey({ key: await openpgp.readKey({ armoredKey: renewed.armored }), revocationCertificate: r.armored, format: 'object' });
  assert.equal(await revoked.publicKey.isRevoked(), true, 'the key reads as revoked');
});
