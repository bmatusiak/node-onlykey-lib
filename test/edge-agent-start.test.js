'use strict';

/*
 * startEdgeAgent's certificate and its lifetime (Brad, 2026-10-03: "Add
 * --expires to edge-agent and use 1 year for the real key"). A fake okcrypto
 * stands in for the key: the certificate is made once (two signatures), carries
 * the expiry asked for, is reused on the next start, and is made again only when
 * the lifetime changes.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

require('../cli/edge-control').setHome(fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-start-'))); /* setHome, never the env (CLI.md §5) */

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const { startEdgeAgent } = require('../cli/edge-agent');

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

async function start(okcrypto, config) {
  const svc = await startEdgeAgent({ okcrypto, client: {}, config, openpgp });
  const key = await openpgp.readKey({ armoredKey: svc.certArmored });
  const expires = await key.getExpirationTime();
  await svc.close();
  return expires;
}

test('the certificate: made once with the lifetime asked for, reused on the next start, made again when the lifetime changes', async () => {
  const okcrypto = fakeOkcrypto();
  const config = { ssh: 'ssh://claude@test', gpgUid: 'Claude (test) <claude@test>', expires: 365 * 86400 };

  const first = await start(okcrypto, config);
  assert.equal(okcrypto.signs, 2, 'two self-signatures by the key');
  assert.ok(first instanceof Date, 'the certificate expires');
  const days = (first.getTime() / 1000 - config.cert.created) / 86400;
  assert.equal(Math.round(days), 365, 'one year after it was made');

  await start(okcrypto, config);
  assert.equal(okcrypto.signs, 2, 'the same lifetime: the saved certificate, no presses');

  config.expires = 0;
  const never = await start(okcrypto, config);
  assert.equal(okcrypto.signs, 4, 'a new lifetime: a new certificate');
  assert.equal(never, Infinity, 'expires 0: it never expires');
});
