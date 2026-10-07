'use strict';

/*
 * Edge and Key Chain's certificate (step 3a: the test moved here from Key Chain's,
 * which must not need Edge). A certificate's self-signatures are PHYSICAL PRESSES,
 * never paid by an Edge budget - even under a live budget that covers that very
 * label - and an ordinary press is not Edge: no link, nothing owed.
 */
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');

const openpgp = require('../src/vendor/openpgp/openpgp.js');
const { request, approve, client, chain } = require('../src/edge');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');
const agentProto = require('../src/protocol/agent');
const certLib = require('../keychain/src/cert');

const AGENT = request.signerFromSecret(new Uint8Array(32).fill(43));
const hex = (b) => Buffer.from(b).toString('hex');
const UID = 'Claude (test) 2026 <claude+agent@test>';
const LABEL = `gpg://${UID}`;

async function stack() {
  const transport = fakeKey();
  const edge = edgeOver(transport);
  await edge.ticket(0, 0, new Uint8Array(32));
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
        /* the key decides: an unarmed sign is a press (the fake, like the firmware) */
        transport.use(new Uint8Array([...digest, ...agentProto.identityHash(identity)]), { slot: 221 });
        return new Uint8Array(crypto.sign(null, Buffer.from(digest), keyOf(identity, 1).privateKey));
      },
    },
  };
  const seen = new Set();
  const channel = {
    async send(msg) {
      const r = await approve.approveRequest(msg, {
        edge, registered: [hex(AGENT.publicKey)], seen, ask: async () => 'approve',
        verifyCopy: async () => ({ ok: true, head: (await edge.head()).head }), timeoutMs: 2000,
      });
      return r.dropped ? null : r;
    },
  };
  const c = client.createEdgeClient({ edge, channel, signer: AGENT });
  /* a live budget that covers THIS label */
  const b = await c.request({ reason: 'work', scopes: [{ op: 'sign', slot: 221, cap: 4, identity: LABEL }], ttlMinutes: 60 });
  const links = async (n) => {
    const h = await edge.head();
    return (await edge.pickup(h.seq - n + 1, n)).map((r) => chain.decodeLink(r.link));
  };
  return { okcrypto, edge, b, links, presses };
}

test('a certificate under a live budget covering its label: both self-signatures are ordinary presses - no link, the budget pays nothing (2026-10-06)', async () => {
  const s = await stack();
  const before = await s.edge.head();
  let pressed = 0;
  const c = await certLib.makeCertificate(s.okcrypto, openpgp, { label: LABEL, expires: 365 * 86400, onPress: () => { pressed += 1; } });
  assert.equal(pressed, 2, 'the user ID certification and the subkey binding: two presses asked for');
  const after = await s.edge.head();
  assert.equal(after.seq, before.seq, 'an ordinary press is not Edge: no link');
  assert.equal(after.owed, 0, 'and nothing owed');
  const key = await openpgp.readKey({ armoredKey: c.armored });
  assert.equal(key.getUserIDs()[0], UID);
  assert.equal(Math.round(((await key.getExpirationTime()).getTime() / 1000 - c.created) / 86400), 365);
});
