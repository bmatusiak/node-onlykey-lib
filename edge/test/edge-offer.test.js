'use strict';
/*
 * Offering another device's log (2026-10-08): the computer keeps your other devices' logs
 * (cli/copy.js keepLog / logsToOffer) and offers each to a phone - HAVE, the LINKS it
 * lacks, then OFFER with that device's owner statement - and the phone HOLDS it until you
 * approve (Brad: "hold these blocks in the app until approved and merged").
 */
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const { p256 } = require('../../src/vendor/exports/@noble/curves/nist.js');
const { client, sync, request, chain } = require('../src');
const copy = require('../cli/copy');
const { fakeKey, edgeOver } = require('./helpers/fake-edge-key');

async function deviceLog(links = 3) {
  const t = fakeKey({ secret: p256.utils.randomSecretKey() });
  const e = edgeOver(t);
  for (let i = 0; i < links; i += 1) t.edgeRecord();
  const { publicKey, deviceId } = await e.publicKey();
  const h = await e.head();
  return { t, e, log: { deviceId, publicKey, records: await e.pickup(0, h.seq + 1), checkpoint: await e.checkpoint(), statement: await e.statement('hard key') } };
}
const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'okedge-offer-'));

test('the computer keeps another device\'s log only when its chain checks and the statement names it; a newer one replaces it, an older one never', async () => {
  const home = tmp();
  const a = await deviceLog();
  const b = await deviceLog();
  assert.deepEqual(copy.keepLog(home, a.log), { kept: true });
  const swapped = copy.keepLog(home, { ...a.log, statement: b.log.statement });
  assert.equal(swapped.kept, false);
  assert.match(swapped.why, /does not name this device/);
  const tampered = a.log.records.map((r, i) => (i === 1 ? { ...r, link: Uint8Array.from(r.link, (x, j) => (j === 50 ? x ^ 1 : x)) } : r));
  assert.match(copy.keepLog(home, { ...a.log, records: tampered }).why, /does not check/);
  a.t.edgeRecord();
  const h = await a.e.head();
  const newer = { ...a.log, records: await a.e.pickup(0, h.seq + 1), checkpoint: await a.e.checkpoint() };
  assert.deepEqual(copy.keepLog(home, newer), { kept: true });
  assert.match(copy.keepLog(home, a.log).why, /already holds it up to/);
  assert.equal(copy.load(home, a.log.deviceId).checkpoint.seq, h.seq);
  assert.equal(copy.load(home, a.log.deviceId).statement.nametag, 'hard key');
  copy.keepLog(home, b.log);
  const offers = copy.logsToOffer(home, a.log.deviceId).map((c) => Buffer.from(c.deviceId).toString('hex'));
  assert.deepEqual(offers, [Buffer.from(b.log.deviceId).toString('hex')], 'every log but the phone being synced');
});

test('offerToPhone: HAVE, only the links the phone lacks, then a signed OFFER carrying the checkpoint and the statement', async () => {
  const { log } = await deviceLog(5);
  const phoneId = new Uint8Array(16).fill(4);
  const signer = request.peerSignerFromSecret(p256.utils.randomSecretKey());
  const sent = [];
  const channel = {
    async send(msg) {
      assert.equal(sync.verify(msg).ok, true, `${msg.type} verifies on the phone`);
      sent.push(msg);
      if (msg.type === sync.HAVE_TYPE) return { ok: true, ranges: [[0, 2]] }; /* the phone holds #0-#2 of that chain already */
      if (msg.type === sync.OFFER_TYPE) return { ok: true, held: true, count: 3 };
      return { ok: true };
    },
  };
  const c = client.createEdgeClient({ edge: null, channel, signer: null });
  const r = await c.offerToPhone(signer, { deviceId: phoneId, chain: log.deviceId, records: log.records, checkpoint: log.checkpoint, statement: log.statement, name: 'NITRO16' });
  assert.deepEqual(r, { sent: 3, held: true, count: 3 });
  assert.deepEqual(sent.map((m) => m.type), [sync.HAVE_TYPE, sync.LINKS_TYPE, sync.OFFER_TYPE]);
  const links = sent[1].payload.links.map(([l]) => chain.decodeLink(Buffer.from(l, 'hex')).seq);
  assert.deepEqual(links, [3, 4, 5]);
  const offer = sent[2].payload;
  assert.equal(offer.chain, Buffer.from(log.deviceId).toString('hex'));
  assert.equal(offer.checkpoint.seq, log.checkpoint.seq);
  assert.equal(offer.statement.nametag, 'hard key');
  assert.equal(offer.statement.publicKey, Buffer.from(log.publicKey).toString('hex'));
});

test('an OFFER without a statement, or with a malformed checkpoint, is dropped by the phone unread', async () => {
  const signer = request.peerSignerFromSecret(p256.utils.randomSecretKey());
  const { log } = await deviceLog(1);
  const good = await sync.buildOffer({ signer, deviceId: new Uint8Array(16), sid: '00'.repeat(8), chain: log.deviceId, linkParts: 0, checkpoint: log.checkpoint, statement: log.statement });
  assert.equal(sync.verify(good).ok, true);
  for (const bad of [
    { ...good, payload: { ...good.payload, statement: null } },
    { ...good, payload: { ...good.payload, checkpoint: { ...good.payload.checkpoint, head: 'zz' } } },
    { ...good, payload: { ...good.payload, statement: { ...good.payload.statement, nametag: '  ' } } },
  ]) assert.equal(sync.verify(bad).ok, false);
});
