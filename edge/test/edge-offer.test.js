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

/* the fake starts with one use owing its result (#0): a complete log has its receipt, with a message */
const DONE0 = 'done #0';
async function deviceLog(links = 3, { result = true } = {}) {
  const t = fakeKey({ secret: p256.utils.randomSecretKey() });
  const e = edgeOver(t);
  if (result) await e.receipt(0, 0, require('../src').receipts.messageHash(DONE0));
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
  for (const x of [a, b]) copy.keepNotes(home, x.log.deviceId, { messages: { 0: DONE0 } });
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
  assert.deepEqual(r, { sent: 4, held: true, count: 3 }); /* #3-#6: the log now holds #0's receipt too */
  assert.deepEqual(sent.map((m) => m.type), [sync.HAVE_TYPE, sync.LINKS_TYPE, sync.OFFER_TYPE]);
  const links = sent[1].payload.links.map(([l]) => chain.decodeLink(Buffer.from(l, 'hex')).seq);
  assert.deepEqual(links, [3, 4, 5, 6]);
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


/*
 * A key with no link yet (a new phone's first sync, 2026-10-08) signs its checkpoint as NO_SEQ.
 * The check read it as a seq and counted toward four billion: the computer's sync hung after the
 * key's CHECKPOINT. Now: an empty chain checks at once, and the computer keeps nothing to offer.
 */
test('an empty chain (checkpoint NO_SEQ) checks at once and is not kept to offer', async () => {
  const secret = p256.utils.randomSecretKey();
  const e = edgeOver(fakeKey({ secret }));
  const { publicKey, deviceId } = await e.publicKey();
  const head = chain.genesis(deviceId);
  const signature = chain.signCheckpoint({ deviceId, seq: sync.NO_SEQ, head }, secret);
  const checkpoint = { seq: sync.NO_SEQ, head, signature };
  const t0 = Date.now();
  assert.deepEqual(sync.anchorCheck({ records: [], publicKey, checkpoint, anchors: [] }), { ok: true, verifiedThrough: -1, open: false });
  assert.ok(Date.now() - t0 < 1000, 'checked at once');
  const other = await deviceLog(1);
  assert.equal(sync.anchorCheck({ records: other.log.records, publicKey, checkpoint, anchors: [] }).ok, false, 'links past an empty checkpoint');
  const statement = await e.statement('Pixel');
  assert.deepEqual(copy.keepLog(tmp(), { deviceId, publicKey, records: [], checkpoint, statement }), { kept: false, why: 'its key has no link yet' });
});

/*
 * A LATE OR RESET COMPUTER (2026-10-08, walking the setup flow): the key's ring holds only its
 * 8 newest links, so a fresh copy began at the ring - "gap" - and could never check the chain
 * from genesis, keep the statement or offer the log. The phone's own history fills the gap,
 * judged against the KEY's head and ring; a history that does not weld is refused, not kept.
 */
test('copy.sync: the phone\'s history fills a gap before the key\'s ring; a forged history is refused', async () => {
  const t = fakeKey({ secret: p256.utils.randomSecretKey() });
  const e = edgeOver(t);
  for (let i = 0; i < 12; i += 1) t.edgeRecord();
  const all = [...(await e.pickup(0, 8)), ...(await e.pickup(8, 5))];
  const ringed = {
    publicKey: () => e.publicKey(),
    head: async () => { const h = await e.head(); return { ...h, oldest: h.seq - 7 }; },
    pickup: async (from, n) => { const h = await e.head(); const lo = h.seq - 7; return from < lo ? [] : e.pickup(from, n); },
  };
  const home = tmp();
  const first = await copy.sync(ringed, home);
  assert.equal(first.verdict.kind, 'gap');
  const forged = all.map((r, i) => (i === 3 ? { ...r, link: Uint8Array.from(r.link, (x, j) => (j === 40 ? x ^ 1 : x)) } : r));
  const bad = await copy.sync(ringed, tmp(), { history: forged });
  assert.notEqual(bad.verdict.kind, 'verified', 'a forged history must not verify');
  const good = await copy.sync(ringed, home, { history: all });
  assert.equal(good.verdict.kind, 'verified');
  assert.equal(copy.load(home, (await e.publicKey()).deviceId).links.length, all.length);
});

/*
 * COMPLETE BEFORE ANOTHER DATA STORE (Brad, 2026-10-09: "a data store must contain all info about
 * the usage of the credental, including the result"): a use without its result, or a receipt whose
 * message did not arrive, keeps the log out of the computer's copy to offer - with the reason.
 */
test('a log missing a use\'s result or a receipt\'s message is not kept to offer', async () => {
  const waiting = await deviceLog(1, { result: false });
  const h1 = tmp();
  const r1 = copy.keepLog(h1, waiting.log);
  assert.equal(r1.kept, false);
  assert.match(r1.why, /not complete - #0: no result/);
  const noMessage = await deviceLog(1);
  const r2 = copy.keepLog(tmp(), noMessage.log);
  assert.equal(r2.kept, false);
  assert.match(r2.why, /message of receipt #\d+ did not arrive/);
  const h3 = tmp();
  copy.keepNotes(h3, noMessage.log.deviceId, { messages: { 0: 'something else' } });
  assert.match(copy.keepLog(h3, noMessage.log).why, /does not match the chain/);
  copy.keepNotes(h3, noMessage.log.deviceId, { messages: { 0: DONE0 } });
  assert.deepEqual(copy.keepLog(h3, noMessage.log), { kept: true });
});
